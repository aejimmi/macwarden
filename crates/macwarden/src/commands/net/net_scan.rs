//! `macwarden net scan` -- active connection scan with rule evaluation,
//! GeoIP enrichment, byte counters, and metrics recording.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tracing::{debug, warn};

use net::{AddressFamily, Destination, GeoLookup, NetworkAction, ProcessIdentity, TrackerDatabase};

use super::net_lsof::{LsofConnection, collect_lsof_connections};
use super::net_rdns::resolve_bare_ips;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A parsed connection from lsof, enriched with rule evaluation results.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScanEntry {
    /// Process name from lsof.
    pub process: String,
    /// Process ID.
    pub pid: u32,
    /// Code signing identity, if resolved.
    pub code_id: Option<String>,
    /// Remote hostname or IP.
    pub destination: String,
    /// Remote port (0 if unknown).
    pub port: u16,
    /// Protocol (TCP or UDP).
    pub protocol: String,
    /// Firewall action (ALLOW, DENY, LOG).
    pub action: String,
    /// Tracker category, if the destination is a known tracker.
    pub tracker: Option<String>,
    /// ISO country code from GeoIP (e.g. "US").
    pub country: Option<String>,
    /// Autonomous system name (e.g. "GOOGLE").
    pub asn_name: Option<String>,
    /// Bytes received by this process (best-effort, process-level).
    pub bytes_in: Option<u64>,
    /// Bytes sent by this process (best-effort, process-level).
    pub bytes_out: Option<u64>,
    /// Well-known service name for the port (e.g. "SSH", "DNS").
    pub service: Option<String>,
}

/// Table row for display.
#[derive(Debug, Tabled)]
struct ScanRow {
    #[tabled(rename = "Process")]
    process: String,
    #[tabled(rename = "Destination")]
    destination: String,
    #[tabled(rename = "Port")]
    port: String,
    #[tabled(rename = "Down")]
    bytes_in: String,
    #[tabled(rename = "Up")]
    bytes_out: String,
    #[tabled(rename = "Country")]
    country: String,
    #[tabled(rename = "Owner")]
    owner: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "Tracker")]
    tracker: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run `macwarden net scan`.
pub(super) fn run(
    process_filter: Option<&str>,
    denied_only: bool,
    trackers_only: bool,
    json: bool,
) -> Result<()> {
    let rule_set = super::build_base_ruleset()?;
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;

    let geo = match GeoLookup::new() {
        Ok(g) => Some(g),
        Err(e) => {
            warn!("GeoIP databases unavailable: {e}");
            None
        }
    };

    let raw = collect_lsof_connections().context("failed to collect network connections")?;
    let mut entries: Vec<ScanEntry> = raw
        .into_iter()
        .map(|lsof| evaluate_connection(lsof, &rule_set, &tracker_db, geo.as_ref()))
        .collect();

    // Filter out link-local/localhost noise by default
    entries.retain(|e| !is_local_noise(&e.destination));

    // Batch reverse DNS for entries that are still bare IPs.
    resolve_bare_ips(&mut entries, &tracker_db);

    // Dedup by (display_process, destination) -- collapse same app+host
    entries.sort_by(|a, b| {
        display_process(a)
            .cmp(&display_process(b))
            .then_with(|| a.destination.cmp(&b.destination))
    });
    entries.dedup_by(|a, b| {
        display_process(a) == display_process(b) && a.destination == b.destination
    });

    apply_filters(&mut entries, process_filter, denied_only, trackers_only);

    record_metrics(&entries);

    if json {
        let out = serde_json::to_string_pretty(&entries)
            .context("failed to serialize scan results as JSON")?;
        println!("{out}");
        return Ok(());
    }

    if entries.is_empty() {
        println!("No active network connections match the given filters.");
        return Ok(());
    }

    print_scan_table(&entries);
    Ok(())
}

/// Apply CLI filters to the scan entries.
fn apply_filters(
    entries: &mut Vec<ScanEntry>,
    process_filter: Option<&str>,
    denied_only: bool,
    trackers_only: bool,
) {
    if let Some(pf) = process_filter {
        let pf_lower = pf.to_ascii_lowercase();
        entries.retain(|e| {
            e.process.to_ascii_lowercase().contains(&pf_lower)
                || e.code_id
                    .as_deref()
                    .is_some_and(|id| id.to_ascii_lowercase().contains(&pf_lower))
        });
    }
    if denied_only {
        entries.retain(|e| e.action == "DENY");
    }
    if trackers_only {
        entries.retain(|e| e.tracker.is_some());
    }
}

// ---------------------------------------------------------------------------
// Code signing enrichment
// ---------------------------------------------------------------------------

/// Try to get a code signing identity for a process via procmon.
#[cfg(target_os = "macos")]
pub(crate) fn lookup_code_id(pid: u32, process_name: &str) -> Option<String> {
    let path = procmon_path(pid)?;
    match procmon::code_signing::get_code_signing_info(pid, &path) {
        Ok(info) => info.code_id,
        Err(e) => {
            debug!(pid, %process_name, %e, "code signing lookup failed");
            None
        }
    }
}

/// Get the executable path for a PID via libproc.
#[cfg(target_os = "macos")]
fn procmon_path(pid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: buf is a valid buffer of sufficient size. proc_pidpath
    // writes a null-terminated path string into it.
    #[allow(unsafe_code)]
    let len = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    let path_str = std::str::from_utf8(buf.get(..len as usize)?).ok()?;
    Some(PathBuf::from(path_str))
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn lookup_code_id(_pid: u32, _process_name: &str) -> Option<String> {
    None
}

/// Best-effort network byte counters for a process.
///
/// Returns `(bytes_in, bytes_out)` as `Option` values. On failure
/// (wrong PID, permission denied, non-macOS), returns `(None, None)`.
#[cfg(target_os = "macos")]
fn lookup_network_usage(pid: u32) -> (Option<u64>, Option<u64>) {
    match procmon::rusage::get_network_usage(pid) {
        Ok(usage) => (Some(usage.bytes_in), Some(usage.bytes_out)),
        Err(e) => {
            debug!(pid, %e, "network usage lookup failed");
            (None, None)
        }
    }
}

/// Non-macOS stub -- byte counters are not available.
#[cfg(not(target_os = "macos"))]
fn lookup_network_usage(_pid: u32) -> (Option<u64>, Option<u64>) {
    (None, None)
}

// ---------------------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------------------

/// Evaluate a single lsof connection against the rule set and tracker DB.
pub(crate) fn evaluate_connection(
    conn: LsofConnection,
    rule_set: &net::RuleSet,
    tracker_db: &TrackerDatabase,
    geo: Option<&GeoLookup>,
) -> ScanEntry {
    let code_id = lookup_code_id(conn.pid, &conn.process);
    let protocol = if conn.protocol == "UDP" {
        Some(net::Protocol::Udp)
    } else {
        Some(net::Protocol::Tcp)
    };
    let ip: IpAddr = conn
        .remote_host
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    // If lsof resolved the hostname, check if it's garbage (EC2-style auto-generated rDNS).
    // If garbage, drop it and use the IP -- our rDNS pass will try again or leave as IP.
    let host = if conn.remote_host.parse::<IpAddr>().is_ok() || is_lsof_garbage(&conn.remote_host) {
        None
    } else {
        Some(conn.remote_host.clone())
    };

    let process_identity = ProcessIdentity {
        pid: conn.pid,
        uid: 0,
        path: PathBuf::from(format!("/proc/{}", conn.process)),
        code_id: code_id.clone(),
        team_id: None,
        is_valid_signature: None,
    };
    let destination = Destination {
        host: host.clone(),
        ip,
        port: Some(conn.remote_port),
        protocol,
        address_family: if ip.is_ipv6() {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        },
    };

    let decision = rule_set.decide_for(&process_identity, &destination);
    let action_str = match decision.action {
        NetworkAction::Allow => "ALLOW",
        NetworkAction::Deny => "DENY",
        NetworkAction::Log => "LOG",
    };

    let tracker = host
        .as_deref()
        .and_then(|h| tracker_db.lookup(h).map(|m| m.category.to_string()));

    // GeoIP enrichment — skip for local network IPs (always returns None).
    let geo_info = if net::is_local_network(&ip) {
        net::GeoInfo::default()
    } else {
        geo.map_or_else(Default::default, |g| g.lookup(ip))
    };

    // Service name for the port
    let service = net::services::service_name(conn.remote_port).map(ToOwned::to_owned);

    // Best-effort byte counters
    let (bytes_in, bytes_out) = lookup_network_usage(conn.pid);

    ScanEntry {
        process: conn.process,
        pid: conn.pid,
        code_id,
        destination: host.unwrap_or_else(|| ip.to_string()),
        port: conn.remote_port,
        protocol: conn.protocol,
        action: action_str.to_owned(),
        tracker,
        country: geo_info.country,
        asn_name: geo_info.asn_name,
        bytes_in,
        bytes_out,
        service,
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Print the scan results as a table with summary.
fn print_scan_table(entries: &[ScanEntry]) {
    let rows: Vec<ScanRow> = entries
        .iter()
        .map(|e| ScanRow {
            process: truncate(&display_process(e), 28),
            destination: truncate(&e.destination, 48),
            port: format_port(e.port, e.service.as_deref()),
            bytes_in: format_bytes(e.bytes_in.unwrap_or(0)),
            bytes_out: format_bytes(e.bytes_out.unwrap_or(0)),
            country: e.country.clone().unwrap_or_else(|| {
                // Show "LAN" for local network IPs instead of "-".
                if e.destination
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| net::is_local_network(&ip))
                {
                    "LAN".to_owned()
                } else {
                    "-".to_owned()
                }
            }),
            owner: e
                .asn_name
                .as_deref()
                .map_or_else(|| "-".to_owned(), |n| truncate(n, 20)),
            action: e.action.clone(),
            tracker: e.tracker.clone().unwrap_or_default(),
        })
        .collect();

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("Active Network Connections");
    println!("{table}");
    print_summary(entries);
}

/// Print the summary line after the table.
fn print_summary(entries: &[ScanEntry]) {
    let total = entries.len();
    let pids: std::collections::HashSet<u32> = entries.iter().map(|e| e.pid).collect();
    let tracker_count = entries.iter().filter(|e| e.tracker.is_some()).count();

    print!("\n{total} connections, {} processes", pids.len());
    if tracker_count > 0 {
        print!(" ({tracker_count} tracker connections detected)");
    }
    println!();

    let shield = super::net_shield::load_shield_config();
    if shield.enabled {
        println!("Tracker shield: ACTIVE");
    } else {
        println!("Tracker shield: MONITOR mode (use `macwarden net shield` to block)");
    }
}

/// Display a friendly process name: extracts last meaningful component from
/// the code signing identity, or falls back to the lsof process name.
fn display_process(e: &ScanEntry) -> String {
    if let Some(ref code_id) = e.code_id {
        format_code_id(code_id)
    } else {
        e.process.clone()
    }
}

/// Extract a short display name from a reverse-DNS code signing identity.
/// Strips common vendor prefixes and returns the remaining suffix.
pub(crate) fn format_code_id(code_id: &str) -> String {
    let parts: Vec<&str> = code_id.splitn(4, '.').collect();
    match parts.len() {
        // "com.apple.WebKit.Networking" -> parts = ["com","apple","WebKit","Networking"]
        // Return "WebKit.Networking" (everything after vendor prefix).
        4.. => parts
            .get(2..)
            .map_or_else(|| code_id.to_owned(), |rest| rest.join(".")),
        // "com.google.Chrome" -> "Chrome"
        3 => parts
            .last()
            .map_or_else(|| code_id.to_owned(), |s| (*s).to_owned()),
        // Anything shorter: return as-is.
        _ => code_id.to_owned(),
    }
}

/// Check if a hostname from lsof is auto-generated garbage (EC2, Cloudfront, etc.).
pub(crate) fn is_lsof_garbage(hostname: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    // AWS auto-generated rDNS
    h.starts_with("ec2-")
        || h.contains(".compute.amazonaws.com")
        || h.contains(".compute-1.amazonaws.com")
        // Google auto-generated rDNS
        || h.contains(".bc.googleusercontent.com")
        || h.ends_with(".1e100.net")
        // CDN auto-generated rDNS
        || h.contains(".cloudfront.net")
        || h.contains(".cdn77.com")
        || (h.starts_with("server-") && h.contains(".r."))
        // DNS infrastructure
        || h.contains("in-addr.arpa")
        // Numeric-prefix hostnames (CDN node IDs like "125848246.nyc.cdn77.com")
        || h.split('.').next().is_some_and(|first| {
            first.len() > 4 && first.chars().all(|c| c.is_ascii_digit())
        })
}

/// Check if a destination is local network noise (link-local, localhost, multicast, unspecified).
pub(crate) fn is_local_noise(dest: &str) -> bool {
    dest.starts_with("fe80:")
        || dest.starts_with("127.")
        || dest.starts_with("::1")
        || dest.starts_with("224.")
        || dest.starts_with("ff0")
        || dest == "localhost"
        || dest == "*"
        || dest == "0.0.0.0"
        || dest == "::"
}

/// Truncate a string to fit in a table column.
fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_owned()
    }
}

/// Format a byte count as a human-readable string.
///
/// Returns "-" for zero/unknown, otherwise "256 B", "1.2 KB", "3.4 MB", etc.
pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "-".to_owned();
    }
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    if bytes < 1024 * 1024 * 1024 {
        return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0));
    }
    format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Format port number, substituting service name when available.
fn format_port(port: u16, service: Option<&str>) -> String {
    match service {
        Some(name) => format!("{port}/{name}"),
        None => port.to_string(),
    }
}

/// Best-effort metrics recording for scan entries. Never fails the scan.
fn record_metrics(entries: &[ScanEntry]) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let db_path = std::path::PathBuf::from(home)
        .join(".macwarden")
        .join("metrics.db");
    let Ok(store) = metrics::MetricsStore::open(&db_path) else {
        debug!("metrics store unavailable");
        return;
    };
    for entry in entries {
        let event = metrics::MetricEvent::ConnectionDecided {
            app_id: entry.code_id.clone(),
            dest_host: Some(entry.destination.clone()),
            dest_ip: entry.destination.clone(),
            action: entry.action.to_ascii_lowercase(),
            tier: "scan".to_owned(),
            rule_name: None,
            tracker_category: entry.tracker.clone(),
        };
        if let Err(e) = store.record(&event) {
            debug!(error = %e, "failed to record scan metric");
        }
    }
}

#[cfg(test)]
#[path = "net_scan_test.rs"]
mod net_scan_test;
