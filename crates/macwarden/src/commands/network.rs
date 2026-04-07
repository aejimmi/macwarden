//! `macwarden network` — show which services have active network connections.
//!
//! Cross-references `lsof -i` output with launchctl services and service
//! groups to show what's phoning home right now.

use std::collections::HashMap;
use std::process::Command;

use anyhow::Result;
use tabled::settings::Style;
use tabled::{Table, Tabled};

use catalog::load_builtin_groups;
use launchd::{MacOsPlatform, Platform};
use policy::{ServiceGroup, find_groups_for_service};

use crate::cli::OutputFormat;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A network connection tied to a process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetEntry {
    /// Process ID.
    pub pid: u32,
    /// Raw process name from lsof.
    pub process: String,
    /// Resolved service label from launchctl.
    pub service: Option<String>,
    /// Service group name from catalog.
    pub group: Option<String>,
    /// Raw connection string from lsof (e.g. `192.168.1.1:49792->1.2.3.4:443`).
    pub connection: String,
    /// Connection type: ESTABLISHED, LISTEN, UDP, etc.
    pub conn_type: String,
    /// Parsed remote IP address.
    pub remote_ip: Option<String>,
    /// Resolved remote hostname via rDNS.
    pub remote_host: Option<String>,
    /// Parsed remote port number.
    pub remote_port: Option<u16>,
    /// ISO 3166-1 alpha-2 country code from GeoIP.
    pub country: Option<String>,
    /// ASN owner name from GeoIP (e.g. "GOOGLE").
    pub owner: Option<String>,
    /// Tracker category if destination matches tracker database.
    pub tracker: Option<String>,
    /// Code signing identity of the process.
    pub code_id: Option<String>,
}

#[derive(Debug, Tabled)]
struct NetRow {
    #[tabled(rename = "Group")]
    group: String,
    #[tabled(rename = "Process")]
    process: String,
    #[tabled(rename = "Remote")]
    remote: String,
    #[tabled(rename = "Country")]
    country: String,
    #[tabled(rename = "Owner")]
    owner: String,
    #[tabled(rename = "Tracker")]
    tracker: String,
    #[tabled(rename = "Type")]
    conn_type: String,
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `network` command.
#[allow(clippy::unnecessary_wraps)]
pub fn run(format: OutputFormat, all: bool) -> Result<()> {
    let groups = load_builtin_groups();

    // Build PID → service label map from launchctl
    let platform = MacOsPlatform::new();
    let pid_to_label: HashMap<u32, String> = platform
        .enumerate()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| e.pid.map(|p| (p, e.label)))
        .collect();

    // Get network connections and enrich with GeoIP, rDNS, code signing, trackers
    let mut entries = collect_network_connections(&pid_to_label, &groups);
    super::network_enrich::enrich_entries(&mut entries);

    // Dedup by (display_process, remote_ip) to collapse multiple connections
    // from the same app to the same host.
    entries.sort_by(|a, b| {
        let rank = |e: &NetEntry| -> u8 {
            if e.group.is_some() {
                0
            } else if e.service.is_some() {
                1
            } else {
                2
            }
        };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.group.cmp(&b.group))
            .then_with(|| {
                super::network_enrich::display_process(a)
                    .cmp(&super::network_enrich::display_process(b))
            })
            .then_with(|| a.remote_ip.cmp(&b.remote_ip))
    });
    entries.dedup_by(|a, b| {
        super::network_enrich::display_process(a) == super::network_enrich::display_process(b)
            && a.remote_ip.is_some()
            && a.remote_ip == b.remote_ip
    });

    // Filter: by default skip LISTEN, wildcard, and link-local/private addresses
    let filtered: Vec<&NetEntry> = if all {
        entries.iter().collect()
    } else {
        entries
            .iter()
            .filter(|e| e.conn_type != "LISTEN" && !e.connection.contains("*:*"))
            .filter(|e| {
                // Skip link-local and private addresses unless --all
                e.remote_ip.as_deref().is_none_or(|ip_str| {
                    ip_str
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| !super::network_enrich::is_local_addr(&ip))
                })
            })
            .collect()
    };

    if filtered.is_empty() {
        println!("No active network connections found.");
        return Ok(());
    }

    match format {
        OutputFormat::Table => print_table(&filtered),
        OutputFormat::Json => {
            let json =
                serde_json::to_string_pretty(&filtered).expect("serialization should not fail");
            println!("{json}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// Parse `lsof -i -n -P` and cross-reference with services and groups.
pub(crate) fn collect_network_connections_pub(
    pid_to_label: &HashMap<u32, String>,
    groups: &[ServiceGroup],
) -> Vec<NetEntry> {
    collect_network_connections(pid_to_label, groups)
}

/// Parse `lsof -i -n -P` and cross-reference with services and groups.
fn collect_network_connections(
    pid_to_label: &HashMap<u32, String>,
    groups: &[ServiceGroup],
) -> Vec<NetEntry> {
    let output = Command::new("lsof").args(["-i", "-n", "-P"]).output().ok();

    let Some(output) = output else {
        return vec![];
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let Some(process_str) = parts.first() else {
            continue;
        };
        let process = (*process_str).to_owned();
        let Some(pid_str) = parts.get(1) else {
            continue;
        };
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let conn_type = classify_connection(
            parts.get(7).copied().unwrap_or(""),
            parts.last().copied().unwrap_or(""),
        );
        let connection = parts.get(8).unwrap_or(&"").to_string();

        let label = pid_to_label.get(&pid).cloned();

        // Classify: check service groups, detect user apps, resolve process names
        let (service_name, group_name) = classify_process(label.as_ref(), &process, groups);

        entries.push(NetEntry {
            pid,
            process: process.clone(),
            service: Some(service_name),
            group: group_name,
            connection,
            conn_type,
            remote_ip: None,
            remote_host: None,
            remote_port: None,
            country: None,
            owner: None,
            tracker: None,
            code_id: None,
        });
    }

    entries
}

/// Classify a process: extract a clean service name and group.
///
/// Handles: launchctl services in known groups, user applications
/// (`application.com.spotify.*`), and bare process names.
fn classify_process(
    label: Option<&String>,
    process_name: &str,
    groups: &[ServiceGroup],
) -> (String, Option<String>) {
    if let Some(l) = label {
        // Check known groups first
        if let Some(g) = find_groups_for_service(l, groups).first() {
            return (l.clone(), Some(g.name.clone()));
        }

        // User application: "application.com.spotify.client.56862295.56862982"
        if l.starts_with("application.") {
            let app_name = extract_app_name(l);
            return (app_name, Some("applications".to_owned()));
        }

        // Known service but not in a group
        return (l.clone(), None);
    }

    // No launchctl label — use the process name, clean it up
    let clean = if process_name.contains('.') && process_name.len() < 6 {
        // Likely a version number like "2.1.87" — resolve via ps
        resolve_process_name(process_name)
    } else {
        process_name.to_owned()
    };

    (clean, Some("applications".to_owned()))
}

/// Extract a clean app name from a launchctl application label.
///
/// `application.com.spotify.client.56862295.56862982` → `Spotify`
/// `application.com.raycast.macos.22437190.53410052.xxx` → `Raycast`
fn extract_app_name(label: &str) -> String {
    let stripped = label.strip_prefix("application.").unwrap_or(label);
    // Split reverse-DNS: com.spotify.client.12345... → take the second segment
    let parts: Vec<&str> = stripped.split('.').collect();
    if let Some(&name) = parts.get(1) {
        // Capitalize: "spotify" → "Spotify"
        let mut chars = name.chars();
        match chars.next() {
            Some(c) => format!("{}{}", c.to_uppercase(), chars.as_str()),
            None => name.to_owned(),
        }
    } else {
        stripped.to_owned()
    }
}

/// Try to resolve a cryptic process name to something readable via `ps`.
fn resolve_process_name(name: &str) -> String {
    // "2.1.87" is Claude Code — its binary is named by version.
    // Try to find a better name from the command line.
    // This is best-effort; fall back to the original name.
    let _ = name; // For now, return common known mappings
    name.to_owned()
}

/// Classify a connection as ESTABLISHED, LISTEN, or UDP.
fn classify_connection(node: &str, state: &str) -> String {
    if state.contains("ESTABLISHED") {
        "ESTABLISHED".to_owned()
    } else if state.contains("LISTEN") {
        "LISTEN".to_owned()
    } else if node == "UDP" {
        "UDP".to_owned()
    } else {
        state.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_table(entries: &[&NetEntry]) {
    let rows: Vec<NetRow> = entries
        .iter()
        .map(|e| NetRow {
            group: e.group.clone().unwrap_or_else(|| {
                if e.service.is_some() {
                    "\u{b7}".to_owned()
                } else {
                    "\u{2014}".to_owned()
                }
            }),
            process: truncate(&super::network_enrich::display_process(e), 30),
            remote: truncate(&super::network_enrich::display_remote(e), 48),
            country: e.country.clone().unwrap_or_else(|| "-".to_owned()),
            owner: e
                .owner
                .as_deref()
                .map_or_else(|| "-".to_owned(), |n| truncate(n, 20)),
            tracker: e.tracker.clone().unwrap_or_default(),
            conn_type: e.conn_type.clone(),
        })
        .collect();

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("{table}");

    let grouped = entries.iter().filter(|e| e.group.is_some()).count();
    let tracker_count = entries.iter().filter(|e| e.tracker.is_some()).count();
    let services = entries.iter().filter(|e| e.service.is_some()).count();
    print!(
        "\n{} connections ({} in known groups, {} from services, {} other)",
        entries.len(),
        grouped,
        services - grouped,
        entries.len() - services,
    );
    if tracker_count > 0 {
        print!(" -- {tracker_count} tracker connections detected");
    }
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
#[path = "network_test.rs"]
mod network_test;
