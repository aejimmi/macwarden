//! `macwarden net learn` — passive connection learning.
//!
//! Watches network connections over time, builds per-app traffic profiles,
//! and suggests firewall rules based on observed behavior.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use net::TrackerDatabase;

use super::net_lsof::collect_lsof_connections;
use super::net_scan::{
    format_bytes, format_code_id, is_local_noise, is_lsof_garbage, lookup_code_id,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Per-app learned traffic profile.
#[derive(Debug, Clone, serde::Serialize)]
struct AppProfile {
    process: String,
    code_id: Option<String>,
    display_name: String,
    destinations: HashMap<String, DestStats>,
    total_connections: u64,
    tracker_connections: u64,
    /// Cumulative bytes received (best-effort, process-level).
    bytes_in: u64,
    /// Cumulative bytes sent (best-effort, process-level).
    bytes_out: u64,
}

/// Per-destination statistics.
#[derive(Debug, Clone, serde::Serialize)]
struct DestStats {
    count: u64,
    tracker_category: Option<String>,
    port: u16,
}

/// Table row for the report.
#[derive(Debug, Tabled)]
struct ReportRow {
    #[tabled(rename = "App")]
    app: String,
    #[tabled(rename = "Destinations")]
    destinations: usize,
    #[tabled(rename = "Trackers")]
    trackers: u64,
    #[tabled(rename = "Down")]
    bytes_in: String,
    #[tabled(rename = "Up")]
    bytes_out: String,
    #[tabled(rename = "Connections")]
    connections: u64,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run `macwarden net learn`.
pub(super) fn run(duration: Option<&str>, apply: bool, json: bool) -> Result<()> {
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;

    let deadline = duration.map(parse_duration).transpose()?;

    let interrupted = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))
        .context("failed to register signal handler")?;

    println!("Learning network activity...");
    if let Some(d) = deadline {
        println!("Duration: {}s. Press Ctrl+C to stop early.\n", d.as_secs());
    } else {
        println!("Press Ctrl+C to stop and see results.\n");
    }

    let poll_interval = Duration::from_secs(3);
    let start = Instant::now();
    let mut profiles: HashMap<String, AppProfile> = HashMap::new();

    loop {
        if interrupted.load(Ordering::Relaxed) {
            break;
        }
        if deadline.is_some_and(|d| start.elapsed() >= d) {
            break;
        }

        if let Ok(connections) = collect_lsof_connections() {
            update_profiles(&mut profiles, &connections, &tracker_db);
        }

        let elapsed = start.elapsed().as_secs();
        let app_count = profiles.len();
        let dest_count: usize = profiles.values().map(|p| p.destinations.len()).sum();
        let tracker_count: u64 = profiles.values().map(|p| p.tracker_connections).sum();
        eprint!(
            "\r  {elapsed}s elapsed | {app_count} apps | {dest_count} destinations | {tracker_count} tracker hits    "
        );

        std::thread::sleep(poll_interval);
    }

    eprintln!(); // Clear progress line

    record_learn_metrics(&profiles);

    if json {
        let out =
            serde_json::to_string_pretty(&profiles).context("failed to serialize learn results")?;
        println!("{out}");
        return Ok(());
    }

    print_report(&profiles, start.elapsed());

    if apply {
        write_rule_files(&profiles, start.elapsed())?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile update
// ---------------------------------------------------------------------------

/// Process a batch of lsof connections into the profiles map.
fn update_profiles(
    profiles: &mut HashMap<String, AppProfile>,
    connections: &[super::net_lsof::LsofConnection],
    tracker_db: &TrackerDatabase,
) {
    // Collect unique PIDs for byte-counter lookups (one syscall per PID).
    let mut pid_bytes: HashMap<u32, (u64, u64)> = HashMap::new();
    for conn in connections {
        if pid_bytes.contains_key(&conn.pid) {
            continue;
        }
        let usage = lookup_pid_bytes(conn.pid);
        pid_bytes.insert(conn.pid, usage);
    }

    for conn in connections {
        if is_local_noise(&conn.remote_host) || is_lsof_garbage(&conn.remote_host) {
            continue;
        }

        let key = conn.process.clone();
        let profile = profiles.entry(key).or_insert_with(|| {
            let code_id = lookup_code_id(conn.pid, &conn.process);
            let display_name = match code_id.as_deref() {
                Some(id) => format_code_id(id),
                None => conn.process.clone(),
            };
            AppProfile {
                process: conn.process.clone(),
                code_id,
                display_name,
                destinations: HashMap::new(),
                total_connections: 0,
                tracker_connections: 0,
                bytes_in: 0,
                bytes_out: 0,
            }
        });

        profile.total_connections += 1;

        // Update byte counters from the latest reading for this PID.
        if let Some(&(bi, bo)) = pid_bytes.get(&conn.pid) {
            if bi > profile.bytes_in {
                profile.bytes_in = bi;
            }
            if bo > profile.bytes_out {
                profile.bytes_out = bo;
            }
        }

        let tracker = tracker_db
            .lookup(&conn.remote_host)
            .map(|m| m.category.to_string());
        if tracker.is_some() {
            profile.tracker_connections += 1;
        }

        let dest = profile
            .destinations
            .entry(conn.remote_host.clone())
            .or_insert(DestStats {
                count: 0,
                tracker_category: tracker,
                port: conn.remote_port,
            });
        dest.count += 1;
    }
}

/// Best-effort byte counter lookup for a PID.
#[cfg(target_os = "macos")]
fn lookup_pid_bytes(pid: u32) -> (u64, u64) {
    match procmon::rusage::get_network_usage(pid) {
        Ok(usage) => (usage.bytes_in, usage.bytes_out),
        Err(_) => (0, 0),
    }
}

/// Non-macOS stub.
#[cfg(not(target_os = "macos"))]
fn lookup_pid_bytes(_pid: u32) -> (u64, u64) {
    (0, 0)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Print the learning report.
fn print_report(profiles: &HashMap<String, AppProfile>, elapsed: Duration) {
    let mins = elapsed.as_secs() / 60;
    let secs = elapsed.as_secs() % 60;
    let elapsed_str = if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    };

    println!("Network Learning Report ({elapsed_str})\n");

    let mut rows: Vec<ReportRow> = profiles
        .values()
        .map(|p| ReportRow {
            app: p.display_name.clone(),
            destinations: p.destinations.len(),
            trackers: p.tracker_connections,
            bytes_in: format_bytes(p.bytes_in),
            bytes_out: format_bytes(p.bytes_out),
            connections: p.total_connections,
        })
        .collect();
    rows.sort_by(|a, b| b.connections.cmp(&a.connections));

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("{table}");

    // Tracker summary
    let tracker_apps: Vec<&AppProfile> = profiles
        .values()
        .filter(|p| p.tracker_connections > 0)
        .collect();

    if tracker_apps.is_empty() {
        println!("\nNo tracker connections detected.");
    } else {
        println!("\nTracker connections found:");
        for app in &tracker_apps {
            let tracker_dests: Vec<String> = app
                .destinations
                .iter()
                .filter_map(|(host, stats)| {
                    stats
                        .tracker_category
                        .as_ref()
                        .map(|cat| format!("{host} ({cat})"))
                })
                .collect();
            if !tracker_dests.is_empty() {
                println!("  {}:  {}", app.display_name, tracker_dests.join(", "));
            }
        }
    }

    println!("\nSuggested:");
    println!("  macwarden net shield         Block 215 known tracker domains");
    println!("  macwarden net learn --apply   Generate allow rules from this baseline");
}

// ---------------------------------------------------------------------------
// Rule generation
// ---------------------------------------------------------------------------

/// Write TOML rule files from learned profiles.
#[allow(clippy::indexing_slicing)] // format! strings are safe
fn write_rule_files(profiles: &HashMap<String, AppProfile>, elapsed: Duration) -> Result<()> {
    use std::fmt::Write as _;

    let rules_dir = dirs_path()?.join("net-rules");
    std::fs::create_dir_all(&rules_dir)
        .with_context(|| format!("failed to create {}", rules_dir.display()))?;

    let elapsed_secs = elapsed.as_secs();
    let mut written = 0u32;

    for profile in profiles.values() {
        let Some(code_id) = &profile.code_id else {
            continue;
        };

        // Group non-tracker destinations by base domain
        let mut base_domains: HashMap<&str, u64> = HashMap::new();
        for (host, stats) in &profile.destinations {
            if stats.tracker_category.is_some() {
                continue;
            }
            let base = extract_base_domain(host);
            *base_domains.entry(base).or_default() += stats.count;
        }

        if base_domains.is_empty() {
            continue;
        }

        let safe_name = profile
            .display_name
            .to_ascii_lowercase()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let file_path = rules_dir.join(format!("learned-{safe_name}.toml"));

        let tracker_excluded = profile
            .destinations
            .values()
            .filter(|s| s.tracker_category.is_some())
            .count();

        let mut content = String::new();
        let _ = writeln!(
            content,
            "# Auto-generated by `macwarden net learn` ({elapsed_secs}s)"
        );
        let _ = writeln!(
            content,
            "# {} connected to {} domains ({tracker_excluded} tracker domains excluded)\n",
            profile.display_name,
            base_domains.len(),
        );

        if let Some((domain, _)) = base_domains.iter().max_by_key(|&(_, &c)| c) {
            let _ = writeln!(
                content,
                "name = \"{} learned baseline\"",
                profile.display_name
            );
            let _ = writeln!(content, "process = \"{code_id}\"");
            let _ = writeln!(content, "dest = \"*.{domain}\"");
            let _ = writeln!(content, "action = \"allow\"");
            let _ = writeln!(content, "enabled = true");
            let _ = writeln!(
                content,
                "note = \"Learned from {elapsed_secs}s of observation\""
            );
        }

        std::fs::write(&file_path, &content)
            .with_context(|| format!("failed to write {}", file_path.display()))?;
        written += 1;
        println!("  Wrote {}", file_path.display());
    }

    if written == 0 {
        println!("No rules generated (no apps with code signing identity detected).");
    } else {
        println!("\n{written} rule files written to {}", rules_dir.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Best-effort metrics recording for learned profiles.
///
/// Records one `ConnectionDecided` event per unique destination per app.
fn record_learn_metrics(profiles: &HashMap<String, AppProfile>) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let db_path = std::path::PathBuf::from(home)
        .join(".macwarden")
        .join("metrics.db");
    let Ok(store) = metrics::MetricsStore::open(&db_path) else {
        return;
    };
    for profile in profiles.values() {
        for (host, stats) in &profile.destinations {
            let event = metrics::MetricEvent::ConnectionDecided {
                app_id: profile.code_id.clone(),
                dest_host: Some(host.clone()),
                dest_ip: host.clone(),
                action: "log".to_owned(),
                tier: "learn".to_owned(),
                rule_name: None,
                tracker_category: stats.tracker_category.clone(),
            };
            let _ = store.record(&event);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a duration string: "30s", "5m", "1h", or bare number (seconds).
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty duration string");
    }

    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let suffix = s.as_bytes().last().copied().unwrap_or(b'?');
    let num_str = s.get(..s.len().saturating_sub(1)).unwrap_or("");
    let num: u64 = num_str
        .parse()
        .with_context(|| format!("invalid duration: {s}"))?;

    match suffix {
        b's' => Ok(Duration::from_secs(num)),
        b'm' => Ok(Duration::from_secs(num * 60)),
        b'h' => Ok(Duration::from_secs(num * 3600)),
        _ => bail!("invalid duration suffix — use s, m, or h"),
    }
}

/// Extract the base domain from a hostname.
/// "mail.google.com" → "google.com", "google.com" → "google.com".
fn extract_base_domain(host: &str) -> &str {
    let parts: Vec<&str> = host.rsplitn(3, '.').collect();
    match (parts.first(), parts.get(1)) {
        (Some(tld), Some(domain)) => {
            let tld_len = tld.len();
            let domain_len = domain.len();
            let suffix_len = tld_len + 1 + domain_len; // "google.com"
            host.get(host.len().saturating_sub(suffix_len)..)
                .unwrap_or(host)
        }
        _ => host,
    }
}

/// Get `~/.macwarden/` path, resolving home directory.
fn dirs_path() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(std::path::PathBuf::from(home).join(".macwarden"))
}

#[cfg(test)]
#[path = "net_learn_test.rs"]
mod net_learn_test;
