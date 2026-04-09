//! `macwarden net apps --live / --expand` — app-grouped connection views.
//!
//! Provides Tiny Shield-style per-application network visibility:
//! - `--live` groups active connections by app with aggregate status
//! - `--expand <app>` drills down to per-destination verdicts for one app

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use net::{AppDb, TrackerDatabase};

use super::net_lsof::collect_lsof_connections;
use super::net_rdns::resolve_bare_ips;
use super::net_scan::{ScanEntry, evaluate_connection, is_local_noise};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Aggregate status for an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppStatus {
    /// All connections allowed/logged.
    Active,
    /// All connections denied.
    Blocked,
    /// Some allowed, some denied.
    Mixed,
}

impl std::fmt::Display for AppStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::Blocked => f.write_str("Blocked"),
            Self::Mixed => f.write_str("Mixed"),
        }
    }
}

/// Per-app summary for the `--live` table.
#[derive(Debug)]
struct AppSummary {
    display_name: String,
    connections: usize,
    blocked: usize,
    trackers: usize,
    status: AppStatus,
}

/// Table row for `--live` display.
#[derive(Debug, Tabled, serde::Serialize)]
struct AppLiveRow {
    #[tabled(rename = "App")]
    app: String,
    #[tabled(rename = "Connections")]
    connections: usize,
    #[tabled(rename = "Blocked")]
    blocked: usize,
    #[tabled(rename = "Trackers")]
    trackers: usize,
    #[tabled(rename = "Status")]
    status: String,
}

/// Table row for `--expand` display.
#[derive(Debug, Tabled, serde::Serialize)]
struct AppExpandRow {
    #[tabled(rename = "Destination")]
    destination: String,
    #[tabled(rename = "Port")]
    port: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "Tracker")]
    tracker: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// `macwarden net apps --live` — show connections grouped by application.
pub(super) fn run_live(json: bool) -> Result<()> {
    let entries = collect_and_evaluate()?;
    let summaries = group_by_app(&entries);

    let rows: Vec<AppLiveRow> = summaries
        .into_iter()
        .map(|s| AppLiveRow {
            app: s.display_name,
            connections: s.connections,
            blocked: s.blocked,
            trackers: s.trackers,
            status: s.status.to_string(),
        })
        .collect();

    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize apps as JSON")?;
        println!("{out}");
        return Ok(());
    }

    if rows.is_empty() {
        println!("No active network connections.");
        return Ok(());
    }

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("Active Apps (live connections)\n{table}");

    let total_conns: usize = rows.iter().map(|r| r.connections).sum();
    let total_blocked: usize = rows.iter().map(|r| r.blocked).sum();
    let total_trackers: usize = rows.iter().map(|r| r.trackers).sum();
    println!(
        "\n{} apps, {} connections ({} blocked, {} tracker)",
        rows.len(),
        total_conns,
        total_blocked,
        total_trackers,
    );
    Ok(())
}

/// `macwarden net apps --expand <app>` — per-destination drill-down.
pub(super) fn run_expand(app_query: &str, json: bool) -> Result<()> {
    let entries = collect_and_evaluate()?;
    let app_db = AppDb::load_builtin().context("failed to load app database")?;

    // Resolve app query: try AppDb name, then code_id substring, then process name
    let matching: Vec<&ScanEntry> = resolve_app_entries(&entries, app_query, &app_db);

    if matching.is_empty() {
        bail!(
            "no connections found for app matching \"{app_query}\"\n\
             Hint: use `macwarden net apps --live` to see active apps"
        );
    }

    // Determine display identity
    let display_name = app_display_name(matching.first(), &app_db);
    let code_id_str = matching
        .first()
        .and_then(|e| e.code_id.as_deref())
        .unwrap_or("unknown");

    let blocked_count = matching.iter().filter(|e| e.action == "DENY").count();
    let total = matching.len();
    let status = compute_status(total, blocked_count);

    let rows: Vec<AppExpandRow> = matching
        .iter()
        .map(|e| AppExpandRow {
            destination: e.destination.clone(),
            port: if e.port > 0 {
                e.port.to_string()
            } else {
                "-".to_owned()
            },
            action: e.action.clone(),
            tracker: e.tracker.clone().unwrap_or_default(),
        })
        .collect();

    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize expand as JSON")?;
        println!("{out}");
        return Ok(());
    }

    println!("{display_name} ({code_id_str})    {status}\n");

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("{table}");

    let tracker_count = matching.iter().filter(|e| e.tracker.is_some()).count();
    println!("\n{total} destinations ({blocked_count} blocked, {tracker_count} tracker)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Data collection
// ---------------------------------------------------------------------------

/// Collect lsof connections, evaluate against rules, resolve DNS, dedup.
fn collect_and_evaluate() -> Result<Vec<ScanEntry>> {
    let rule_set = super::build_base_ruleset()?;
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;

    let geo = net::GeoLookup::new().ok();

    let raw = collect_lsof_connections().context("failed to collect network connections")?;
    let mut entries: Vec<ScanEntry> = raw
        .into_iter()
        .map(|lsof| evaluate_connection(lsof, &rule_set, &tracker_db, geo.as_ref()))
        .collect();

    entries.retain(|e| !is_local_noise(&e.destination));
    resolve_bare_ips(&mut entries, &tracker_db);

    // Dedup by (process, destination)
    entries.sort_by(|a, b| {
        a.process
            .cmp(&b.process)
            .then_with(|| a.destination.cmp(&b.destination))
    });
    entries.dedup_by(|a, b| a.process == b.process && a.destination == b.destination);

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

/// Group scan entries by application, producing per-app summaries.
fn group_by_app(entries: &[ScanEntry]) -> Vec<AppSummary> {
    let mut groups: HashMap<String, Vec<&ScanEntry>> = HashMap::new();
    for entry in entries {
        let key = app_key(entry);
        groups.entry(key).or_default().push(entry);
    }

    let mut summaries: Vec<AppSummary> = groups
        .into_values()
        .map(|entries| {
            let total = entries.len();
            let blocked = entries.iter().filter(|e| e.action == "DENY").count();
            let trackers = entries.iter().filter(|e| e.tracker.is_some()).count();

            let display_name = entries
                .first()
                .map(|e| {
                    e.code_id
                        .as_deref()
                        .map_or_else(|| e.process.clone(), super::net_scan::format_code_id)
                })
                .unwrap_or_default();

            AppSummary {
                display_name,
                connections: total,
                blocked,
                trackers,
                status: compute_status(total, blocked),
            }
        })
        .collect();

    summaries.sort_by(|a, b| b.connections.cmp(&a.connections));
    summaries
}

/// Key for grouping: prefer code_id, fall back to process name.
fn app_key(entry: &ScanEntry) -> String {
    entry
        .code_id
        .clone()
        .unwrap_or_else(|| entry.process.clone())
}

/// Compute aggregate status from total and blocked counts.
fn compute_status(total: usize, blocked: usize) -> AppStatus {
    if blocked == 0 {
        AppStatus::Active
    } else if blocked == total {
        AppStatus::Blocked
    } else {
        AppStatus::Mixed
    }
}

// ---------------------------------------------------------------------------
// App resolution
// ---------------------------------------------------------------------------

/// Resolve an app query to matching scan entries.
///
/// Tries in order: AppDb name lookup, code_id substring, process name substring.
fn resolve_app_entries<'a>(
    entries: &'a [ScanEntry],
    query: &str,
    app_db: &AppDb,
) -> Vec<&'a ScanEntry> {
    let query_lower = query.to_ascii_lowercase();

    // Try AppDb name lookup first → get code_id → filter entries
    if let Some(profile) = app_db.lookup_by_name(query) {
        let matches: Vec<&ScanEntry> = entries
            .iter()
            .filter(|e| e.code_id.as_deref().is_some_and(|id| id == profile.code_id))
            .collect();
        if !matches.is_empty() {
            return matches;
        }
    }

    // Try code_id substring match
    let by_code_id: Vec<&ScanEntry> = entries
        .iter()
        .filter(|e| {
            e.code_id
                .as_deref()
                .is_some_and(|id| id.to_ascii_lowercase().contains(&query_lower))
        })
        .collect();
    if !by_code_id.is_empty() {
        return by_code_id;
    }

    // Fall back to process name substring
    entries
        .iter()
        .filter(|e| e.process.to_ascii_lowercase().contains(&query_lower))
        .collect()
}

/// Get a display name for an app from the first matching entry.
fn app_display_name(entry: Option<&&ScanEntry>, app_db: &AppDb) -> String {
    let Some(e) = entry else {
        return "Unknown".to_owned();
    };
    if let Some(code_id) = &e.code_id {
        if let Some(profile) = app_db.lookup(code_id) {
            return profile.name.clone();
        }
        return super::net_scan::format_code_id(code_id);
    }
    e.process.clone()
}

#[cfg(test)]
#[path = "net_apps_test.rs"]
mod net_apps_test;
