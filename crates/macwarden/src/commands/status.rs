//! `macwarden status` -- show current macwarden status.

use anyhow::{Context, Result};

use macwarden_catalog::load_builtin_groups;
use macwarden_core::{ServiceState, resolve_group_services};
use macwarden_launchd::{MacOsPlatform, Platform};
use macwarden_snapshot::SnapshotStore;

use crate::cli::{self, OutputFormat};
use crate::commands::enforce;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Status output
// ---------------------------------------------------------------------------

/// Serialisable status summary.
#[derive(Debug, serde::Serialize)]
struct StatusReport {
    active_profile: String,
    sip_status: String,
    total_services: usize,
    running: usize,
    stopped: usize,
    disabled: usize,
    unknown_state: usize,
    snapshot_dir_exists: bool,
    last_snapshot: Option<SnapshotInfo>,
    groups: Vec<GroupSummary>,
}

/// Summary of the most recent snapshot.
#[derive(Debug, serde::Serialize)]
struct SnapshotInfo {
    timestamp: String,
    profile_name: String,
    entry_count: usize,
}

/// Per-group service summary.
#[derive(Debug, serde::Serialize)]
struct GroupSummary {
    name: String,
    total: usize,
    running: usize,
    disabled: usize,
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `status` command.
///
/// Displays the active profile, SIP status, service counts by state,
/// snapshot information, and group summaries.
pub fn run(format: OutputFormat) -> Result<()> {
    let active_profile = cli::read_active_profile()?;
    let services = discover_services()?;

    let running = services
        .iter()
        .filter(|s| s.state == ServiceState::Running)
        .count();
    let stopped = services
        .iter()
        .filter(|s| s.state == ServiceState::Stopped)
        .count();
    let disabled = services
        .iter()
        .filter(|s| s.state == ServiceState::Disabled)
        .count();
    let unknown_state = services
        .iter()
        .filter(|s| s.state == ServiceState::Unknown)
        .count();

    // SIP status.
    let platform = MacOsPlatform::new();
    let sip_status = match platform.sip_status() {
        Ok(state) => state.to_string(),
        Err(_) => "unknown".to_owned(),
    };

    // Snapshot info.
    let snap_dir = enforce::snapshot_dir()?;
    let snapshot_dir_exists = snap_dir.is_dir();
    let last_snapshot = if snapshot_dir_exists {
        let store = SnapshotStore::new(snap_dir);
        match store.latest() {
            Ok(Some(snap)) => Some(SnapshotInfo {
                timestamp: snap.timestamp,
                profile_name: snap.profile_name,
                entry_count: snap.entries.len(),
            }),
            _ => None,
        }
    } else {
        None
    };

    // Group summaries.
    let builtin_groups = load_builtin_groups();
    let groups: Vec<GroupSummary> = builtin_groups
        .iter()
        .map(|group| {
            let matched = resolve_group_services(group, &services);
            let grp_running = matched
                .iter()
                .filter(|s| s.state == ServiceState::Running)
                .count();
            let grp_disabled = matched
                .iter()
                .filter(|s| s.state == ServiceState::Disabled)
                .count();
            GroupSummary {
                name: group.name.clone(),
                total: matched.len(),
                running: grp_running,
                disabled: grp_disabled,
            }
        })
        .collect();

    let report = StatusReport {
        active_profile,
        sip_status,
        total_services: services.len(),
        running,
        stopped,
        disabled,
        unknown_state,
        snapshot_dir_exists,
        last_snapshot,
        groups,
    };

    match format {
        OutputFormat::Table => print_table(&report),
        OutputFormat::Json => print_json(&report)?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Table output
// ---------------------------------------------------------------------------

/// Print the status report as a human-readable summary.
fn print_table(report: &StatusReport) {
    println!("macwarden status\n");
    println!("  Active profile:   {}", report.active_profile);
    println!("  SIP status:       {}", report.sip_status);
    println!("  Total services:   {}", report.total_services);
    println!("  Running:          {}", report.running);
    println!("  Stopped:          {}", report.stopped);
    println!("  Disabled:         {}", report.disabled);
    println!("  Unknown state:    {}", report.unknown_state);
    println!(
        "  Snapshot dir:     {}",
        if report.snapshot_dir_exists {
            "exists"
        } else {
            "not found"
        },
    );

    if let Some(snap) = &report.last_snapshot {
        println!(
            "  Last snapshot:    {} (profile: {}, {} entries)",
            snap.timestamp, snap.profile_name, snap.entry_count,
        );
    }

    if !report.groups.is_empty() {
        println!("\n  Groups:");
        for g in &report.groups {
            println!(
                "    {:<20} {:>3} total  {:>3} running  {:>3} disabled",
                g.name, g.total, g.running, g.disabled,
            );
        }
    }
}

/// Print the status report as JSON.
fn print_json(report: &StatusReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("failed to serialize status")?;
    println!("{json}");
    Ok(())
}
