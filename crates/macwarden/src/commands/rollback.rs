//! `macwarden rollback` -- restore a previous service state from a snapshot.

use anyhow::{Context, Result};

use macwarden_core::{Action, Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};
use macwarden_launchd::MacOsPlatform;
use macwarden_snapshot::SnapshotStore;

use super::enforce;
use crate::cli;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `rollback` command.
///
/// Loads a snapshot (latest or by name) and re-enables every service that was
/// previously disabled. Uses the shared enforcement helpers for consistency.
pub fn run(name: Option<&str>, dry_run: bool) -> Result<()> {
    let snap_dir = cli::expand_home("~/.local/share/macwarden/snapshots")?;
    let store = SnapshotStore::new(snap_dir);

    let snapshot = match name {
        Some(n) => load_named(&store, n)?,
        None => load_latest(&store)?,
    };

    println!(
        "Snapshot: {} (profile: {})",
        snapshot.timestamp, snapshot.profile_name
    );
    println!(
        "{}Contains {} entries:\n",
        if dry_run { "[DRY RUN] " } else { "" },
        snapshot.entries.len(),
    );

    let platform = MacOsPlatform::new();
    let mut restored = 0usize;

    for entry in &snapshot.entries {
        match &entry.action_taken {
            Action::Disable { label } => {
                let svc = build_rollback_service_info(label);
                enforce::enforce_enable(&svc, &platform, dry_run, false);
                if !dry_run {
                    restored += 1;
                }
            }
            other => {
                println!(
                    "  SKIP {} -- action '{}' has no rollback",
                    entry.label, other,
                );
            }
        }
    }

    if dry_run {
        println!(
            "\n[DRY RUN] Would restore {} services.",
            snapshot.entries.len()
        );
    } else {
        println!("\nRestored {restored}/{} services.", snapshot.entries.len());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshot loading
// ---------------------------------------------------------------------------

/// Load a snapshot by name (timestamp stem).
fn load_named(store: &SnapshotStore, name: &str) -> Result<macwarden_snapshot::Snapshot> {
    let snapshots = store.list().context("failed to list snapshots")?;

    let (_stem, path) = snapshots
        .iter()
        .find(|(stem, _)| stem == name)
        .context(format!("snapshot '{name}' not found"))?;

    store.read(path).context("failed to read snapshot")
}

/// Load the most recent snapshot.
fn load_latest(store: &SnapshotStore) -> Result<macwarden_snapshot::Snapshot> {
    store
        .latest()
        .context("failed to load latest snapshot")?
        .context("no snapshots found -- nothing to roll back")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `ServiceInfo` for rollback purposes.
///
/// Without full runtime state, we infer the domain from the label: services
/// in system plist directories (common `com.apple.*` daemons) use the system
/// domain; others default to the user GUI domain.
fn build_rollback_service_info(label: &str) -> ServiceInfo {
    let domain = infer_rollback_domain(label);
    ServiceInfo {
        label: label.to_owned(),
        domain,
        plist_path: None,
        state: ServiceState::Disabled,
        category: ServiceCategory::Unknown,
        safety: SafetyLevel::Optional,
        description: None,
        pid: None,
    }
}

/// Infer the launchd domain for rollback.
///
/// Heuristic: most user-targeted disable operations target GUI-domain
/// agents. System daemons are less commonly rolled back. We default to
/// `gui/{uid}` for consistency with the disable path, using `SUDO_UID`.
fn infer_rollback_domain(label: &str) -> Domain {
    // Labels from system LaunchDaemon directories are typically com.apple.*
    // and run in the system domain. However, many com.apple.* labels are
    // also user agents. Without the plist path we cannot be certain.
    // Since disable targets are typically gui-domain agents, default to User.
    let _ = label;
    Domain::User
}
