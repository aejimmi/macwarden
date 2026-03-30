//! Shared enforcement helpers used by disable, enable, apply, and rollback.
//!
//! Extracted from `disable.rs` and `enable.rs` to eliminate duplication.

use std::path::PathBuf;

use anyhow::{Context, Result};

use macwarden_core::{Action, ServiceInfo, is_critical};
use macwarden_launchd::Platform;
use macwarden_snapshot::{Snapshot, SnapshotEntry, SnapshotStore};

use crate::cli;

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Execute the three-step enforcement sequence for disabling a single service.
///
/// 1. `launchctl disable {domain}/{label}` -- prevent future loading
/// 2. `launchctl bootout {domain}/{label}` -- unload now (always attempt)
/// 3. `kill -9 {pid}` -- cleanup (always attempt if pid known)
///
/// We always attempt bootout and kill regardless of detected state because
/// when running as root, `launchctl list` only shows the system domain --
/// user-domain services appear as "unknown" even if they're running.
///
/// When `quiet` is true, progress output goes to `tracing::info!` instead
/// of stdout. Use quiet mode in long-running contexts (monitor) where only
/// the summary line matters.
pub fn enforce_disable(svc: &ServiceInfo, platform: &dyn Platform, dry_run: bool, quiet: bool) {
    let domain = domain_string(svc);

    if is_critical(&svc.label) {
        if quiet {
            tracing::info!(label = %svc.label, "skipping critical service");
        } else {
            println!("  SKIP {} (critical service)", svc.label);
        }
        return;
    }

    // Step 1: disable -- always do this
    if quiet {
        tracing::info!(label = %svc.label, domain = %domain, "launchctl disable");
    } else {
        println!("  launchctl disable {domain}/{}", svc.label);
    }
    if !dry_run && let Err(e) = platform.disable(&domain, &svc.label) {
        if quiet {
            tracing::warn!(label = %svc.label, error = %e, "disable failed");
        } else {
            eprintln!("    warning: disable failed: {e}");
        }
    }

    // Step 2: bootout -- always attempt (silently ignore "not loaded" errors)
    if quiet {
        tracing::info!(label = %svc.label, domain = %domain, "launchctl bootout");
    } else {
        println!("  launchctl bootout {domain}/{}", svc.label);
    }
    if !dry_run && let Err(e) = platform.bootout(&domain, &svc.label) {
        let msg = e.to_string();
        // "not loaded" / "no such process" are expected for stopped services
        if !msg.contains("36:") && !msg.contains("3:") && !msg.contains("No such process") {
            if quiet {
                tracing::warn!(label = %svc.label, error = %e, "bootout failed");
            } else {
                eprintln!("    warning: bootout failed: {e}");
            }
        }
    }

    // Step 3: kill -- if we know the pid, try it
    if let Some(pid) = svc.pid {
        if quiet {
            tracing::info!(label = %svc.label, pid, "kill -9");
        } else {
            println!("  kill -9 {pid} ({})", svc.label);
        }
        if !dry_run && let Err(e) = platform.kill_process(pid) {
            if quiet {
                tracing::warn!(label = %svc.label, pid, error = %e, "kill failed");
            } else {
                eprintln!("    warning: kill failed: {e}");
            }
        }
    }
}

/// Enable a single service via `launchctl enable`.
///
/// When `quiet` is true, progress output goes to `tracing::info!`.
pub fn enforce_enable(svc: &ServiceInfo, platform: &dyn Platform, dry_run: bool, quiet: bool) {
    let domain = domain_string(svc);

    if quiet {
        tracing::info!(label = %svc.label, domain = %domain, "launchctl enable");
    } else {
        println!("  launchctl enable {domain}/{}", svc.label);
    }
    if !dry_run && let Err(e) = platform.enable(&domain, &svc.label) {
        if quiet {
            tracing::warn!(label = %svc.label, error = %e, "enable failed");
        } else {
            eprintln!("    warning: enable failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Domain mapping
// ---------------------------------------------------------------------------

/// Map a core `Domain` to the launchctl domain string.
///
/// Under `sudo`, `$UID` and `$EUID` are 0 (root). We need the real
/// user's UID for `gui/` domain operations. `$SUDO_UID` preserves the
/// original user's UID when running under sudo.
pub fn domain_string(svc: &ServiceInfo) -> String {
    match svc.domain {
        macwarden_core::Domain::System => "system".to_owned(),
        macwarden_core::Domain::User | macwarden_core::Domain::Global => {
            let uid = std::env::var("SUDO_UID")
                .or_else(|_| std::env::var("UID"))
                .or_else(|_| std::env::var("EUID"))
                .unwrap_or_else(|_| "501".to_owned());
            format!("gui/{uid}")
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// Write a pre-enforcement snapshot so the operation can be rolled back.
pub fn write_snapshot(profile_name: &str, targets: &[&ServiceInfo]) -> Result<()> {
    let store = SnapshotStore::new(snapshot_dir()?);
    store
        .ensure_dir()
        .context("failed to create snapshot directory")?;

    let entries: Vec<SnapshotEntry> = targets
        .iter()
        .map(|svc| SnapshotEntry {
            label: svc.label.clone(),
            prior_state: svc.state,
            action_taken: Action::Disable {
                label: svc.label.clone(),
            },
        })
        .collect();

    let snapshot = Snapshot {
        timestamp: timestamp_now(),
        profile_name: profile_name.to_owned(),
        entries,
    };

    let path = store.write(&snapshot).context("failed to write snapshot")?;
    println!("Snapshot saved to {}", path.display());
    Ok(())
}

/// Returns the snapshot storage directory.
pub fn snapshot_dir() -> Result<PathBuf> {
    cli::expand_home("~/.local/share/macwarden/snapshots")
}

/// Generate a Unix-epoch timestamp string (no chrono dependency needed).
pub fn timestamp_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

// ---------------------------------------------------------------------------
// Shell commands
// ---------------------------------------------------------------------------

/// Run shell commands (group-specific like `mdutil -a -i off`).
pub fn run_shell_commands(commands: &[String], dry_run: bool) {
    for cmd in commands {
        println!("\n  Running: {cmd}");
        if !dry_run {
            let result = std::process::Command::new("sh").args(["-c", cmd]).status();
            match result {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    eprintln!("    warning: command exited with {status}");
                }
                Err(e) => {
                    eprintln!("    warning: failed to run command: {e}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Active profile
// ---------------------------------------------------------------------------

/// Write the active profile name to the config directory.
pub fn save_active_profile(name: &str) -> Result<()> {
    let path = cli::active_profile_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    std::fs::write(&path, name).context("failed to write active profile")?;
    Ok(())
}
