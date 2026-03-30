//! `macwarden disable` -- disable a service or group of services.

use anyhow::{Context, Result};

use macwarden_catalog::load_builtin_groups;
use macwarden_core::{ServiceGroup, ServiceInfo, find_group, resolve_group_services};
use macwarden_launchd::MacOsPlatform;

use super::enforce;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `disable` command.
///
/// Resolves the target to a list of services (via group or single label),
/// writes a snapshot of current state, then executes the three-step
/// enforcement sequence: disable, bootout, kill.
pub fn run(target: &str, dry_run: bool, except: &[String]) -> Result<()> {
    let services = discover_services()?;
    let groups = load_builtin_groups();
    let platform = MacOsPlatform::new();

    let (mut targets, group_cmds) = resolve_targets(target, &services, &groups)?;

    // Filter out excepted services.
    if !except.is_empty() {
        let before = targets.len();
        targets.retain(|svc| !except.iter().any(|e| svc.label.contains(e.as_str())));
        let skipped = before - targets.len();
        if skipped > 0 {
            println!("Skipping {skipped} excepted service(s).\n");
        }
    }

    if targets.is_empty() {
        println!("No matching services found for '{target}'.");
        return Ok(());
    }

    // Write a snapshot before making any changes.
    if !dry_run && let Err(e) = enforce::write_snapshot(target, &targets) {
        eprintln!("warning: failed to save snapshot: {e}");
    }

    println!(
        "{}Disabling {} service(s):\n",
        if dry_run { "[DRY RUN] " } else { "" },
        targets.len(),
    );

    for svc in &targets {
        enforce::enforce_disable(svc, &platform, dry_run, false);
    }

    enforce::run_shell_commands(&group_cmds, dry_run);

    if !dry_run {
        println!("\nDone. Services are marked disabled and won't restart after reboot.");
        println!("SIP-protected processes may keep running until then.");
        println!("Use `macwarden inspect {target}` to verify state.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

/// Resolve a target string to a list of services and optional group commands.
///
/// Returns `(services_to_disable, group_disable_commands)`.
fn resolve_targets<'a>(
    target: &str,
    services: &'a [ServiceInfo],
    groups: &[ServiceGroup],
) -> Result<(Vec<&'a ServiceInfo>, Vec<String>)> {
    if let Some(group) = find_group(target, groups) {
        let matched = resolve_group_services(group, services);
        return Ok((matched, group.disable_commands.clone()));
    }

    let svc = services
        .iter()
        .find(|s| s.label == target)
        .context(format!("service '{target}' not found"))?;

    Ok((vec![svc], vec![]))
}
