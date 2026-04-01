//! `macwarden disable` -- disable a service or group of services.

use anyhow::{Context, Result};

use catalog::load_builtin_groups;
use launchd::MacOsPlatform;
use policy::{RespawnBehavior, ServiceGroup, ServiceInfo, find_group, resolve_group_services};

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

    let resolved = resolve_targets(target, &services, &groups)?;
    let mut targets = resolved.services;
    let group_cmds = resolved.disable_commands;
    let respawn = resolved.respawn_behavior;
    let has_scrub_data = !resolved.cleanup_commands.is_empty();

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
        // Warn about services that will respawn (based on group catalog data).
        if respawn != RespawnBehavior::StaysDead {
            let labels: Vec<String> = targets.iter().map(|s| s.label.clone()).collect();
            enforce::warn_respawning(&labels);
        }

        if has_scrub_data {
            println!("\nRun `macwarden scrub {target}` to delete data these services collected.");
        }

        println!("\nDone. Services are marked disabled and won't restart after reboot.");
        println!("SIP-protected processes may keep running until then.");
        println!("Use `macwarden inspect {target}` to verify state.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

/// Resolved target: services to act on plus group metadata.
struct ResolvedTarget<'a> {
    services: Vec<&'a ServiceInfo>,
    disable_commands: Vec<String>,
    cleanup_commands: Vec<String>,
    respawn_behavior: RespawnBehavior,
}

/// Resolve a target string to a list of services and group metadata.
fn resolve_targets<'a>(
    target: &str,
    services: &'a [ServiceInfo],
    groups: &[ServiceGroup],
) -> Result<ResolvedTarget<'a>> {
    if let Some(group) = find_group(target, groups) {
        let matched = resolve_group_services(group, services);
        return Ok(ResolvedTarget {
            services: matched,
            disable_commands: group.disable_commands.clone(),
            cleanup_commands: group.cleanup_commands.clone(),
            respawn_behavior: group.respawn_behavior,
        });
    }

    let svc = services
        .iter()
        .find(|s| s.label == target)
        .context(format!("service '{target}' not found"))?;

    Ok(ResolvedTarget {
        services: vec![svc],
        disable_commands: vec![],
        cleanup_commands: vec![],
        respawn_behavior: RespawnBehavior::default(),
    })
}
