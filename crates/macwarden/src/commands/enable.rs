//! `macwarden enable` -- enable a previously disabled service or group.

use anyhow::{Context, Result};

use macwarden_catalog::load_builtin_groups;
use macwarden_core::{ServiceGroup, ServiceInfo, find_group, resolve_group_services};
use macwarden_launchd::MacOsPlatform;

use super::enforce;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `enable` command.
///
/// Resolves the target to a list of services (via group or single label),
/// then enables each one and optionally runs group-specific enable commands.
pub fn run(target: &str, dry_run: bool) -> Result<()> {
    let services = discover_services()?;
    let groups = load_builtin_groups();
    let platform = MacOsPlatform::new();

    let (targets, group_cmds) = resolve_targets(target, &services, &groups)?;

    if targets.is_empty() {
        println!("No matching services found for '{target}'.");
        return Ok(());
    }

    println!(
        "{}Enabling {} service(s):\n",
        if dry_run { "[DRY RUN] " } else { "" },
        targets.len(),
    );

    for svc in &targets {
        enforce::enforce_enable(svc, &platform, dry_run, false);
    }

    enforce::run_shell_commands(&group_cmds, dry_run);

    Ok(())
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

/// Resolve a target string to a list of services and optional group commands.
fn resolve_targets<'a>(
    target: &str,
    services: &'a [ServiceInfo],
    groups: &[ServiceGroup],
) -> Result<(Vec<&'a ServiceInfo>, Vec<String>)> {
    if let Some(group) = find_group(target, groups) {
        let matched = resolve_group_services(group, services);
        return Ok((matched, group.enable_commands.clone()));
    }

    let svc = services
        .iter()
        .find(|s| s.label == target)
        .context(format!("service '{target}' not found"))?;

    Ok((vec![svc], vec![]))
}
