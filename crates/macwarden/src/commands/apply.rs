//! `macwarden apply` -- apply a profile, executing enforcement actions.

use std::collections::HashSet;

use anyhow::{Context, Result};

use macwarden_catalog::load_builtin_profiles;
use macwarden_core::{Action, diff, resolve_extends, validate_actions, validate_profile};
use macwarden_launchd::MacOsPlatform;

use super::enforce;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `apply` command.
///
/// Resolves the named profile, discovers services, computes the diff (actions
/// needed to bring the system into compliance), then executes enforcement.
pub fn run(profile_name: &str, dry_run: bool) -> Result<()> {
    let builtins = load_builtin_profiles();

    let profile = builtins
        .iter()
        .find(|p| p.profile.name == profile_name)
        .context(format!("profile '{profile_name}' not found"))?;

    validate_profile(profile).context("profile validation failed")?;

    let resolved = resolve_extends(profile, &builtins)
        .context(format!("failed to resolve profile '{profile_name}'"))?;

    let services = discover_services()?;
    let actions = diff(&services, &resolved);

    if actions.is_empty() {
        println!("Profile '{profile_name}' requires no changes.");
        return Ok(());
    }

    // Validate against the safe-list.
    let action_list: Vec<_> = actions.iter().map(|(_, a)| a.clone()).collect();
    if let Err(e) = validate_actions(&action_list) {
        anyhow::bail!(
            "safe-list violation: refusing to act on critical services: {}",
            e.rejected.join(", "),
        );
    }

    // Deduplicate -- engine emits Disable AND Kill for running services,
    // but enforce_disable handles kill internally.
    let mut seen = HashSet::new();
    let to_disable: Vec<_> = actions
        .iter()
        .filter(|(_, a)| matches!(a, Action::Disable { .. }))
        .filter(|(svc, _)| seen.insert(svc.label.clone()))
        .map(|(svc, _)| svc)
        .collect();

    let platform = MacOsPlatform::new();

    if !dry_run
        && !to_disable.is_empty()
        && let Err(e) = enforce::write_snapshot(profile_name, &to_disable)
    {
        eprintln!("warning: failed to save snapshot: {e}");
    }

    println!(
        "{}Applying profile '{}' ({} services to disable):\n",
        if dry_run { "[DRY RUN] " } else { "" },
        profile_name,
        to_disable.len(),
    );

    for svc in &to_disable {
        enforce::enforce_disable(svc, &platform, dry_run, false);
    }

    if !dry_run {
        if let Err(e) = enforce::save_active_profile(profile_name) {
            eprintln!("warning: {e}");
        }
        println!("\nDone. Profile '{profile_name}' applied.");
        println!("Services marked disabled won't restart after reboot.");
        println!("SIP-protected processes may keep running until then.");
    }

    Ok(())
}
