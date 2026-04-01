//! `macwarden explain` — show why a service is allowed or denied.

use anyhow::{Context, Result};

use catalog::load_builtin_profiles;
use policy::{explain, resolve_extends};

use crate::cli;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `explain` command.
///
/// Loads the active profile, discovers services, and prints a human-readable
/// explanation of the policy decision for the given service label.
pub fn run(label: &str) -> Result<()> {
    let profile_name = cli::read_active_profile()?;
    let builtins = load_builtin_profiles();

    let profile = builtins
        .iter()
        .find(|p| p.profile.name == profile_name)
        .context(format!("profile '{profile_name}' not found"))?;

    let resolved = resolve_extends(profile, &builtins)
        .context(format!("failed to resolve profile '{profile_name}'"))?;

    let services = discover_services()?;

    let explanation = explain(label, &resolved, &services);
    println!("{explanation}");

    Ok(())
}
