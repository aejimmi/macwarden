//! `macwarden profiles` — list and inspect available profiles.

use anyhow::Result;

use macwarden_catalog::load_builtin_profiles;

use crate::cli::ProfilesSubcmd;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `profiles` command.
///
/// Without a subcommand, lists all available profiles. With `show <name>`,
/// displays the full rule set for a specific profile.
pub fn run(subcmd: Option<&ProfilesSubcmd>) -> Result<()> {
    let builtins = load_builtin_profiles();

    match subcmd {
        None => {
            list_profiles(&builtins);
            Ok(())
        }
        Some(ProfilesSubcmd::Show { name }) => show_profile(&builtins, name),
    }
}

/// Print a summary list of all available profiles.
fn list_profiles(profiles: &[macwarden_core::Profile]) {
    println!("Available profiles:\n");

    for p in profiles {
        let extends = if p.profile.extends.is_empty() {
            String::new()
        } else {
            format!(" (extends: {})", p.profile.extends.join(", "))
        };
        println!(
            "  {} — {}{}",
            p.profile.name, p.profile.description, extends
        );
    }

    println!("\nUse `macwarden profiles show <name>` for details.");
}

/// Pretty-print the full rules of a specific profile.
fn show_profile(profiles: &[macwarden_core::Profile], name: &str) -> Result<()> {
    let profile = profiles
        .iter()
        .find(|p| p.profile.name == name)
        .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found"))?;

    println!("Profile: {}", profile.profile.name);
    println!("Description: {}", profile.profile.description);

    if !profile.profile.extends.is_empty() {
        println!("Extends: {}", profile.profile.extends.join(", "));
    }

    println!(
        "Enforcement: {} (exec_policy: {})",
        profile.enforcement.action, profile.enforcement.exec_policy,
    );

    println!("\nDeny rules:");
    if profile.rules.deny.is_empty() {
        println!("  (none)");
    } else {
        for rule in &profile.rules.deny {
            println!("  - {rule}");
        }
    }

    println!("\nAllow rules:");
    if profile.rules.allow.is_empty() {
        println!("  (none)");
    } else {
        for rule in &profile.rules.allow {
            println!("  - {rule}");
        }
    }

    println!("\nCategory rules:");
    if profile.rules.categories.is_empty() {
        println!("  (none)");
    } else {
        let mut cats: Vec<_> = profile.rules.categories.iter().collect();
        cats.sort_by_key(|(k, _)| (*k).clone());
        for (cat, action) in cats {
            println!("  {cat}: {action}");
        }
    }

    Ok(())
}
