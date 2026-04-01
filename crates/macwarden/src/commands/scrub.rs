//! `macwarden scrub` — delete data artifacts left by disabled services.
//!
//! Runs `cleanup_commands` for a group: Spotlight indexes, behavioral
//! databases, ML caches, diagnostic logs, and other traces.

use anyhow::{Context, Result};

use catalog::load_builtin_groups;
use policy::find_group;

use super::enforce;

/// Run the `scrub` command.
///
/// Looks up the named group, prints what will be deleted, and runs
/// the group's `cleanup_commands`.
pub fn run(target: &str, dry_run: bool) -> Result<()> {
    let groups = load_builtin_groups();

    let group = find_group(target, &groups)
        .context(format!("group '{target}' not found — scrub works on groups, not individual services"))?;

    if group.cleanup_commands.is_empty() {
        println!("No data to scrub for group '{}'.", group.name);
        println!("This group does not produce on-disk artifacts.");
        return Ok(());
    }

    println!(
        "{}Scrubbing data for group '{}':\n",
        if dry_run { "[DRY RUN] " } else { "" },
        group.name,
    );

    enforce::run_shell_commands(&group.cleanup_commands, dry_run);

    if !dry_run {
        println!("\nDone. Artifacts from '{}' have been removed.", group.name);
    }

    Ok(())
}
