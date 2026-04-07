//! `macwarden doctor` — diagnostic checks for the local environment.

use std::path::Path;

use anyhow::Result;

use catalog::DEFAULT_PLIST_DIRS;

use crate::cli;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `doctor` command.
///
/// Performs a series of environment checks and prints a diagnostic report
/// with pass/fail status for each item.
pub fn run() -> Result<()> {
    println!("macwarden doctor\n");

    check_running_as_root();
    check_plist_dirs()?;
    check_config_dir()?;
    check_active_profile()?;
    check_snapshot_dir()?;

    println!("\nDone.");
    Ok(())
}

/// Check whether the process is running as root.
fn check_running_as_root() {
    let is_root = std::env::var("USER").map(|u| u == "root").unwrap_or(false);

    if is_root {
        print_status(true, "running as root");
    } else {
        print_status(false, "not running as root (some operations require root)");
    }
}

/// Check that plist directories exist and are readable.
fn check_plist_dirs() -> Result<()> {
    for dir_str in DEFAULT_PLIST_DIRS {
        let dir = cli::expand_home(dir_str)?;
        let exists = dir.is_dir();
        let label = format!("plist directory: {}", dir.display());
        print_status(exists, &label);
    }
    Ok(())
}

/// Check that the config directory exists.
fn check_config_dir() -> Result<()> {
    let config_dir = cli::expand_home("~/.macwarden")?;
    let exists = config_dir.is_dir();
    print_status(exists, &format!("config dir: {}", config_dir.display()));
    Ok(())
}

/// Check whether an active profile is set.
fn check_active_profile() -> Result<()> {
    let path = cli::active_profile_path()?;
    let has_profile = Path::new(&path).is_file();
    if has_profile {
        let name = cli::read_active_profile()?;
        print_status(true, &format!("active profile: {name}"));
    } else {
        print_status(false, "no active profile set (will default to 'base')");
    }
    Ok(())
}

/// Check that the snapshot directory exists.
fn check_snapshot_dir() -> Result<()> {
    let snap_dir = cli::expand_home("~/.macwarden/snapshots")?;
    let exists = snap_dir.is_dir();
    print_status(exists, &format!("snapshot dir: {}", snap_dir.display()));
    Ok(())
}

/// Print a pass/fail status line.
fn print_status(ok: bool, message: &str) {
    let icon = if ok { "PASS" } else { "FAIL" };
    println!("  [{icon}] {message}");
}
