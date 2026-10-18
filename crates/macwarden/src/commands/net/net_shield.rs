//! `macwarden net shield` -- one-command tracker blocking.
//!
//! Reads and writes a shield state file at `~/.macwarden/net-shield.toml`.
//! When the shield is enabled, tracker categories set to `"deny"` produce
//! `DENY` decisions instead of `LOG` in the scan and explain commands.

use std::path::Path;

use anyhow::{Context, Result};

use net::shield::SHIELD_FILENAME;
use net::{ShieldConfig, TrackerCategory, TrackerDatabase};

// `ShieldConfig` itself now lives in `net::shield` so the daemon and the
// NetworkExtension decision core (`enforce-ne-ffi`) compose one identical
// ruleset from the same file. This module keeps only the CLI command surface
// plus the load/save helpers, which take a `base_dir` (the `~/.macwarden/`
// directory) exactly like `net::loader` and `banwatch::persist` — so they are
// hermetically testable against a `tempfile::TempDir` rather than hard-wired to
// `$HOME`.

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// The shield config path within `base_dir` (`base_dir/net-shield.toml`).
fn shield_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join(SHIELD_FILENAME)
}

/// Load the shield config from `base_dir`, returning defaults if absent or
/// unreadable/malformed (fail-open — [`ShieldConfig::load`] never errors).
pub(crate) fn load_shield_config(base_dir: &Path) -> ShieldConfig {
    ShieldConfig::load(&shield_path(base_dir))
}

/// Save the shield config under `base_dir`, creating the directory as needed and
/// keeping the file owner-only.
fn save_shield_config(base_dir: &Path, cfg: &ShieldConfig) -> Result<()> {
    let path = shield_path(base_dir);
    std::fs::create_dir_all(base_dir).context("failed to create config directory")?;
    net::secure_dir(base_dir);
    let content = toml::to_string_pretty(cfg).context("failed to serialize shield config")?;
    std::fs::write(&path, content).context("failed to write shield config")?;
    net::secure_file(&path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

/// Run `macwarden net shield`.
pub(super) fn run(off: bool, only: &[String]) -> Result<()> {
    let base_dir = super::macwarden_base_dir();
    if off {
        return run_disable(&base_dir);
    }
    run_enable(&base_dir, only)
}

/// Enable the tracker shield.
fn run_enable(base_dir: &Path, only: &[String]) -> Result<()> {
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;
    let stats = tracker_db.stats();
    let cfg = if only.is_empty() {
        ShieldConfig::enabled_all()
    } else {
        ShieldConfig::enabled_partial(only)
    };
    save_shield_config(base_dir, &cfg)?;

    let partial = !only.is_empty();
    if partial {
        println!("Tracker Shield activated (partial).");
    } else {
        println!("Tracker Shield activated.");
    }

    let mut total_blocked: usize = 0;
    for &(cat, label) in &CATEGORY_LABELS {
        let count = stats.get(&cat).copied().unwrap_or(0);
        let denied = cfg.is_category_denied(&cat.to_string());
        if denied {
            total_blocked += count;
            println!("  {label:<20} {count:>3} domains -> DENY");
        } else {
            println!("  {label:<20} {count:>3} domains -> LOG (not blocked)");
        }
    }

    println!("\n{total_blocked} tracker domains now blocked.");
    println!("Use `macwarden net shield --off` to disable.");
    Ok(())
}

/// Disable the tracker shield.
fn run_disable(base_dir: &Path) -> Result<()> {
    let cfg = ShieldConfig::default();
    save_shield_config(base_dir, &cfg)?;
    println!("Tracker Shield disabled.");
    println!("All tracker connections will be logged (not blocked).");
    Ok(())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Category enum values paired with display labels.
const CATEGORY_LABELS: [(TrackerCategory, &str); 4] = [
    (TrackerCategory::Advertising, "Advertising:"),
    (TrackerCategory::Analytics, "Analytics:"),
    (TrackerCategory::Fingerprinting, "Fingerprinting:"),
    (TrackerCategory::Social, "Social:"),
];

#[cfg(test)]
#[path = "net_shield_test.rs"]
mod net_shield_test;
