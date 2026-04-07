//! `macwarden net shield` -- one-command tracker blocking.
//!
//! Reads and writes a shield state file at `~/.macwarden/net-shield.toml`.
//! When the shield is enabled, tracker categories set to `"deny"` produce
//! `DENY` decisions instead of `LOG` in the scan and explain commands.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use net::{NetworkAction, TrackerCategory, TrackerDatabase};

use crate::cli;

// ---------------------------------------------------------------------------
// Shield config path
// ---------------------------------------------------------------------------

/// Path to the shield config file.
const SHIELD_FILE: &str = "~/.macwarden/net-shield.toml";

// ---------------------------------------------------------------------------
// ShieldConfig
// ---------------------------------------------------------------------------

/// Persisted tracker shield state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ShieldConfig {
    /// Whether the shield is active.
    #[serde(default)]
    pub enabled: bool,
    /// Action for the advertising category (`"deny"` or `"log"`).
    #[serde(default = "default_log_str")]
    pub advertising: String,
    /// Action for the analytics category.
    #[serde(default = "default_log_str")]
    pub analytics: String,
    /// Action for the fingerprinting category.
    #[serde(default = "default_log_str")]
    pub fingerprinting: String,
    /// Action for the social category.
    #[serde(default = "default_log_str")]
    pub social: String,
}

fn default_log_str() -> String {
    "log".to_owned()
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertising: default_log_str(),
            analytics: default_log_str(),
            fingerprinting: default_log_str(),
            social: default_log_str(),
        }
    }
}

impl ShieldConfig {
    /// Build a fully-enabled shield (all categories deny).
    fn enabled_all() -> Self {
        Self {
            enabled: true,
            advertising: "deny".to_owned(),
            analytics: "deny".to_owned(),
            fingerprinting: "deny".to_owned(),
            social: "deny".to_owned(),
        }
    }

    /// Build a partially-enabled shield -- only named categories are denied.
    fn enabled_partial(only: &[String]) -> Self {
        let mut cfg = Self {
            enabled: true,
            ..Self::default()
        };
        for cat in only {
            match cat.to_ascii_lowercase().as_str() {
                "advertising" => "deny".clone_into(&mut cfg.advertising),
                "analytics" => "deny".clone_into(&mut cfg.analytics),
                "fingerprinting" => "deny".clone_into(&mut cfg.fingerprinting),
                "social" => "deny".clone_into(&mut cfg.social),
                _ => {} // unknown category -- silently ignored
            }
        }
        cfg
    }

    /// Return the `NetworkAction` for a named category.
    pub(crate) fn category_action(&self, name: &str) -> NetworkAction {
        let val = match name {
            "advertising" => &self.advertising,
            "analytics" => &self.analytics,
            "fingerprinting" => &self.fingerprinting,
            "social" => &self.social,
            _ => return NetworkAction::Log,
        };
        if val == "deny" {
            NetworkAction::Deny
        } else {
            NetworkAction::Log
        }
    }

    /// Check whether a category name is set to deny.
    pub(crate) fn is_category_denied(&self, name: &str) -> bool {
        self.category_action(name) == NetworkAction::Deny
    }
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load the shield config from disk, returning defaults if absent or unreadable.
pub(crate) fn load_shield_config() -> ShieldConfig {
    let Ok(path) = cli::expand_home(SHIELD_FILE) else {
        return ShieldConfig::default();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return ShieldConfig::default();
    };
    toml::from_str(&content).unwrap_or_default()
}

/// Save the shield config to disk, creating parent directories as needed.
fn save_shield_config(cfg: &ShieldConfig) -> Result<()> {
    let path = cli::expand_home(SHIELD_FILE).context("failed to resolve shield config path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    let content = toml::to_string_pretty(cfg).context("failed to serialize shield config")?;
    std::fs::write(&path, content).context("failed to write shield config")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

/// Run `macwarden net shield`.
pub(super) fn run(off: bool, only: &[String]) -> Result<()> {
    if off {
        return run_disable();
    }
    run_enable(only)
}

/// Enable the tracker shield.
fn run_enable(only: &[String]) -> Result<()> {
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;
    let stats = tracker_db.stats();
    let cfg = if only.is_empty() {
        ShieldConfig::enabled_all()
    } else {
        ShieldConfig::enabled_partial(only)
    };
    save_shield_config(&cfg)?;

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
fn run_disable() -> Result<()> {
    let cfg = ShieldConfig::default();
    save_shield_config(&cfg)?;
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
