//! Tracker shield configuration (`net-shield.toml`).
//!
//! The shield is a one-command tracker-blocking toggle. When enabled, tracker
//! categories set to `"deny"` upgrade the corresponding [`TrackerSettings`]
//! field from `Log` to `Deny` during ruleset composition (see
//! [`crate::loader::base_profile`]). This type is the single source of truth
//! for the shield state so that the daemon and the NetworkExtension decision
//! core (`enforce-ne-ffi`) compose an identical ruleset from the same file.
//!
//! [`TrackerSettings`]: crate::profile::TrackerSettings

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::rule::NetworkAction;

/// Canonical filename of the shield config within `~/.macwarden/`.
pub const SHIELD_FILENAME: &str = "net-shield.toml";

/// Persisted tracker shield state.
///
/// A missing category value defaults to `"log"` (observe, do not block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
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
    #[must_use]
    pub fn enabled_all() -> Self {
        Self {
            enabled: true,
            advertising: "deny".to_owned(),
            analytics: "deny".to_owned(),
            fingerprinting: "deny".to_owned(),
            social: "deny".to_owned(),
        }
    }

    /// Build a partially-enabled shield -- only named categories are denied.
    ///
    /// Unknown category names are silently ignored.
    #[must_use]
    pub fn enabled_partial(only: &[String]) -> Self {
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

    /// Load the shield config from `path`, failing open to the default
    /// (disabled) config if the file is absent, unreadable, or malformed.
    ///
    /// Never returns an error: a broken shield file must not brick the network.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let Ok(content) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        toml::from_str(&content).unwrap_or_default()
    }

    /// Return the [`NetworkAction`] for a named category.
    ///
    /// Unknown category names resolve to [`NetworkAction::Log`].
    #[must_use]
    pub fn category_action(&self, name: &str) -> NetworkAction {
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
    #[must_use]
    pub fn is_category_denied(&self, name: &str) -> bool {
        self.category_action(name) == NetworkAction::Deny
    }
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
