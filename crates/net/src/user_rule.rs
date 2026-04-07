//! TOML-based user rules loaded from individual files on disk.
//!
//! Each file in `~/.macwarden/net-rules/` describes a single network
//! rule. The [`load_user_rules`] function reads all `.toml` files from
//! a directory and converts them to [`NetworkRule`] values.

use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};
use crate::host::HostPattern;
use crate::rule::{
    DestMatcher, NetworkAction, NetworkRule, PortMatcher, ProcessMatcher, RuleDuration, RuleId,
};

// ---------------------------------------------------------------------------
// UserRuleFile
// ---------------------------------------------------------------------------

/// A network rule defined in a standalone TOML file.
///
/// Lives in `~/.macwarden/net-rules/` and is loaded via
/// [`load_user_rules`]. Fields map directly to the TOML structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRuleFile {
    /// Human-readable name.
    pub name: String,
    /// Process code_id, path, or `"*"` for any.
    pub process: String,
    /// Destination host pattern or `"*"` for any.
    pub dest: String,
    /// Optional destination port.
    #[serde(default)]
    pub dest_port: Option<u16>,
    /// Action to take when matched.
    pub action: NetworkAction,
    /// Whether this rule is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional human-readable note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Default `true` for the `enabled` field.
fn default_enabled() -> bool {
    true
}

impl UserRuleFile {
    /// Parse a `UserRuleFile` from TOML content.
    ///
    /// # Errors
    ///
    /// Returns `NetError::RuleParse` if the TOML is malformed.
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| NetError::RuleParse {
            path: "<inline>".to_owned(),
            message: e.to_string(),
        })
    }

    /// Convert this file-based rule into a [`NetworkRule`] with a given ID.
    ///
    /// # Errors
    ///
    /// Returns `NetError::InvalidRule` if the process or destination
    /// pattern cannot be compiled.
    pub fn to_network_rule(&self, id: u64) -> Result<NetworkRule> {
        let process = if self.process == "*" {
            ProcessMatcher::Any
        } else if self.process.starts_with('/') {
            ProcessMatcher::path(&self.process)?
        } else {
            ProcessMatcher::code_id(&self.process)?
        };

        let destination = if self.dest == "*" {
            DestMatcher::default()
        } else {
            let host = HostPattern::new(&self.dest)?;
            DestMatcher {
                host: Some(host),
                port: self.dest_port.map(PortMatcher::Single),
                ..Default::default()
            }
        };

        Ok(NetworkRule {
            id: RuleId(id),
            name: self.name.clone(),
            process,
            destination,
            action: self.action,
            duration: RuleDuration::Permanent,
            enabled: self.enabled,
            note: self.note.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// load_user_rules
// ---------------------------------------------------------------------------

/// Load all user rules from `.toml` files in a directory.
///
/// Each file is parsed as a [`UserRuleFile`] and converted to a
/// [`NetworkRule`]. Files that fail to parse are skipped with a
/// `tracing::warn!` log.
///
/// # Errors
///
/// Returns `NetError::RuleParse` if the directory cannot be read.
pub fn load_user_rules(dir: &std::path::Path) -> Result<Vec<NetworkRule>> {
    let entries = std::fs::read_dir(dir).map_err(|e| NetError::RuleParse {
        path: dir.display().to_string(),
        message: format!("cannot read directory: {e}"),
    })?;

    let mut rules = Vec::new();
    let mut counter: u64 = 10_000; // offset to avoid ID collision with profile rules

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable directory entry");
                continue;
            }
        };

        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("toml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable rule file");
                continue;
            }
        };

        let file_rule = match UserRuleFile::from_toml(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unparseable rule file");
                continue;
            }
        };

        match file_rule.to_network_rule(counter) {
            Ok(rule) => {
                rules.push(rule);
                counter += 1;
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping invalid rule");
            }
        }
    }

    Ok(rules)
}

#[cfg(test)]
#[path = "user_rule_test.rs"]
mod user_rule_test;
