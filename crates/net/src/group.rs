//! Network rule groups -- toggleable bundles of related network rules.
//!
//! Groups map directly to TOML files in `knowledge/network/groups/`. Each group
//! contains a set of rules with domain patterns that can be enabled or
//! disabled as a unit. One toggle controls dozens of domain rules.
//!
//! Groups are loaded at startup via `include_str!` (same pattern as the
//! tracker database). They are evaluated as Tier 2 in the five-tier
//! matcher, after user rules and before trackers.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::host::HostPattern;
use crate::matcher::GroupedRule;
use crate::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};

// ---------------------------------------------------------------------------
// Embedded TOML data
// ---------------------------------------------------------------------------

const ICLOUD_SERVICES_TOML: &str =
    include_str!("../../../knowledge/network/groups/icloud-services.toml");
const MACOS_SERVICES_TOML: &str =
    include_str!("../../../knowledge/network/groups/macos-services.toml");
const BROWSER_ESSENTIALS_TOML: &str =
    include_str!("../../../knowledge/network/groups/browser-essentials.toml");
const DEVELOPMENT_TOML: &str = include_str!("../../../knowledge/network/groups/development.toml");
const GAMING_TOML: &str = include_str!("../../../knowledge/network/groups/gaming.toml");
const MEDIA_STREAMING_TOML: &str =
    include_str!("../../../knowledge/network/groups/media-streaming.toml");
const PRODUCTIVITY_TOML: &str = include_str!("../../../knowledge/network/groups/productivity.toml");
const COMMUNICATION_TOML: &str =
    include_str!("../../../knowledge/network/groups/communication.toml");

/// All builtin group TOML sources.
const BUILTIN_GROUP_SOURCES: &[&str] = &[
    ICLOUD_SERVICES_TOML,
    MACOS_SERVICES_TOML,
    BROWSER_ESSENTIALS_TOML,
    DEVELOPMENT_TOML,
    GAMING_TOML,
    MEDIA_STREAMING_TOML,
    PRODUCTIVITY_TOML,
    COMMUNICATION_TOML,
];

// ---------------------------------------------------------------------------
// NetworkGroup
// ---------------------------------------------------------------------------

/// A network rule group -- a toggleable bundle of related rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGroup {
    /// Unique group name (e.g. `"icloud-services"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this group is enabled by default.
    #[serde(default = "default_true")]
    pub default_enabled: bool,
    /// Priority for Tier 2 ordering. Lower = evaluated first.
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Rules within this group.
    pub rules: Vec<NetworkGroupRule>,
}

/// A rule within a group -- simplified from full `NetworkRule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGroupRule {
    /// Human-readable name (e.g. `"iCloud core domains"`).
    pub name: String,
    /// Process pattern: `"*"` for any, or a code_id/path pattern.
    pub process: String,
    /// Destination host patterns (domain patterns).
    pub dest_hosts: Vec<String>,
    /// What to do when matched.
    pub action: NetworkAction,
    /// Optional explanatory note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Wrapper matching the TOML structure `[group]`.
#[derive(Debug, Deserialize)]
struct GroupFile {
    group: NetworkGroup,
}

/// Default value for `default_enabled`.
fn default_true() -> bool {
    true
}

/// Default value for `priority`.
fn default_priority() -> u32 {
    50
}

// ---------------------------------------------------------------------------
// NetworkGroups
// ---------------------------------------------------------------------------

/// All loaded network groups.
#[derive(Debug, Clone)]
pub struct NetworkGroups {
    /// Loaded groups, sorted by priority (lower first).
    groups: Vec<NetworkGroup>,
}

impl NetworkGroups {
    /// Load built-in groups from embedded TOML data.
    ///
    /// # Errors
    ///
    /// Returns `NetError::GroupParse` if any embedded TOML file is malformed.
    pub fn load_builtin() -> Result<Self, NetError> {
        let mut groups = Vec::with_capacity(BUILTIN_GROUP_SOURCES.len());

        for toml_src in BUILTIN_GROUP_SOURCES {
            let file: GroupFile = toml::from_str(toml_src).map_err(|e| NetError::GroupParse {
                group: "builtin".to_owned(),
                message: e.to_string(),
            })?;
            groups.push(file.group);
        }

        groups.sort_by_key(|g| g.priority);
        Ok(Self { groups })
    }

    /// Get a group by name.
    pub fn get(&self, name: &str) -> Option<&NetworkGroup> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// All loaded groups, sorted by priority (lower first).
    pub fn all(&self) -> &[NetworkGroup] {
        &self.groups
    }

    /// List all group names with their default enabled status.
    pub fn list(&self) -> Vec<(&str, bool)> {
        self.groups
            .iter()
            .map(|g| (g.name.as_str(), g.default_enabled))
            .collect()
    }

    /// Convert enabled groups into [`GroupedRule`] values for the matcher.
    ///
    /// For each group, checks if it is enabled (from `default_enabled`,
    /// overridden by `enable_overrides` and `disable_overrides`). If enabled,
    /// expands each `NetworkGroupRule` into one `GroupedRule` per `dest_hosts`
    /// entry.
    ///
    /// # Errors
    ///
    /// Returns `NetError::GroupParse` if a host pattern or process pattern
    /// within an enabled group is invalid.
    pub fn to_grouped_rules(
        &self,
        enable_overrides: &HashSet<String>,
        disable_overrides: &HashSet<String>,
    ) -> Result<Vec<GroupedRule>, NetError> {
        let mut out = Vec::new();
        let mut rule_counter: u64 = 10_000;

        for group in &self.groups {
            if !is_group_enabled(group, enable_overrides, disable_overrides) {
                continue;
            }
            expand_group(group, &mut out, &mut rule_counter)?;
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine whether a group is enabled given default + overrides.
fn is_group_enabled(
    group: &NetworkGroup,
    enable_overrides: &HashSet<String>,
    disable_overrides: &HashSet<String>,
) -> bool {
    // Explicit disable overrides everything.
    if disable_overrides.contains(&group.name) {
        return false;
    }
    // Explicit enable overrides the default.
    if enable_overrides.contains(&group.name) {
        return true;
    }
    group.default_enabled
}

/// Expand a single group into `GroupedRule` values.
fn expand_group(
    group: &NetworkGroup,
    out: &mut Vec<GroupedRule>,
    counter: &mut u64,
) -> Result<(), NetError> {
    for group_rule in &group.rules {
        let process = parse_process(&group_rule.process, &group.name)?;

        for host_pattern in &group_rule.dest_hosts {
            let host = HostPattern::new(host_pattern).map_err(|e| NetError::GroupParse {
                group: group.name.clone(),
                message: format!(
                    "invalid host pattern `{host_pattern}` in rule `{}`: {e}",
                    group_rule.name,
                ),
            })?;

            let rule = NetworkRule {
                id: RuleId(*counter),
                name: group_rule.name.clone(),
                process: process.clone(),
                destination: DestMatcher {
                    host: Some(host),
                    ..Default::default()
                },
                action: group_rule.action,
                duration: RuleDuration::Permanent,
                enabled: true,
                note: group_rule.note.clone(),
            };

            out.push(GroupedRule {
                rule,
                group_name: group.name.clone(),
                group_priority: group.priority,
            });

            *counter += 1;
        }
    }
    Ok(())
}

/// Parse a process string from the group TOML.
fn parse_process(process: &str, group_name: &str) -> Result<ProcessMatcher, NetError> {
    if process == "*" {
        return Ok(ProcessMatcher::Any);
    }
    // If it looks like a path (starts with /), use Path matcher.
    if process.starts_with('/') {
        ProcessMatcher::path(process).map_err(|e| NetError::GroupParse {
            group: group_name.to_owned(),
            message: format!("invalid process path `{process}`: {e}"),
        })
    } else {
        ProcessMatcher::code_id(process).map_err(|e| NetError::GroupParse {
            group: group_name.to_owned(),
            message: format!("invalid process code_id `{process}`: {e}"),
        })
    }
}

#[cfg(test)]
#[path = "group_test.rs"]
mod group_test;
