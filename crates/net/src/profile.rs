//! Network profile section -- parses and resolves the `[network]` section
//! of a macwarden profile TOML.
//!
//! The profile declares:
//! - A default action for unmatched connections
//! - Tracker shield settings (per-category deny/log/allow)
//! - Which network groups to enable/disable
//! - Which blocklists to enable
//! - Inline per-process rules (with optional category expansion)
//!
//! The [`NetworkProfile::resolve`] method assembles a complete
//! [`RuleSet`](crate::matcher::RuleSet) from these settings plus the
//! loaded group, tracker, category, and blocklist databases.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::blocklist::Blocklist;
use crate::domain_trie::DomainTrie;
use crate::error::NetError;
use crate::group::NetworkGroups;
use crate::host::HostPattern;
use crate::matcher::RuleSet;
use crate::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};
use crate::tracker::{TrackerCategory, TrackerDatabase};
use appdb::{AppCategory, AppDb};

// ---------------------------------------------------------------------------
// NetworkProfile
// ---------------------------------------------------------------------------

/// The `[network]` section of a macwarden profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    /// Default action for connections with no matching rule.
    #[serde(default = "default_log")]
    pub default: NetworkAction,

    /// Tracker shield settings (per-category actions).
    #[serde(default)]
    pub trackers: TrackerSettings,

    /// Which network groups to enable/disable.
    #[serde(default)]
    pub groups: GroupSettings,

    /// Which blocklists to enable.
    #[serde(default)]
    pub blocklists: BlocklistSettings,

    /// Per-process rules defined inline in the profile.
    #[serde(default)]
    pub rules: Vec<ProfileNetworkRule>,
}

impl NetworkProfile {
    /// Resolve this profile into a [`RuleSet`] that the matcher can use.
    ///
    /// Expands categories, loads groups, loads trackers, applies settings.
    ///
    /// # Errors
    ///
    /// Returns `NetError::ProfileResolve` if category expansion, group
    /// loading, or rule construction fails.
    pub fn resolve(
        &self,
        groups: &NetworkGroups,
        tracker_db: &TrackerDatabase,
        category_db: &AppDb,
        blocklists: &[Blocklist],
    ) -> Result<RuleSet, NetError> {
        let user_rules = self.resolve_user_rules(category_db)?;
        let group_rules = self.resolve_groups(groups)?;
        let tracker_rules = self.resolve_trackers(tracker_db)?;
        let blocklist_domains = self.resolve_blocklists(blocklists);

        let mut rule_set = RuleSet {
            user_rules,
            group_rules,
            tracker_rules,
            blocklist_domains,
            blocklist_trie: DomainTrie::new(),
            default_action: self.default,
        };
        rule_set.sort_user_rules();
        rule_set.rebuild_blocklist_trie();
        Ok(rule_set)
    }
}

// ---------------------------------------------------------------------------
// Resolve helpers
// ---------------------------------------------------------------------------

impl NetworkProfile {
    /// Expand inline profile rules into `NetworkRule` values.
    fn resolve_user_rules(&self, category_db: &AppDb) -> Result<Vec<NetworkRule>, NetError> {
        let mut out = Vec::new();
        let mut counter: u64 = 1;

        for profile_rule in &self.rules {
            let processes = expand_profile_process(&profile_rule.process, category_db)?;
            let dest = build_dest_matcher(&profile_rule.dest)?;

            for process in processes {
                out.push(NetworkRule {
                    id: RuleId(counter),
                    name: profile_rule.name.clone(),
                    process,
                    destination: dest.clone(),
                    action: profile_rule.action,
                    duration: RuleDuration::Permanent,
                    enabled: true,
                    note: profile_rule.note.clone(),
                });
                counter += 1;
            }
        }

        Ok(out)
    }

    /// Build group rules from enabled groups.
    fn resolve_groups(
        &self,
        groups: &NetworkGroups,
    ) -> Result<Vec<crate::matcher::GroupedRule>, NetError> {
        let enable: HashSet<String> = self.groups.enable.iter().cloned().collect();
        let disable: HashSet<String> = self.groups.disable.iter().cloned().collect();
        groups
            .to_grouped_rules(&enable, &disable)
            .map_err(|e| NetError::ProfileResolve {
                message: format!("group expansion failed: {e}"),
            })
    }

    /// Build tracker rules for categories set to "deny".
    fn resolve_trackers(
        &self,
        tracker_db: &TrackerDatabase,
    ) -> Result<Vec<crate::matcher::TrackerRule>, NetError> {
        let all_rules = tracker_db
            .to_tracker_rules()
            .map_err(|e| NetError::ProfileResolve {
                message: format!("tracker rule generation failed: {e}"),
            })?;

        // Only include tracker rules for categories the profile denies.
        let denied_categories = self.trackers.denied_categories();

        Ok(all_rules
            .into_iter()
            .filter(|r| denied_categories.contains(&r.category))
            .collect())
    }

    /// Build blocklist entries from enabled blocklists.
    fn resolve_blocklists(&self, blocklists: &[Blocklist]) -> Vec<crate::matcher::BlocklistEntry> {
        let enabled: HashSet<&str> = self.blocklists.enable.iter().map(String::as_str).collect();

        blocklists
            .iter()
            .filter(|bl| enabled.contains(bl.name()))
            .flat_map(Blocklist::to_blocklist_entries)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TrackerSettings
// ---------------------------------------------------------------------------

/// Per-category tracker shield settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerSettings {
    /// Action for advertising trackers.
    #[serde(default = "default_log")]
    pub advertising: NetworkAction,
    /// Action for analytics trackers.
    #[serde(default = "default_log")]
    pub analytics: NetworkAction,
    /// Action for fingerprinting trackers.
    #[serde(default = "default_log")]
    pub fingerprinting: NetworkAction,
    /// Action for social media trackers.
    #[serde(default = "default_log")]
    pub social: NetworkAction,
    /// Whether to auto-allow critical-breakage-risk tracker domains.
    #[serde(default = "default_true")]
    pub breakage_detection: bool,
}

impl Default for TrackerSettings {
    fn default() -> Self {
        Self {
            advertising: default_log(),
            analytics: default_log(),
            fingerprinting: default_log(),
            social: default_log(),
            breakage_detection: true,
        }
    }
}

impl TrackerSettings {
    /// Return the set of tracker category name strings that are set to `Deny`.
    fn denied_categories(&self) -> HashSet<String> {
        let mut set = HashSet::new();
        if self.advertising == NetworkAction::Deny {
            set.insert(TrackerCategory::Advertising.to_string());
        }
        if self.analytics == NetworkAction::Deny {
            set.insert(TrackerCategory::Analytics.to_string());
        }
        if self.fingerprinting == NetworkAction::Deny {
            set.insert(TrackerCategory::Fingerprinting.to_string());
        }
        if self.social == NetworkAction::Deny {
            set.insert(TrackerCategory::Social.to_string());
        }
        set
    }
}

// ---------------------------------------------------------------------------
// GroupSettings
// ---------------------------------------------------------------------------

/// Which network groups to enable/disable (overriding defaults).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Groups to explicitly enable (overrides `default_enabled = false`).
    #[serde(default)]
    pub enable: Vec<String>,
    /// Groups to explicitly disable (overrides `default_enabled = true`).
    #[serde(default)]
    pub disable: Vec<String>,
}

// ---------------------------------------------------------------------------
// BlocklistSettings
// ---------------------------------------------------------------------------

/// Which blocklists to enable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlocklistSettings {
    /// Names of blocklists to activate.
    #[serde(default)]
    pub enable: Vec<String>,
}

// ---------------------------------------------------------------------------
// ProfileNetworkRule
// ---------------------------------------------------------------------------

/// A network rule defined inline in a profile's `[[network.rules]]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileNetworkRule {
    /// Human-readable name.
    pub name: String,
    /// Process specification: a string or `{ category = "browser" }`.
    pub process: ProfileProcess,
    /// Destination: a host pattern string or `"*"` for any.
    pub dest: String,
    /// What to do when matched.
    pub action: NetworkAction,
    /// Optional explanatory note.
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// ProfileProcess
// ---------------------------------------------------------------------------

/// Process specification in a profile -- can be a simple string, a
/// category reference, or a team ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProfileProcess {
    /// Simple string: code_id, path, or `"*"`.
    Pattern(String),
    /// Category reference: `{ category = "browser" }`.
    Category {
        /// The app category to expand.
        category: AppCategory,
    },
    /// Team ID reference: `{ team_id = "EQHXZ8M8AV" }`.
    TeamId {
        /// The code signing team identifier.
        team_id: String,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Default action: `Log` (monitor mode).
fn default_log() -> NetworkAction {
    NetworkAction::Log
}

/// Default `true` for boolean fields.
fn default_true() -> bool {
    true
}

/// Expand a `ProfileProcess` into one or more `ProcessMatcher` values.
fn expand_profile_process(
    process: &ProfileProcess,
    category_db: &AppDb,
) -> Result<Vec<ProcessMatcher>, NetError> {
    match process {
        ProfileProcess::Pattern(pattern) => {
            let matcher = parse_process_pattern(pattern)?;
            Ok(vec![matcher])
        }
        ProfileProcess::Category { category } => {
            let code_ids = category_db.expand_category(*category);
            if code_ids.is_empty() {
                return Err(NetError::ProfileResolve {
                    message: format!("category `{category}` has no apps registered"),
                });
            }
            code_ids
                .iter()
                .map(|id| {
                    ProcessMatcher::code_id(id).map_err(|e| NetError::ProfileResolve {
                        message: format!("invalid code_id `{id}` from category `{category}`: {e}"),
                    })
                })
                .collect()
        }
        ProfileProcess::TeamId { team_id } => {
            if team_id.is_empty() {
                return Err(NetError::ProfileResolve {
                    message: "team_id must not be empty".to_owned(),
                });
            }
            Ok(vec![ProcessMatcher::TeamId(team_id.clone())])
        }
    }
}

/// Known app category names — used to catch the common mistake of writing
/// `process = "browser"` instead of `process = { category = "browser" }`.
const CATEGORY_NAMES: &[&str] = &[
    "browser",
    "communication",
    "productivity",
    "media",
    "design",
    "development",
    "cloud",
    "system",
    "security",
    "gaming",
    "utility",
];

/// Parse a process pattern string into a `ProcessMatcher`.
fn parse_process_pattern(pattern: &str) -> Result<ProcessMatcher, NetError> {
    if pattern == "*" {
        return Ok(ProcessMatcher::Any);
    }
    // Catch common mistake: `process = "browser"` instead of
    // `process = { category = "browser" }`. A bare category name as a
    // code_id pattern would silently match nothing useful.
    if CATEGORY_NAMES.contains(&pattern.to_lowercase().as_str()) {
        return Err(NetError::ProfileResolve {
            message: format!(
                "`process = \"{pattern}\"` looks like a category name — \
                 use `process = {{ category = \"{pattern}\" }}` instead"
            ),
        });
    }
    if pattern.starts_with('/') {
        ProcessMatcher::path(pattern).map_err(|e| NetError::ProfileResolve {
            message: format!("invalid process path `{pattern}`: {e}"),
        })
    } else {
        ProcessMatcher::code_id(pattern).map_err(|e| NetError::ProfileResolve {
            message: format!("invalid process code_id `{pattern}`: {e}"),
        })
    }
}

/// Build a `DestMatcher` from a destination string.
fn build_dest_matcher(dest: &str) -> Result<DestMatcher, NetError> {
    if dest == "*" {
        return Ok(DestMatcher::default());
    }
    let host = HostPattern::new(dest).map_err(|e| NetError::ProfileResolve {
        message: format!("invalid dest pattern `{dest}`: {e}"),
    })?;
    Ok(DestMatcher {
        host: Some(host),
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "profile_test.rs"]
mod profile_test;
