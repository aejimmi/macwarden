//! Service groups — named collections of related services.
//!
//! A service group maps a human concept (e.g. "spotlight", "siri") to a set of
//! service label patterns plus optional system commands for enable/disable.

use std::fmt;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

use crate::error::CoreError;
use crate::types::ServiceInfo;

// ---------------------------------------------------------------------------
// Safety tier
// ---------------------------------------------------------------------------

/// How confident you can be that disabling a group won't break anything.
///
/// Variant declaration order matters — `Recommended < Optional < Keep` via
/// derived `Ord`, so sorting puts easy wins first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Safety {
    /// Safe to disable — no meaningful local function lost.
    Recommended,
    /// Disabling loses a specific feature; your call.
    Optional,
    /// System health or stability — leave unless you know what you're doing.
    Keep,
}

// ---------------------------------------------------------------------------
// Respawn behaviour
// ---------------------------------------------------------------------------

/// How aggressively a group's services respawn after being killed.
///
/// Informs the user whether one-shot enforcement is sufficient or whether
/// continuous monitoring (`macwarden watch`) is needed to keep services dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RespawnBehavior {
    /// Service stays dead after `launchctl disable` + kill.
    #[default]
    StaysDead,
    /// Respawns via launchd `KeepAlive` / `RunAtLoad` — caught by `launchctl
    /// disable`, but may briefly reappear between reboots.
    RespawnsLaunchd,
    /// Respawns aggressively despite `launchctl disable` — via XPC Activity,
    /// BTM, or parent-process spawning. Requires `macwarden watch` for
    /// continuous enforcement.
    RespawnsAggressive,
}

impl fmt::Display for RespawnBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::StaysDead => "stays-dead",
            Self::RespawnsLaunchd => "respawns-launchd",
            Self::RespawnsAggressive => "respawns-aggressive",
        };
        f.write_str(s)
    }
}

impl fmt::Display for Safety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Safety::Recommended => "recommended",
            Safety::Optional => "optional",
            Safety::Keep => "keep",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ServiceGroup
// ---------------------------------------------------------------------------

/// A named group of related services.
///
/// Groups bundle label patterns with optional system commands that should run
/// when the group is enabled or disabled (e.g. `mdutil -a -i off` for
/// spotlight).
#[derive(Debug, Clone)]
pub struct ServiceGroup {
    /// Human-readable name (e.g. "spotlight", "siri").
    pub name: String,
    /// What this group does.
    pub description: String,
    /// How safe it is to disable this group.
    pub safety: Safety,
    /// How aggressively the group's services respawn after being killed.
    pub respawn_behavior: RespawnBehavior,
    /// Service label patterns (exact or glob) that belong to this group.
    pub patterns: Vec<String>,
    /// Additional system commands to run when disabling this group.
    pub disable_commands: Vec<String>,
    /// Additional system commands to run when enabling this group.
    pub enable_commands: Vec<String>,
    /// Commands to run after disabling to reclaim artifacts (caches, indexes,
    /// databases). Only executed on explicit user request, never automatically.
    pub cleanup_commands: Vec<String>,
}

impl ServiceGroup {
    /// Check if a service label matches any of the group's patterns.
    ///
    /// Patterns are matched using glob syntax (e.g. `com.apple.Siri*` matches
    /// `com.apple.Siri.agent`).
    pub fn matches(&self, label: &str) -> bool {
        build_glob_set(&self.patterns).is_match(label)
    }
}

// ---------------------------------------------------------------------------
// TOML parsing
// ---------------------------------------------------------------------------

/// Serde helper for `groups.toml` top-level structure (multi-group file).
#[derive(Debug, Deserialize)]
struct GroupsFile {
    group: Vec<GroupEntry>,
}

/// Serde helper for a single-group file (`[group]` instead of `[[group]]`).
#[derive(Debug, Deserialize)]
struct SingleGroupFile {
    group: GroupEntry,
}

/// A single group entry as it appears in TOML.
#[derive(Debug, Deserialize)]
struct GroupEntry {
    name: String,
    description: String,
    safety: Safety,
    #[serde(default)]
    respawn_behavior: RespawnBehavior,
    patterns: Vec<String>,
    #[serde(default)]
    disable_commands: Vec<String>,
    #[serde(default)]
    enable_commands: Vec<String>,
    #[serde(default)]
    cleanup_commands: Vec<String>,
}

/// Parse service groups from a TOML string.
///
/// Expected format:
/// ```toml
/// [[group]]
/// name = "spotlight"
/// description = "Spotlight search and metadata indexing"
/// patterns = ["com.apple.Spotlight", "com.apple.metadata.mds*"]
/// disable_commands = ["mdutil -a -i off"]
/// enable_commands = ["mdutil -a -i on"]
/// ```
pub fn parse_groups_toml(content: &str) -> crate::error::Result<Vec<ServiceGroup>> {
    let parsed: GroupsFile = toml::from_str(content).map_err(|e| CoreError::ProfileParse {
        message: format!("failed to parse groups TOML: {e}"),
    })?;

    Ok(parsed
        .group
        .into_iter()
        .map(|g| ServiceGroup {
            name: g.name,
            description: g.description,
            safety: g.safety,
            respawn_behavior: g.respawn_behavior,
            patterns: g.patterns,
            disable_commands: g.disable_commands,
            enable_commands: g.enable_commands,
            cleanup_commands: g.cleanup_commands,
        })
        .collect())
}

/// Parse a single group from a per-group TOML file.
///
/// Expected format:
/// ```toml
/// [group]
/// name = "spotlight"
/// description = "Spotlight search and metadata indexing"
/// safety = "optional"
/// patterns = ["com.apple.Spotlight", "com.apple.metadata.mds*"]
/// ```
pub fn parse_group_file(content: &str) -> crate::error::Result<ServiceGroup> {
    let parsed: SingleGroupFile =
        toml::from_str(content).map_err(|e| CoreError::ProfileParse {
            message: format!("failed to parse group file: {e}"),
        })?;

    let g = parsed.group;
    Ok(ServiceGroup {
        name: g.name,
        description: g.description,
        safety: g.safety,
        respawn_behavior: g.respawn_behavior,
        patterns: g.patterns,
        disable_commands: g.disable_commands,
        enable_commands: g.enable_commands,
        cleanup_commands: g.cleanup_commands,
    })
}

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

/// Look up a group by name (case-insensitive).
pub fn find_group<'a>(name: &str, groups: &'a [ServiceGroup]) -> Option<&'a ServiceGroup> {
    let lower = name.to_lowercase();
    groups.iter().find(|g| g.name == lower)
}

/// Find all groups that contain the given service label.
pub fn find_groups_for_service<'a>(
    label: &str,
    groups: &'a [ServiceGroup],
) -> Vec<&'a ServiceGroup> {
    groups.iter().filter(|g| g.matches(label)).collect()
}

/// Resolve a group's patterns against a concrete service list.
///
/// Returns references to all services whose labels match any of the group's
/// patterns.
pub fn resolve_group_services<'a>(
    group: &ServiceGroup,
    all_services: &'a [ServiceInfo],
) -> Vec<&'a ServiceInfo> {
    let glob_set = build_glob_set(&group.patterns);
    all_services
        .iter()
        .filter(|svc| glob_set.is_match(&svc.label))
        .collect()
}

// ---------------------------------------------------------------------------
// Glob helper
// ---------------------------------------------------------------------------

/// Build a [`GlobSet`] from a list of pattern strings.
///
/// Invalid patterns are silently skipped — all built-in patterns are tested.
fn build_glob_set(patterns: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().unwrap_or_else(|_| {
        GlobSetBuilder::new()
            .build()
            .expect("empty glob set must compile")
    })
}

#[cfg(test)]
#[path = "group_test.rs"]
mod group_test;
