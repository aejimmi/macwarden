//! Profile types, TOML loading, extends resolution, and validation.
//!
//! Profiles declare which services should run and which should be disabled.
//! They compose via an `extends` chain (max 3 levels, no cycles).

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, ProfileError};
use crate::safelist::is_critical;

/// Maximum depth for profile extends chains.
const MAX_EXTENDS_DEPTH: usize = 3;

// ---------------------------------------------------------------------------
// Profile types
// ---------------------------------------------------------------------------

/// A macwarden profile declaring service allow/deny rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)] // Field name matches TOML `[profile]` section.
pub struct Profile {
    /// Profile metadata (TOML `[profile]` section).
    pub profile: ProfileMeta,
    /// Allow/deny rules.
    pub rules: Rules,
    /// Enforcement behavior.
    pub enforcement: Enforcement,
}

/// Profile metadata (name, description, extends, version constraint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMeta {
    /// Unique profile name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Names of parent profiles this profile inherits from.
    #[serde(default)]
    pub extends: Vec<String>,
    /// Minimum macOS version required.
    #[serde(default)]
    pub macos_min: Option<semver::Version>,
}

/// Allow/deny rule sets and per-category overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// Service labels or glob patterns to deny (disable/kill).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Service labels or glob patterns to explicitly allow.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Per-category actions, keyed by category name (e.g. `"telemetry"`).
    #[serde(default)]
    pub categories: HashMap<String, CategoryAction>,
}

/// What to do with an entire service category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CategoryAction {
    /// Allow all services in this category to run.
    Allow,
    /// Deny (disable) all services in this category.
    Deny,
    /// Log but take no enforcement action.
    #[serde(rename = "log-only")]
    LogOnly,
}

impl fmt::Display for CategoryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::LogOnly => write!(f, "log-only"),
        }
    }
}

/// Enforcement configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    /// What enforcement action to take.
    pub action: EnforcementAction,
    /// Tier 2 execution policy.
    #[serde(default = "default_exec_policy")]
    pub exec_policy: ExecPolicy,
}

fn default_exec_policy() -> ExecPolicy {
    ExecPolicy::Allow
}

/// The enforcement action applied to denied services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementAction {
    /// Disable via launchctl.
    Disable,
    /// Kill the process.
    Kill,
    /// Log only, take no action.
    LogOnly,
}

impl fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disable => write!(f, "disable"),
            Self::Kill => write!(f, "kill"),
            Self::LogOnly => write!(f, "log-only"),
        }
    }
}

/// Tier 2 execution policy for Endpoint Security AUTH_EXEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecPolicy {
    /// Allow execution by default.
    Allow,
    /// Deny execution by default.
    Deny,
}

impl fmt::Display for ExecPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

// ---------------------------------------------------------------------------
// TOML loading
// ---------------------------------------------------------------------------

/// Parse a profile from a TOML file on disk.
pub fn load_profile(path: &Path) -> crate::error::Result<Profile> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::ProfileParse {
        message: format!("cannot read {}: {e}", path.display()),
    })?;
    parse_profile_toml(&content)
}

/// Parse a profile from a TOML string.
pub fn parse_profile_toml(content: &str) -> crate::error::Result<Profile> {
    toml::from_str(content).map_err(|e| CoreError::ProfileParse {
        message: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Extends resolution
// ---------------------------------------------------------------------------

/// Resolve the extends chain for a profile, merging parent rules.
///
/// Child rules win conflicts. Maximum depth is 3 levels. Circular
/// references are detected and produce an error.
pub fn resolve_extends(profile: &Profile, available: &[Profile]) -> crate::error::Result<Profile> {
    let mut chain: Vec<Profile> = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(profile.profile.name.clone());

    collect_chain(profile, available, &mut chain, &mut seen, 0)?;

    // Merge: start from the deepest ancestor and overlay toward the child.
    // The child's own rules are applied last (highest priority).
    let mut merged = profile.clone();
    // chain is ordered [parent, grandparent, ...] — reverse for bottom-up merge.
    chain.reverse();

    for ancestor in &chain {
        merge_into(&mut merged, ancestor);
    }

    // Re-apply the child's own rules on top (child wins conflicts).
    overlay_child(&mut merged, profile);

    // Clear extends since we've resolved them.
    merged.profile.extends.clear();

    Ok(merged)
}

/// Recursively collect the extends chain (parents first, depth-limited).
fn collect_chain(
    profile: &Profile,
    available: &[Profile],
    chain: &mut Vec<Profile>,
    seen: &mut HashSet<String>,
    depth: usize,
) -> crate::error::Result<()> {
    if depth >= MAX_EXTENDS_DEPTH {
        return Err(CoreError::MaxExtendsDepth {
            max_depth: MAX_EXTENDS_DEPTH,
        });
    }

    for parent_name in &profile.profile.extends {
        if !seen.insert(parent_name.clone()) {
            return Err(CoreError::CircularExtends {
                chain: format!("{} -> {}", profile.profile.name, parent_name),
            });
        }

        let parent = available
            .iter()
            .find(|p| p.profile.name == *parent_name)
            .ok_or_else(|| CoreError::ProfileNotFound {
                name: parent_name.clone(),
            })?;

        // Recurse into the parent's extends first.
        collect_chain(parent, available, chain, seen, depth + 1)?;
        chain.push(parent.clone());
    }

    Ok(())
}

/// Merge ancestor's rules into the target (union deny/allow, insert missing categories).
fn merge_into(target: &mut Profile, ancestor: &Profile) {
    for label in &ancestor.rules.deny {
        if !target.rules.deny.contains(label) {
            target.rules.deny.push(label.clone());
        }
    }
    for label in &ancestor.rules.allow {
        if !target.rules.allow.contains(label) {
            target.rules.allow.push(label.clone());
        }
    }
    for (cat, action) in &ancestor.rules.categories {
        target
            .rules
            .categories
            .entry(cat.clone())
            .or_insert(*action);
    }
}

/// Re-apply the child's rules on top after merging ancestors.
fn overlay_child(target: &mut Profile, child: &Profile) {
    // Child's categories override ancestors.
    for (cat, action) in &child.rules.categories {
        target.rules.categories.insert(cat.clone(), *action);
    }
    // Child's enforcement wins.
    target.enforcement = child.enforcement.clone();
}

// ---------------------------------------------------------------------------
// Profile validation
// ---------------------------------------------------------------------------

/// Validate that a profile does not attempt to deny critical services.
pub fn validate_profile(profile: &Profile) -> Result<(), ProfileError> {
    let violations: Vec<&String> = profile
        .rules
        .deny
        .iter()
        .filter(|label| is_critical(label))
        .collect();

    if violations.is_empty() {
        Ok(())
    } else {
        let labels: Vec<&str> = violations.iter().map(|s| s.as_str()).collect();
        Err(ProfileError {
            message: format!(
                "deny list references critical services: {}",
                labels.join(", ")
            ),
        })
    }
}

#[cfg(test)]
#[path = "profile_test.rs"]
mod profile_test;
