//! Artifact domains — named collections of filesystem artifacts to clean.
//!
//! An artifact domain maps a human concept (e.g. "saved-state", "browser-traces")
//! to a set of filesystem paths and shell commands that `macwarden scrub` can
//! clean, independent of launchd services.

use std::collections::HashSet;

use serde::Deserialize;

use crate::error::CoreError;
use crate::group::Safety;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A named collection of related filesystem artifacts.
///
/// Each domain groups paths and commands that belong to the same privacy
/// concern (e.g. all browser cache paths, all saved-state directories).
#[derive(Debug, Clone)]
pub struct ArtifactDomain {
    /// Domain name (e.g. "saved-state", "browser-traces").
    pub name: String,
    /// What this domain covers.
    pub description: String,
    /// How safe it is to clean these artifacts.
    pub safety: Safety,
    /// The cleanable artifacts in this domain.
    pub artifacts: Vec<Artifact>,
}

/// A single cleanable item — a file, directory, or shell command.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Artifact identifier (e.g. "saved-state-chrome", "unified-log").
    pub name: String,
    /// What this artifact is.
    pub description: String,
    /// How to clean it — delete a path or run a command.
    pub action: ArtifactAction,
}

/// The cleanup action for an artifact.
#[derive(Debug, Clone)]
pub enum ArtifactAction {
    /// Delete a filesystem path (may contain `~` for home directory).
    Path(String),
    /// Run a shell command (e.g. `log erase --all`).
    Command(String),
}

// ---------------------------------------------------------------------------
// TOML serde helpers
// ---------------------------------------------------------------------------

/// Top-level structure of a single-domain artifact TOML file.
#[derive(Debug, Deserialize)]
struct ArtifactFile {
    domain: DomainEntry,
    artifact: Vec<ArtifactEntry>,
}

/// The `[domain]` table in an artifact TOML file.
#[derive(Debug, Deserialize)]
struct DomainEntry {
    name: String,
    description: String,
    safety: Safety,
}

/// A single `[[artifact]]` entry in a TOML file.
#[derive(Debug, Deserialize)]
struct ArtifactEntry {
    name: String,
    description: String,
    path: Option<String>,
    command: Option<String>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a single-domain artifact TOML file.
///
/// Expected format:
/// ```toml
/// [domain]
/// name = "saved-state"
/// description = "Window snapshots every app leaves behind at quit"
/// safety = "recommended"
///
/// [[artifact]]
/// name = "saved-state-all"
/// path = "~/Library/Saved Application State/"
/// description = "Window snapshots for all applications"
/// ```
pub fn parse_artifact_file(content: &str) -> crate::error::Result<ArtifactDomain> {
    let parsed: ArtifactFile = toml::from_str(content).map_err(|e| CoreError::ArtifactParse {
        message: format!("failed to parse artifact TOML: {e}"),
    })?;

    validate_domain_name(&parsed.domain.name)?;

    if parsed.artifact.is_empty() {
        return Err(CoreError::ArtifactParse {
            message: format!(
                "domain '{}' has no artifacts — at least one [[artifact]] is required",
                parsed.domain.name
            ),
        });
    }

    let artifacts = parsed
        .artifact
        .into_iter()
        .map(|a| convert_artifact_entry(a, &parsed.domain.name))
        .collect::<crate::error::Result<Vec<_>>>()?;

    Ok(ArtifactDomain {
        name: parsed.domain.name,
        description: parsed.domain.description,
        safety: parsed.domain.safety,
        artifacts,
    })
}

/// Convert a raw TOML entry into an [`Artifact`], validating action fields.
fn convert_artifact_entry(
    entry: ArtifactEntry,
    domain_name: &str,
) -> crate::error::Result<Artifact> {
    validate_artifact_name(&entry.name, domain_name)?;

    let action = match (entry.path, entry.command) {
        (Some(p), None) => ArtifactAction::Path(p),
        (None, Some(c)) => ArtifactAction::Command(c),
        (Some(_), Some(_)) => {
            return Err(CoreError::ArtifactParse {
                message: format!(
                    "artifact '{}' in domain '{}' has both path and command — only one allowed",
                    entry.name, domain_name
                ),
            });
        }
        (None, None) => {
            return Err(CoreError::ArtifactParse {
                message: format!(
                    "artifact '{}' in domain '{}' has neither path nor command — one is required",
                    entry.name, domain_name
                ),
            });
        }
    };

    Ok(Artifact {
        name: entry.name,
        description: entry.description,
        action,
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a name uses only `[a-z0-9-]` and is non-empty.
fn is_valid_slug(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate a domain name.
fn validate_domain_name(name: &str) -> crate::error::Result<()> {
    if !is_valid_slug(name) {
        return Err(CoreError::ArtifactParse {
            message: format!(
                "domain name '{name}' is invalid — must be non-empty, lowercase ASCII [a-z0-9-]"
            ),
        });
    }
    Ok(())
}

/// Validate an artifact name.
fn validate_artifact_name(name: &str, domain_name: &str) -> crate::error::Result<()> {
    if !is_valid_slug(name) {
        return Err(CoreError::ArtifactParse {
            message: format!(
                "artifact name '{name}' in domain '{domain_name}' is invalid \
                 — must be non-empty, lowercase ASCII [a-z0-9-]"
            ),
        });
    }
    Ok(())
}

/// Validate global name uniqueness across all artifact domains.
///
/// Checks:
/// - No two domains share the same name.
/// - No two artifacts (across all domains) share the same name.
/// - No artifact name collides with any domain name.
pub fn validate_artifact_catalog(domains: &[ArtifactDomain]) -> crate::error::Result<()> {
    let mut domain_names: HashSet<&str> = HashSet::new();
    for d in domains {
        if !domain_names.insert(&d.name) {
            return Err(CoreError::ArtifactValidation {
                message: format!("duplicate domain name: '{}'", d.name),
            });
        }
    }

    let mut artifact_names: HashSet<&str> = HashSet::new();
    for d in domains {
        for a in &d.artifacts {
            if !artifact_names.insert(&a.name) {
                return Err(CoreError::ArtifactValidation {
                    message: format!(
                        "duplicate artifact name: '{}' (found in domain '{}')",
                        a.name, d.name
                    ),
                });
            }
        }
    }

    for d in domains {
        for a in &d.artifacts {
            if domain_names.contains(a.name.as_str()) {
                return Err(CoreError::ArtifactValidation {
                    message: format!(
                        "artifact name '{}' in domain '{}' collides with a domain name",
                        a.name, d.name
                    ),
                });
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

/// Find an artifact domain by name (case-insensitive).
pub fn find_artifact_domain<'a>(
    name: &str,
    domains: &'a [ArtifactDomain],
) -> Option<&'a ArtifactDomain> {
    let lower = name.to_lowercase();
    domains.iter().find(|d| d.name == lower)
}

/// Find an individual artifact by name across all domains (case-insensitive).
///
/// Returns the owning domain and the artifact.
pub fn find_artifact<'a>(
    name: &str,
    domains: &'a [ArtifactDomain],
) -> Option<(&'a ArtifactDomain, &'a Artifact)> {
    let lower = name.to_lowercase();
    for domain in domains {
        for artifact in &domain.artifacts {
            if artifact.name == lower {
                return Some((domain, artifact));
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "artifact_test.rs"]
mod artifact_test;
