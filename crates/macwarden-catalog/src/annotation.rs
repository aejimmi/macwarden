//! Service annotation types and the annotation database.
//!
//! The annotation database maps service labels to human-readable descriptions,
//! categories, and safety levels. It supports both exact-match and glob-pattern
//! lookups.

use std::collections::HashMap;

use macwarden_core::{SafetyLevel, ServiceCategory};
use globset::{Glob, GlobMatcher};
use serde::Deserialize;

use crate::error::{CatalogError, Result};

// ---------------------------------------------------------------------------
// ServiceAnnotation
// ---------------------------------------------------------------------------

/// Metadata annotation for a launchd service.
#[derive(Debug, Clone)]
pub struct ServiceAnnotation {
    /// Glob pattern or exact label (e.g. `com.apple.Siri.*`).
    pub label_pattern: String,
    /// Human-readable description of the service.
    pub description: String,
    /// Functional category.
    pub category: ServiceCategory,
    /// How safe it is to disable.
    pub safety: SafetyLevel,
    /// Minimum macOS version where this service exists.
    pub macos_min: Option<semver::Version>,
    /// Maximum macOS version where this service exists.
    pub macos_max: Option<semver::Version>,
}

// ---------------------------------------------------------------------------
// Serde helper for TOML parsing
// ---------------------------------------------------------------------------

/// TOML document wrapper: `[[services]]` array at the top level.
#[derive(Debug, Deserialize)]
struct AnnotationDoc {
    services: Vec<RawAnnotation>,
}

/// A single annotation entry as it appears in TOML.
#[derive(Debug, Deserialize)]
struct RawAnnotation {
    pattern: String,
    description: String,
    category: ServiceCategory,
    safety: SafetyLevel,
    #[serde(default)]
    macos_min: Option<semver::Version>,
    #[serde(default)]
    macos_max: Option<semver::Version>,
}

impl From<RawAnnotation> for ServiceAnnotation {
    fn from(raw: RawAnnotation) -> Self {
        Self {
            label_pattern: raw.pattern,
            description: raw.description,
            category: raw.category,
            safety: raw.safety,
            macos_min: raw.macos_min,
            macos_max: raw.macos_max,
        }
    }
}

// ---------------------------------------------------------------------------
// AnnotationDb
// ---------------------------------------------------------------------------

/// Compiled glob pattern paired with its index into the annotations vec.
struct GlobEntry {
    matcher: GlobMatcher,
    index: usize,
}

/// Database of service annotations with fast lookup.
///
/// Exact label matches are resolved via a `HashMap`. Glob patterns are checked
/// linearly (first match wins). The built-in database has ~50 entries so
/// linear scan is fast enough.
pub struct AnnotationDb {
    /// All annotations in insertion order.
    annotations: Vec<ServiceAnnotation>,
    /// Exact-match index: label -> position in `annotations`.
    exact: HashMap<String, usize>,
    /// Glob-match entries for patterns containing wildcards.
    globs: Vec<GlobEntry>,
}

impl std::fmt::Debug for AnnotationDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnotationDb")
            .field("count", &self.annotations.len())
            .finish_non_exhaustive()
    }
}

impl AnnotationDb {
    /// Look up the best matching annotation for a service label.
    ///
    /// Checks exact matches first, then glob patterns in definition order.
    /// Returns `None` if no annotation matches.
    pub fn lookup(&self, label: &str) -> Option<&ServiceAnnotation> {
        // Exact match is authoritative.
        if let Some(&idx) = self.exact.get(label) {
            return self.annotations.get(idx);
        }

        // Fall back to first matching glob.
        for entry in &self.globs {
            if entry.matcher.is_match(label) {
                return self.annotations.get(entry.index);
            }
        }

        None
    }

    /// Load the compiled-in annotation database.
    ///
    /// Delegates to [`crate::loader::load_builtin_annotations`].
    pub fn load_builtin() -> Self {
        crate::loader::load_builtin_annotations()
    }

    /// Parse annotations from a TOML string.
    ///
    /// Expected format:
    /// ```toml
    /// [[services]]
    /// pattern = "com.apple.analyticsd"
    /// description = "Apple analytics collection"
    /// category = "telemetry"
    /// safety = "telemetry"
    /// ```
    pub fn load_from_toml(content: &str) -> Result<Self> {
        let doc: AnnotationDoc =
            toml::from_str(content).map_err(|e| CatalogError::AnnotationParse {
                message: e.to_string(),
            })?;

        let annotations: Vec<ServiceAnnotation> = doc
            .services
            .into_iter()
            .map(ServiceAnnotation::from)
            .collect();

        let mut exact = HashMap::new();
        let mut globs = Vec::new();

        for (i, ann) in annotations.iter().enumerate() {
            if is_glob_pattern(&ann.label_pattern) {
                let glob =
                    Glob::new(&ann.label_pattern).map_err(|e| CatalogError::AnnotationParse {
                        message: format!("invalid glob pattern '{}': {}", ann.label_pattern, e),
                    })?;
                globs.push(GlobEntry {
                    matcher: glob.compile_matcher(),
                    index: i,
                });
            } else {
                exact.insert(ann.label_pattern.clone(), i);
            }
        }

        Ok(Self {
            annotations,
            exact,
            globs,
        })
    }

    /// Returns the number of annotations in the database.
    pub fn len(&self) -> usize {
        self.annotations.len()
    }

    /// Returns `true` if the database contains no annotations.
    pub fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Returns an iterator over all annotations.
    pub fn iter(&self) -> impl Iterator<Item = &ServiceAnnotation> {
        self.annotations.iter()
    }
}

/// Returns `true` if the pattern contains glob meta-characters.
fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

#[cfg(test)]
#[path = "annotation_test.rs"]
mod annotation_test;
