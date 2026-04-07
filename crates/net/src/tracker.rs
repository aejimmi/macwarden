//! Tracker database — curated domains organized by category.
//!
//! Embeds four TOML data files at compile time (same `include_str!` pattern
//! as `crates/catalog/src/loader.rs`). Each file declares a tracker
//! category with its domains, breakage risk, and descriptions.
//!
//! The database supports fast hostname lookup via pre-compiled
//! [`HostPattern`] matchers, and can produce [`TrackerRule`] values
//! for integration with the five-tier [`RuleSet`](crate::matcher::RuleSet).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::host::HostPattern;
use crate::matcher::{BreakageRisk, TrackerRule};

// ---------------------------------------------------------------------------
// Embedded TOML data
// ---------------------------------------------------------------------------

const ADVERTISING_TOML: &str = include_str!("../../../knowledge/network/trackers/advertising.toml");
const ANALYTICS_TOML: &str = include_str!("../../../knowledge/network/trackers/analytics.toml");
const FINGERPRINTING_TOML: &str =
    include_str!("../../../knowledge/network/trackers/fingerprinting.toml");
const SOCIAL_TOML: &str = include_str!("../../../knowledge/network/trackers/social.toml");

/// All builtin sources, paired with their category for error messages.
const BUILTIN_SOURCES: &[(TrackerCategory, &str)] = &[
    (TrackerCategory::Advertising, ADVERTISING_TOML),
    (TrackerCategory::Analytics, ANALYTICS_TOML),
    (TrackerCategory::Fingerprinting, FINGERPRINTING_TOML),
    (TrackerCategory::Social, SOCIAL_TOML),
];

// ---------------------------------------------------------------------------
// TrackerCategory
// ---------------------------------------------------------------------------

/// The four types of tracking in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrackerCategory {
    /// Ad networks, retargeting, ad delivery.
    Advertising,
    /// Usage analytics, telemetry, crash reporting.
    Analytics,
    /// Device/browser fingerprinting.
    Fingerprinting,
    /// Social media tracking pixels and share buttons.
    Social,
}

impl fmt::Display for TrackerCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advertising => write!(f, "advertising"),
            Self::Analytics => write!(f, "analytics"),
            Self::Fingerprinting => write!(f, "fingerprinting"),
            Self::Social => write!(f, "social"),
        }
    }
}

// ---------------------------------------------------------------------------
// TrackerDomain (serde)
// ---------------------------------------------------------------------------

/// A single tracker domain entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerDomain {
    /// Domain pattern, e.g. `"google-analytics.com"`.
    pub pattern: String,
    /// Human-readable name, e.g. `"Google Analytics"`.
    pub description: String,
    /// Risk of breakage if this domain is blocked.
    pub breakage_risk: BreakageRisk,
    /// Optional explanation for breakage or context.
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// TrackerCategoryData (serde)
// ---------------------------------------------------------------------------

/// A full tracker category as loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerCategoryData {
    /// Human-readable category name (e.g. `"Advertising"`).
    pub name: String,
    /// What this category covers.
    pub description: String,
    /// Whether blocking is enabled by default.
    #[serde(default = "default_true")]
    pub default_enabled: bool,
    /// All domain entries in this category.
    pub domains: Vec<TrackerDomain>,
}

/// Default value for `default_enabled`.
fn default_true() -> bool {
    true
}

/// Wrapper matching the TOML structure `[tracker_category]`.
#[derive(Debug, Deserialize)]
struct TrackerFile {
    tracker_category: TrackerCategoryData,
}

// ---------------------------------------------------------------------------
// CompiledTracker (internal)
// ---------------------------------------------------------------------------

/// Pre-compiled tracker entry for fast hostname matching.
#[derive(Debug, Clone)]
struct CompiledTracker {
    pattern: HostPattern,
    category: TrackerCategory,
    breakage_risk: BreakageRisk,
    description: String,
}

// ---------------------------------------------------------------------------
// TrackerMatch
// ---------------------------------------------------------------------------

/// Result of a successful tracker database lookup.
#[derive(Debug, Clone)]
pub struct TrackerMatch {
    /// Which category the matched domain belongs to.
    pub category: TrackerCategory,
    /// The domain entry that matched.
    pub domain: TrackerDomain,
}

// ---------------------------------------------------------------------------
// TrackerDatabase
// ---------------------------------------------------------------------------

/// The full tracker database — all categories loaded with pre-compiled
/// host patterns for fast matching.
#[derive(Debug, Clone)]
pub struct TrackerDatabase {
    /// Category metadata and raw domain data.
    categories: HashMap<TrackerCategory, TrackerCategoryData>,
    /// Flattened, pre-compiled patterns for matching.
    compiled: Vec<CompiledTracker>,
}

impl TrackerDatabase {
    /// Load all builtin tracker categories from embedded TOML data.
    ///
    /// # Errors
    ///
    /// Returns `NetError::TrackerParse` if any embedded TOML file is malformed
    /// or contains an invalid host pattern.
    pub fn load_builtin() -> Result<Self, NetError> {
        let mut categories = HashMap::with_capacity(BUILTIN_SOURCES.len());
        let mut compiled = Vec::new();

        for &(cat, toml_src) in BUILTIN_SOURCES {
            let file: TrackerFile =
                toml::from_str(toml_src).map_err(|e| NetError::TrackerParse {
                    category: cat.to_string(),
                    message: e.to_string(),
                })?;
            let data = file.tracker_category;
            compile_domains(cat, &data.domains, &mut compiled)?;
            categories.insert(cat, data);
        }

        Ok(Self {
            categories,
            compiled,
        })
    }

    /// Look up a hostname against the tracker database.
    ///
    /// Returns the first matching tracker entry, if any. Matching is
    /// case-insensitive and supports domain-boundary walking (subdomains
    /// of a listed pattern also match).
    pub fn lookup(&self, hostname: &str) -> Option<TrackerMatch> {
        self.compiled.iter().find_map(|ct| {
            if ct.pattern.matches(hostname) {
                Some(TrackerMatch {
                    category: ct.category,
                    domain: TrackerDomain {
                        pattern: ct.pattern.as_str().to_owned(),
                        description: ct.description.clone(),
                        breakage_risk: ct.breakage_risk,
                        note: None,
                    },
                })
            } else {
                None
            }
        })
    }

    /// Get the raw category data (name, description, domains) for a category.
    pub fn category(&self, cat: TrackerCategory) -> Option<&TrackerCategoryData> {
        self.categories.get(&cat)
    }

    /// Summary statistics: domain count per category.
    pub fn stats(&self) -> HashMap<TrackerCategory, usize> {
        self.categories
            .iter()
            .map(|(&cat, data)| (cat, data.domains.len()))
            .collect()
    }

    /// Convert the entire database into [`TrackerRule`] values suitable
    /// for insertion into a [`RuleSet`](crate::matcher::RuleSet).
    ///
    /// # Errors
    ///
    /// Returns `NetError::TrackerParse` if any pattern fails to compile
    /// (should not happen for the builtin database).
    pub fn to_tracker_rules(&self) -> Result<Vec<TrackerRule>, NetError> {
        self.compiled
            .iter()
            .map(|ct| {
                Ok(TrackerRule {
                    pattern: HostPattern::new(ct.pattern.as_str()).map_err(|e| {
                        NetError::TrackerParse {
                            category: ct.category.to_string(),
                            message: e.to_string(),
                        }
                    })?,
                    category: ct.category.to_string(),
                    breakage_risk: ct.breakage_risk,
                    description: ct.description.clone(),
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compile all domain entries in a category into `CompiledTracker` values.
fn compile_domains(
    cat: TrackerCategory,
    domains: &[TrackerDomain],
    out: &mut Vec<CompiledTracker>,
) -> Result<(), NetError> {
    for d in domains {
        let pattern = HostPattern::new(&d.pattern).map_err(|e| NetError::TrackerParse {
            category: cat.to_string(),
            message: format!("pattern `{}`: {e}", d.pattern),
        })?;
        out.push(CompiledTracker {
            pattern,
            category: cat,
            breakage_risk: d.breakage_risk,
            description: d.description.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tracker_test.rs"]
mod tracker_test;
