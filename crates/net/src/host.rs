//! Domain pattern matching with boundary-aware semantics.
//!
//! [`HostPattern`] supports three modes:
//! - `"apple.com"` — matches `apple.com` and all subdomains (`*.apple.com`)
//!   but NOT `evilapple.com` (domain-boundary walking).
//! - `"=apple.com"` — matches only `apple.com` exactly (no subdomains).
//! - `"*.analytics.*"` — treated as a literal glob pattern.
//!
//! All matching is case-insensitive.

use std::fmt;

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};

// ---------------------------------------------------------------------------
// HostPattern
// ---------------------------------------------------------------------------

/// Domain pattern with boundary-aware matching.
///
/// - `"apple.com"` matches `apple.com` AND `*.apple.com` but NOT `evilapple.com`.
/// - `"=apple.com"` matches ONLY `apple.com` (no subdomains).
/// - `"*.analytics.*"` is treated as a literal glob pattern.
///
/// All matching is case-insensitive.
#[derive(Debug, Clone)]
pub struct HostPattern {
    /// The original pattern string (for display / serialization).
    raw: String,
    /// The matching strategy.
    kind: HostPatternKind,
}

/// Internal matching strategy.
#[derive(Debug, Clone)]
enum HostPatternKind {
    /// Match only the exact domain (from `=` prefix).
    Exact(String),
    /// Match the domain and all its subdomains (from bare domain).
    DomainWalk {
        domain: String,
        subdomain_glob: GlobMatcher,
    },
    /// Match using an explicit glob pattern (from `*` / `?` / `[` in input).
    Glob(GlobMatcher),
}

impl HostPattern {
    /// Create a new host pattern.
    ///
    /// # Errors
    ///
    /// Returns `NetError::InvalidHostPattern` if the pattern cannot be compiled.
    pub fn new(pattern: &str) -> Result<Self> {
        let raw = pattern.to_owned();

        if let Some(exact) = pattern.strip_prefix('=') {
            return Ok(Self {
                raw,
                kind: HostPatternKind::Exact(exact.to_ascii_lowercase()),
            });
        }

        if is_glob(pattern) {
            let glob = compile_glob(pattern, &raw)?;
            return Ok(Self {
                raw,
                kind: HostPatternKind::Glob(glob),
            });
        }

        // Plain domain: match domain + all subdomains via "*.{domain}" glob.
        let lower = pattern.to_ascii_lowercase();
        let subdomain_pattern = format!("*.{lower}");
        let subdomain_glob = compile_glob(&subdomain_pattern, &raw)?;
        Ok(Self {
            raw,
            kind: HostPatternKind::DomainWalk {
                domain: lower,
                subdomain_glob,
            },
        })
    }

    /// Returns `true` if `host` matches this pattern.
    pub fn matches(&self, host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        match &self.kind {
            HostPatternKind::Exact(domain) => lower == *domain,
            HostPatternKind::DomainWalk {
                domain,
                subdomain_glob,
            } => lower == *domain || subdomain_glob.is_match(&lower),
            HostPatternKind::Glob(glob) => glob.is_match(&lower),
        }
    }

    /// Returns the original pattern string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Serde support: serialize as the raw pattern string.
impl Serialize for HostPattern {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

/// Serde support: deserialize from a pattern string.
impl<'de> Deserialize<'de> for HostPattern {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the string contains glob metacharacters.
pub(crate) fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Compile a glob pattern from `pattern`.
fn compile_glob(pattern: &str, raw: &str) -> Result<GlobMatcher> {
    let glob = Glob::new(pattern).map_err(|e| NetError::InvalidHostPattern {
        pattern: raw.to_owned(),
        message: e.to_string(),
    })?;
    Ok(glob.compile_matcher())
}

#[cfg(test)]
#[path = "host_test.rs"]
mod host_test;
