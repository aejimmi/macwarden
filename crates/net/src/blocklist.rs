//! Blocklist parsing for external domain lists.
//!
//! Supports two formats:
//! - **Hosts**: Standard `0.0.0.0 domain.com` or `127.0.0.1 domain.com` files
//!   (Ad Away, Steven Black).
//! - **Domain list**: One domain per line with `#` comments
//!   (Peter Lowe, Energized).
//!
//! Parsed domains are stored in a `HashSet` for O(1) exact lookups.
//! Subdomain matching is done via domain decomposition at query time.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::matcher::BlocklistEntry;

// ---------------------------------------------------------------------------
// BlocklistFormat
// ---------------------------------------------------------------------------

/// Supported blocklist file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlocklistFormat {
    /// Standard hosts file: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`.
    Hosts,
    /// One domain per line, `#` comments.
    DomainList,
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// A parsed blocklist — a set of normalized, lowercase domains.
#[derive(Debug, Clone)]
pub struct Blocklist {
    /// Human-readable name of this blocklist.
    name: String,
    /// All domains, normalized to lowercase.
    domains: HashSet<String>,
    /// Which format this list was parsed from.
    format: BlocklistFormat,
}

/// Hostnames that are always skipped when parsing hosts files.
const SKIP_HOSTS: &[&str] = &["localhost", "local", "broadcasthost"];

impl Blocklist {
    /// Parse a blocklist from raw text content.
    ///
    /// # Errors
    ///
    /// Returns `NetError::BlocklistParse` if a hosts-format line has
    /// a redirect address but no domain.
    pub fn parse(name: &str, content: &str, format: BlocklistFormat) -> Result<Self, NetError> {
        let domains = match format {
            BlocklistFormat::Hosts => parse_hosts(name, content)?,
            BlocklistFormat::DomainList => parse_domain_list(content),
        };
        Ok(Self {
            name: name.to_owned(),
            domains,
            format,
        })
    }

    /// Check if a hostname matches this blocklist.
    ///
    /// Uses domain decomposition for subdomain walking:
    /// `"api.tracker.example.com"` checks `"api.tracker.example.com"`,
    /// then `"tracker.example.com"`, then `"example.com"`.
    pub fn contains(&self, hostname: &str) -> bool {
        let lower = hostname.to_ascii_lowercase();
        let mut candidate: &str = &lower;
        loop {
            if self.domains.contains(candidate) {
                return true;
            }
            match candidate.find('.') {
                Some(pos) => candidate = &candidate[pos + 1..],
                None => return false,
            }
        }
    }

    /// Number of domains in the list.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// The blocklist name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The format this blocklist was parsed from.
    pub fn format(&self) -> BlocklistFormat {
        self.format
    }

    /// Convert all domains into [`BlocklistEntry`] values suitable
    /// for insertion into a [`RuleSet`](crate::matcher::RuleSet).
    pub fn to_blocklist_entries(&self) -> Vec<BlocklistEntry> {
        self.domains
            .iter()
            .map(|d| BlocklistEntry {
                domain: d.clone(),
                list_name: self.name.clone(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse hosts-format content (`0.0.0.0 domain.com` / `127.0.0.1 domain.com`).
fn parse_hosts(name: &str, content: &str) -> Result<HashSet<String>, NetError> {
    let mut domains = HashSet::new();

    for (line_idx, raw_line) in content.lines().enumerate() {
        let line = strip_inline_comment(raw_line).trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else {
            continue;
        };

        // Only accept redirect addresses (0.0.0.0, 127.0.0.1, ::1, etc.)
        if !is_redirect_addr(addr) {
            continue;
        }

        let domain = match parts.next() {
            Some(d) => d.to_ascii_lowercase(),
            None => {
                return Err(NetError::BlocklistParse {
                    name: name.to_owned(),
                    line: line_idx + 1,
                    message: format!("redirect address `{addr}` with no domain"),
                });
            }
        };

        if SKIP_HOSTS.contains(&domain.as_str()) {
            continue;
        }

        if !domain.is_empty() {
            domains.insert(domain);
        }
    }

    Ok(domains)
}

/// Parse domain-list format (one domain per line, `#` comments).
fn parse_domain_list(content: &str) -> HashSet<String> {
    content
        .lines()
        .filter_map(|raw_line| {
            let line = strip_inline_comment(raw_line).trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let domain = line.to_ascii_lowercase();
            if domain.is_empty() {
                return None;
            }
            Some(domain)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip an inline comment from a line (`domain.com # comment` -> `domain.com`).
fn strip_inline_comment(line: &str) -> &str {
    match line.find('#') {
        Some(pos) => line.get(..pos).unwrap_or(line),
        None => line,
    }
}

/// Returns `true` if the address is a typical hosts-file redirect address.
fn is_redirect_addr(addr: &str) -> bool {
    matches!(
        addr,
        "0.0.0.0" | "127.0.0.1" | "::1" | "::0" | "0:0:0:0:0:0:0:0" | "0:0:0:0:0:0:0:1"
    )
}

// ---------------------------------------------------------------------------
// BlocklistConfig
// ---------------------------------------------------------------------------

/// Configuration for a blocklist subscription.
///
/// Describes where to find a blocklist, its format, and how to use it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistConfig {
    /// Human-readable name (e.g. `"Peter Lowe"`).
    pub name: String,
    /// Path or URL to the blocklist file.
    pub source: String,
    /// File format.
    pub format: BlocklistFormat,
    /// Action to take for matched domains.
    #[serde(default = "default_deny")]
    pub action: crate::rule::NetworkAction,
    /// Auto-update interval (e.g. `"24h"`, `"7d"`).
    #[serde(default)]
    pub update_interval: Option<String>,
    /// Whether this blocklist is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Default action for blocklist matches.
fn default_deny() -> crate::rule::NetworkAction {
    crate::rule::NetworkAction::Deny
}

/// Default `true` for boolean fields.
fn default_true() -> bool {
    true
}

/// Load a [`Blocklist`] from a local file using the given configuration.
///
/// # Errors
///
/// Returns `NetError::BlocklistLoad` if the file cannot be read, or
/// `NetError::BlocklistParse` if the content is malformed.
pub fn load_from_file(config: &BlocklistConfig) -> Result<Blocklist, NetError> {
    let path = Path::new(&config.source);
    let content = std::fs::read_to_string(path).map_err(|e| NetError::BlocklistLoad {
        path: config.source.clone(),
        message: e.to_string(),
    })?;
    Blocklist::parse(&config.name, &content, config.format)
}

#[cfg(test)]
#[path = "blocklist_test.rs"]
mod blocklist_test;
