//! TOML-based user rules loaded from individual files on disk.
//!
//! Each file in `~/.macwarden/net-rules/` describes a single network
//! rule. The [`load_user_rules`] function reads all `.toml` files from
//! a directory and converts them to [`NetworkRule`] values.
//!
//! # Hardening (spec 009 R2/R3)
//!
//! This loader runs inside the root-run NetworkExtension provider, which fails
//! **open** (allow-all) if it is OOM-killed. Two classes of abuse are defended
//! here:
//!
//! * **Confused-deputy symlinks (R2).** Directory entries that are symlinks are
//!   skipped and files are opened with `O_NOFOLLOW`, so a caller cannot point a
//!   `net-rules/*.toml` entry at a root-only file and have the extension read —
//!   and then leak via a log — its contents. Parse failures log the path and a
//!   coarse kind only, never the TOML error's `Display` (which embeds the
//!   offending source line).
//! * **Unbounded reads (R3).** Per-file, file-count, and total-byte caps
//!   ([`RuleLoadLimits`]) bound how much the loader will read in one pass, so a
//!   huge file or a flood of files cannot exhaust memory and fail the provider
//!   open. Over-cap entries are skipped-and-warned, never read.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};
use crate::host::HostPattern;
use crate::policy::parse_ip_or_cidr;
use crate::rule::{
    DestMatcher, NetworkAction, NetworkRule, PortMatcher, ProcessMatcher, Protocol, RuleDuration,
    RuleId,
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
    /// Optional destination IP address or CIDR range (e.g. `"10.0.0.0/8"`).
    #[serde(default)]
    pub dest_ip: Option<String>,
    /// Optional destination protocol.
    ///
    /// **Note:** ES `RESERVED_5` events carry no protocol, so a rule that
    /// constrains protocol silently never fires on ES events -- same caveat as
    /// `dest_port`. Persisted for other backends and hand-written rules.
    #[serde(default)]
    pub dest_protocol: Option<Protocol>,
    /// Optional signing team id. When set, selects
    /// [`ProcessMatcher::TeamId`]; mutually exclusive with a non-`*` `process`.
    #[serde(default)]
    pub team_id: Option<String>,
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
        let process = self.resolve_process()?;
        let destination = self.resolve_destination()?;

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

    /// Resolve the process matcher, honoring `team_id` and its mutual
    /// exclusion with a non-`*` `process`.
    fn resolve_process(&self) -> Result<ProcessMatcher> {
        if let Some(team) = &self.team_id {
            if self.process != "*" {
                return Err(NetError::InvalidRule {
                    message: "rule cannot set both team_id and a non-`*` process".to_owned(),
                });
            }
            if team.len() != 10
                || !team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return Err(NetError::InvalidRule {
                    message: format!("team_id `{team}` must be 10 characters of [A-Z0-9]"),
                });
            }
            return Ok(ProcessMatcher::TeamId(team.clone()));
        }
        if self.process == "*" {
            Ok(ProcessMatcher::Any)
        } else if self.process.starts_with('/') {
            ProcessMatcher::path(&self.process)
        } else {
            ProcessMatcher::code_id(&self.process)
        }
    }

    /// Resolve the destination matcher from host, ip, port, and protocol.
    fn resolve_destination(&self) -> Result<DestMatcher> {
        let host = if self.dest == "*" {
            None
        } else {
            Some(HostPattern::new(&self.dest)?)
        };
        let ip = self.dest_ip.as_deref().map(parse_ip_or_cidr).transpose()?;
        Ok(DestMatcher {
            host,
            ip,
            port: self.dest_port.map(PortMatcher::Single),
            protocol: self.dest_protocol,
        })
    }
}

// ---------------------------------------------------------------------------
// load_user_rules
// ---------------------------------------------------------------------------

/// Caps on how much [`load_user_rules`] will read from a rule directory in one
/// pass (spec 009 R3). The loader runs inside a fail-open NE provider, so these
/// bound memory use: an over-cap file or a flood of files is skipped-and-warned
/// rather than read, and can never OOM the provider into allow-all.
#[derive(Debug, Clone, Copy)]
struct RuleLoadLimits {
    /// Largest single rule file (bytes) that will be read. A `net block` rule is
    /// well under a kilobyte; 256 KiB is generous headroom yet far from OOM.
    per_file_bytes: u64,
    /// Most rule files that will be read from the directory. Beyond this, the
    /// remaining `.toml` entries are skipped, bounding reload cost and memory.
    file_count: usize,
    /// Most total bytes read across all files in one pass. Once the running
    /// total would exceed this, further files are skipped-and-warned.
    total_bytes: u64,
}

impl Default for RuleLoadLimits {
    fn default() -> Self {
        Self {
            per_file_bytes: 256 * 1024,
            file_count: 1024,
            total_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Load all user rules from `.toml` files in a directory.
///
/// Each file is parsed as a [`UserRuleFile`] and converted to a
/// [`NetworkRule`]. Symlinked entries are skipped (confused-deputy defense) and
/// files that are oversized, unreadable, or fail to parse are skipped with a
/// `tracing::warn!` log that carries only the path and a coarse kind — never the
/// file's content. Reads are bounded by [`RuleLoadLimits`] to keep the
/// fail-open NE provider from being OOM-killed.
///
/// # Errors
///
/// Returns `NetError::RuleParse` if the directory itself cannot be read.
/// Individual bad files are skipped, not propagated.
pub fn load_user_rules(dir: &Path) -> Result<Vec<NetworkRule>> {
    load_user_rules_with_limits(dir, RuleLoadLimits::default())
}

/// [`load_user_rules`] with explicit caps, so tests can exercise the cap logic
/// with small limits instead of allocating hundreds of megabytes.
fn load_user_rules_with_limits(dir: &Path, limits: RuleLoadLimits) -> Result<Vec<NetworkRule>> {
    let entries = std::fs::read_dir(dir).map_err(|e| NetError::RuleParse {
        path: dir.display().to_string(),
        message: format!("cannot read directory: {e}"),
    })?;

    let mut rules = Vec::new();
    let mut counter: u64 = 10_000; // offset to avoid ID collision with profile rules
    let mut files_read: usize = 0;
    let mut total_bytes: u64 = 0;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable directory entry");
                continue;
            }
        };

        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        if files_read >= limits.file_count {
            tracing::warn!(
                dir = %dir.display(),
                max_files = limits.file_count,
                "rule-file count cap reached; skipping remaining files"
            );
            break;
        }

        // `DirEntry::metadata` is an `lstat`: it does not follow symlinks, so a
        // symlink entry reports as such and is skipped before any open.
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unstatable rule file");
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "skipping symlinked rule file");
            continue;
        }
        if meta.len() > limits.per_file_bytes {
            tracing::warn!(path = %path.display(), size = meta.len(), "skipping rule file: too large");
            continue;
        }
        if total_bytes.saturating_add(meta.len()) > limits.total_bytes {
            tracing::warn!(
                dir = %dir.display(),
                max_total_bytes = limits.total_bytes,
                "rule-directory total-byte cap reached; skipping remaining files"
            );
            break;
        }

        let content = match read_rule_file(&path, limits.per_file_bytes) {
            Ok(c) => c,
            Err(e) => {
                // An io error's `Display` describes the failure (e.g. ELOOP from
                // O_NOFOLLOW), not the file's content, so it is safe to log.
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable rule file");
                continue;
            }
        };
        total_bytes = total_bytes.saturating_add(content.len() as u64);
        files_read += 1;

        // NEVER log the parse error's `Display`: a TOML error embeds the
        // offending source line, which would leak the file's contents — exactly
        // the confused-deputy leak R2 guards against. Path and a coarse kind only.
        let Ok(file_rule) = UserRuleFile::from_toml(&content) else {
            tracing::warn!(path = %path.display(), "skipping rule file: malformed TOML");
            continue;
        };

        match file_rule.to_network_rule(counter) {
            Ok(rule) => {
                rules.push(rule);
                counter += 1;
            }
            Err(e) => {
                // A conversion error describes the rule's own fields (its name,
                // team id shape), not raw file bytes, so it is safe to log.
                tracing::warn!(path = %path.display(), error = %e, "skipping invalid rule");
            }
        }
    }

    Ok(rules)
}

/// Read at most `cap` bytes of `path` as UTF-8, opening with `O_NOFOLLOW` so a
/// symlinked final path component is refused (`ELOOP`) rather than traversed.
///
/// The `O_NOFOLLOW` open and the [`Read::take`] cap are belt-and-suspenders over
/// the caller's `lstat` pre-checks: they also defend against a symlink or size
/// change racing in between the stat and the open (TOCTOU).
fn read_rule_file(path: &Path, cap: u64) -> std::io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut buf = String::new();
    file.take(cap).read_to_string(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
#[path = "user_rule_test.rs"]
mod user_rule_test;
