//! Persisted policy configuration -- the durable source of truth for the
//! network firewall's global mode, group overrides, the Apple/DNS flags, and
//! the user-managed allow-list.
//!
//! [`PolicyConfig`] is serialized to `~/.macwarden/net-profile.toml` (the path
//! is resolved by the daemon/CLI layer -- this module is path-agnostic and
//! stays platform-dependency-free). It translates the panel-managed policy
//! knobs into the existing five-tier engine:
//!
//! - `mode` sets the Tier-5 `default_action` (Allow-All -> `Log`,
//!   Block-All -> `Deny`).
//! - `groups` merges into [`NetworkProfile::groups`].
//! - `allowlist` + `allow_dns_traffic` compile into synthetic **Tier-1 Allow**
//!   [`NetworkRule`]s (in a reserved id band) that the daemon appends to the
//!   resolved rule set's `user_rules`.
//!
//! The `allow_apple_programs` flag is *not* expressed as a static rule -- it
//! needs the live code-signing verdict and executable path, so it is enforced
//! by a decide-time shim in the daemon (see the daemon's policy shim). This
//! module only carries the flag and the [`is_apple_code_id`] helper.
//!
//! **Fail-open:** [`PolicyConfig::load`] never errors. A missing file yields
//! the default (Allow-All) config; a malformed file logs a `warn!` and also
//! yields the default. A single malformed allow-list entry is dropped (with a
//! `warn!`) rather than discarding the whole file.

use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::NetError;
use crate::fsperm::{secure_dir, secure_file};
use crate::host::HostPattern;
use crate::profile::{GroupSettings, NetworkProfile};
use crate::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};

// ---------------------------------------------------------------------------
// Reserved id band
// ---------------------------------------------------------------------------

/// Base id for synthetic allow-list / DNS Allow rules.
///
/// Chosen to sit between file-rule ids (`10_000+`) and session-rule ids
/// (`900_000+`) so synthetic rules never collide with either.
pub const ALLOWLIST_RULE_ID_BASE: u64 = 800_000;

/// Path of the macOS system resolver, allowed wholesale when
/// `allow_dns_traffic` is on (see [`PolicyConfig::to_allow_rules`]).
pub const DNS_RESOLVER_PATH: &str = "/usr/sbin/mDNSResponder";

/// Code id of the macOS system resolver.
pub const DNS_RESOLVER_CODE_ID: &str = "com.apple.mDNSResponder";

// ---------------------------------------------------------------------------
// PolicyMode
// ---------------------------------------------------------------------------

/// The global firewall mode.
///
/// Maps onto the existing Tier-5 `default_action` -- no new tier is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicyMode {
    /// Allow-All: everything is allowed-and-logged unless an explicit Deny
    /// matches first. Serialized as `"allow"`.
    #[default]
    #[serde(rename = "allow")]
    AllowAll,
    /// Block-All: a connection is denied unless something earlier explicitly
    /// allows it. Serialized as `"block"`.
    #[serde(rename = "block")]
    BlockAll,
}

impl PolicyMode {
    /// The Tier-5 default action this mode maps to.
    ///
    /// Allow-All -> `Log` (allow-with-logging, retains the connection log the
    /// panel/metrics depend on). Block-All -> `Deny`.
    #[must_use]
    pub fn default_action(self) -> NetworkAction {
        match self {
            Self::AllowAll => NetworkAction::Log,
            Self::BlockAll => NetworkAction::Deny,
        }
    }
}

// ---------------------------------------------------------------------------
// AllowListEntry
// ---------------------------------------------------------------------------

/// A user-managed exception, surfaced as a Tier-1 Allow rule.
///
/// At least one of `app`/`team_id`/`host`/`ip` must be present (an all-`None`
/// entry would mean "allow everything," defeating Block-All). `app` and
/// `team_id` are mutually exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowListEntry {
    /// Process code id, or a path (leading `/`). Mutually exclusive with
    /// `team_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Exact 10-char signing team id. Mutually exclusive with `app`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Host pattern (ANDed with `ip` when both are set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// IP address or CIDR range (ANDed with `host` when both are set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpNet>,
    /// Free-form user note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl AllowListEntry {
    /// Validate an entry at construction/load: at least one selector, and
    /// `app`/`team_id` mutual exclusion.
    ///
    /// # Errors
    ///
    /// Returns `NetError::InvalidRule` for an all-`None` entry or an
    /// `app`+`team_id` conflict.
    pub fn validate(&self) -> Result<(), NetError> {
        if self.app.is_none() && self.team_id.is_none() && self.host.is_none() && self.ip.is_none()
        {
            return Err(NetError::InvalidRule {
                message: "allow-list entry must set at least one of app/team_id/host/ip".to_owned(),
            });
        }
        if self.app.is_some() && self.team_id.is_some() {
            return Err(NetError::InvalidRule {
                message: "allow-list entry cannot set both app and team_id".to_owned(),
            });
        }
        Ok(())
    }

    /// Compile this entry into a Tier-1 Allow [`NetworkRule`].
    ///
    /// # Errors
    ///
    /// Returns `NetError` if the entry fails [`validate`](Self::validate) or a
    /// process/host pattern cannot be compiled.
    pub fn to_network_rule(&self, id: u64) -> Result<NetworkRule, NetError> {
        self.validate()?;
        let process = self.process_matcher()?;
        let destination = DestMatcher {
            host: self.host.as_deref().map(HostPattern::new).transpose()?,
            ip: self.ip,
            ..Default::default()
        };
        Ok(NetworkRule {
            id: RuleId(id),
            name: self.rule_name(),
            process,
            destination,
            action: NetworkAction::Allow,
            duration: RuleDuration::Permanent,
            enabled: true,
            note: self.note.clone(),
        })
    }

    /// Build the process matcher for this entry.
    fn process_matcher(&self) -> Result<ProcessMatcher, NetError> {
        if let Some(team) = &self.team_id {
            return Ok(ProcessMatcher::TeamId(team.clone()));
        }
        match &self.app {
            Some(app) if app.starts_with('/') => ProcessMatcher::path(app),
            Some(app) => ProcessMatcher::code_id(app),
            None => Ok(ProcessMatcher::Any),
        }
    }

    /// A stable, human-readable name for the synthetic rule.
    fn rule_name(&self) -> String {
        let proc = self
            .team_id
            .as_deref()
            .or(self.app.as_deref())
            .unwrap_or("*");
        let dest = match (&self.host, &self.ip) {
            (Some(h), Some(ip)) => format!("{h} {ip}"),
            (Some(h), None) => h.clone(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => "*".to_owned(),
        };
        format!("Allow-list: {proc} -> {dest}")
    }
}

// ---------------------------------------------------------------------------
// PolicyConfig
// ---------------------------------------------------------------------------

/// The persisted policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Global mode (Allow-All vs Block-All).
    #[serde(default)]
    pub mode: PolicyMode,
    /// Allow connections from Apple-signed processes (enforced by the daemon's
    /// decide-time shim, with the graylist carve-out).
    #[serde(default)]
    pub allow_apple_programs: bool,
    /// Allow the system resolver process (`mDNSResponder`) wholesale.
    #[serde(default = "default_true")]
    pub allow_dns_traffic: bool,
    /// Durable group enable/disable overrides.
    #[serde(default)]
    pub groups: GroupSettings,
    /// User-managed exceptions (Block-All allow-list).
    #[serde(default)]
    pub allowlist: Vec<AllowListEntry>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::AllowAll,
            allow_apple_programs: false,
            allow_dns_traffic: true,
            groups: GroupSettings::default(),
            allowlist: Vec::new(),
        }
    }
}

impl PolicyConfig {
    /// Load the config from `path`, **never** failing (fail-open).
    ///
    /// A missing file yields the default silently; a malformed file logs a
    /// `warn!` and yields the default; individual malformed allow-list entries
    /// are dropped with a `warn!`.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "policy config unreadable; using Allow-All default");
                return Self::default();
            }
        };
        Self::from_toml(&content).unwrap_or_else(|e| {
            warn!(path = %path.display(), error = %e, "policy config malformed; using Allow-All default");
            Self::default()
        })
    }

    /// Parse a config from TOML, dropping (with a `warn!`) any allow-list entry
    /// that fails to validate rather than discarding the whole file.
    ///
    /// # Errors
    ///
    /// Returns `NetError::ProfileResolve` only when the TOML is syntactically
    /// invalid.
    pub fn from_toml(content: &str) -> Result<Self, NetError> {
        let raw: RawPolicyConfig =
            toml::from_str(content).map_err(|e| NetError::ProfileResolve {
                message: format!("policy config parse error: {e}"),
            })?;
        Ok(raw.into_config())
    }

    /// Serialize and atomically write the config to `path` (temp file +
    /// rename), creating parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns `NetError::PolicyIo` on serialization or filesystem failure.
    pub fn save(&self, path: &Path) -> Result<(), NetError> {
        let content = toml::to_string_pretty(self).map_err(|e| NetError::PolicyIo {
            message: format!("serialize failed: {e}"),
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| NetError::PolicyIo {
                message: format!("create dir {}: {e}", parent.display()),
            })?;
            secure_dir(parent);
        }
        let tmp = tmp_path(path);
        std::fs::write(&tmp, content).map_err(|e| NetError::PolicyIo {
            message: format!("write {}: {e}", tmp.display()),
        })?;
        secure_file(&tmp);
        std::fs::rename(&tmp, path).map_err(|e| NetError::PolicyIo {
            message: format!("rename {} -> {}: {e}", tmp.display(), path.display()),
        })?;
        Ok(())
    }

    /// Apply mode + group knobs onto a resolved base [`NetworkProfile`].
    ///
    /// Sets `default` from the mode and merges the group enable/disable
    /// overrides (deduplicating).
    pub fn apply_to(&self, profile: &mut NetworkProfile) {
        profile.default = self.mode.default_action();
        merge_dedup(&mut profile.groups.enable, &self.groups.enable);
        merge_dedup(&mut profile.groups.disable, &self.groups.disable);
    }

    /// Compile the allow-list and (when enabled) the DNS carve-out into
    /// synthetic Tier-1 Allow [`NetworkRule`]s in the reserved id band.
    ///
    /// # Errors
    ///
    /// Returns `NetError` if a well-formed-on-disk entry still fails to
    /// compile (e.g. an invalid host pattern). Entries are validated on load,
    /// so this is defensive.
    pub fn to_allow_rules(&self) -> Result<Vec<NetworkRule>, NetError> {
        let mut out = Vec::new();
        let mut id = ALLOWLIST_RULE_ID_BASE;
        for entry in &self.allowlist {
            out.push(entry.to_network_rule(id)?);
            id += 1;
        }
        if self.allow_dns_traffic {
            out.extend(dns_allow_rules(&mut id)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Apple helper
// ---------------------------------------------------------------------------

/// Returns `true` if `code_id` is an Apple-platform code id (`com.apple.` prefix).
///
/// A pure heuristic used only as a fallback where the live signing verdict is
/// unavailable; the daemon prefers the real `is_apple_signed` bit.
#[must_use]
pub fn is_apple_code_id(code_id: &str) -> bool {
    code_id.starts_with("com.apple.")
}

/// Parse an IP address or CIDR range. A bare address is treated as a host
/// route (`/32` for IPv4, `/128` for IPv6).
///
/// # Errors
///
/// Returns `NetError::InvalidCidr` if `s` is neither a valid CIDR nor a bare
/// IP literal.
pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet, NetError> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    let ip = s.parse::<IpAddr>().map_err(|e| NetError::InvalidCidr {
        cidr: s.to_owned(),
        message: e.to_string(),
    })?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    IpNet::new(ip, prefix).map_err(|e| NetError::InvalidCidr {
        cidr: s.to_owned(),
        message: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the DNS resolver Allow rules (path + code id), advancing `id`.
fn dns_allow_rules(id: &mut u64) -> Result<Vec<NetworkRule>, NetError> {
    let mut rules = Vec::with_capacity(2);
    rules.push(NetworkRule {
        id: RuleId(*id),
        name: "Allow DNS: mDNSResponder (path)".to_owned(),
        process: ProcessMatcher::path(DNS_RESOLVER_PATH)?,
        destination: DestMatcher::default(),
        action: NetworkAction::Allow,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: Some("Allow DNS Traffic: system resolver process".to_owned()),
    });
    *id += 1;
    rules.push(NetworkRule {
        id: RuleId(*id),
        name: "Allow DNS: mDNSResponder (code id)".to_owned(),
        process: ProcessMatcher::code_id(DNS_RESOLVER_CODE_ID)?,
        destination: DestMatcher::default(),
        action: NetworkAction::Allow,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: Some("Allow DNS Traffic: system resolver process".to_owned()),
    });
    *id += 1;
    Ok(rules)
}

/// Merge `src` into `dst`, skipping values already present.
fn merge_dedup(dst: &mut Vec<String>, src: &[String]) {
    for item in src {
        if !dst.contains(item) {
            dst.push(item.clone());
        }
    }
}

/// Default `true` for `allow_dns_traffic`.
fn default_true() -> bool {
    true
}

/// The sibling temp path used for atomic writes.
fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

// ---------------------------------------------------------------------------
// Raw (lenient) deserialization layer
// ---------------------------------------------------------------------------

/// The on-disk shape parsed leniently so one bad allow-list entry cannot
/// discard the whole file.
#[derive(Debug, Deserialize)]
struct RawPolicyConfig {
    #[serde(default)]
    mode: PolicyMode,
    #[serde(default)]
    allow_apple_programs: bool,
    #[serde(default = "default_true")]
    allow_dns_traffic: bool,
    #[serde(default)]
    groups: GroupSettings,
    #[serde(default)]
    allowlist: Vec<RawAllowEntry>,
}

impl RawPolicyConfig {
    /// Convert to the typed config, dropping invalid allow-list entries.
    fn into_config(self) -> PolicyConfig {
        let allowlist = self
            .allowlist
            .into_iter()
            .filter_map(RawAllowEntry::into_entry)
            .collect();
        PolicyConfig {
            mode: self.mode,
            allow_apple_programs: self.allow_apple_programs,
            allow_dns_traffic: self.allow_dns_traffic,
            groups: self.groups,
            allowlist,
        }
    }
}

/// A raw allow-list entry with `ip` as a string, parsed on conversion.
#[derive(Debug, Deserialize)]
struct RawAllowEntry {
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

impl RawAllowEntry {
    /// Convert to a typed [`AllowListEntry`], returning `None` (with a `warn!`)
    /// for an invalid entry.
    fn into_entry(self) -> Option<AllowListEntry> {
        let ip = match self.ip.as_deref().map(parse_ip_or_cidr).transpose() {
            Ok(ip) => ip,
            Err(e) => {
                warn!(error = %e, "dropping allow-list entry with invalid ip");
                return None;
            }
        };
        let entry = AllowListEntry {
            app: self.app,
            team_id: self.team_id,
            host: self.host,
            ip,
            note: self.note,
        };
        match entry.validate() {
            Ok(()) => Some(entry),
            Err(e) => {
                warn!(error = %e, "dropping invalid allow-list entry");
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod policy_test;
