//! Core network rule types.
//!
//! Defines `NetworkRule`, `ProcessMatcher`, `DestMatcher`,
//! and all supporting enums for the network firewall engine.
//!
//! [`HostPattern`] is defined in the [`host`](crate::host) module and
//! re-exported here for convenience.

use std::fmt;
use std::time::SystemTime;

use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::connection::{Destination, ProcessIdentity};
use crate::error::{NetError, Result};
pub use crate::host::HostPattern;
use crate::host::is_glob;

// ---------------------------------------------------------------------------
// RuleId
// ---------------------------------------------------------------------------

/// Unique identifier for a network rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub u64);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkAction
// ---------------------------------------------------------------------------

/// What to do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    /// Allow the connection.
    #[default]
    Allow,
    /// Deny (drop) the connection.
    Deny,
    /// Allow but log to the connection log.
    Log,
}

impl fmt::Display for NetworkAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Log => write!(f, "log"),
        }
    }
}

// ---------------------------------------------------------------------------
// RuleDuration
// ---------------------------------------------------------------------------

/// How long a rule lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleDuration {
    /// Rule persists across restarts. Written to disk.
    Permanent,
    /// Rule lasts until daemon restarts. In-memory only.
    Session,
    /// Rule expires at a specific time. Written to disk, auto-cleaned.
    Until {
        /// Expiration time.
        expiry: SystemTime,
    },
}

// ---------------------------------------------------------------------------
// PortMatcher
// ---------------------------------------------------------------------------

/// Matches a destination port or port range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortMatcher {
    /// Matches a single port number.
    Single(u16),
    /// Matches an inclusive port range.
    Range(u16, u16),
}

impl PortMatcher {
    /// Returns `true` if `port` falls within this matcher.
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(p) => port == *p,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
        }
    }
}

impl fmt::Display for PortMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(p) => write!(f, "{p}"),
            Self::Range(lo, hi) => write!(f, "{lo}-{hi}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessMatcher
// ---------------------------------------------------------------------------

/// How to match the process initiating a connection.
#[derive(Debug, Clone)]
pub enum ProcessMatcher {
    /// Matches any process. Used for global rules.
    Any,
    /// Match by code signing identity (glob-matchable).
    /// e.g. `"com.apple.*"`, `"com.google.Chrome"`.
    CodeId(GlobMatcher, String),
    /// Match by file path (glob-matchable).
    /// e.g. `"/usr/bin/curl"`, `"/Applications/MyApp.app/*"`.
    Path(GlobMatcher, String),
    /// Match by code signing team identifier (exact match).
    ///
    /// Team IDs are fixed 10-character alphanumeric strings like
    /// `"EQHXZ8M8AV"`. More stable than path or code_id -- survives
    /// binary updates, path changes, and version bumps.
    TeamId(String),
}

impl ProcessMatcher {
    /// Create a `CodeId` matcher from a pattern string.
    ///
    /// # Errors
    ///
    /// Returns `NetError::InvalidRule` if the glob pattern is invalid.
    pub fn code_id(pattern: &str) -> Result<Self> {
        let glob = Glob::new(pattern)
            .map_err(|e| NetError::InvalidRule {
                message: format!("invalid code_id pattern `{pattern}`: {e}"),
            })?
            .compile_matcher();
        Ok(Self::CodeId(glob, pattern.to_owned()))
    }

    /// Create a `Path` matcher from a pattern string.
    ///
    /// # Errors
    ///
    /// Returns `NetError::InvalidRule` if the glob pattern is invalid.
    pub fn path(pattern: &str) -> Result<Self> {
        let glob = Glob::new(pattern)
            .map_err(|e| NetError::InvalidRule {
                message: format!("invalid path pattern `{pattern}`: {e}"),
            })?
            .compile_matcher();
        Ok(Self::Path(glob, pattern.to_owned()))
    }

    /// Returns `true` if this matcher matches the given process identity.
    pub fn matches(&self, process: &ProcessIdentity) -> bool {
        match self {
            Self::Any => true,
            Self::CodeId(glob, _) => process
                .code_id
                .as_deref()
                .is_some_and(|id| glob.is_match(id)),
            Self::Path(glob, _) => glob.is_match(process.path.to_string_lossy().as_ref()),
            Self::TeamId(team) => process.team_id.as_deref() == Some(team.as_str()),
        }
    }

    /// Check if this matcher matches the connection's process identity.
    ///
    /// Checks both the direct process and the responsible "via" process.
    /// If either matches, the rule fires. This handles the common case
    /// where a helper process (e.g. `com.apple.WebKit.Networking`) makes
    /// the actual connection on behalf of an app (e.g. Safari).
    pub fn matches_connection(
        &self,
        process: &ProcessIdentity,
        via: Option<&ProcessIdentity>,
    ) -> bool {
        if self.matches(process) {
            return true;
        }
        if let Some(via_process) = via {
            return self.matches(via_process);
        }
        false
    }

    /// Returns the specificity score for ordering.
    ///
    /// Higher = more specific. `TeamId` (2) > `CodeId`/`Path` (1) > `Any` (0).
    /// Team ID ranks highest because it is the most stable process identifier
    /// -- it survives binary updates, path changes, and version bumps.
    pub(crate) fn specificity(&self) -> u8 {
        match self {
            Self::Any => 0,
            Self::CodeId(..) | Self::Path(..) => 1,
            Self::TeamId(_) => 2,
        }
    }

    /// Returns `true` if this is an exact (non-glob) match.
    pub(crate) fn is_exact(&self) -> bool {
        match self {
            Self::Any => false,
            Self::CodeId(_, raw) | Self::Path(_, raw) => !is_glob(raw),
            Self::TeamId(_) => true,
        }
    }

    /// Returns the pattern string, or `"*"` for `Any`.
    pub fn pattern(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::CodeId(_, raw) | Self::Path(_, raw) => raw,
            Self::TeamId(team) => team,
        }
    }
}

/// Serde support: serialize `ProcessMatcher` as a tagged enum.
impl Serialize for ProcessMatcher {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Any => map.serialize_entry("any", &true)?,
            Self::CodeId(_, raw) => map.serialize_entry("code_id", raw)?,
            Self::Path(_, raw) => map.serialize_entry("path", raw)?,
            Self::TeamId(team) => map.serialize_entry("team_id", team)?,
        }
        map.end()
    }
}

/// Serde support: deserialize `ProcessMatcher` from a tagged map.
impl<'de> Deserialize<'de> for ProcessMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;

        /// Helper struct for deserialization.
        #[derive(Deserialize)]
        struct ProcessMatcherHelper {
            any: Option<bool>,
            code_id: Option<String>,
            path: Option<String>,
            team_id: Option<String>,
        }

        let helper = ProcessMatcherHelper::deserialize(deserializer)?;
        if helper.any == Some(true) {
            return Ok(Self::Any);
        }
        if let Some(ref code_id) = helper.code_id {
            return Self::code_id(code_id).map_err(D::Error::custom);
        }
        if let Some(ref path) = helper.path {
            return Self::path(path).map_err(D::Error::custom);
        }
        if let Some(ref team_id) = helper.team_id {
            if team_id.is_empty() {
                return Err(D::Error::custom("team_id must not be empty"));
            }
            return Ok(Self::TeamId(team_id.clone()));
        }
        Err(D::Error::custom(
            "ProcessMatcher must have one of: any, code_id, path, team_id",
        ))
    }
}

// ---------------------------------------------------------------------------
// DestMatcher
// ---------------------------------------------------------------------------

/// Destination matcher. All present fields are ANDed together.
/// All `None` = matches any destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestMatcher {
    /// Domain pattern with boundary-aware matching.
    pub host: Option<HostPattern>,
    /// IP address or CIDR range.
    pub ip: Option<IpNet>,
    /// Port number or range.
    ///
    /// **Note:** ES `RESERVED_5` events do NOT include port data. This field
    /// exists for future backends but will always be `None` from ES events.
    /// Rules that match only on port will silently never fire.
    pub port: Option<PortMatcher>,
    /// Protocol (TCP or UDP).
    ///
    /// **Note:** ES `RESERVED_5` events do NOT include protocol data. Same
    /// caveat as `port` — exists for future use, always `None` from ES.
    pub protocol: Option<Protocol>,
}

impl DestMatcher {
    /// Returns `true` if the destination matches all present fields.
    pub fn matches(&self, dest: &Destination) -> bool {
        if !self.matches_host(dest) {
            return false;
        }
        if let Some(ref net) = self.ip
            && !net.contains(&dest.ip)
        {
            return false;
        }
        if !self.matches_port(dest) {
            return false;
        }
        if !self.matches_protocol(dest) {
            return false;
        }
        true
    }

    /// Returns a specificity score for ordering.
    /// More present fields = higher score.
    pub(crate) fn specificity(&self) -> u8 {
        let mut score = 0u8;
        if self.host.is_some() {
            score += 2;
        }
        if self.ip.is_some() {
            score += 2;
        }
        if self.port.is_some() {
            score += 1;
        }
        if self.protocol.is_some() {
            score += 1;
        }
        score
    }

    /// Returns `true` if all fields are `None` (matches everything).
    pub fn is_any(&self) -> bool {
        self.host.is_none() && self.ip.is_none() && self.port.is_none() && self.protocol.is_none()
    }

    /// Check host field match.
    fn matches_host(&self, dest: &Destination) -> bool {
        let Some(ref host_pat) = self.host else {
            return true;
        };
        match dest.host.as_deref() {
            Some(h) => host_pat.matches(h),
            None => false,
        }
    }

    /// Check port field match.
    fn matches_port(&self, dest: &Destination) -> bool {
        let Some(ref port_matcher) = self.port else {
            return true;
        };
        match dest.port {
            Some(p) => port_matcher.matches(p),
            None => false,
        }
    }

    /// Check protocol field match.
    fn matches_protocol(&self, dest: &Destination) -> bool {
        let Some(ref proto) = self.protocol else {
            return true;
        };
        match dest.protocol {
            Some(ref p) => p == proto,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkRule
// ---------------------------------------------------------------------------

/// A network firewall rule. Matches a process + destination to an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Unique rule identifier.
    pub id: RuleId,
    /// Human-readable name (e.g. "Allow Safari to apple.com").
    pub name: String,
    /// Which process this rule applies to.
    pub process: ProcessMatcher,
    /// Which destination this rule applies to.
    pub destination: DestMatcher,
    /// What to do when matched.
    pub action: NetworkAction,
    /// How long this rule lives.
    pub duration: RuleDuration,
    /// Whether this rule is currently active.
    pub enabled: bool,
    /// Optional human note.
    pub note: Option<String>,
}

impl NetworkRule {
    /// Returns `true` if this rule matches the given process and destination.
    pub fn matches(&self, process: &ProcessIdentity, dest: &Destination) -> bool {
        self.enabled && self.process.matches(process) && self.destination.matches(dest)
    }

    /// Returns `true` if this rule matches the process (or via process) and destination.
    ///
    /// Checks both the direct process and the responsible "via" process.
    pub fn matches_with_via(
        &self,
        process: &ProcessIdentity,
        via: Option<&ProcessIdentity>,
        dest: &Destination,
    ) -> bool {
        self.enabled
            && self.process.matches_connection(process, via)
            && self.destination.matches(dest)
    }

    /// Returns a composite specificity score for priority ordering.
    /// `(process_specificity, dest_specificity, is_process_exact)`.
    pub(crate) fn specificity(&self) -> (u8, u8, bool) {
        (
            self.process.specificity(),
            self.destination.specificity(),
            self.process.is_exact(),
        )
    }
}

#[cfg(test)]
#[path = "rule_test.rs"]
mod rule_test;
