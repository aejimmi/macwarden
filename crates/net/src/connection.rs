//! Connection event and decision types.
//!
//! Models the data extracted from an ES network AUTH event and the
//! decision the matcher produces.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::rule::{NetworkAction, Protocol, RuleId};

// ---------------------------------------------------------------------------
// ProcessIdentity
// ---------------------------------------------------------------------------

/// Identity of the process that initiated a network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Process ID.
    pub pid: u32,
    /// User ID of the process owner.
    pub uid: u32,
    /// Path to the executable.
    pub path: PathBuf,
    /// Code signing identity, if available.
    pub code_id: Option<String>,
    /// Code signing team identifier (e.g. `"EQHXZ8M8AV"`), if available.
    ///
    /// More stable than path or code_id -- survives binary updates and
    /// version bumps. `None` for unsigned binaries or when signing info
    /// was not retrieved.
    #[serde(default)]
    pub team_id: Option<String>,
    /// Whether the code signature is valid, if checked.
    ///
    /// `None` when signature validation was skipped or unavailable.
    /// `Some(false)` indicates a broken or tampered signature.
    #[serde(default)]
    pub is_valid_signature: Option<bool>,
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref id) = self.code_id {
            write!(f, "{id}")?;
        } else {
            write!(f, "{}", self.path.display())?;
        }
        if let Some(ref team) = self.team_id {
            write!(f, " [team {team}]")?;
        }
        write!(f, " (pid {})", self.pid)
    }
}

// ---------------------------------------------------------------------------
// AddressFamily
// ---------------------------------------------------------------------------

/// IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4 (`AF_INET`).
    Inet,
    /// IPv6 (`AF_INET6`).
    Inet6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet => write!(f, "IPv4"),
            Self::Inet6 => write!(f, "IPv6"),
        }
    }
}

// ---------------------------------------------------------------------------
// Destination
// ---------------------------------------------------------------------------

/// Destination of an outbound connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// DNS hostname, if resolved.
    pub host: Option<String>,
    /// Resolved IP address.
    pub ip: IpAddr,
    /// Destination port, if available (best-effort from ES event).
    pub port: Option<u16>,
    /// Protocol, if available.
    pub protocol: Option<Protocol>,
    /// Address family.
    pub address_family: AddressFamily,
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref host) = self.host {
            write!(f, "{host}")?;
        } else {
            write!(f, "{}", self.ip)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ConnectionEvent
// ---------------------------------------------------------------------------

/// A connection attempt as observed by the Endpoint Security framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// When the connection was attempted.
    pub timestamp: SystemTime,
    /// The process that initiated the connection.
    pub process: ProcessIdentity,
    /// The responsible "via" process, if the direct process is a helper.
    ///
    /// For example, when Safari opens a page, `com.apple.WebKit.Networking`
    /// makes the actual connection (the `process` field), while Safari itself
    /// is the responsible app (this field). Rules targeting Safari will match
    /// via this field even though Safari did not make the connection directly.
    #[serde(default)]
    pub via_process: Option<ProcessIdentity>,
    /// The destination of the connection.
    pub destination: Destination,
}

// ---------------------------------------------------------------------------
// MatchTier
// ---------------------------------------------------------------------------

/// Which tier of the matching system produced the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "snake_case")]
pub enum MatchTier {
    /// Tier 0: essential domain safe-list (never blocked).
    SafeList,
    /// Tier 1: user-defined rule.
    UserRule,
    /// Tier 2: network rule group.
    RuleGroup {
        /// Name of the matched group.
        group_name: String,
    },
    /// Tier 3: tracker database.
    Tracker {
        /// Tracker category (e.g. "advertising").
        category: String,
    },
    /// Tier 4: external blocklist.
    Blocklist {
        /// Name of the blocklist.
        list_name: String,
    },
    /// Tier 5: profile default action.
    ProfileDefault,
}

impl fmt::Display for MatchTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SafeList => write!(f, "safe-list"),
            Self::UserRule => write!(f, "user-rule"),
            Self::RuleGroup { group_name } => write!(f, "group/{group_name}"),
            Self::Tracker { category } => write!(f, "tracker-shield/{category}"),
            Self::Blocklist { list_name } => write!(f, "blocklist/{list_name}"),
            Self::ProfileDefault => write!(f, "profile-default"),
        }
    }
}

// ---------------------------------------------------------------------------
// MatchedRule
// ---------------------------------------------------------------------------

/// Details of the rule that produced a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    /// ID of the matched rule (if applicable).
    pub rule_id: RuleId,
    /// Human-readable name of the matched rule.
    pub rule_name: String,
    /// Which tier the match came from.
    pub tier: MatchTier,
}

// ---------------------------------------------------------------------------
// NetworkDecision
// ---------------------------------------------------------------------------

/// The result of evaluating a connection against the rule set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDecision {
    /// What action to take.
    pub action: NetworkAction,
    /// Which rule matched, if any. `None` = profile default.
    pub matched_rule: Option<MatchedRule>,
    /// Human-readable explanation for the decision.
    pub explanation: String,
}

impl fmt::Display for NetworkDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            NetworkAction::Allow => "ALLOWED",
            NetworkAction::Deny => "DENIED",
            NetworkAction::Log => "LOGGED",
        };
        write!(f, "{action}: {}", self.explanation)
    }
}

// ---------------------------------------------------------------------------
// Local network detection
// ---------------------------------------------------------------------------

/// Returns `true` if the IP address belongs to a local/private network.
///
/// Matches:
/// - IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
/// - IPv4: `127.0.0.0/8` (loopback)
/// - IPv4: `169.254.0.0/16` (link-local)
/// - IPv6: `::1` (loopback)
/// - IPv6: `fe80::/10` (link-local)
/// - IPv6: `fc00::/7` (unique local address)
#[must_use]
pub fn is_local_network(ip: &IpAddr) -> bool {
    match *ip {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => is_local_v6(v6),
    }
}

/// IPv4 local/private network check.
fn is_local_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [10 | 127 | 224..=239, ..] // 10.0.0.0/8, loopback, multicast
        | [172, 16..=31, ..] // 172.16.0.0/12
        | [192, 168, ..] // 192.168.0.0/16
        | [169, 254, ..] // link-local
        | [0, 0, 0, 0] // unspecified
    )
}

/// IPv6 local/private network check.
fn is_local_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    // fe80::/10 (link-local)
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fc00::/7 (unique local)
    segments[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
#[path = "connection_test.rs"]
mod connection_test;
