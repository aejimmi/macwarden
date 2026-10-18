//! Shared record types: ban records, escalation counters, signals, and events.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Detector id for the no-privilege repeat-blocked-verdict detector.
pub const DETECTOR_REPEAT_BLOCKED: &str = "repeat-blocked";
/// Detector id for the opt-in unified-log auth-failure detector.
pub const DETECTOR_AUTH_FAILURE: &str = "auth-failure";
/// Detector id for the BPF-fed port-scan detector.
pub const DETECTOR_PORT_SCAN: &str = "port-scan";
/// Pseudo-detector id recorded for an operator-initiated manual ban.
pub const DETECTOR_MANUAL: &str = "manual";

/// What produced a ban — one of the curated detectors, or a manual action.
///
/// Serialized as a lowercase string so the wire/metrics layers can carry it as
/// a plain field; an unrecognized value round-trips to [`BanSource::Unknown`]
/// so a newer store never panics an older reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BanSource {
    /// Repeated deny verdicts from the daemon's own connection stream.
    RepeatBlocked,
    /// Repeated `sshd` / Screen Sharing auth failures in the unified log.
    AuthFailure,
    /// Distinct-port / SYN-spray scanning seen on the capture feed.
    PortScan,
    /// An operator-initiated ban over IPC.
    Manual,
    /// An unrecognized source from a newer store.
    #[serde(other)]
    Unknown,
}

impl BanSource {
    /// The detector id string this source is keyed under.
    #[must_use]
    pub fn detector(self) -> &'static str {
        match self {
            Self::RepeatBlocked => DETECTOR_REPEAT_BLOCKED,
            Self::AuthFailure => DETECTOR_AUTH_FAILURE,
            Self::PortScan => DETECTOR_PORT_SCAN,
            Self::Manual | Self::Unknown => DETECTOR_MANUAL,
        }
    }

    /// Resolve a detector id string to its source.
    #[must_use]
    pub fn from_detector(detector: &str) -> Self {
        match detector {
            DETECTOR_REPEAT_BLOCKED => Self::RepeatBlocked,
            DETECTOR_AUTH_FAILURE => Self::AuthFailure,
            DETECTOR_PORT_SCAN => Self::PortScan,
            _ => Self::Manual,
        }
    }
}

/// A single active-ban record, persisted in the etch store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanRecord {
    /// The banned source IP.
    pub ip: IpAddr,
    /// The detector id that triggered the ban.
    pub detector: String,
    /// When the ban was applied (unix seconds).
    pub banned_at: i64,
    /// When the ban expires (unix seconds); `None` = permanent.
    pub expires_at: Option<i64>,
    /// The prior escalation count at the time of this ban (0 = first offense).
    pub escalation_count: u32,
    /// What produced this ban.
    pub source: BanSource,
}

impl BanRecord {
    /// Whether this ban is still in force at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: i64) -> bool {
        match self.expires_at {
            Some(exp) => exp > now,
            None => true,
        }
    }
}

/// Per-IP escalation counter plus the timestamp of its most recent ban.
///
/// The `last_ban` timestamp lets the sweep decay stale counters so escalation
/// state cannot grow without bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanCount {
    /// Number of times this IP has been banned (drives escalation).
    pub count: u32,
    /// Unix timestamp of the most recent ban that updated this counter.
    pub last_ban: i64,
}

/// A failure signal fed into the engine by a detector.
///
/// Every value that reaches the ban path arrives as a typed `Signal`, never as
/// raw bytes — the detectors are the total parse boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// The offending source IP (the OS-emitted peer address).
    pub ip: IpAddr,
    /// The detector id producing this signal.
    pub detector: &'static str,
}

impl Signal {
    /// Construct a signal for `detector` from `ip`.
    #[must_use]
    pub fn new(ip: IpAddr, detector: &'static str) -> Self {
        Self { ip, detector }
    }
}

/// A ban lifecycle event emitted by the engine, for metrics + IPC push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanEvent {
    /// An IP was just banned.
    Banned(BanRecord),
    /// An IP's ban was lifted (expiry, manual unban).
    Unbanned {
        /// The IP that was unbanned.
        ip: IpAddr,
        /// The detector id whose ban was lifted.
        detector: String,
    },
}

#[cfg(test)]
#[path = "record_test.rs"]
mod record_test;
