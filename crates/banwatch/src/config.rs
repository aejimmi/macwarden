//! `~/.macwarden/banwatch.toml` parsing with fail-open defaults.
//!
//! Loading never fails: a missing file yields all defaults; a malformed file
//! logs a `warn!` and also yields defaults; a single bad duration string falls
//! back to that field's default. This mirrors `net::policy::PolicyConfig::load`.
//! Durations are TOML strings (`"1h"`, `"30d"`, `"0"`) parsed by
//! [`crate::duration::parse_duration`].

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use tracing::warn;

use crate::duration::parse_duration;
use crate::record::{DETECTOR_AUTH_FAILURE, DETECTOR_PORT_SCAN, DETECTOR_REPEAT_BLOCKED};

/// Canonical config filename within `~/.macwarden/`.
pub const CONFIG_FILENAME: &str = "banwatch.toml";

/// Default base ban time in seconds (1 hour).
const DEFAULT_BAN_TIME: i64 = 3_600;
/// Default escalation cap in seconds (1 week).
const DEFAULT_MAXTIME: i64 = 604_800;
/// Default escalation-count decay window in seconds (30 days).
const DEFAULT_DECAY: i64 = 2_592_000;
/// Default failure window in seconds (10 minutes).
const DEFAULT_FIND_TIME: i64 = 600;
/// Default failures-to-ban.
const DEFAULT_MAX_RETRY: u32 = 5;

/// Resolved per-detector engine parameters (failures-to-ban within a window).
#[derive(Debug, Clone)]
pub struct DetectorParams {
    /// Whether this detector is active.
    pub enabled: bool,
    /// Failures within [`Self::find_time`] that trigger a ban.
    pub max_retry: u32,
    /// The failure window, in seconds.
    pub find_time: i64,
}

/// Resolved port-scan detector thresholds (in addition to its engine params).
#[derive(Debug, Clone)]
pub struct PortScanParams {
    /// Whether the port-scan detector is active.
    pub enabled: bool,
    /// Distinct local ports from one remote IP within the window that trip it.
    pub distinct_ports: u32,
    /// SYNs from one remote IP within the window that trip it.
    pub syn_rate: u32,
    /// The scan-detection window, in seconds.
    pub find_time: i64,
}

/// Fully resolved banwatch configuration.
#[derive(Debug, Clone)]
pub struct BanwatchConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Base ban time (seconds); negative = permanent.
    pub ban_time: i64,
    /// Whether repeat offenders escalate.
    pub ban_time_increment: bool,
    /// Escalation multipliers, indexed by clamped escalation count.
    pub ban_time_multipliers: Vec<u32>,
    /// Escalation cap in seconds (`<= 0` disables the cap).
    pub ban_time_maxtime: i64,
    /// Escalation-count decay window in seconds (`0` disables decay).
    pub ban_count_decay: i64,
    /// User `ignoreip` CIDRs (merged with private/loopback defaults).
    pub ignoreip: Vec<String>,
    /// Whether to ignore the host's own interface addresses.
    pub ignore_self: bool,
    /// The repeat-blocked detector.
    pub repeat_blocked: DetectorParams,
    /// The auth-failure detector.
    pub auth_failure: DetectorParams,
    /// The port-scan detector.
    pub port_scan: PortScanParams,
}

impl Default for BanwatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_time: DEFAULT_BAN_TIME,
            ban_time_increment: true,
            ban_time_multipliers: vec![1, 2, 4, 8, 16, 32, 64],
            ban_time_maxtime: DEFAULT_MAXTIME,
            ban_count_decay: DEFAULT_DECAY,
            ignoreip: Vec::new(),
            ignore_self: true,
            repeat_blocked: DetectorParams {
                enabled: true,
                max_retry: DEFAULT_MAX_RETRY,
                find_time: DEFAULT_FIND_TIME,
            },
            auth_failure: DetectorParams {
                enabled: false,
                max_retry: DEFAULT_MAX_RETRY,
                find_time: DEFAULT_FIND_TIME,
            },
            port_scan: PortScanParams {
                enabled: false,
                distinct_ports: 15,
                syn_rate: 100,
                find_time: 60,
            },
        }
    }
}

impl BanwatchConfig {
    /// Load and resolve the config from `path`, failing open to defaults.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "banwatch config unreadable; using defaults");
                return Self::default();
            }
        };
        match toml::from_str::<RawFile>(&text) {
            Ok(raw) => raw.resolve(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "banwatch config malformed; using defaults");
                Self::default()
            }
        }
    }

    /// The engine params for each detector, keyed by detector id — the map the
    /// engine consults per signal.
    #[must_use]
    pub fn detector_params(&self) -> HashMap<&'static str, DetectorParams> {
        HashMap::from([
            (DETECTOR_REPEAT_BLOCKED, self.repeat_blocked.clone()),
            (DETECTOR_AUTH_FAILURE, self.auth_failure.clone()),
            // The port-scan analyzer does its own windowed counting and emits a
            // single ready-to-ban signal, so the engine bans on the first one.
            (
                DETECTOR_PORT_SCAN,
                DetectorParams {
                    enabled: self.port_scan.enabled,
                    max_retry: 1,
                    find_time: self.port_scan.find_time,
                },
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// Raw on-disk shape
// ---------------------------------------------------------------------------

/// The raw TOML file: a `[banwatch]` table plus a `[detectors.*]` map.
#[derive(Debug, Default, Deserialize)]
struct RawFile {
    #[serde(default)]
    banwatch: RawGlobal,
    #[serde(default)]
    detectors: RawDetectors,
}

#[derive(Debug, Default, Deserialize)]
struct RawGlobal {
    enabled: Option<bool>,
    ban_time: Option<String>,
    ban_time_increment: Option<bool>,
    ban_time_multipliers: Option<Vec<u32>>,
    ban_time_maxtime: Option<String>,
    ban_count_decay: Option<String>,
    ignoreip: Option<Vec<String>>,
    ignore_self: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDetectors {
    #[serde(rename = "repeat-blocked")]
    repeat_blocked: Option<RawDetector>,
    #[serde(rename = "auth-failure")]
    auth_failure: Option<RawDetector>,
    #[serde(rename = "port-scan")]
    port_scan: Option<RawPortScan>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDetector {
    enabled: Option<bool>,
    max_retry: Option<u32>,
    find_time: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawPortScan {
    enabled: Option<bool>,
    distinct_ports: Option<u32>,
    syn_rate: Option<u32>,
    find_time: Option<String>,
}

/// Parse a duration field, warning and using `default` when absent or malformed.
fn dur_or(field: &str, raw: Option<&str>, default: i64) -> i64 {
    match raw {
        None => default,
        Some(s) => parse_duration(s).unwrap_or_else(|| {
            warn!(field, value = %s, "malformed banwatch duration; using default");
            default
        }),
    }
}

impl RawFile {
    /// Resolve the raw file into a [`BanwatchConfig`], applying field defaults.
    fn resolve(self) -> BanwatchConfig {
        let d = BanwatchConfig::default();
        let g = self.banwatch;
        BanwatchConfig {
            enabled: g.enabled.unwrap_or(d.enabled),
            ban_time: dur_or("ban_time", g.ban_time.as_deref(), d.ban_time),
            ban_time_increment: g.ban_time_increment.unwrap_or(d.ban_time_increment),
            ban_time_multipliers: g.ban_time_multipliers.unwrap_or(d.ban_time_multipliers),
            ban_time_maxtime: dur_or(
                "ban_time_maxtime",
                g.ban_time_maxtime.as_deref(),
                d.ban_time_maxtime,
            ),
            ban_count_decay: dur_or(
                "ban_count_decay",
                g.ban_count_decay.as_deref(),
                d.ban_count_decay,
            ),
            ignoreip: g.ignoreip.unwrap_or(d.ignoreip),
            ignore_self: g.ignore_self.unwrap_or(d.ignore_self),
            repeat_blocked: resolve_detector(self.detectors.repeat_blocked, &d.repeat_blocked),
            auth_failure: resolve_detector(self.detectors.auth_failure, &d.auth_failure),
            port_scan: resolve_port_scan(self.detectors.port_scan, &d.port_scan),
        }
    }
}

/// Resolve one `[detectors.*]` table against its default.
fn resolve_detector(raw: Option<RawDetector>, default: &DetectorParams) -> DetectorParams {
    let Some(r) = raw else {
        return default.clone();
    };
    DetectorParams {
        enabled: r.enabled.unwrap_or(default.enabled),
        max_retry: r.max_retry.unwrap_or(default.max_retry),
        find_time: dur_or(
            "detector.find_time",
            r.find_time.as_deref(),
            default.find_time,
        ),
    }
}

/// Resolve the `[detectors.port-scan]` table against its default.
fn resolve_port_scan(raw: Option<RawPortScan>, default: &PortScanParams) -> PortScanParams {
    let Some(r) = raw else {
        return default.clone();
    };
    PortScanParams {
        enabled: r.enabled.unwrap_or(default.enabled),
        distinct_ports: r.distinct_ports.unwrap_or(default.distinct_ports),
        syn_rate: r.syn_rate.unwrap_or(default.syn_rate),
        find_time: dur_or(
            "port-scan.find_time",
            r.find_time.as_deref(),
            default.find_time,
        ),
    }
}

#[cfg(test)]
#[path = "config_test.rs"]
mod config_test;
