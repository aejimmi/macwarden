//! Metric event types collected from all macwarden enforcement domains.
//!
//! Each variant maps to a `kind` string discriminant stored in the database.
//! Top-level fields (`app_id`, `domain`, `action`) are extracted for indexed
//! columns; remaining fields go into a JSON `payload` column.

use serde::{Deserialize, Serialize};

/// A single metric event from any enforcement domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum MetricEvent {
    /// A service was enforced (disabled, enabled, or killed).
    #[serde(rename = "service_enforced")]
    ServiceEnforced {
        /// Launchd service label.
        label: String,
        /// Action taken: "disable", "enable", or "kill".
        action: String,
        /// What triggered the enforcement: "sweep", "fsevent", or "sensor".
        source: String,
        /// Active profile name.
        profile: String,
    },

    /// A service drifted from its expected state.
    #[serde(rename = "service_drift")]
    ServiceDrift {
        /// Launchd service label.
        label: String,
        /// Expected state (e.g. "disabled").
        expected: String,
        /// Actual observed state (e.g. "running").
        actual: String,
    },

    /// A reconciliation sweep completed.
    #[serde(rename = "sweep_completed")]
    SweepCompleted {
        /// Sweep wall-clock duration in milliseconds.
        duration_ms: u64,
        /// Number of services checked.
        checked: usize,
        /// Number of drift corrections applied.
        drift_count: usize,
    },

    /// A hardware sensor (camera/microphone) changed state.
    #[serde(rename = "sensor_triggered")]
    SensorTriggered {
        /// Device: "camera" or "microphone".
        device: String,
        /// State: "active" or "inactive".
        state: String,
        /// Path of the process using the device.
        process_path: String,
        /// Code signing identity, if available.
        code_id: Option<String>,
    },

    /// A network connection was decided (allow/deny/log).
    #[serde(rename = "connection_decided")]
    ConnectionDecided {
        /// Code signing identity of the originating process.
        app_id: Option<String>,
        /// Destination hostname (DNS), if resolved.
        dest_host: Option<String>,
        /// Destination IP address.
        dest_ip: String,
        /// Decision: "allow", "deny", or "log".
        action: String,
        /// Matching tier: "safelist", "user_rule", "group", "tracker",
        /// "blocklist", or "default".
        tier: String,
        /// Name of the matched rule, if any.
        rule_name: Option<String>,
        /// Tracker category if tier is "tracker".
        tracker_category: Option<String>,
    },

    /// Periodic Endpoint Security statistics flush.
    #[serde(rename = "es_stats")]
    EsStats {
        /// Total ES events received.
        received: u64,
        /// Events allowed by rule engine.
        allowed: u64,
        /// Events denied by rule engine.
        denied: u64,
        /// Events in log-only mode.
        logged: u64,
        /// Events auto-allowed by safety-net timer.
        auto_allowed: u64,
    },
}

impl MetricEvent {
    /// Returns the string discriminant for database storage.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ServiceEnforced { .. } => "service_enforced",
            Self::ServiceDrift { .. } => "service_drift",
            Self::SweepCompleted { .. } => "sweep_completed",
            Self::SensorTriggered { .. } => "sensor_triggered",
            Self::ConnectionDecided { .. } => "connection_decided",
            Self::EsStats { .. } => "es_stats",
        }
    }

    /// Returns the app identity, if this event is attributable to a specific app.
    ///
    /// Populated for `ConnectionDecided` (from `app_id`) and `SensorTriggered`
    /// (from `code_id`).
    pub fn app_id(&self) -> Option<&str> {
        match self {
            Self::ConnectionDecided { app_id, .. } => app_id.as_deref(),
            Self::SensorTriggered { code_id, .. } => code_id.as_deref(),
            _ => None,
        }
    }

    /// Returns the destination domain, if applicable.
    ///
    /// Populated for `ConnectionDecided` (from `dest_host`).
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::ConnectionDecided { dest_host, .. } => dest_host.as_deref(),
            _ => None,
        }
    }

    /// Returns the action taken, if applicable.
    ///
    /// Populated for `ServiceEnforced` and `ConnectionDecided`.
    pub fn action(&self) -> Option<&str> {
        match self {
            Self::ServiceEnforced { action, .. } | Self::ConnectionDecided { action, .. } => {
                Some(action.as_str())
            }
            _ => None,
        }
    }

    /// Serializes the variant-specific fields to a JSON string for the
    /// `payload` column, excluding fields already stored in top-level columns.
    pub fn payload_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}
