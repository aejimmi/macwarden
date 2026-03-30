//! Core domain types for macwarden.
//!
//! All types are pure data with no platform dependencies.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// The launchd domain a service belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Domain {
    /// System-wide daemons (`/System/Library/LaunchDaemons`, `/Library/LaunchDaemons`).
    System,
    /// Per-user agents (`~/Library/LaunchAgents`, `/Library/LaunchAgents`).
    User,
    /// Global agents (`/System/Library/LaunchAgents`).
    Global,
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Global => write!(f, "global"),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceState
// ---------------------------------------------------------------------------

/// Runtime state of a launchd service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    /// The service is currently running (has a PID).
    Running,
    /// The service is loaded but not running.
    Stopped,
    /// The service has been explicitly disabled.
    Disabled,
    /// State could not be determined.
    Unknown,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Disabled => write!(f, "disabled"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceCategory
// ---------------------------------------------------------------------------

/// Functional category assigned to a service by the annotation database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceCategory {
    /// Core operating system services (launchd, WindowServer, etc.).
    CoreOs,
    /// Networking daemons (mDNSResponder, WiFi, etc.).
    Networking,
    /// Security services (securityd, opendirectoryd, etc.).
    Security,
    /// Audio, video, and media frameworks.
    Media,
    /// iCloud, sync, and cloud services.
    Cloud,
    /// Analytics, diagnostics, and telemetry.
    Telemetry,
    /// Keyboard, trackpad, and other input.
    Input,
    /// Accessibility services (VoiceOver, etc.).
    Accessibility,
    /// Developer tools (Xcode, instruments, etc.).
    Developer,
    /// Third-party (non-Apple) services.
    ThirdParty,
    /// Not yet categorized.
    Unknown,
}

impl fmt::Display for ServiceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoreOs => write!(f, "core-os"),
            Self::Networking => write!(f, "networking"),
            Self::Security => write!(f, "security"),
            Self::Media => write!(f, "media"),
            Self::Cloud => write!(f, "cloud"),
            Self::Telemetry => write!(f, "telemetry"),
            Self::Input => write!(f, "input"),
            Self::Accessibility => write!(f, "accessibility"),
            Self::Developer => write!(f, "developer"),
            Self::ThirdParty => write!(f, "third-party"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// SafetyLevel
// ---------------------------------------------------------------------------

/// How safe it is to disable a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    /// Must never be disabled — system will not function.
    Critical,
    /// Disabling degrades functionality but system remains usable.
    Important,
    /// Safe to disable with no system impact.
    Optional,
    /// Recommended to disable for privacy.
    Telemetry,
}

impl fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::Important => write!(f, "important"),
            Self::Optional => write!(f, "optional"),
            Self::Telemetry => write!(f, "telemetry"),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceInfo
// ---------------------------------------------------------------------------

/// Complete information about a launchd-managed service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// The launchd label (e.g. `com.apple.Siri.agent`).
    pub label: String,
    /// Which launchd domain the service belongs to.
    pub domain: Domain,
    /// Path to the plist file, if known.
    pub plist_path: Option<PathBuf>,
    /// Current runtime state.
    pub state: ServiceState,
    /// Functional category from the annotation database.
    pub category: ServiceCategory,
    /// Safety level from the annotation database.
    pub safety: SafetyLevel,
    /// Human-readable description, if available.
    pub description: Option<String>,
    /// Process ID if the service is currently running.
    pub pid: Option<u32>,
}

impl fmt::Display for ServiceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, {}, {})",
            self.label, self.domain, self.state, self.category
        )
    }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// An enforcement action to be applied to a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Action {
    /// Disable the service via `launchctl disable`.
    Disable {
        /// Service label to disable.
        label: String,
    },
    /// Enable a previously disabled service.
    Enable {
        /// Service label to enable.
        label: String,
    },
    /// Kill a running service process.
    Kill {
        /// Service label to kill.
        label: String,
        /// Process ID to signal.
        pid: u32,
    },
}

impl Action {
    /// Returns the service label this action targets.
    pub fn label(&self) -> &str {
        match self {
            Self::Disable { label } | Self::Enable { label } | Self::Kill { label, .. } => label,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disable { label } => write!(f, "disable {label}"),
            Self::Enable { label } => write!(f, "enable {label}"),
            Self::Kill { label, pid } => write!(f, "kill {label} (pid {pid})"),
        }
    }
}

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;
