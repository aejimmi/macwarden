//! Platform abstraction for launchd operations.
//!
//! The [`Platform`] trait defines the interface for interacting with the
//! macOS service management layer. Concrete implementations exist for
//! real macOS (`MacOsPlatform`) and testing (`MockPlatform`).

use std::fmt;

use serde::Serialize;

use crate::error::LaunchdError;

/// A single entry from `launchctl list` output.
#[derive(Debug, Clone)]
pub struct LaunchctlEntry {
    /// The launchd service label.
    pub label: String,
    /// Process ID if the service is currently running.
    pub pid: Option<u32>,
    /// Last exit status, if available.
    pub last_exit_status: Option<i32>,
}

/// System Integrity Protection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipState {
    /// SIP is enabled (default macOS configuration).
    Enabled,
    /// SIP has been disabled (required for ES Tier 2).
    Disabled,
    /// SIP state could not be determined.
    Unknown,
}

impl fmt::Display for SipState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enabled => write!(f, "enabled"),
            Self::Disabled => write!(f, "disabled"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceDetail / ProcessDetail
// ---------------------------------------------------------------------------

/// Detailed information about a service from `launchctl print`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServiceDetail {
    /// The launchd service label.
    pub label: String,
    /// Runtime state (e.g. "running", "waiting").
    pub state: String,
    /// Launchd domain (e.g. "gui/501").
    pub domain: String,
    /// Process ID if the service is currently running.
    pub pid: Option<u32>,
    /// Path to the service executable.
    pub program: Option<String>,
    /// Command-line arguments.
    pub arguments: Vec<String>,
    /// Keep-alive policy description.
    pub keep_alive: Option<String>,
    /// Whether the service runs at load.
    pub run_at_load: Option<bool>,
    /// Mach/XPC service endpoints registered by this service.
    pub mach_services: Vec<String>,
    /// Seconds before forced termination on stop.
    pub exit_timeout: Option<u32>,
    /// Number of times the service has been started.
    pub runs: Option<u32>,
}

/// Process-level information from `ps` and `lsof`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessDetail {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User who owns the process.
    pub user: String,
    /// CPU usage percentage.
    pub cpu_percent: f32,
    /// Memory usage percentage.
    pub mem_percent: f32,
    /// Resident set size in kilobytes.
    pub rss_kb: u64,
    /// Full command line.
    pub command: String,
    /// Open file paths (first 20).
    pub open_files: Vec<String>,
}

// ---------------------------------------------------------------------------
// Platform trait
// ---------------------------------------------------------------------------

/// Abstraction over macOS launchd operations.
///
/// Allows swapping real system calls for mock implementations in tests.
pub trait Platform {
    /// Lists all services known to launchd.
    fn enumerate(&self) -> Result<Vec<LaunchctlEntry>, LaunchdError>;

    /// Disables a service in the given domain.
    ///
    /// Equivalent to `launchctl disable {domain}/{label}`.
    fn disable(&self, domain: &str, label: &str) -> Result<(), LaunchdError>;

    /// Enables a previously disabled service in the given domain.
    ///
    /// Equivalent to `launchctl enable {domain}/{label}`.
    fn enable(&self, domain: &str, label: &str) -> Result<(), LaunchdError>;

    /// Sends SIGKILL to a process by PID.
    fn kill_process(&self, pid: u32) -> Result<(), LaunchdError>;

    /// Checks whether a service with the given label is currently running.
    fn is_running(&self, label: &str) -> Result<bool, LaunchdError>;

    /// Queries the current System Integrity Protection state.
    fn sip_status(&self) -> Result<SipState, LaunchdError>;

    /// Retrieves detailed information about a service via `launchctl print`.
    fn inspect(&self, domain: &str, label: &str) -> Result<ServiceDetail, LaunchdError>;

    /// Retrieves process-level details (CPU, memory, open files) for a PID.
    fn process_detail(&self, pid: u32) -> Result<ProcessDetail, LaunchdError>;

    /// Unloads a service via `launchctl bootout`.
    fn bootout(&self, domain: &str, label: &str) -> Result<(), LaunchdError>;
}
