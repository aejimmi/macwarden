//! `launchd` -- macOS launchctl platform layer for macwarden.
//!
//! Provides the interface between macwarden's policy engine and the macOS
//! service management layer. Wraps `launchctl`, process signals, and SIP
//! detection behind a [`Platform`] trait for testability.
//!
//! # Modules
//!
//! - [`error`] -- Error types for platform operations
//! - [`platform`] -- `Platform` trait, `LaunchctlEntry`, `SipState`
//! - [`macos`] -- Real macOS implementation via system commands
//! - [`mock`] -- Test double that records calls
//! - [`executor`] -- Translates policy `Action`s into platform calls

pub mod error;
pub mod executor;
pub mod macos;
pub mod mock;
pub mod platform;

// Re-export key types at crate root for convenience.
pub use error::LaunchdError;
pub use executor::{ActionResult, execute_actions};
pub use macos::{
    MacOsPlatform, TelemetryScan, binary_frameworks, binary_telemetry_scan, parse_launchctl_output,
    parse_launchctl_print,
};
pub use mock::MockPlatform;
pub use platform::{LaunchctlEntry, Platform, ProcessDetail, ServiceDetail, SipState};
