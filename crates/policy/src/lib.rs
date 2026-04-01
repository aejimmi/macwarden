//! `policy` — pure-Rust policy engine, profile model, and decision logic.
//!
//! This crate has ZERO platform dependencies. It compiles and tests on any OS.
//! All macOS-specific behavior lives in other crates (`launchd`, etc.).
//!
//! # Modules
//!
//! - [`types`] — Core domain types (`ServiceInfo`, `Domain`, `ServiceState`, etc.)
//! - [`error`] — Error types for the core crate
//! - [`safelist`] — Critical service protection (hardcoded, non-overridable)
//! - [`profile`] — Profile loading, validation, and extends resolution
//! - [`engine`] — Policy decision engine, diff computation, explain output

pub mod engine;
pub mod error;
pub mod group;
pub mod profile;
pub mod safelist;
pub mod types;

// Re-export key types at crate root for convenience.
pub use engine::{Decision, decide, diff, explain};
pub use error::CoreError;
pub use group::{
    RespawnBehavior, Safety, ServiceGroup, find_group, find_groups_for_service, parse_group_file,
    parse_groups_toml, resolve_group_services,
};
pub use profile::{
    CategoryAction, Enforcement, EnforcementAction, ExecPolicy, Profile, ProfileMeta, Rules,
    load_profile, parse_profile_toml, resolve_extends, validate_profile,
};
pub use safelist::{is_critical, validate_actions};
pub use types::{Action, Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};
