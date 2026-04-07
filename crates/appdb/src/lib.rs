//! `appdb` — app profile database for macwarden.
//!
//! Shared identity and metadata for macOS applications, consumed by both
//! network gating (which domains can an app reach?) and execution gating
//! (should this app be allowed to run?).
//!
//! Pure Rust, zero platform dependencies. Compiles and tests on any OS.
//!
//! # Data source
//!
//! App profiles live in `knowledge/apps/` at the workspace root — one TOML file
//! per app. See `knowledge/apps/_schema.toml` for the format. Contributors add
//! apps by creating a new TOML file and adding an `include_str!` line to
//! [`loader`].
//!
//! # Modules
//!
//! - [`profile`] — `AppProfile`, `AppCategory`, `ConnectionContext`, `BreakageRisk`
//! - [`db`] — `AppDb` with load, lookup, categorize, expand
//! - [`loader`] — Embedded TOML data
//! - [`error`] — `AppDbError`

pub mod db;
pub mod error;
mod loader;
pub mod profile;

// Re-export key types at crate root.
pub use db::AppDb;
pub use error::AppDbError;
pub use profile::{AppCategory, AppProfile, BreakageRisk, ConnectionContext};
