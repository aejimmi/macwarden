//! Binary inventory scanner and storage for macwarden.
//!
//! Discovers installed applications and system binaries, hashes them,
//! and stores the results in an etch-backed persistent store. Supports
//! hash blocklist checking for known-bad binary detection.
//!
//! # Modules
//!
//! - [`record`] -- `BinaryRecord` data type
//! - [`db`] -- Etch-backed persistent storage
//! - [`scanner`] -- Directory walker for binary discovery
//! - [`bundle`] -- macOS `.app` bundle `Info.plist` parser
//! - [`blocklist`] -- Known-bad hash set loader
//! - [`error`] -- Error types
//!
//! File hashing lives in the shared `openbinary-agent-core` SDK
//! (`openbinary_agent_core::hash`) — the CLI layer hashes discovered binaries
//! before building records.

pub mod blocklist;
pub mod bundle;
pub mod db;
pub mod error;
pub mod record;
pub mod scanner;

pub use blocklist::HashBlocklist;
pub use bundle::BundleMetadata;
pub use db::InventoryStore;
pub use error::InventoryError;
pub use record::BinaryRecord;
pub use scanner::DiscoveredBinary;
