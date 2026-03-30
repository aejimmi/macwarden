//! `macwarden-snapshot` -- state snapshots and rollback for macwarden.
//!
//! Captures service states before enforcement actions are applied, enabling
//! rollback to a known-good state. Snapshots are stored as JSON files named
//! by ISO 8601 timestamp.
//!
//! # Modules
//!
//! - [`error`] -- Error types for snapshot operations
//! - [`types`] -- `Snapshot` and `SnapshotEntry` data structures
//! - [`store`] -- Filesystem-backed snapshot persistence

pub mod error;
pub mod store;
pub mod types;

// Re-export key types at crate root for convenience.
pub use error::SnapshotError;
pub use store::SnapshotStore;
pub use types::{Snapshot, SnapshotEntry};
