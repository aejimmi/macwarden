//! Error types for the snapshot crate.

use std::io;

/// All errors produced by the snapshot crate.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Snapshot serialization failed.
    #[error("snapshot serialization failed: {0}")]
    Serialize(String),

    /// Snapshot deserialization failed.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),

    /// A requested snapshot was not found.
    #[error("snapshot not found: {0}")]
    NotFound(String),
}

/// Convenience alias for results using [`SnapshotError`].
pub type Result<T> = std::result::Result<T, SnapshotError>;
