//! Error types for the inventory crate.

use std::path::PathBuf;

/// Errors that can occur during inventory operations.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// Failed to open or write to the etch store.
    #[error("store error: {0}")]
    Store(String),

    /// Failed to read a directory during scanning.
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to read or parse an Info.plist file.
    #[error("failed to read bundle plist {path}: {source}")]
    Plist { path: PathBuf, source: plist::Error },

    /// Failed to hash a file.
    #[error("failed to hash {path}: {source}")]
    Hash {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to read a blocklist file.
    #[error("failed to read blocklist {path}: {source}")]
    Blocklist {
        path: PathBuf,
        source: std::io::Error,
    },
}
