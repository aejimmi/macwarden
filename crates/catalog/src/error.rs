//! Error types for the catalog crate.

use std::path::PathBuf;

/// All errors produced by the catalog crate.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// Failed to parse a plist file.
    #[error("failed to parse plist at {path}: {message}")]
    PlistParse {
        /// Path to the offending plist.
        path: PathBuf,
        /// Human-readable parse error detail.
        message: String,
    },

    /// Failed to parse the annotation TOML database.
    #[error("failed to parse annotation database: {message}")]
    AnnotationParse {
        /// Human-readable parse error detail.
        message: String,
    },

    /// An IO error occurred while reading a file.
    #[error("IO error at {path}: {source}")]
    IoError {
        /// Path that caused the error.
        path: PathBuf,
        /// The underlying IO error.
        source: std::io::Error,
    },
}

/// Convenience alias for results using [`CatalogError`].
pub type Result<T> = std::result::Result<T, CatalogError>;
