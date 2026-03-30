//! Error types for the macknows library.

use std::path::PathBuf;

/// All errors that can occur in macknows library operations.
#[derive(Debug, thiserror::Error)]
pub enum MacknowsError {
    /// A required database file was not found at the expected path.
    #[error("database not found: {path}")]
    DatabaseNotFound {
        /// The path that was checked.
        path: PathBuf,
    },

    /// Failed to open a SQLite database.
    #[error("failed to open database at {path}: {source}")]
    DatabaseOpen {
        /// The underlying rusqlite error.
        source: rusqlite::Error,
        /// The path that failed to open.
        path: PathBuf,
    },

    /// A SQL query failed.
    #[error("{context}: {source}")]
    Query {
        /// The underlying rusqlite error.
        source: rusqlite::Error,
        /// Description of what query was being attempted.
        context: String,
    },

    /// JSON parsing failed on a database field.
    #[error("JSON parse error in {context}: {source}")]
    JsonParse {
        /// The underlying serde_json error.
        source: serde_json::Error,
        /// Description of what was being parsed.
        context: String,
    },

    /// An I/O operation failed.
    #[error("I/O error: {source}")]
    Io {
        /// The underlying I/O error.
        #[from]
        source: std::io::Error,
    },
}

/// Convenience alias for macknows results.
pub type Result<T> = std::result::Result<T, MacknowsError>;
