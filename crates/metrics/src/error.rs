//! Error types for the metrics crate.

/// All errors produced by the metrics crate.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// Failed to open or create the metrics database.
    #[error("failed to open metrics database at {path}: {source}")]
    Open {
        /// Filesystem path that was attempted.
        path: String,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },

    /// Schema initialization failed.
    #[error("schema initialization failed: {0}")]
    Schema(#[source] rusqlite::Error),

    /// Failed to set file permissions.
    #[error("failed to set permissions on {path}: {source}")]
    Permissions {
        /// Filesystem path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to insert an event.
    #[error("failed to record event ({kind}): {source}")]
    Insert {
        /// The event kind that failed.
        kind: String,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },

    /// Failed to execute a query.
    #[error("query failed ({operation}): {source}")]
    Query {
        /// Description of the query.
        operation: String,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },

    /// JSON serialization or deserialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid time range (start > end).
    #[error("invalid time range: start ({start}) is after end ({end})")]
    InvalidRange {
        /// Start timestamp (epoch ms).
        start: i64,
        /// End timestamp (epoch ms).
        end: i64,
    },
}

/// Convenience alias for results using [`MetricsError`].
pub type Result<T> = std::result::Result<T, MetricsError>;
