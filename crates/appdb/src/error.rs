//! Error types for the appdb crate.

/// Errors that can occur when loading or querying the app database.
#[derive(Debug, thiserror::Error)]
pub enum AppDbError {
    /// Failed to parse an app profile TOML file.
    #[error("failed to parse app profile: {message}")]
    ProfileParse {
        /// Description of the parse error.
        message: String,
    },
}

/// Convenience alias for `Result<T, AppDbError>`.
pub type Result<T> = std::result::Result<T, AppDbError>;
