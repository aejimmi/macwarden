//! Error types for the launchd crate.

use std::io;

/// All errors produced by the launchd platform crate.
#[derive(Debug, thiserror::Error)]
pub enum LaunchdError {
    /// A subprocess exited with a non-zero status or produced unexpected output.
    #[error("command `{cmd}` failed: {stderr}")]
    CommandFailed {
        /// The command that was run.
        cmd: String,
        /// Captured stderr output.
        stderr: String,
    },

    /// Failed to parse command output.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Operation requires elevated privileges.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Convenience alias for results using [`LaunchdError`].
pub type Result<T> = std::result::Result<T, LaunchdError>;
