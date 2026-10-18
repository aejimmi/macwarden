//! Error type for the daemon IPC server.

use ipc::validate::ValidationError;

/// A failure inside the IPC server. Handlers translate these into typed
/// [`ipc::protocol::Response::Error`] frames; the accept loop logs and survives.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding, permission, or socket-setup failure at startup.
    #[error("socket setup failed: {0}")]
    Socket(String),

    /// The parent directory of the socket is not owned by the server's euid.
    #[error("socket parent directory not owned by server euid")]
    ParentOwnership,

    /// Another daemon already accepts connections on the socket path, so this
    /// instance must not steal it — it exits and the panel uses the existing one.
    #[error("daemon already running on {0}")]
    AlreadyRunning(String),

    /// A boundary validator rejected a request field (R9).
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// A rule file could not be written or removed (R7).
    #[error("rule file io error: {0}")]
    RuleFileIo(String),

    /// Building or reloading the live rule set failed (R7).
    #[error("ruleset reload failed: {0}")]
    Reload(String),

    /// The live-connection scan failed (R4).
    #[error("connection scan failed: {0}")]
    Scan(String),

    /// A metrics-store query failed (R5).
    #[error("metrics query failed: {0}")]
    Metrics(String),

    /// A banwatch operation failed (spec 010 R8).
    #[error("banwatch error: {0}")]
    Banwatch(String),

    /// An underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for the IPC server.
pub type Result<T> = std::result::Result<T, ServerError>;
