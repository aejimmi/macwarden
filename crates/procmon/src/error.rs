//! Error types for process monitoring operations.

/// Errors that can occur during process monitoring.
#[derive(Debug, thiserror::Error)]
pub enum ProcmonError {
    /// The target process does not exist or has exited.
    #[error("process {pid} not found")]
    ProcessNotFound {
        /// PID of the missing process.
        pid: u32,
    },

    /// Failed to resolve the executable path for a process.
    #[error("failed to get process path for pid {pid}: {message}")]
    PathLookup {
        /// PID of the target process.
        pid: u32,
        /// Description of the failure.
        message: String,
    },

    /// Code signing verification failed.
    #[error("code signing lookup failed for pid {pid}: {message}")]
    CodeSigning {
        /// PID of the target process.
        pid: u32,
        /// Description of the failure.
        message: String,
    },

    /// Responsible PID lookup failed.
    #[error("responsible pid lookup failed for pid {pid}: {message}")]
    ResponsiblePid {
        /// PID of the target process.
        pid: u32,
        /// Description of the failure.
        message: String,
    },

    /// Socket enumeration failed.
    #[error("socket enumeration failed for pid {pid}: {message}")]
    SocketEnum {
        /// PID of the target process.
        pid: u32,
        /// Description of the failure.
        message: String,
    },

    /// Resource usage lookup failed.
    #[error("resource usage lookup failed for pid {pid}: {message}")]
    ResourceUsage {
        /// PID of the target process.
        pid: u32,
        /// Description of the failure.
        message: String,
    },
}

#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
