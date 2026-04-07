//! Error types for the sensors crate.

/// Errors from hardware sensor monitoring.
#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    /// A CoreAudio API call returned an error status.
    #[error("CoreAudio {function} failed (OSStatus {code})")]
    CoreAudio {
        /// Name of the function that failed.
        function: &'static str,
        /// The OSStatus error code.
        code: i32,
    },

    /// A CoreMediaIO API call returned an error status.
    #[error("CoreMediaIO {function} failed (OSStatus {code})")]
    CoreMediaIO {
        /// Name of the function that failed.
        function: &'static str,
        /// The OSStatus error code.
        code: i32,
    },

    /// An IOKit API call returned an error status.
    #[error("IOKit {function} failed (kern_return_t {code})")]
    IOKit {
        /// Name of the function that failed.
        function: &'static str,
        /// The kern_return_t error code.
        code: i32,
    },

    /// Device enumeration failed.
    #[error("device enumeration failed: {reason}")]
    DeviceEnumeration {
        /// What went wrong.
        reason: &'static str,
    },

    /// No hardware device of the expected type was found.
    #[error("no {kind} device found")]
    NoDevice {
        /// "camera" or "microphone".
        kind: &'static str,
    },
}
