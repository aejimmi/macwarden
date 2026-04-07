//! Error types for the Endpoint Security client.

/// Errors from Endpoint Security client operations.
#[derive(Debug, thiserror::Error)]
pub enum EsError {
    /// ES client creation failed.
    #[error("failed to create ES client: {code}")]
    ClientCreate {
        /// The `es_new_client` result code.
        code: u32,
    },

    /// ES event subscription failed.
    #[error("failed to subscribe to events: {code}")]
    Subscribe {
        /// The `es_subscribe` result code.
        code: u32,
    },

    /// ES event response failed.
    #[error("failed to respond to event: {code}")]
    Respond {
        /// The `es_respond_auth_result` result code.
        code: u32,
    },

    /// Endpoint Security is not available on this platform.
    #[error("ES not available on this platform")]
    NotAvailable,

    /// The requested event type exceeds the known safe range.
    ///
    /// Subscribing to event types past `ES_EVENT_TYPE_LAST` causes
    /// a kernel panic on macOS. This error prevents that.
    #[error("event type {event_type} may not be safe to subscribe (past safety threshold)")]
    UnsafeEventType {
        /// The event type value that was rejected.
        event_type: u32,
    },
}

#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
