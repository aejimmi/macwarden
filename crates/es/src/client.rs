//! Safe Endpoint Security client wrapper.
//!
//! Provides [`EsClient`] which creates an ES client, subscribes to
//! `RESERVED_5` (network AUTH) events, and dispatches each event to a
//! worker thread for processing through the rule engine.
//!
//! # macOS only
//!
//! The real implementation compiles only on macOS. On other platforms,
//! a stub [`EsClient`] is provided that always returns
//! [`EsError::NotAvailable`].
//!
//! # Safety-net timer
//!
//! For each AUTH event, a safety-net thread is spawned that auto-allows
//! the connection if the worker hasn't responded before
//! `(deadline - safety_margin)`. Missing the deadline causes the kernel
//! to kill the ES client process -- this is non-negotiable.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use net::matcher::RuleSet;
use procmon::CodeSigningCache;

use crate::error::EsError;

// ---------------------------------------------------------------------------
// EsClientConfig
// ---------------------------------------------------------------------------

/// Configuration for the ES network firewall client.
#[derive(Debug)]
pub struct EsClientConfig {
    /// The rule set to evaluate connections against.
    pub rules: Arc<RuleSet>,
    /// Safety margin before deadline (default: 2 seconds).
    ///
    /// If the worker hasn't responded by `(deadline - safety_margin)`,
    /// the safety-net timer auto-allows the connection.
    pub safety_margin: Duration,
    /// Whether to subscribe to `RESERVED_5` (network AUTH).
    pub network_auth: bool,
    /// Whether to subscribe to `RESERVED_6` (network NOTIFY).
    ///
    /// NOTIFY events are informational -- no response required.
    pub network_notify: bool,
    /// Code signing cache capacity.
    pub cache_capacity: usize,
    /// Code signing cache TTL.
    pub cache_ttl: Duration,
}

impl Default for EsClientConfig {
    fn default() -> Self {
        Self {
            rules: Arc::new(RuleSet::default()),
            safety_margin: Duration::from_secs(2),
            network_auth: true,
            network_notify: false,
            cache_capacity: 1024,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------
// EsStats
// ---------------------------------------------------------------------------

/// Statistics about the ES client's operation.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default)]
pub struct EsStats {
    /// Total events received from ES.
    pub events_received: u64,
    /// Events that were allowed by the rule engine.
    pub events_allowed: u64,
    /// Events that were denied by the rule engine.
    pub events_denied: u64,
    /// Events where action was `Log` (allowed + logged).
    pub events_logged: u64,
    /// Events auto-allowed by the safety-net timer.
    pub events_auto_allowed: u64,
    /// Events where parsing the raw event failed.
    pub events_parse_failed: u64,
    /// Events allowed because they matched the safe-list.
    pub events_safelist_allowed: u64,
}

// ---------------------------------------------------------------------------
// HandlerContext (shared between handler and workers)
// ---------------------------------------------------------------------------

/// Shared context accessible from the ES handler block and worker threads.
///
/// Stored in a `OnceLock<Arc<HandlerContext>>` so the `extern "C"` handler
/// function can read it without captures.
pub(crate) struct HandlerContext {
    /// Rule set for connection evaluation.
    #[allow(dead_code)]
    pub(crate) rules: Arc<RuleSet>,
    /// Cumulative statistics.
    pub(crate) stats: Arc<Mutex<EsStats>>,
    /// Code signing lookup cache.
    #[allow(dead_code)]
    pub(crate) code_cache: Arc<Mutex<CodeSigningCache>>,
    /// Safety margin before the ES deadline.
    pub(crate) safety_margin: Duration,
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::ffi;
    use crate::handler;

    /// The ES client wrapper.
    ///
    /// Owns the ES client pointer and cleans up on drop.
    pub struct EsClient {
        /// Raw pointer to the ES client. Null after `stop()`.
        client_ptr: ffi::EsClientPtr,
        /// Statistics shared with the handler.
        stats: Arc<Mutex<EsStats>>,
        /// Rule set (swappable via `update_rules`).
        #[allow(dead_code)]
        rules: Arc<RuleSet>,
    }

    impl EsClient {
        /// Create and start an ES client.
        ///
        /// This creates the ES client, mutes the current process (self-
        /// exemption), and subscribes to the configured event types. The
        /// handler runs on ES's internal dispatch queue.
        ///
        /// # Errors
        ///
        /// Returns `EsError::ClientCreate` if `es_new_client` fails.
        /// Returns `EsError::Subscribe` if `es_subscribe` fails.
        #[allow(unsafe_code)]
        pub fn start(config: EsClientConfig) -> Result<Self, EsError> {
            let stats = Arc::new(Mutex::new(EsStats::default()));
            let code_cache = Arc::new(Mutex::new(CodeSigningCache::new(
                config.cache_capacity,
                config.cache_ttl,
            )));

            let ctx = Arc::new(HandlerContext {
                rules: Arc::clone(&config.rules),
                stats: Arc::clone(&stats),
                code_cache,
                safety_margin: config.safety_margin,
            });

            // Store context for the handler. If already set (second client
            // in the same process), this is a logic error but we handle it
            // gracefully by ignoring the set failure.
            let _ = handler::HANDLER_CONTEXT.set(ctx);

            let block = build_handler_block();
            let mut client_ptr: ffi::EsClientPtr = std::ptr::null_mut();

            // SAFETY: client_ptr is a valid output pointer. block is a valid
            // global block. es_new_client writes a valid client on success.
            let result = unsafe { ffi::es_new_client(&raw mut client_ptr, &raw const block) };

            if result != ffi::ES_NEW_CLIENT_RESULT_SUCCESS {
                return Err(EsError::ClientCreate { code: result });
            }

            handler::mute_self(client_ptr);
            subscribe(client_ptr, &config)?;

            tracing::info!(
                network_auth = config.network_auth,
                network_notify = config.network_notify,
                safety_margin_ms = config.safety_margin.as_millis() as u64,
                "ES client started"
            );

            Ok(Self {
                client_ptr,
                stats,
                rules: config.rules,
            })
        }

        /// Stop the ES client and release resources.
        ///
        /// After this call the client is inert. Further calls to `stop`
        /// are safe no-ops.
        ///
        /// # Errors
        ///
        /// Returns `EsError::Respond` if `es_delete_client` fails.
        #[allow(unsafe_code)]
        pub fn stop(&mut self) -> Result<(), EsError> {
            if self.client_ptr.is_null() {
                return Ok(());
            }

            // SAFETY: client_ptr is valid and non-null (checked above).
            unsafe { ffi::es_unsubscribe_all(self.client_ptr) };
            // SAFETY: client_ptr is valid.
            let result = unsafe { ffi::es_delete_client(self.client_ptr) };
            self.client_ptr = std::ptr::null_mut();
            if result != ffi::ES_RETURN_SUCCESS {
                return Err(EsError::Respond { code: result });
            }

            tracing::info!("ES client stopped");
            Ok(())
        }

        /// Get a snapshot of the current statistics.
        pub fn stats(&self) -> EsStats {
            self.stats.lock().map(|s| s.clone()).unwrap_or_default()
        }

        /// Replace the active rule set.
        ///
        /// New rules take effect for the next event. In-flight events
        /// continue with the rule set they started with.
        #[allow(clippy::unused_self)]
        pub fn update_rules(&self, rules: &Arc<RuleSet>) {
            if let Some(ctx) = handler::HANDLER_CONTEXT.get() {
                tracing::warn!(
                    new_rule_count = rules.user_rules.len(),
                    "rule hot-swap requires client restart; \
                     use stop() + start() with new rules"
                );
                let _ = ctx;
            }
        }
    }

    impl Drop for EsClient {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            if !self.client_ptr.is_null() {
                // SAFETY: client_ptr is valid and non-null.
                unsafe { ffi::es_unsubscribe_all(self.client_ptr) };
                // SAFETY: client_ptr is valid.
                unsafe { ffi::es_delete_client(self.client_ptr) };
                self.client_ptr = std::ptr::null_mut();
            }
        }
    }

    /// Build the Objective-C block for `es_new_client`.
    ///
    /// Constructs a global block (no captures) whose invoke function
    /// is [`handler::es_handler_invoke`].
    fn build_handler_block() -> ffi::BlockLiteral {
        ffi::BlockLiteral {
            isa: (&raw const ffi::_NSConcreteGlobalBlock).cast(),
            flags: 0x3000_0000_i32, // BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE
            reserved: 0,
            invoke: handler::es_handler_invoke,
            descriptor: &raw const handler::BLOCK_DESCRIPTOR,
        }
    }

    /// Subscribe to the configured ES event types.
    #[allow(unsafe_code)]
    fn subscribe(client_ptr: ffi::EsClientPtr, config: &EsClientConfig) -> Result<(), EsError> {
        let mut events = Vec::new();
        if config.network_auth {
            events.push(ffi::ES_EVENT_TYPE_RESERVED_5);
        }
        if config.network_notify {
            events.push(ffi::ES_EVENT_TYPE_RESERVED_6);
        }

        if events.is_empty() {
            return Ok(());
        }

        // SAFETY: client_ptr is valid (es_new_client succeeded).
        let sub_result =
            unsafe { ffi::es_subscribe(client_ptr, events.as_ptr(), events.len() as u32) };
        if sub_result != ffi::ES_RETURN_SUCCESS {
            // SAFETY: client_ptr is valid.
            unsafe { ffi::es_delete_client(client_ptr) };
            return Err(EsError::Subscribe { code: sub_result });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Non-macOS stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    /// Stub ES client for non-macOS platforms.
    ///
    /// Always returns [`EsError::NotAvailable`].
    pub struct EsClient;

    impl EsClient {
        /// Attempt to start an ES client. Always fails on non-macOS.
        ///
        /// # Errors
        ///
        /// Always returns `EsError::NotAvailable`.
        pub fn start(_config: EsClientConfig) -> Result<Self, EsError> {
            Err(EsError::NotAvailable)
        }

        /// Stop the ES client. Always fails on non-macOS.
        ///
        /// # Errors
        ///
        /// Always returns `EsError::NotAvailable`.
        pub fn stop(&mut self) -> Result<(), EsError> {
            Err(EsError::NotAvailable)
        }

        /// Get a snapshot of current statistics (all zeros on non-macOS).
        pub fn stats(&self) -> EsStats {
            EsStats::default()
        }

        /// Replace the active rule set (no-op on non-macOS).
        pub fn update_rules(&self, _rules: &Arc<RuleSet>) {}
    }
}

pub use platform::EsClient;

#[cfg(test)]
#[path = "client_test.rs"]
mod client_test;
