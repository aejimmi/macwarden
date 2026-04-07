//! `es` -- Endpoint Security client for macwarden.
//!
//! Provides a safe wrapper around Apple's Endpoint Security framework
//! for subscribing to `ES_EVENT_TYPE_RESERVED_5` (network connection
//! AUTH) events. Each event is processed through the rule engine in
//! [`net`] and responded with allow or deny.
//!
//! # Platform
//!
//! The real ES client only compiles and runs on macOS with SIP disabled.
//! On other platforms, [`EsClient::start`] returns [`EsError::NotAvailable`].
//!
//! # Architecture
//!
//! ```text
//! ES framework
//!   |
//!   +-- es_new_client(handler_block)
//!   |     |
//!   |     +-- handler: retain message, spawn worker
//!   |           |
//!   |           +-- worker: parse event, lookup process, decide, respond
//!   |           |
//!   |           +-- safety-net: sleep(deadline - 2s), auto-allow if needed
//!   |
//!   +-- es_subscribe(RESERVED_5)
//!   |
//!   +-- es_mute_process(self)  -- self-exemption
//! ```
//!
//! # Safety
//!
//! All unsafe FFI code is isolated in [`ffi`]. The [`client`] module
//! provides a safe interface.

pub mod client;
pub mod error;
#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
mod handler;

pub use client::{EsClient, EsClientConfig, EsStats};
pub use error::EsError;
