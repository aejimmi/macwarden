//! Process monitoring for macwarden.
//!
//! Provides process identification, code signing verification, socket
//! enumeration, and resource usage statistics via macOS `libproc` and
//! Security.framework FFI.
//!
//! # Platform
//!
//! FFI functions require macOS. Types and cache compile anywhere.
//!
//! # Architecture
//!
//! All unsafe FFI code is isolated in [`ffi`]. Safe wrappers in
//! [`code_signing`], [`responsible`], [`sockets`], and [`rusage`]
//! convert raw C data into Rust types from [`types`]. The
//! [`cache`] module provides an LRU cache for code signing results.

pub mod cache;
pub mod error;
pub mod types;

#[cfg(target_os = "macos")]
pub mod code_signing;
#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
pub mod responsible;
#[cfg(target_os = "macos")]
pub mod rusage;
#[cfg(target_os = "macos")]
pub mod sockets;

// Convenience re-exports
pub use cache::CodeSigningCache;
pub use error::ProcmonError;
pub use types::{
    CodeSigningInfo, NetworkUsage, ProcessInfo, ResponsibleProcess, SocketInfo, SocketProtocol,
    SocketState,
};
