//! Raw FFI bindings to `libEndpointSecurity.tbd`.
//!
//! **All unsafe code in the es crate lives in this module.**
//!
//! This module is `cfg(target_os = "macos")` -- it only compiles on macOS.
//! Safe wrappers in [`client`](crate::client) call these functions with
//! validated inputs and handle all error cases.
//!
//! # Block ABI
//!
//! `es_new_client` expects an Objective-C block as its handler callback.
//! On Apple platforms, blocks follow a documented ABI: a `Block_literal`
//! struct with an `isa` pointer, flags, and an `invoke` function pointer.
//! We construct a global block (no captures) manually -- the handler
//! reads its context from a static `OnceLock` in the client module.
//!
//! # Safety invariants
//!
//! - Every `extern "C"` function here is `unsafe` by definition (FFI).
//! - Callers must ensure all pointer arguments are valid.
//! - `es_respond_auth_result` must be called exactly once per AUTH message.
//! - `es_retain_message` / `es_release_message` must be paired.
//! - Never subscribe to event types past `ES_EVENT_TYPE_LAST`.

#![cfg(target_os = "macos")]
#![allow(unsafe_code, dead_code)]

use std::os::raw::c_void;

// ---------------------------------------------------------------------------
// Opaque ES types
// ---------------------------------------------------------------------------

/// Opaque pointer to an ES client instance.
pub type EsClientPtr = *mut c_void;

/// Opaque pointer to an ES message.
pub type EsMessagePtr = *const c_void;

// ---------------------------------------------------------------------------
// Send-safe pointer wrappers
// ---------------------------------------------------------------------------

/// A `Send`-safe wrapper around an ES client pointer.
///
/// # Safety
///
/// The ES client is thread-safe by design -- Apple's documentation states
/// that `es_respond_auth_result` and other ES functions can be called from
/// any thread. This wrapper allows moving the pointer into spawned threads.
#[derive(Debug, Clone, Copy)]
pub struct SendClientPtr(EsClientPtr);

impl SendClientPtr {
    /// Wrap a raw ES client pointer.
    pub fn new(ptr: EsClientPtr) -> Self {
        Self(ptr)
    }

    /// Get the raw pointer for FFI calls.
    pub fn as_ptr(self) -> EsClientPtr {
        self.0
    }
}

// SAFETY: ES client pointers are thread-safe per Apple's documentation.
// All ES API functions that take a client pointer are safe to call from
// any thread.
unsafe impl Send for SendClientPtr {}

/// A `Send`-safe wrapper around an ES message pointer.
///
/// # Safety
///
/// After `es_retain_message`, the message is valid until
/// `es_release_message` is called. The message can be used from any
/// thread between retain and release.
#[derive(Debug, Clone, Copy)]
pub struct SendMessagePtr(EsMessagePtr);

impl SendMessagePtr {
    /// Wrap a raw ES message pointer.
    pub fn new(ptr: EsMessagePtr) -> Self {
        Self(ptr)
    }

    /// Get the raw pointer for FFI calls.
    pub fn as_ptr(self) -> EsMessagePtr {
        self.0
    }
}

// SAFETY: Retained ES messages are safe to use from any thread.
// The retain/release contract guarantees the message stays valid.
unsafe impl Send for SendMessagePtr {}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// ES event type identifier.
pub type EsEventType = u32;

/// `ES_EVENT_TYPE_AUTH_EXEC` -- process execution authorization.
pub const ES_EVENT_TYPE_AUTH_EXEC: EsEventType = 0;

/// `ES_EVENT_TYPE_RESERVED_5` -- network connection AUTH (type 153).
///
/// Reverse-engineered by Patrick Wardle (March 2026). Apple has NOT
/// documented this event type. The struct layout may change.
pub const ES_EVENT_TYPE_RESERVED_5: EsEventType = 153;

/// `ES_EVENT_TYPE_RESERVED_6` -- network connection NOTIFY (type 154).
///
/// Informational only -- no response required.
pub const ES_EVENT_TYPE_RESERVED_6: EsEventType = 154;

// ---------------------------------------------------------------------------
// Result codes
// ---------------------------------------------------------------------------

/// `es_new_client` succeeded.
pub const ES_NEW_CLIENT_RESULT_SUCCESS: u32 = 0;

/// General ES API success.
pub const ES_RETURN_SUCCESS: u32 = 0;

/// `es_respond_auth_result` succeeded.
pub const ES_RESPOND_RESULT_SUCCESS: u32 = 0;

// ---------------------------------------------------------------------------
// Auth results
// ---------------------------------------------------------------------------

/// Allow the authorized operation.
pub const ES_AUTH_RESULT_ALLOW: u32 = 0;

/// Deny the authorized operation.
pub const ES_AUTH_RESULT_DENY: u32 = 1;

// ---------------------------------------------------------------------------
// Audit token
// ---------------------------------------------------------------------------

/// macOS audit token (8 x u32).
///
/// Identifies a process for security purposes. Obtained from the ES
/// message's `process` field or from mach port messages.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuditToken {
    /// Raw token values. Use `audit_token_to_pid` / `audit_token_to_euid`
    /// from libbsm to extract fields.
    pub val: [u32; 8],
}

// ---------------------------------------------------------------------------
// Block ABI structures
// ---------------------------------------------------------------------------

/// Objective-C block literal for the ES handler callback.
///
/// Follows the Apple block ABI. We create a "global block" (no captures)
/// whose `invoke` function reads context from a `OnceLock` static.
///
/// # Layout
///
/// ```text
/// isa        -> &_NSConcreteGlobalBlock
/// flags      -> BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE (0x3000_0000)
/// reserved   -> 0
/// invoke     -> extern "C" fn(block, client, message)
/// descriptor -> &BlockDescriptor { reserved: 0, size: size_of::<BlockLiteral>() }
/// ```
#[repr(C)]
pub struct BlockLiteral {
    /// Pointer to the block class. For global blocks: `&_NSConcreteGlobalBlock`.
    pub isa: *const c_void,
    /// Block flags. `BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE` = `0x3000_0000`.
    pub flags: i32,
    /// Reserved field, must be zero.
    pub reserved: i32,
    /// The function to call when the block is invoked.
    pub invoke: unsafe extern "C" fn(*const BlockLiteral, EsClientPtr, EsMessagePtr),
    /// Pointer to the block descriptor.
    pub descriptor: *const BlockDescriptor,
}

// SAFETY: BlockLiteral is created with only static data (global block,
// no captures). The isa pointer and descriptor point to static/global
// memory. The invoke function pointer is a plain function.
unsafe impl Send for BlockLiteral {}
// SAFETY: Same rationale -- all fields are static/global.
unsafe impl Sync for BlockLiteral {}

/// Block descriptor for the Objective-C block ABI.
#[repr(C)]
pub struct BlockDescriptor {
    /// Reserved, must be zero.
    pub reserved: u64,
    /// Size of the `BlockLiteral` struct.
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Global block class
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// The Objective-C class object for global blocks.
    pub static _NSConcreteGlobalBlock: *const c_void;
}

// ---------------------------------------------------------------------------
// EndpointSecurity.framework
// ---------------------------------------------------------------------------

#[link(name = "EndpointSecurity")]
unsafe extern "C" {
    /// Create a new ES client with a block-based handler.
    pub fn es_new_client(client: *mut EsClientPtr, handler: *const BlockLiteral) -> u32;

    /// Destroy an ES client and release all resources.
    pub fn es_delete_client(client: EsClientPtr) -> u32;

    /// Subscribe to one or more ES event types.
    pub fn es_subscribe(client: EsClientPtr, events: *const EsEventType, event_count: u32) -> u32;

    /// Unsubscribe from all currently subscribed event types.
    pub fn es_unsubscribe_all(client: EsClientPtr) -> u32;

    /// Respond to an AUTH event with allow or deny.
    ///
    /// Must be called exactly once per AUTH message before the deadline.
    pub fn es_respond_auth_result(
        client: EsClientPtr,
        message: EsMessagePtr,
        result: u32,
        cache: bool,
    ) -> u32;

    /// Respond to a flags-result AUTH event.
    pub fn es_respond_flags_result(
        client: EsClientPtr,
        message: EsMessagePtr,
        flags: u32,
        cache: bool,
    ) -> u32;

    /// Retain an ES message for use after the handler returns.
    ///
    /// Must be paired with `es_release_message`.
    pub fn es_retain_message(message: EsMessagePtr);

    /// Release a previously retained ES message.
    pub fn es_release_message(message: EsMessagePtr);

    /// Clear the ES result cache for this client.
    pub fn es_clear_cache(client: EsClientPtr) -> u32;

    /// Mute a process so that events from it are not delivered.
    ///
    /// Used for self-exemption: mute macwarden's own process so we
    /// don't block ourselves.
    pub fn es_mute_process(client: EsClientPtr, audit_token: *const AuditToken) -> u32;
}

// ---------------------------------------------------------------------------
// libbsm audit token helpers
// ---------------------------------------------------------------------------

#[link(name = "bsm")]
unsafe extern "C" {
    /// Extract the PID from an audit token.
    pub fn audit_token_to_pid(token: AuditToken) -> i32;

    /// Extract the effective UID from an audit token.
    pub fn audit_token_to_euid(token: AuditToken) -> u32;
}

#[cfg(test)]
#[path = "ffi_test.rs"]
mod ffi_test;
