//! R2 Layer 2 — audit-token code-signature peer verification (macOS only).
//!
//! **All FFI and `unsafe` for the IPC crate's Layer 2 check lives in this
//! module.** It is `cfg(target_os = "macos")` and links Security.framework and
//! CoreFoundation only here, so the rest of the `ipc` crate stays pure Rust
//! (serde + `cfg(unix)` `libc`) and compiles Security-free on Linux.
//!
//! # Sequence (validated PoC)
//!
//! `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN)` → `audit_token_t` (32 bytes) →
//! `CFDataCreate` → `CFDictionaryCreate({ kSecGuestAttributeAudit: data })` →
//! `SecCodeCopyGuestWithAttributes(NULL, dict, 0, &code)` →
//! `SecRequirementCreateWithString(req_str, 0, &req)` →
//! `SecCodeCheckValidity(code, 0, req)`. `OSStatus == 0` accepts; any non-zero
//! denies (`-67050` `errSecCSReqFailed` is the legitimate identity mismatch).
//!
//! Keyed on the peer's **audit token**, never the pid — the pid form is racy
//! under pid reuse; the token carries a `pidversion` that closes that race.
//!
//! # Memory discipline
//!
//! Every Core Foundation object produced with a `Create`/`Copy` call is owned by
//! a [`CfGuard`] whose `Drop` calls `CFRelease` exactly once, so every early
//! return and error path is leak-free.

#![cfg(target_os = "macos")]
#![allow(unsafe_code)]

use std::borrow::Cow;
use std::os::fd::RawFd;
use std::os::raw::{c_char, c_int, c_void};

use tracing::{debug, warn};

use super::{AuthError, PeerVerifier, peer_uid};

// ---------------------------------------------------------------------------
// Constants (validated against the macOS SDK by the security PoC)
// ---------------------------------------------------------------------------

/// `SOL_LOCAL` socket option level (`sys/un.h`).
const SOL_LOCAL: c_int = 0;
/// `LOCAL_PEERTOKEN` socket option name (`sys/un.h`).
const LOCAL_PEERTOKEN: c_int = 0x006;
/// `kSecCSDefaultFlags` (`CSCommon.h`).
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
/// `kCFStringEncodingUTF8`.
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// `errSecSuccess`.
const ERR_SEC_SUCCESS: OSStatus = 0;
/// `errSecCSReqFailed` — the peer is validly signed but does not satisfy the
/// requirement (the legitimate identity-mismatch reject).
const ERR_SEC_CS_REQ_FAILED: OSStatus = -67050;
/// `errSecCSUnsigned` — the peer binary carries no signature at all.
const ERR_SEC_CS_UNSIGNED: OSStatus = -67062;

/// macOS Security-framework status code.
pub type OSStatus = i32;

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDataRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFIndex = isize;
type SecCodeRef = *mut c_void;
type SecRequirementRef = *mut c_void;

/// `audit_token_t` (`mach/message.h`): `struct { unsigned int val[8]; }` — 32
/// bytes, carrying the peer's pid, pidversion, uid, gid, and audit ids.
#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    val: [u32; 8],
}

/// The panel's designated requirement (R2 Layer 2). The connecting binary must
/// satisfy this to drive the daemon's query/mutation surface.
///
/// TODO(signing): the real Apple Team ID lands with the signing/notarization
/// pipeline — append `and certificate leaf[subject.OU] = "<TEAMID>"` here. Until
/// the panel is signed, dev builds connect via the
/// `MACWARDEN_ALLOW_UNSIGNED_PEER` opt-in (see [`CodesignVerifier`]); production
/// MUST NOT set that variable.
pub const MACWARDEN_PANEL_REQUIREMENT: &str =
    "anchor apple generic and identifier \"ai.macwarden.panel\"";

// ---------------------------------------------------------------------------
// FFI — Security.framework + CoreFoundation. Linked only on macOS.
// ---------------------------------------------------------------------------

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Dictionary key selecting the audit-token guest-lookup path.
    static kSecGuestAttributeAudit: CFStringRef;
    /// Resolve a `SecCode` guest by attributes (audit token → code ref).
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    /// Compile a designated-requirement string into a `SecRequirement`.
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> OSStatus;
    /// Check a live `SecCode` against a requirement.
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> OSStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Retaining key-callbacks vtable for `CFDictionaryCreate`.
    static kCFTypeDictionaryKeyCallBacks: c_void;
    /// Retaining value-callbacks vtable for `CFDictionaryCreate`.
    static kCFTypeDictionaryValueCallBacks: c_void;
    /// Release one reference to a Core Foundation object.
    fn CFRelease(cf: CFTypeRef);
    /// Copy `length` bytes into a new `CFData`.
    fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    /// Create an immutable `CFDictionary` from parallel key/value arrays.
    fn CFDictionaryCreate(
        alloc: CFAllocatorRef,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: CFIndex,
        key_cb: *const c_void,
        val_cb: *const c_void,
    ) -> CFDictionaryRef;
    /// Create a `CFString` from a NUL-terminated C string.
    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
}

// ---------------------------------------------------------------------------
// RAII: release every CF object exactly once, on every path.
// ---------------------------------------------------------------------------

/// Owns one `+1` Core Foundation reference and releases it on drop, so early
/// returns and error paths never leak. Construct via [`CfGuard::owned`], which
/// rejects the null pointer a failed `Create`/`Copy` returns.
struct CfGuard(CFTypeRef);

impl CfGuard {
    /// Take ownership of a `+1` CF reference. Returns `None` for null (a failed
    /// allocation) so the caller can map it to a typed error.
    fn owned(ptr: CFTypeRef) -> Option<Self> {
        if ptr.is_null() { None } else { Some(Self(ptr)) }
    }

    /// The wrapped reference (borrowed; the guard retains ownership).
    fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for CfGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null CF object this guard owns a +1 ref to
        // (enforced by `owned`); it is released exactly once, here.
        unsafe { CFRelease(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Typed errors — fail closed on every non-success path.
// ---------------------------------------------------------------------------

/// A Layer 2 verification failure. Every variant denies; the `OSStatus`-carrying
/// variants are for the daemon's logs only and never reach the peer (the wire
/// boundary collapses all of them to `Unauthorized`).
#[derive(Debug, thiserror::Error)]
pub enum PeerTokenError {
    /// `getsockopt(LOCAL_PEERTOKEN)` failed or returned an unexpected length.
    #[error("peer audit token unavailable (getsockopt LOCAL_PEERTOKEN failed)")]
    PeerTokenUnavailable,
    /// `SecCodeCopyGuestWithAttributes` (or its CF inputs) failed.
    #[error("guest code lookup failed (OSStatus {0})")]
    GuestLookupFailed(OSStatus),
    /// The requirement string did not compile.
    #[error("designated requirement failed to compile (OSStatus {0})")]
    RequirementCompile(OSStatus),
    /// `SecCodeCheckValidity` rejected the peer (`-67050` = identity mismatch).
    #[error("code-signature check failed (OSStatus {0})")]
    CheckFailed(OSStatus),
    /// The peer binary carries no code signature.
    #[error("peer binary is unsigned")]
    Unsigned,
}

// ---------------------------------------------------------------------------
// The primitive: audit token → SecCode → requirement check.
// ---------------------------------------------------------------------------

/// Read the peer's audit token from a connected socket fd.
fn peer_audit_token(fd: RawFd) -> Result<AuditToken, PeerTokenError> {
    let mut token = AuditToken { val: [0u32; 8] };
    let mut len = std::mem::size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: `fd` is a connected socket; `token`/`len` are exclusively-owned
    // out-params of the correct type and size (32 bytes) that getsockopt fills.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            std::ptr::from_mut(&mut token).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<AuditToken>() {
        return Err(PeerTokenError::PeerTokenUnavailable);
    }
    Ok(token)
}

/// Wrap the audit token as a `SecCode` via `SecCodeCopyGuestWithAttributes`.
fn code_ref_from_token(token: &AuditToken) -> Result<CfGuard, PeerTokenError> {
    let bytes = std::ptr::from_ref(token).cast::<u8>();
    let size = std::mem::size_of::<AuditToken>() as CFIndex;
    // SAFETY: `bytes` points to the 32-byte token; CFDataCreate copies it.
    let data = unsafe { CFDataCreate(std::ptr::null(), bytes, size) };
    let data = CfGuard::owned(data).ok_or(PeerTokenError::GuestLookupFailed(0))?;
    // SAFETY: framework-provided immutable global CFString key.
    let audit_key = unsafe { kSecGuestAttributeAudit };
    // Address-of only (never dereferenced): the framework's immutable callback
    // vtables. Taking the address of an extern static is safe.
    let key_cb = &raw const kCFTypeDictionaryKeyCallBacks;
    let val_cb = &raw const kCFTypeDictionaryValueCallBacks;
    let keys: [*const c_void; 1] = [audit_key];
    let values: [*const c_void; 1] = [data.as_ptr()];
    // SAFETY: 1-length parallel key/value arrays with the CF-type callback
    // vtables; the dictionary retains `data`, so `data` may drop after this.
    let dict = unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            key_cb,
            val_cb,
        )
    };
    let dict = CfGuard::owned(dict).ok_or(PeerTokenError::GuestLookupFailed(0))?;
    guest_code(&dict)
}

/// `SecCodeCopyGuestWithAttributes(NULL, dict, …)` → the peer's `SecCode`.
fn guest_code(dict: &CfGuard) -> Result<CfGuard, PeerTokenError> {
    let mut code: SecCodeRef = std::ptr::null_mut();
    // SAFETY: `dict` is a valid CFDictionary; `code` is an out-param.
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            std::ptr::null_mut(),
            dict.as_ptr(),
            K_SEC_CS_DEFAULT_FLAGS,
            &raw mut code,
        )
    };
    if status != ERR_SEC_SUCCESS || code.is_null() {
        return Err(PeerTokenError::GuestLookupFailed(status));
    }
    CfGuard::owned(code.cast_const()).ok_or(PeerTokenError::GuestLookupFailed(status))
}

/// Compile a designated-requirement string into a `SecRequirement`.
fn requirement_from_string(text: &str) -> Result<CfGuard, PeerTokenError> {
    let c = std::ffi::CString::new(text).map_err(|_| PeerTokenError::RequirementCompile(0))?;
    // SAFETY: `c` is a valid NUL-terminated C string; default allocator; UTF-8.
    let cf = unsafe {
        CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), K_CF_STRING_ENCODING_UTF8)
    };
    let cf = CfGuard::owned(cf).ok_or(PeerTokenError::RequirementCompile(0))?;
    let mut req: SecRequirementRef = std::ptr::null_mut();
    // SAFETY: `cf` is a valid CFString; `req` is an out-param. The requirement
    // copies the string, so `cf` may drop after this.
    let status = unsafe {
        SecRequirementCreateWithString(cf.as_ptr(), K_SEC_CS_DEFAULT_FLAGS, &raw mut req)
    };
    if status != ERR_SEC_SUCCESS || req.is_null() {
        return Err(PeerTokenError::RequirementCompile(status));
    }
    CfGuard::owned(req.cast_const()).ok_or(PeerTokenError::RequirementCompile(status))
}

/// `SecCodeCheckValidity` — map its `OSStatus` to a fail-closed verdict.
fn check_validity(code: &CfGuard, req: &CfGuard) -> Result<(), PeerTokenError> {
    // SAFETY: `code` and `req` are valid Sec objects owned by their guards.
    let status = unsafe {
        SecCodeCheckValidity(
            code.as_ptr().cast_mut(),
            K_SEC_CS_DEFAULT_FLAGS,
            req.as_ptr(),
        )
    };
    match status {
        ERR_SEC_SUCCESS => Ok(()),
        ERR_SEC_CS_UNSIGNED => Err(PeerTokenError::Unsigned),
        other => Err(PeerTokenError::CheckFailed(other)),
    }
}

/// Verify the peer on `fd` against `requirement`. Any failure denies.
fn verify_peer_codesign(fd: RawFd, requirement: &str) -> Result<(), PeerTokenError> {
    let token = peer_audit_token(fd)?;
    let code = code_ref_from_token(&token)?;
    let req = requirement_from_string(requirement)?;
    check_validity(&code, &req)
}

// ---------------------------------------------------------------------------
// Public verifier: uid pre-gate (Layer 1) then code-signature (Layer 2).
// ---------------------------------------------------------------------------

/// The macOS daemon's peer verifier: the R2 Layer 1 uid pre-gate followed by the
/// Layer 2 audit-token code-signature check against [`MACWARDEN_PANEL_REQUIREMENT`]
/// (or a config override). Fails closed — any token, guest-lookup, compile, or
/// check failure denies; nothing but `Unauthorized` reaches the peer.
///
/// # Unsigned-dev opt-in
///
/// Setting `MACWARDEN_ALLOW_UNSIGNED_PEER=1` skips Layer 2 (the uid gate still
/// runs) and logs the skip at `warn`. This exists only because the panel is not
/// yet signed/notarized; **production must not set it**. Default is off.
pub struct CodesignVerifier {
    expected_uid: u32,
    requirement: Cow<'static, str>,
    allow_unsigned: bool,
}

impl CodesignVerifier {
    /// Verify against the built-in [`MACWARDEN_PANEL_REQUIREMENT`]. Reads the
    /// unsigned-dev opt-in from the environment.
    #[must_use]
    pub fn new(expected_uid: u32) -> Self {
        Self::build(
            expected_uid,
            Cow::Borrowed(MACWARDEN_PANEL_REQUIREMENT),
            unsigned_opt_in(),
        )
    }

    /// Verify against a caller-supplied requirement (dev builds signed with a
    /// different identity). Reads the unsigned-dev opt-in from the environment.
    #[must_use]
    pub fn with_requirement(expected_uid: u32, requirement: impl Into<Cow<'static, str>>) -> Self {
        Self::build(expected_uid, requirement.into(), unsigned_opt_in())
    }

    fn build(expected_uid: u32, requirement: Cow<'static, str>, allow_unsigned: bool) -> Self {
        Self {
            expected_uid,
            requirement,
            allow_unsigned,
        }
    }
}

/// Whether `MACWARDEN_ALLOW_UNSIGNED_PEER=1` is set (dev opt-in; default off).
fn unsigned_opt_in() -> bool {
    std::env::var_os("MACWARDEN_ALLOW_UNSIGNED_PEER").is_some_and(|v| v == "1")
}

impl PeerVerifier for CodesignVerifier {
    fn verify(&self, fd: RawFd) -> Result<(), AuthError> {
        // Layer 1: uid pre-gate (reuse the shared helper).
        let (uid, _gid) = peer_uid(fd)?;
        if uid != self.expected_uid {
            return Err(AuthError::UidMismatch {
                expected: self.expected_uid,
                actual: uid,
            });
        }
        if self.allow_unsigned {
            warn!(
                "MACWARDEN_ALLOW_UNSIGNED_PEER set: skipping R2 Layer 2 \
                 code-signature check (DEV ONLY — must be unset in production)"
            );
            return Ok(());
        }
        // Layer 2: audit-token code-signature check. Fail closed.
        match verify_peer_codesign(fd, &self.requirement) {
            Ok(()) => Ok(()),
            Err(e @ PeerTokenError::CheckFailed(ERR_SEC_CS_REQ_FAILED)) => {
                debug!(error = %e, "peer rejected: did not satisfy panel designated requirement");
                Err(AuthError::CodeSignature)
            }
            Err(e) => {
                warn!(error = %e, "peer rejected: code-signature verification failed");
                Err(AuthError::CodeSignature)
            }
        }
    }
}

#[cfg(test)]
#[path = "codesign_test.rs"]
mod codesign_test;
