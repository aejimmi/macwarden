//! macOS-gated integration tests for R2 Layer 2 (audit-token code-signature
//! verification). Mirrors the validated PoC: a real `UnixListener`/`UnixStream`
//! pair, verify the connecting binary against its OWN designated requirement
//! (accept) and against a deliberately-wrong requirement (reject), plus the
//! `MACWARDEN_ALLOW_UNSIGNED_PEER` dev opt-in. Never compiled or run on Linux.

#![allow(clippy::panic, unsafe_code)]

use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_char;
use std::os::unix::net::{UnixListener, UnixStream};

use super::*;

// --- test-only FFI: read the peer's own designated requirement as a string ---

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopyDesignatedRequirement(
        code: SecCodeRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> OSStatus;
    fn SecRequirementCopyString(
        requirement: SecRequirementRef,
        flags: u32,
        text: *mut CFStringRef,
    ) -> OSStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringGetCStringPtr(s: CFStringRef, encoding: u32) -> *const c_char;
    fn CFStringGetLength(s: CFStringRef) -> CFIndex;
    fn CFStringGetCString(s: CFStringRef, buf: *mut c_char, size: CFIndex, encoding: u32) -> bool;
}

/// Copy a `CFString` into an owned Rust `String` (test helper).
fn cfstring_to_string(s: &CfGuard) -> String {
    // SAFETY: `s` wraps a valid CFString; the fast path borrows its buffer.
    let fast = unsafe { CFStringGetCStringPtr(s.as_ptr(), K_CF_STRING_ENCODING_UTF8) };
    if !fast.is_null() {
        // SAFETY: `fast` is a NUL-terminated C string owned by the CFString.
        let cstr = unsafe { std::ffi::CStr::from_ptr(fast) };
        return cstr.to_string_lossy().into_owned();
    }
    // SAFETY: `s` wraps a valid CFString.
    let len = unsafe { CFStringGetLength(s.as_ptr()) };
    let cap = (len * 4 + 1).max(1) as usize;
    let mut buf = vec![0_i8; cap];
    // SAFETY: `buf` holds `cap` bytes; the encoding is valid; `s` is valid.
    let ok = unsafe {
        CFStringGetCString(
            s.as_ptr(),
            buf.as_mut_ptr(),
            cap as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
        )
    };
    if !ok {
        return String::from("<unprintable>");
    }
    // SAFETY: `CFStringGetCString` wrote a NUL-terminated C string into `buf`.
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_string_lossy().into_owned()
}

/// The connecting peer's own designated requirement, as a requirement string.
fn peer_designated_requirement(fd: RawFd) -> Result<String, PeerTokenError> {
    let token = peer_audit_token(fd)?;
    let code = code_ref_from_token(&token)?;
    let mut req: SecRequirementRef = std::ptr::null_mut();
    // SAFETY: `code` is a valid SecCode; `req` is an out-param.
    let status = unsafe {
        SecCodeCopyDesignatedRequirement(
            code.as_ptr().cast_mut(),
            K_SEC_CS_DEFAULT_FLAGS,
            &raw mut req,
        )
    };
    if status != ERR_SEC_SUCCESS || req.is_null() {
        return Err(PeerTokenError::RequirementCompile(status));
    }
    let req = CfGuard::owned(req.cast_const()).ok_or(PeerTokenError::RequirementCompile(status))?;
    let mut text: CFStringRef = std::ptr::null();
    // SAFETY: `req` is a valid SecRequirement; `text` is an out-param.
    let s2 = unsafe {
        SecRequirementCopyString(
            req.as_ptr().cast_mut(),
            K_SEC_CS_DEFAULT_FLAGS,
            &raw mut text,
        )
    };
    if s2 != ERR_SEC_SUCCESS || text.is_null() {
        return Err(PeerTokenError::RequirementCompile(s2));
    }
    let text = CfGuard::owned(text).ok_or(PeerTokenError::RequirementCompile(s2))?;
    Ok(cfstring_to_string(&text))
}

/// A real accepted socket pair; the returned `TempDir` keeps the path alive.
fn accepted_pair() -> (UnixStream, UnixStream, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("codesign.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let client = UnixStream::connect(&path).expect("connect");
    let (server, _addr) = listener.accept().expect("accept");
    (server, client, dir)
}

#[test]
fn test_codesign_accepts_peer_own_designated_requirement() {
    let (server, _client, _dir) = accepted_pair();
    let fd = server.as_raw_fd();
    let dr = peer_designated_requirement(fd).expect("peer designated requirement");
    // The test binary trivially satisfies its own DR.
    verify_peer_codesign(fd, &dr).expect("peer must satisfy its own designated requirement");
}

#[test]
fn test_codesign_rejects_wrong_requirement() {
    let (server, _client, _dir) = accepted_pair();
    let fd = server.as_raw_fd();
    // A requirement the ad-hoc test binary cannot satisfy → errSecCSReqFailed.
    let wrong = "anchor apple generic and identifier \"ai.macwarden.panel.NONEXISTENT\"";
    match verify_peer_codesign(fd, wrong) {
        Err(PeerTokenError::CheckFailed(ERR_SEC_CS_REQ_FAILED)) => {}
        other => panic!("expected CheckFailed(errSecCSReqFailed), got {other:?}"),
    }
}

#[test]
fn test_codesign_verifier_rejects_and_opt_in_skips() {
    let (server, _client, _dir) = accepted_pair();
    let fd = server.as_raw_fd();
    let (uid, _gid) = peer_uid(fd).expect("peer_uid");

    // Sole toucher of MACWARDEN_ALLOW_UNSIGNED_PEER, so no other test races it.
    // Default (unset): the ad-hoc peer fails the panel requirement → Unauthorized.
    // SAFETY: single-threaded env access within this test; no concurrent reader.
    unsafe { std::env::remove_var("MACWARDEN_ALLOW_UNSIGNED_PEER") };
    let rejecting = CodesignVerifier::new(uid);
    assert!(
        matches!(rejecting.verify(fd), Err(AuthError::CodeSignature)),
        "default-off must reject the unsigned/mismatched peer"
    );

    // Opt-in ON: Layer 2 is skipped (uid gate still ran) → admitted.
    // SAFETY: single-threaded env access within this test; no concurrent reader.
    unsafe { std::env::set_var("MACWARDEN_ALLOW_UNSIGNED_PEER", "1") };
    let allowing = CodesignVerifier::new(uid);
    assert!(
        allowing.verify(fd).is_ok(),
        "opt-in must skip Layer 2 and admit"
    );

    // Uid gate still runs under the opt-in: a mismatched uid is rejected.
    let wrong_uid = CodesignVerifier::new(uid.wrapping_add(1));
    assert!(matches!(
        wrong_uid.verify(fd),
        Err(AuthError::UidMismatch { .. })
    ));

    // SAFETY: single-threaded env access within this test; no concurrent reader.
    unsafe { std::env::remove_var("MACWARDEN_ALLOW_UNSIGNED_PEER") };
}
