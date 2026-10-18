use super::*;

use std::ffi::CString;
use std::path::Path;
use std::ptr;

use crate::decision::NeDecision;

const DENY: i32 = NeDecision::Deny as i32;
const ALLOW: i32 = NeDecision::Allow as i32;
const LOG: i32 = NeDecision::Log as i32;

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

fn write_rule(base: &Path, content: &str) {
    let rules = base.join("net-rules");
    std::fs::create_dir_all(&rules).expect("mkdir net-rules");
    std::fs::write(rules.join("rule.toml"), content).expect("write rule");
}

#[test]
#[allow(clippy::panic)]
fn test_guard_catches_panic_and_returns_default() {
    let value = guard(ALLOW, || panic!("boom"));
    assert_eq!(value, ALLOW, "a panic must fail open to the default");
}

#[test]
fn test_guard_passes_through_ok() {
    let value = guard(ALLOW, || DENY);
    assert_eq!(value, DENY);
}

#[test]
fn test_decide_null_handle_fails_open_to_allow() {
    // SAFETY: null handle and null strings are handled gracefully.
    let out = unsafe {
        macwarden_ne_decide(
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            0,
        )
    };
    assert_eq!(out, ALLOW);
}

#[test]
fn test_init_decide_free_roundtrip_denies_rule() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        dir.path(),
        "name = \"block\"\nprocess = \"/usr/bin/curl\"\ndest = \"tracker.example.com\"\naction = \"deny\"\n",
    );

    let path = cstr(dir.path().to_str().expect("utf8 path"));
    // SAFETY: valid NUL-terminated dir path.
    let handle = unsafe { macwarden_ne_init_at(path.as_ptr()) };
    assert!(!handle.is_null(), "init_at should succeed for a real dir");

    let curl = cstr("/usr/bin/curl");
    let host = cstr("tracker.example.com");
    // SAFETY: live handle, valid strings, nulls where unknown.
    let denied = unsafe {
        macwarden_ne_decide(
            handle,
            ptr::null(),
            curl.as_ptr(),
            host.as_ptr(),
            ptr::null(),
            443,
            6,
        )
    };
    assert_eq!(denied, DENY);

    // A different process to the same host is allow-all (Log).
    let other = cstr("/usr/bin/other");
    // SAFETY: live handle, valid strings.
    let logged = unsafe {
        macwarden_ne_decide(
            handle,
            ptr::null(),
            other.as_ptr(),
            host.as_ptr(),
            ptr::null(),
            443,
            6,
        )
    };
    assert_eq!(logged, LOG);

    // SAFETY: handle freed exactly once.
    unsafe { macwarden_ne_free(handle) };
}

#[test]
fn test_reload_via_ffi_picks_up_new_rule() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = cstr(dir.path().to_str().expect("utf8 path"));
    // SAFETY: valid dir path.
    let handle = unsafe { macwarden_ne_init_at(path.as_ptr()) };
    assert!(!handle.is_null());

    let curl = cstr("/usr/bin/curl");
    let host = cstr("tracker.example.com");

    // SAFETY: live handle.
    let before = unsafe {
        macwarden_ne_decide(
            handle,
            ptr::null(),
            curl.as_ptr(),
            host.as_ptr(),
            ptr::null(),
            443,
            6,
        )
    };
    assert_eq!(before, LOG);

    write_rule(
        dir.path(),
        "name = \"block\"\nprocess = \"/usr/bin/curl\"\ndest = \"tracker.example.com\"\naction = \"deny\"\n",
    );
    // SAFETY: live handle.
    let reloaded = unsafe { macwarden_ne_reload(handle) };
    assert!(reloaded, "reload should succeed");

    // SAFETY: live handle.
    let after = unsafe {
        macwarden_ne_decide(
            handle,
            ptr::null(),
            curl.as_ptr(),
            host.as_ptr(),
            ptr::null(),
            443,
            6,
        )
    };
    assert_eq!(after, DENY);

    // SAFETY: freed once.
    unsafe { macwarden_ne_free(handle) };
}

#[test]
fn test_reload_null_handle_is_false() {
    // SAFETY: null handle handled gracefully.
    let ok = unsafe { macwarden_ne_reload(ptr::null()) };
    assert!(!ok);
}

#[test]
fn test_free_null_is_noop() {
    // SAFETY: null free is a documented no-op.
    unsafe { macwarden_ne_free(ptr::null_mut()) };
}
