//! The C ABI the Swift `NEFilterDataProvider` system extension links against.
//!
//! Every function is panic-safe: a caught panic maps to a fail-open result
//! (ALLOW for decisions, null/false for lifecycle) so a bug in the decision
//! path can never wedge the user's network. See `include/macwarden_ne.h` for
//! the hand-written header the sysext includes.

use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use crate::decision::NeDecision;
use crate::handle::{MacwardenNe, default_base_dir};

/// Run `f`, returning `default` if it panics (fail-open at the boundary).
fn guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        tracing::error!("panic caught at FFI boundary; failing open");
        default
    })
}

/// Borrow a C string as `&str`, treating null/invalid UTF-8 as `None`.
///
/// # Safety
///
/// `ptr` must be null or a valid, NUL-terminated C string valid for the call.
unsafe fn cstr_opt<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` is non-null here and the caller guarantees it is a valid,
    // NUL-terminated C string valid for the duration of the borrow.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Initialize the decision core from the default `~/.macwarden/` directory
/// (or `MACWARDEN_HOME`). Returns an owned handle, or null on failure.
///
/// The caller owns the returned pointer and must release it with
/// [`macwarden_ne_free`].
#[unsafe(no_mangle)]
pub extern "C" fn macwarden_ne_init() -> *mut MacwardenNe {
    guard(ptr::null_mut(), || match default_base_dir() {
        Ok(dir) => init_from(dir),
        Err(e) => {
            tracing::error!(error = %e, "macwarden_ne_init: no base dir");
            ptr::null_mut()
        }
    })
}

/// Initialize from an explicit base directory (chiefly for tests). Returns an
/// owned handle, or null on failure.
///
/// # Safety
///
/// `dir` must be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn macwarden_ne_init_at(dir: *const c_char) -> *mut MacwardenNe {
    guard(ptr::null_mut(), || {
        // SAFETY: `dir` is null or a valid NUL-terminated C string per contract.
        let Some(dir) = (unsafe { cstr_opt(dir) }) else {
            tracing::error!("macwarden_ne_init_at: null/invalid dir");
            return ptr::null_mut();
        };
        init_from(dir.into())
    })
}

/// Load a handle from a resolved base directory.
fn init_from(dir: std::path::PathBuf) -> *mut MacwardenNe {
    match MacwardenNe::load(dir) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(e) => {
            tracing::error!(error = %e, "macwarden_ne_init: load failed");
            ptr::null_mut()
        }
    }
}

/// Decide a flow. Returns 0 = ALLOW, 1 = DENY, 2 = LOG.
///
/// A null handle, null strings, or any internal panic all fail open to ALLOW.
/// `proto` is an IANA number (6 = TCP, 17 = UDP); `port == 0` means unknown.
///
/// # Safety
///
/// `handle` must be null or a pointer returned by `macwarden_ne_init*` and not
/// yet freed. Each string must be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn macwarden_ne_decide(
    handle: *const MacwardenNe,
    code_id: *const c_char,
    path: *const c_char,
    host: *const c_char,
    ip: *const c_char,
    port: u16,
    proto: u8,
) -> i32 {
    guard(NeDecision::Allow as i32, || {
        // SAFETY: `handle` is null or a live handle from `macwarden_ne_init*`.
        let Some(ne) = (unsafe { handle.as_ref() }) else {
            return NeDecision::Allow as i32;
        };
        // SAFETY: each pointer is null or a valid NUL-terminated C string.
        let code_id = unsafe { cstr_opt(code_id) };
        // SAFETY: as above.
        let path = unsafe { cstr_opt(path) };
        // SAFETY: as above.
        let host = unsafe { cstr_opt(host) };
        // SAFETY: as above.
        let ip = unsafe { cstr_opt(ip) };
        ne.decide(code_id, path, host, ip, port, proto) as i32
    })
}

/// Rebuild the embedded rule set from disk. Returns true on success.
///
/// On failure (including a panic) the previous rule set is retained and this
/// returns false.
///
/// # Safety
///
/// `handle` must be null or a live handle from `macwarden_ne_init*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn macwarden_ne_reload(handle: *const MacwardenNe) -> bool {
    guard(false, || {
        // SAFETY: `handle` is null or a live handle from `macwarden_ne_init*`.
        let Some(ne) = (unsafe { handle.as_ref() }) else {
            return false;
        };
        match ne.reload() {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(error = %e, "macwarden_ne_reload: keeping previous ruleset");
                false
            }
        }
    })
}

/// Release a handle created by `macwarden_ne_init*`. Null is a no-op.
///
/// # Safety
///
/// `handle` must be null or a live handle from `macwarden_ne_init*`, freed at
/// most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn macwarden_ne_free(handle: *mut MacwardenNe) {
    if handle.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: non-null here; the caller guarantees it came from
        // `macwarden_ne_init*` and is freed at most once.
        drop(unsafe { Box::from_raw(handle) });
    });
}

#[cfg(test)]
#[path = "ffi_test.rs"]
mod ffi_test;
