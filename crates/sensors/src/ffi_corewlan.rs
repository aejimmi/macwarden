//! Raw FFI bindings for Objective-C runtime and CoreWLAN.
//!
//! **All CoreWLAN unsafe code in the sensors crate lives in this module.**
//!
//! This module is `pub(crate)` -- it is never exposed outside the crate.
//! The safe wrapper in `wifi.rs` calls these functions with validated inputs
//! and handles all error cases.
//!
//! # Security invariants
//!
//! - Every `extern "C"` function here is `unsafe` by definition (FFI).
//! - Callers must ensure:
//!   - All pointer arguments are valid and correctly aligned.
//!   - ObjC selectors match the expected method signatures.
//!   - Returned ObjC objects are not used after being released.
//! - NSString results are converted via the existing `cfstring_to_string_and_release`
//!   helper in `ffi.rs` (NSString is toll-free bridged with CFString).
//! - No ObjC objects escape the FFI boundary -- all data is copied into Rust types.

use std::os::raw::{c_char, c_void};

use crate::ffi::CFStringRef;

// ---------------------------------------------------------------------------
// Objective-C runtime types
// ---------------------------------------------------------------------------

/// Opaque pointer to an Objective-C class.
pub type ObjcClass = *const c_void;

/// Opaque pointer to an Objective-C selector.
pub type ObjcSel = *const c_void;

/// Opaque pointer to an Objective-C object instance.
pub type ObjcId = *mut c_void;

// ---------------------------------------------------------------------------
// Objective-C runtime extern functions
// ---------------------------------------------------------------------------

#[link(name = "objc", kind = "dylib")]
unsafe extern "C" {
    /// Look up an Objective-C class by name.
    ///
    /// Returns null if the class is not loaded (e.g., framework not linked).
    pub fn objc_getClass(name: *const c_char) -> ObjcClass;

    /// Register (or look up) a selector by name.
    ///
    /// Always succeeds -- creates the selector if it doesn't exist.
    pub fn sel_registerName(name: *const c_char) -> ObjcSel;

    /// Send a message to an Objective-C object.
    ///
    /// This is the core ObjC dispatch primitive. The actual return type and
    /// argument types depend on the selector being called. Callers must cast
    /// this function pointer to the correct signature before calling.
    pub fn objc_msgSend(receiver: ObjcId, selector: ObjcSel, ...) -> ObjcId;
}

// ---------------------------------------------------------------------------
// CoreWLAN framework link
// ---------------------------------------------------------------------------

// Linking CoreWLAN ensures the CWWiFiClient class is available at runtime.
// We don't declare extern functions from CoreWLAN directly -- all interaction
// goes through the ObjC runtime (`objc_msgSend`).
#[link(name = "CoreWLAN", kind = "framework")]
unsafe extern "C" {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a zero-argument ObjC message that returns an object pointer.
///
/// Equivalent to `[receiver selectorName]` in Objective-C.
///
/// Returns `None` if the result is null.
///
/// # Safety
///
/// - `receiver` must be a valid ObjC object or class pointer.
/// - `sel` must be a valid selector for a method that takes no arguments
///   and returns an object pointer (or nil).
pub(crate) unsafe fn msg_send_id(receiver: ObjcId, sel: ObjcSel) -> Option<ObjcId> {
    // SAFETY: Caller guarantees receiver and selector validity.
    // objc_msgSend with zero extra args and id return type.
    let result = unsafe { objc_msgSend(receiver, sel) };
    if result.is_null() { None } else { Some(result) }
}

/// Get the SSID string from a `CWInterface` object.
///
/// Calls `[interface ssid]` which returns an `NSString*` (or nil).
/// Converts the NSString to a Rust `String` via CFString toll-free bridging.
/// The NSString is NOT released here -- `sharedWiFiClient` objects manage
/// their own memory, and the returned NSString is autoreleased.
///
/// # Safety
///
/// - `interface` must be a valid `CWInterface*` object.
pub(crate) unsafe fn cw_interface_ssid(interface: ObjcId) -> Option<String> {
    // SAFETY: "ssid" is a valid selector on CWInterface.
    let sel = unsafe { sel_registerName(c"ssid".as_ptr()) };
    // SAFETY: interface is valid, ssid returns NSString* or nil.
    let ns_string = unsafe { objc_msgSend(interface, sel) };
    if ns_string.is_null() {
        return None;
    }

    // NSString is toll-free bridged with CFString.
    // We must NOT release this -- it's owned by the CWInterface.
    // Use CFStringGetCString to copy the contents without taking ownership.
    let cf_string: CFStringRef = ns_string.cast::<c_void>();
    cfstring_copy_to_string(cf_string)
}

/// Copy a CFString's contents into a Rust `String` WITHOUT releasing it.
///
/// Unlike `cfstring_to_string_and_release` in `ffi.rs`, this does NOT call
/// `CFRelease`. Use this when the CFString is owned by another object
/// (e.g., an autoreleased NSString from an ObjC method return).
fn cfstring_copy_to_string(cf_string: CFStringRef) -> Option<String> {
    if cf_string.is_null() {
        return None;
    }
    let mut buf = [0i8; 256];
    // SAFETY: `cf_string` is a valid CFString (caller guarantees).
    // `buf` is a 256-byte stack buffer. `CFStringGetCString` writes a
    // null-terminated C string and returns nonzero on success.
    let ok = unsafe {
        crate::ffi::CFStringGetCString(
            cf_string,
            buf.as_mut_ptr(),
            buf.len() as i64,
            crate::ffi::K_CF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: `CFStringGetCString` wrote a null-terminated string on success.
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(String::from)
}

#[cfg(test)]
mod ffi_corewlan_test {
    use super::*;

    #[test]
    fn test_objc_get_class_returns_non_null_for_known_class() {
        // NSObject is always available in the ObjC runtime.
        // SAFETY: c"NSObject" is a valid null-terminated class name.
        let cls = unsafe { objc_getClass(c"NSObject".as_ptr()) };
        assert!(!cls.is_null(), "NSObject class should exist");
    }

    #[test]
    fn test_objc_get_class_returns_null_for_unknown() {
        // SAFETY: Valid null-terminated string for a nonexistent class.
        let cls = unsafe { objc_getClass(c"MacWardenFakeClass12345".as_ptr()) };
        assert!(cls.is_null(), "nonexistent class should return null");
    }

    #[test]
    fn test_sel_register_name_returns_non_null() {
        // SAFETY: Valid null-terminated selector name.
        let sel = unsafe { sel_registerName(c"init".as_ptr()) };
        assert!(!sel.is_null(), "selector should always be created");
    }

    #[test]
    fn test_cfstring_copy_to_string_null() {
        let result = cfstring_copy_to_string(std::ptr::null());
        assert!(result.is_none());
    }
}
