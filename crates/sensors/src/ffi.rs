//! Raw FFI bindings for CoreAudio and CoreFoundation.
//!
//! **All CoreAudio unsafe code in the sensors crate lives in this module.**
//!
//! This module is `pub(crate)` — it is never exposed outside the crate.
//! Safe wrappers in `microphone.rs` and `camera.rs` call these functions
//! with validated inputs and handle all error cases.
//!
//! # Security invariants
//!
//! - Every `extern "C"` function here is `unsafe` by definition (FFI).
//! - Callers must ensure:
//!   - All pointer arguments are valid and correctly aligned.
//!   - Buffer sizes match the actual buffer allocation.
//!   - Device IDs were obtained from a prior successful API call.
//! - The `fourcc` helper is a compile-time `const fn` with no safety concerns.
//! - CoreFoundation objects must be released with `CFRelease` to avoid leaks.

use std::os::raw::{c_char, c_void};

// ---------------------------------------------------------------------------
// CoreAudio types
// ---------------------------------------------------------------------------

/// Unique identifier for an audio object (device, stream, etc.).
pub type AudioObjectID = u32;

/// Four-character code identifying a property.
pub type AudioObjectPropertySelector = u32;

/// Scope within an audio object (global, input, output).
pub type AudioObjectPropertyScope = u32;

/// Element within a scope.
pub type AudioObjectPropertyElement = u32;

/// macOS system error code.
pub type OSStatus = i32;

/// Identifies a specific property on an audio object.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AudioObjectPropertyAddress {
    /// Which property.
    pub selector: AudioObjectPropertySelector,
    /// Which scope (global, input, output).
    pub scope: AudioObjectPropertyScope,
    /// Which element.
    pub element: AudioObjectPropertyElement,
}

/// Function pointer type for property change callbacks.
///
/// Called by CoreAudio on a system thread when a monitored property changes.
pub type AudioObjectPropertyListenerProc = unsafe extern "C" fn(
    object_id: AudioObjectID,
    number_addresses: u32,
    addresses: *const AudioObjectPropertyAddress,
    client_data: *mut c_void,
) -> OSStatus;

// ---------------------------------------------------------------------------
// CoreFoundation types
// ---------------------------------------------------------------------------

/// Opaque CoreFoundation string reference.
pub type CFStringRef = *const c_void;
/// Opaque CoreFoundation allocator reference.
pub type CFAllocatorRef = *const c_void;
/// Opaque CoreFoundation type reference (generic CF object).
pub type CFTypeRef = *const c_void;

// ---------------------------------------------------------------------------
// CoreAudio constants
// ---------------------------------------------------------------------------

/// The singleton representing the audio hardware system.
pub const AUDIO_SYSTEM_OBJECT: AudioObjectID = 1;

/// Property: whether the device is being used by any process on the system.
pub const PROP_DEVICE_IS_RUNNING_SOMEWHERE: AudioObjectPropertySelector = fourcc(*b"gone");

/// Property: list of all audio devices on the system.
pub const PROP_HARDWARE_DEVICES: AudioObjectPropertySelector = fourcc(*b"dev#");

/// Property: list of streams on a device (used to check if device has input).
pub const PROP_DEVICE_STREAMS: AudioObjectPropertySelector = fourcc(*b"stm#");

/// Property: device name (returns CFStringRef).
pub const PROP_OBJECT_NAME: AudioObjectPropertySelector = fourcc(*b"lnam");

/// Property: device UID (returns CFStringRef).
pub const PROP_DEVICE_UID: AudioObjectPropertySelector = fourcc(*b"uid ");

/// Global scope — not input-specific or output-specific.
pub const SCOPE_GLOBAL: AudioObjectPropertyScope = fourcc(*b"glob");

/// Input scope — for input streams/channels.
pub const SCOPE_INPUT: AudioObjectPropertyScope = fourcc(*b"inpt");

/// Main element (element 0).
pub const ELEMENT_MAIN: AudioObjectPropertyElement = 0;

/// No error.
pub const NO_ERROR: OSStatus = 0;

// ---------------------------------------------------------------------------
// CoreFoundation constants
// ---------------------------------------------------------------------------

/// UTF-8 encoding constant for CoreFoundation strings.
pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

// ---------------------------------------------------------------------------
// CoreAudio extern functions
// ---------------------------------------------------------------------------

#[link(name = "CoreAudio", kind = "framework")]
unsafe extern "C" {
    /// Read a property's data into a caller-provided buffer.
    pub fn AudioObjectGetPropertyData(
        object_id: AudioObjectID,
        address: *const AudioObjectPropertyAddress,
        qualifier_data_size: u32,
        qualifier_data: *const c_void,
        io_data_size: *mut u32,
        out_data: *mut c_void,
    ) -> OSStatus;

    /// Get the size (in bytes) of a property's data.
    pub fn AudioObjectGetPropertyDataSize(
        object_id: AudioObjectID,
        address: *const AudioObjectPropertyAddress,
        qualifier_data_size: u32,
        qualifier_data: *const c_void,
        out_data_size: *mut u32,
    ) -> OSStatus;

    /// Register a C function to be called when a property changes.
    pub fn AudioObjectAddPropertyListener(
        object_id: AudioObjectID,
        address: *const AudioObjectPropertyAddress,
        listener: AudioObjectPropertyListenerProc,
        client_data: *mut c_void,
    ) -> OSStatus;

    /// Remove a previously registered property listener.
    ///
    /// The `listener` and `client_data` must match the values passed
    /// to `AudioObjectAddPropertyListener` exactly.
    pub fn AudioObjectRemovePropertyListener(
        object_id: AudioObjectID,
        address: *const AudioObjectPropertyAddress,
        listener: AudioObjectPropertyListenerProc,
        client_data: *mut c_void,
    ) -> OSStatus;
}

// ---------------------------------------------------------------------------
// CoreFoundation extern functions
// ---------------------------------------------------------------------------

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Create a CFString from a C string.
    pub fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;

    /// Copy a CFString's contents into a C buffer.
    pub fn CFStringGetCString(
        the_string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: i64,
        encoding: u32,
    ) -> u8;

    /// Release a CoreFoundation object.
    pub fn CFRelease(cf: *const c_void);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a 4-byte ASCII code to a `u32` (big-endian / network byte order).
///
/// Apple's audio frameworks use FourCC codes as property selectors.
/// For example, `b"gone"` → `0x676F_6E65`.
pub(crate) const fn fourcc(code: [u8; 4]) -> u32 {
    ((code[0] as u32) << 24) | ((code[1] as u32) << 16) | ((code[2] as u32) << 8) | (code[3] as u32)
}

/// Read a CFString into a Rust `String`, then release the CFString.
///
/// Returns `None` if the CFString is null or cannot be converted to UTF-8.
/// The caller transfers ownership of `cf_string` to this function — it will
/// be released regardless of success or failure.
pub(crate) fn cfstring_to_string_and_release(cf_string: CFStringRef) -> Option<String> {
    if cf_string.is_null() {
        return None;
    }
    let mut buf = [0i8; 256];
    // SAFETY: `cf_string` is a valid CFString (caller guarantees).
    // `buf` is a 256-byte stack buffer. `CFStringGetCString` writes a
    // null-terminated C string and returns true on success.
    let ok = unsafe {
        CFStringGetCString(
            cf_string,
            buf.as_mut_ptr(),
            buf.len() as i64,
            K_CF_STRING_ENCODING_UTF8,
        )
    };
    // Release regardless of success.
    // SAFETY: `cf_string` is a valid CF object the caller transferred to us.
    unsafe { CFRelease(cf_string.cast::<c_void>()) };

    if ok == 0 {
        return None;
    }
    // SAFETY: `CFStringGetCString` wrote a null-terminated string on success.
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(String::from)
}

/// Read a CFString property from a CoreAudio object.
///
/// Queries `selector` on `object_id` in global scope, reads the resulting
/// CFStringRef, converts to String, and releases the CFString.
pub(crate) fn audio_object_string_property(
    object_id: AudioObjectID,
    selector: AudioObjectPropertySelector,
) -> Option<String> {
    let address = AudioObjectPropertyAddress {
        selector,
        scope: SCOPE_GLOBAL,
        element: ELEMENT_MAIN,
    };
    let mut cf_string: CFStringRef = std::ptr::null();
    let mut size = std::mem::size_of::<CFStringRef>() as u32;

    // SAFETY: `object_id` was obtained from a successful API call.
    // `address` is valid stack reference. `cf_string` and `size` are valid
    // stack variables. CoreAudio writes a single CFStringRef pointer.
    let status = unsafe {
        AudioObjectGetPropertyData(
            object_id,
            &raw const address,
            0,
            std::ptr::null(),
            &raw mut size,
            std::ptr::from_mut(&mut cf_string).cast::<c_void>(),
        )
    };
    if status != NO_ERROR {
        return None;
    }
    cfstring_to_string_and_release(cf_string)
}

#[cfg(test)]
mod ffi_test {
    use super::*;

    #[test]
    fn test_fourcc_known_values() {
        assert_eq!(fourcc(*b"glob"), 0x676C_6F62);
        assert_eq!(fourcc(*b"gone"), 0x676F_6E65);
        assert_eq!(fourcc(*b"dIn "), 0x6449_6E20);
    }

    #[test]
    fn test_fourcc_new_selectors() {
        assert_eq!(fourcc(*b"dev#"), 0x6465_7623);
        assert_eq!(fourcc(*b"stm#"), 0x7374_6D23);
        assert_eq!(fourcc(*b"inpt"), 0x696E_7074);
        assert_eq!(fourcc(*b"lnam"), 0x6C6E_616D);
        assert_eq!(fourcc(*b"uid "), 0x7569_6420);
    }

    #[test]
    fn test_property_address_is_repr_c() {
        assert_eq!(std::mem::size_of::<AudioObjectPropertyAddress>(), 12);
    }
}
