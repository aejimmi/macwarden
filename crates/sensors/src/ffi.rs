//! Raw FFI bindings for CoreAudio.
//!
//! **All unsafe code in the sensors crate lives in this module.**
//!
//! This module is `pub(crate)` — it is never exposed outside the crate.
//! Safe wrappers in `microphone.rs` call these functions with validated
//! inputs and handle all error cases.
//!
//! # Security invariants
//!
//! - Every `extern "C"` function here is `unsafe` by definition (FFI).
//! - Callers must ensure:
//!   - All pointer arguments are valid and correctly aligned.
//!   - Buffer sizes match the actual buffer allocation.
//!   - Device IDs were obtained from a prior successful API call.
//! - The `fourcc` helper is a compile-time `const fn` with no safety concerns.
//!
//! # Camera note
//!
//! CoreMediaIO bindings were removed — Apple's CMIO C API crashes (SIGSEGV)
//! on macOS Sequoia+. Camera detection uses `ioreg` instead (see camera.rs).
//! CMIO bindings can be re-added if Apple stabilises Camera Extensions.

use std::os::raw::c_void;

// ---------------------------------------------------------------------------
// Types
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
// Constants
// ---------------------------------------------------------------------------

/// The singleton representing the audio hardware system.
pub const AUDIO_SYSTEM_OBJECT: AudioObjectID = 1;

/// Property: default audio input device.
pub const PROP_DEFAULT_INPUT_DEVICE: AudioObjectPropertySelector = fourcc(b"dIn ");

/// Property: whether the device is being used by any process on the system.
pub const PROP_DEVICE_IS_RUNNING_SOMEWHERE: AudioObjectPropertySelector = fourcc(b"gone");

/// Global scope — not input-specific or output-specific.
pub const SCOPE_GLOBAL: AudioObjectPropertyScope = fourcc(b"glob");

/// Main element (element 0).
pub const ELEMENT_MAIN: AudioObjectPropertyElement = 0;

/// No error.
pub const NO_ERROR: OSStatus = 0;

// ---------------------------------------------------------------------------
// Extern functions
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
// Helpers
// ---------------------------------------------------------------------------

/// Convert a 4-byte ASCII code to a `u32` (big-endian / network byte order).
///
/// Apple's audio frameworks use FourCC codes as property selectors.
/// For example, `b"gone"` → `0x676F_6E65`.
const fn fourcc(code: &[u8; 4]) -> u32 {
    ((code[0] as u32) << 24)
        | ((code[1] as u32) << 16)
        | ((code[2] as u32) << 8)
        | (code[3] as u32)
}

#[cfg(test)]
mod ffi_test {
    use super::*;

    #[test]
    fn test_fourcc_known_values() {
        assert_eq!(fourcc(b"glob"), 0x676C_6F62);
        assert_eq!(fourcc(b"gone"), 0x676F_6E65);
        assert_eq!(fourcc(b"dIn "), 0x6449_6E20);
    }

    #[test]
    fn test_property_address_is_repr_c() {
        assert_eq!(std::mem::size_of::<AudioObjectPropertyAddress>(), 12);
    }
}
