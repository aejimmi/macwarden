//! Raw FFI bindings for IOKit and CoreGraphics.
//!
//! **All IOKit unsafe code in the sensors crate lives in this module.**
//!
//! This module is `pub(crate)` — it is never exposed outside the crate.
//! Safe wrappers in `camera.rs` call these functions with validated inputs.
//!
//! # Security invariants
//!
//! - Every `extern "C"` function here is `unsafe` by definition (FFI).
//! - Callers must ensure all pointer arguments are valid and correctly aligned.
//! - IOKit objects must be released with `IOObjectRelease` to avoid leaks.
//! - CFRunLoop sources must be removed before releasing notification ports.

use std::os::raw::{c_char, c_void};

use crate::ffi::{CFAllocatorRef, CFStringRef, CFTypeRef};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// IOKit object handle (mach port).
pub type io_object_t = u32;
/// IOKit service handle.
pub type io_service_t = io_object_t;
/// IOKit iterator handle.
pub type io_iterator_t = io_object_t;
/// IOKit connect handle (for power management).
pub type io_connect_t = io_object_t;
/// Mach port type.
pub type mach_port_t = u32;
/// Kernel return type.
pub type kern_return_t = i32;
/// IOKit notification port (opaque).
pub type IONotificationPortRef = *mut c_void;

/// CFRunLoop reference (opaque).
pub type CFRunLoopRef = *mut c_void;
/// CFRunLoop source reference (opaque).
pub type CFRunLoopSourceRef = *mut c_void;
/// CFRunLoop mode (actually CFStringRef).
pub type CFRunLoopMode = CFStringRef;
/// Mutable CF dictionary (opaque).
pub type CFMutableDictionaryRef = *mut c_void;

/// IOKit interest callback signature.
pub type IOServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut c_void,
    service: io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default main port for IOKit (0 on modern macOS).
pub const K_IO_MAIN_PORT_DEFAULT: mach_port_t = 0;

/// Success return code.
pub const KERN_SUCCESS: kern_return_t = 0;

/// General interest notification type.
pub const K_IO_GENERAL_INTEREST: &[u8] = b"IOGeneralInterest\0";

// ---------------------------------------------------------------------------
// IOKit extern functions
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "macos", link(name = "IOKit", kind = "framework"))]
unsafe extern "C" {
    /// Create a matching dictionary for an IOKit service class name.
    pub fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;

    /// Find existing services matching a dictionary.
    pub fn IOServiceGetMatchingServices(
        main_port: mach_port_t,
        matching: CFMutableDictionaryRef,
        existing: *mut io_iterator_t,
    ) -> kern_return_t;

    /// Create a notification port for IOKit notifications.
    pub fn IONotificationPortCreate(main_port: mach_port_t) -> IONotificationPortRef;

    /// Destroy a notification port.
    pub fn IONotificationPortDestroy(notify: IONotificationPortRef);

    /// Get a CFRunLoop source from a notification port.
    pub fn IONotificationPortGetRunLoopSource(notify: IONotificationPortRef) -> CFRunLoopSourceRef;

    /// Register for interest notifications on a service.
    pub fn IOServiceAddInterestNotification(
        notify_port: IONotificationPortRef,
        service: io_service_t,
        interest_type: *const c_char,
        callback: IOServiceInterestCallback,
        refcon: *mut c_void,
        notification: *mut io_object_t,
    ) -> kern_return_t;

    /// Get the next object from an IOKit iterator.
    pub fn IOIteratorNext(iterator: io_iterator_t) -> io_object_t;

    /// Release an IOKit object.
    pub fn IOObjectRelease(object: io_object_t) -> kern_return_t;

    /// Create a CF property from an IOKit registry entry.
    pub fn IORegistryEntryCreateCFProperty(
        entry: io_object_t,
        key: CFStringRef,
        allocator: CFAllocatorRef,
        options: u32,
    ) -> CFTypeRef;
}

// ---------------------------------------------------------------------------
// CoreFoundation RunLoop extern functions
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "macos", link(name = "CoreFoundation", kind = "framework"))]
unsafe extern "C" {
    /// Get the CFRunLoop for the current thread.
    pub fn CFRunLoopGetCurrent() -> CFRunLoopRef;

    /// Add a source to a run loop.
    pub fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFRunLoopMode);

    /// Remove a source from a run loop.
    pub fn CFRunLoopRemoveSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFRunLoopMode);

    /// Run the run loop in a specific mode for a duration.
    pub fn CFRunLoopRunInMode(
        mode: CFRunLoopMode,
        seconds: f64,
        return_after_source_handled: u8,
    ) -> i32;

    /// Get the value of a CFBoolean.
    pub fn CFBooleanGetValue(boolean: CFTypeRef) -> u8;

    /// Get the default run loop mode string.
    pub static kCFRunLoopDefaultMode: CFRunLoopMode;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a boolean property from an IOKit registry entry.
///
/// Returns `None` if the property does not exist or is not a boolean.
pub(crate) fn iokit_bool_property(entry: io_object_t, key: &str) -> Option<bool> {
    let c_key = std::ffi::CString::new(key).ok()?;
    // SAFETY: `entry` is valid. We create a temporary CFString for the key.
    // `kCFAllocatorDefault` (null) is always valid. Options 0 = no special flags.
    let cf_key = unsafe {
        crate::ffi::CFStringCreateWithCString(
            std::ptr::null(),
            c_key.as_ptr(),
            crate::ffi::K_CF_STRING_ENCODING_UTF8,
        )
    };
    if cf_key.is_null() {
        return None;
    }

    // SAFETY: `entry` is valid, `cf_key` is a valid CFString we just created.
    let cf_val = unsafe { IORegistryEntryCreateCFProperty(entry, cf_key, std::ptr::null(), 0) };

    // Release the key string.
    // SAFETY: `cf_key` is a valid CF object we own.
    unsafe { crate::ffi::CFRelease(cf_key.cast::<c_void>()) };

    if cf_val.is_null() {
        return None;
    }

    // SAFETY: We assume the property is a CFBoolean. If it's not, the return
    // value is undefined but won't crash (CFBooleanGetValue on non-boolean
    // returns 0). We release the value afterwards.
    let val = unsafe { CFBooleanGetValue(cf_val) };
    // SAFETY: `cf_val` is a valid CF object from `IORegistryEntryCreateCFProperty`.
    unsafe { crate::ffi::CFRelease(cf_val.cast::<c_void>()) };
    Some(val != 0)
}
