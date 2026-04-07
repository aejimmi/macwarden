//! Sleep/wake awareness for sensor event suppression.
//!
//! Monitors macOS power state transitions via IOKit's
//! `IORegisterForSystemPower`. Sets a shared `awake` flag that the
//! `DebouncedSender` can check to suppress spurious events during
//! wake transitions.
//!
//! The power monitor needs its own CFRunLoop thread for IOKit
//! power notifications.

use std::os::raw::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::ffi_iokit;

/// Grace period after wake before allowing sensor events (hardware reinit).
const WAKE_GRACE: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// FFI — IOKit power management
// ---------------------------------------------------------------------------

/// Power notification callback type.
type IOServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut c_void,
    service: ffi_iokit::io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
);

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        notify_port: *mut ffi_iokit::IONotificationPortRef,
        callback: IOServiceInterestCallback,
        notifier: *mut ffi_iokit::io_object_t,
    ) -> ffi_iokit::io_connect_t;

    fn IODeregisterForSystemPower(
        notifier: *mut ffi_iokit::io_object_t,
    ) -> ffi_iokit::kern_return_t;

    fn IOAllowPowerChange(
        kernel_port: ffi_iokit::io_connect_t,
        notification_id: isize,
    ) -> ffi_iokit::kern_return_t;
}

/// System will sleep notification.
const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
/// System has powered on notification.
const K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON: u32 = 0xE000_0300;
/// Can system sleep? (must acknowledge).
const K_IO_MESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;

// ---------------------------------------------------------------------------
// Power monitor
// ---------------------------------------------------------------------------

/// Monitors macOS power state transitions (sleep/wake).
///
/// Sets a shared `awake` flag to `false` during sleep and for a grace
/// period after wake. The `DebouncedSender` checks this flag to suppress
/// sensor events during transitions.
pub struct PowerMonitor {
    /// Shared flag: `true` when system is awake and sensors should emit.
    awake: Arc<AtomicBool>,
    /// Signal the runloop thread to stop.
    stop: Arc<AtomicBool>,
    /// Join handle for the CFRunLoop thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Context passed to the power notification callback.
struct PowerContext {
    awake: Arc<AtomicBool>,
    root_port: ffi_iokit::io_connect_t,
}

// SAFETY: PowerContext is Send because:
// - `awake` is Arc<AtomicBool> (Send + Sync).
// - `root_port` is a plain integer (io_connect_t = u32).
unsafe impl Send for PowerContext {}

impl PowerMonitor {
    /// Start monitoring power state transitions.
    ///
    /// Returns the monitor and a shared `awake` flag that callers can check.
    pub fn start() -> Result<(Self, Arc<AtomicBool>), crate::error::SensorError> {
        let awake = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));

        let awake_clone = Arc::clone(&awake);
        let stop_clone = Arc::clone(&stop);

        let thread = std::thread::Builder::new()
            .name("power-monitor".into())
            .spawn(move || {
                power_runloop(awake_clone, stop_clone);
            })
            .map_err(|_| crate::error::SensorError::DeviceEnumeration {
                reason: "failed to spawn power monitor thread",
            })?;

        tracing::info!("power monitor started");

        Ok((
            Self {
                awake: Arc::clone(&awake),
                stop,
                thread: Some(thread),
            },
            awake,
        ))
    }

    /// Check if the system is currently awake.
    pub fn is_awake(&self) -> bool {
        self.awake.load(Ordering::Relaxed)
    }
}

impl Drop for PowerMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        tracing::info!("power monitor stopped");
    }
}

/// Run the power notification CFRunLoop.
/// Takes ownership because it runs in a `move` closure on a spawned thread.
#[allow(clippy::needless_pass_by_value)]
fn power_runloop(awake: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    let mut notify_port: ffi_iokit::IONotificationPortRef = std::ptr::null_mut();
    let mut notifier: ffi_iokit::io_object_t = 0;

    let ctx = Box::new(PowerContext {
        awake: Arc::clone(&awake),
        root_port: 0, // Will be set after registration.
    });
    let refcon = Box::into_raw(ctx);

    // SAFETY: IORegisterForSystemPower is a public IOKit API.
    // `refcon` is a valid heap pointer. `notify_port` and `notifier`
    // are valid stack variables for out parameters.
    let root_port = unsafe {
        IORegisterForSystemPower(
            refcon.cast::<c_void>(),
            &raw mut notify_port,
            power_callback,
            &raw mut notifier,
        )
    };

    if root_port == 0 {
        tracing::warn!("failed to register for system power notifications");
        // SAFETY: `refcon` was just created, no callback registered.
        let _ = unsafe { Box::from_raw(refcon) };
        return;
    }

    // Set root_port in context for use in callbacks.
    // SAFETY: `refcon` is valid and no callback has fired yet.
    unsafe { (*refcon).root_port = root_port };

    if notify_port.is_null() {
        tracing::warn!("IORegisterForSystemPower returned null notify port");
        // SAFETY: `refcon` is valid.
        let _ = unsafe { Box::from_raw(refcon) };
        return;
    }

    // SAFETY: `notify_port` is valid from successful registration.
    let rl_source = unsafe { ffi_iokit::IONotificationPortGetRunLoopSource(notify_port) };
    if rl_source.is_null() {
        tracing::warn!("failed to get run loop source for power notifications");
        // SAFETY: `notifier` is valid from IORegisterForSystemPower.
        unsafe { IODeregisterForSystemPower(&raw mut notifier) };
        // SAFETY: `refcon` was created by Box::into_raw, no callback registered.
        let _ = unsafe { Box::from_raw(refcon) };
        return;
    }

    // SAFETY: CFRunLoopGetCurrent is safe from the current thread.
    let run_loop = unsafe { ffi_iokit::CFRunLoopGetCurrent() };
    // SAFETY: All parameters are valid.
    unsafe {
        ffi_iokit::CFRunLoopAddSource(run_loop, rl_source, ffi_iokit::kCFRunLoopDefaultMode);
    }

    // Run the loop until stop is signaled.
    while !stop.load(Ordering::Relaxed) {
        // SAFETY: Valid mode, 1 second timeout.
        unsafe {
            ffi_iokit::CFRunLoopRunInMode(ffi_iokit::kCFRunLoopDefaultMode, 1.0, 1);
        }
    }

    // Clean up.
    // SAFETY: Removing source and deregistering in correct order.
    unsafe {
        ffi_iokit::CFRunLoopRemoveSource(run_loop, rl_source, ffi_iokit::kCFRunLoopDefaultMode);
    }
    // SAFETY: `notifier` is valid from successful registration.
    unsafe { IODeregisterForSystemPower(&raw mut notifier) };
    // SAFETY: `refcon` was created by Box::into_raw, callbacks are done.
    let _ = unsafe { Box::from_raw(refcon) };
}

/// IOKit power notification callback.
///
/// # Safety
///
/// Called by IOKit on a system thread. `refcon` must be a valid pointer
/// to a `PowerContext` created by `Box::into_raw`.
unsafe extern "C" fn power_callback(
    refcon: *mut c_void,
    _service: ffi_iokit::io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `refcon` is a valid `PowerContext`. We borrow only.
        let ctx = unsafe { &*(refcon.cast::<PowerContext>()) };

        match message_type {
            K_IO_MESSAGE_SYSTEM_WILL_SLEEP => {
                tracing::info!("system going to sleep — suppressing sensor events");
                ctx.awake.store(false, Ordering::Relaxed);
                // Acknowledge sleep promptly.
                // SAFETY: `root_port` is valid, `message_argument` is the notification ID.
                unsafe {
                    IOAllowPowerChange(ctx.root_port, message_argument as isize);
                }
            }
            K_IO_MESSAGE_CAN_SYSTEM_SLEEP => {
                // Allow sleep without delay.
                // SAFETY: Same as above.
                unsafe {
                    IOAllowPowerChange(ctx.root_port, message_argument as isize);
                }
            }
            K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON => {
                tracing::info!("system woke up — grace period before resuming sensor events");
                let awake = Arc::clone(&ctx.awake);
                // Spawn a short-lived thread for the grace period to avoid
                // blocking the IOKit callback.
                std::thread::spawn(move || {
                    std::thread::sleep(WAKE_GRACE);
                    awake.store(true, Ordering::Relaxed);
                    tracing::info!("wake grace period ended — sensor events resumed");
                });
            }
            _ => {} // Ignore other power messages.
        }
    }));
    if result.is_err() {
        tracing::error!("panic in power callback — suppressed");
    }
}

#[cfg(test)]
#[path = "power_test.rs"]
mod power_test;
