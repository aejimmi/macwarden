//! Safe microphone monitoring via CoreAudio.
//!
//! Wraps `AudioObjectGetPropertyData` and `AudioObjectAddPropertyListener`
//! in safe Rust functions. All `unsafe` blocks have SAFETY comments.
//!
//! Two modes:
//! - **Point-in-time**: `is_active()` checks if the mic is currently in use.
//! - **Real-time**: `MicMonitor::start()` fires events through a channel
//!   whenever the mic state changes.

use std::os::raw::c_void;
use std::sync::mpsc;

use crate::SensorEvent;
use crate::error::SensorError;
use crate::ffi;

// ---------------------------------------------------------------------------
// Point-in-time queries
// ---------------------------------------------------------------------------

/// Check if any microphone is currently active (used by any process).
pub fn is_active() -> Result<bool, SensorError> {
    let device_id = default_input_device()?;
    is_device_running(device_id)
}

/// Get the system's default audio input device.
fn default_input_device() -> Result<ffi::AudioObjectID, SensorError> {
    let address = ffi::AudioObjectPropertyAddress {
        selector: ffi::PROP_DEFAULT_INPUT_DEVICE,
        scope: ffi::SCOPE_GLOBAL,
        element: ffi::ELEMENT_MAIN,
    };

    let mut device_id: ffi::AudioObjectID = 0;
    let mut size = std::mem::size_of::<ffi::AudioObjectID>() as u32;

    // SAFETY: `AUDIO_SYSTEM_OBJECT` (constant 1) is always valid.
    // `address` is a valid stack reference. `device_id` and `size` are
    // valid stack-allocated variables with correct types and sizes.
    // CoreAudio writes exactly `size_of::<AudioObjectID>()` bytes into
    // `device_id` and does not retain any pointers after returning.
    let status = unsafe {
        ffi::AudioObjectGetPropertyData(
            ffi::AUDIO_SYSTEM_OBJECT,
            &address,
            0,
            std::ptr::null(),
            &mut size,
            std::ptr::from_mut(&mut device_id).cast::<c_void>(),
        )
    };

    if status != ffi::NO_ERROR {
        return Err(SensorError::CoreAudio {
            function: "AudioObjectGetPropertyData(DefaultInputDevice)",
            code: status,
        });
    }

    if device_id == 0 {
        return Err(SensorError::NoDevice { kind: "microphone" });
    }

    Ok(device_id)
}

/// Check if a specific audio device is being used by any process.
fn is_device_running(device_id: ffi::AudioObjectID) -> Result<bool, SensorError> {
    let address = ffi::AudioObjectPropertyAddress {
        selector: ffi::PROP_DEVICE_IS_RUNNING_SOMEWHERE,
        scope: ffi::SCOPE_GLOBAL,
        element: ffi::ELEMENT_MAIN,
    };

    let mut is_running: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;

    // SAFETY: `device_id` was obtained from a successful
    // `AudioObjectGetPropertyData` call. `is_running` and `size` are valid
    // stack variables. CoreAudio writes a single `u32` and returns.
    let status = unsafe {
        ffi::AudioObjectGetPropertyData(
            device_id,
            &address,
            0,
            std::ptr::null(),
            &mut size,
            std::ptr::from_mut(&mut is_running).cast::<c_void>(),
        )
    };

    if status != ffi::NO_ERROR {
        return Err(SensorError::CoreAudio {
            function: "AudioObjectGetPropertyData(IsRunningSomewhere)",
            code: status,
        });
    }

    Ok(is_running != 0)
}

// ---------------------------------------------------------------------------
// Real-time monitoring
// ---------------------------------------------------------------------------

/// RAII guard for a microphone property listener.
///
/// Registers a CoreAudio property listener on creation. Removes the listener
/// and frees the callback context when dropped. This ensures no resource leaks
/// even on early returns or panics.
pub struct MicMonitor {
    device_id: ffi::AudioObjectID,
    address: ffi::AudioObjectPropertyAddress,
    /// Raw pointer to the heap-allocated callback context.
    /// Created via `Box::into_raw`, reclaimed via `Box::from_raw` on drop.
    client_data: *mut c_void,
}

// SAFETY: `MicMonitor` is `Send` because:
// - `device_id` and `address` are plain data (Copy types).
// - `client_data` points to a `Box<mpsc::Sender<SensorEvent>>` which is Send.
// - We only access `client_data` during drop (to free it), never concurrently.
// The CoreAudio callback accesses the data on a system thread, but only reads
// from the Sender (which is thread-safe). We never mutate through `client_data`
// after construction.
unsafe impl Send for MicMonitor {}

impl MicMonitor {
    /// Start monitoring the default microphone for state changes.
    ///
    /// Returns a `MicMonitor` guard and an event receiver. The guard must be
    /// kept alive for monitoring to continue. Drop it to stop.
    pub fn start(sender: mpsc::Sender<SensorEvent>) -> Result<Self, SensorError> {
        let device_id = default_input_device()?;

        let address = ffi::AudioObjectPropertyAddress {
            selector: ffi::PROP_DEVICE_IS_RUNNING_SOMEWHERE,
            scope: ffi::SCOPE_GLOBAL,
            element: ffi::ELEMENT_MAIN,
        };

        // Heap-allocate the sender so we can pass it through `void*`.
        // `Box::into_raw` prevents Rust from dropping it — we reclaim it
        // in `Drop::drop` via `Box::from_raw`.
        let client_data = Box::into_raw(Box::new(sender)).cast::<c_void>();

        // SAFETY: `device_id` is a valid device from `default_input_device`.
        // `address` is a valid stack reference. `mic_listener_proc` has the
        // correct signature for `AudioObjectPropertyListenerProc`.
        // `client_data` is a valid heap pointer that will outlive this
        // registration (freed only in Drop after the listener is removed).
        let status = unsafe {
            ffi::AudioObjectAddPropertyListener(device_id, &address, mic_listener_proc, client_data)
        };

        if status != ffi::NO_ERROR {
            // Registration failed — reclaim the client data to avoid a leak.
            // SAFETY: `client_data` was just created by `Box::into_raw` above
            // and no listener was registered, so nothing else references it.
            let _ = unsafe { Box::from_raw(client_data.cast::<mpsc::Sender<SensorEvent>>()) };

            return Err(SensorError::CoreAudio {
                function: "AudioObjectAddPropertyListener",
                code: status,
            });
        }

        tracing::info!(device_id, "microphone listener registered");

        Ok(Self {
            device_id,
            address,
            client_data,
        })
    }
}

impl Drop for MicMonitor {
    fn drop(&mut self) {
        // SAFETY: We pass the exact same (device_id, address, proc, client_data)
        // that were used in `AudioObjectAddPropertyListener`. CoreAudio
        // guarantees no more callbacks fire after `RemovePropertyListener`
        // returns, so it is safe to reclaim `client_data` afterwards.
        let status = unsafe {
            ffi::AudioObjectRemovePropertyListener(
                self.device_id,
                &self.address,
                mic_listener_proc,
                self.client_data,
            )
        };

        if status != ffi::NO_ERROR {
            tracing::warn!(
                code = status,
                "failed to remove microphone listener — may leak"
            );
        }

        // SAFETY: `client_data` was created by `Box::into_raw` in `start()`.
        // The listener has been removed, so no callback can reference this
        // pointer. We are the sole owner — safe to reclaim and drop.
        let _ = unsafe { Box::from_raw(self.client_data.cast::<mpsc::Sender<SensorEvent>>()) };

        tracing::info!("microphone listener removed");
    }
}

// ---------------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------------

/// CoreAudio property listener callback for the microphone.
///
/// Fires on a system thread when the `kAudioDevicePropertyDeviceIsRunningSomewhere`
/// property changes. Queries the current state and sends an event.
///
/// # Safety
///
/// Called by CoreAudio from a system thread. `client_data` must be a valid
/// pointer to a `mpsc::Sender<SensorEvent>` created by `Box::into_raw`.
unsafe extern "C" fn mic_listener_proc(
    object_id: ffi::AudioObjectID,
    _number_addresses: u32,
    _addresses: *const ffi::AudioObjectPropertyAddress,
    client_data: *mut c_void,
) -> ffi::OSStatus {
    // Catch any panic to prevent unwinding through C stack frames,
    // which is undefined behavior.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `client_data` is a valid pointer to a heap-allocated
        // `Sender<SensorEvent>`, created by `Box::into_raw` in `MicMonitor::start`.
        // We only borrow it (shared reference) — no ownership transfer.
        // The pointer remains valid because `MicMonitor::drop` removes the
        // listener before freeing the pointer.
        let sender = unsafe { &*(client_data.cast::<mpsc::Sender<SensorEvent>>()) };

        let active = is_device_running(object_id).unwrap_or(false);
        let event = if active {
            SensorEvent::MicrophoneActivated
        } else {
            SensorEvent::MicrophoneDeactivated
        };

        // Best-effort send. If the receiver is dropped, we're shutting down.
        let _ = sender.send(event);
    }));

    if result.is_err() {
        tracing::error!("panic in microphone listener callback — suppressed");
    }

    ffi::NO_ERROR
}

#[cfg(test)]
#[path = "microphone_test.rs"]
mod microphone_test;
