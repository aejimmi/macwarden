//! Multi-device microphone monitoring via CoreAudio.
//!
//! Enumerates ALL audio input devices and monitors each independently.
//! Detects hot-plug/unplug of audio devices.
//!
//! Two modes:
//! - **Point-in-time**: `is_active()` checks if any mic is currently in use.
//! - **Real-time**: `MicMonitor::start()` fires events through a channel
//!   whenever any mic's state changes or a device is connected/disconnected.

use std::os::raw::c_void;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use crate::error::SensorError;
use crate::ffi;
use crate::{MediaDevice, MediaDeviceKind, SensorEvent};

// ---------------------------------------------------------------------------
// Point-in-time queries
// ---------------------------------------------------------------------------

/// Check if any microphone is currently active (used by any process).
pub fn is_active() -> Result<bool, SensorError> {
    let devices = enumerate_input_devices()?;
    for dev in &devices {
        #[allow(clippy::cast_possible_truncation)]
        if is_device_running(dev.id as ffi::AudioObjectID)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Enumerate all audio input devices on the system.
pub fn enumerate_input_devices() -> Result<Vec<MediaDevice>, SensorError> {
    let device_ids = all_audio_device_ids()?;
    let mut result = Vec::new();

    for &device_id in &device_ids {
        if !has_input_streams(device_id) {
            continue;
        }
        let name = ffi::audio_object_string_property(device_id, ffi::PROP_OBJECT_NAME)
            .unwrap_or_else(|| format!("Audio Device {device_id}"));
        let uid =
            ffi::audio_object_string_property(device_id, ffi::PROP_DEVICE_UID).unwrap_or_default();

        result.push(MediaDevice {
            id: u64::from(device_id),
            name,
            uid,
            kind: MediaDeviceKind::Microphone,
        });
    }

    if result.is_empty() {
        return Err(SensorError::NoDevice { kind: "microphone" });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Get all audio device IDs from the system.
fn all_audio_device_ids() -> Result<Vec<ffi::AudioObjectID>, SensorError> {
    let address = ffi::AudioObjectPropertyAddress {
        selector: ffi::PROP_HARDWARE_DEVICES,
        scope: ffi::SCOPE_GLOBAL,
        element: ffi::ELEMENT_MAIN,
    };

    let mut size: u32 = 0;
    // SAFETY: AUDIO_SYSTEM_OBJECT is always valid. `address` is a valid stack
    // reference. We query size first — no buffer written.
    let status = unsafe {
        ffi::AudioObjectGetPropertyDataSize(
            ffi::AUDIO_SYSTEM_OBJECT,
            &raw const address,
            0,
            std::ptr::null(),
            &raw mut size,
        )
    };
    if status != ffi::NO_ERROR {
        return Err(SensorError::CoreAudio {
            function: "AudioObjectGetPropertyDataSize(Devices)",
            code: status,
        });
    }

    let count = size as usize / std::mem::size_of::<ffi::AudioObjectID>();
    if count == 0 {
        return Err(SensorError::NoDevice { kind: "microphone" });
    }

    let mut ids = vec![0u32; count];
    // SAFETY: `ids` has `count` elements, matching `size` bytes. CoreAudio
    // writes exactly `size` bytes of AudioObjectID values.
    let status = unsafe {
        ffi::AudioObjectGetPropertyData(
            ffi::AUDIO_SYSTEM_OBJECT,
            &raw const address,
            0,
            std::ptr::null(),
            &raw mut size,
            ids.as_mut_ptr().cast::<c_void>(),
        )
    };
    if status != ffi::NO_ERROR {
        return Err(SensorError::CoreAudio {
            function: "AudioObjectGetPropertyData(Devices)",
            code: status,
        });
    }
    Ok(ids)
}

/// Check if a device has input streams (i.e., is an input device).
fn has_input_streams(device_id: ffi::AudioObjectID) -> bool {
    let address = ffi::AudioObjectPropertyAddress {
        selector: ffi::PROP_DEVICE_STREAMS,
        scope: ffi::SCOPE_INPUT,
        element: ffi::ELEMENT_MAIN,
    };
    let mut size: u32 = 0;
    // SAFETY: `device_id` is from a successful enumeration. We only query size.
    let status = unsafe {
        ffi::AudioObjectGetPropertyDataSize(
            device_id,
            &raw const address,
            0,
            std::ptr::null(),
            &raw mut size,
        )
    };
    status == ffi::NO_ERROR && size > 0
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

    // SAFETY: `device_id` was obtained from a successful enumeration.
    // `is_running` and `size` are valid stack variables.
    let status = unsafe {
        ffi::AudioObjectGetPropertyData(
            device_id,
            &raw const address,
            0,
            std::ptr::null(),
            &raw mut size,
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

/// Shared state for the multi-device microphone monitor.
struct MicMonitorInner {
    /// Per-device listeners for cleanup.
    device_listeners: Vec<DeviceListener>,
    /// Event sender.
    sender: mpsc::Sender<SensorEvent>,
}

/// Tracks a registered CoreAudio property listener for one device.
struct DeviceListener {
    device_id: ffi::AudioObjectID,
    address: ffi::AudioObjectPropertyAddress,
    client_data: *mut c_void,
}

// SAFETY: `DeviceListener` is Send because `client_data` points to a
// heap-allocated `DeviceCallbackContext` that is only accessed from CoreAudio
// callbacks (via the pointer) and during cleanup (sole owner after listener
// removal). The pointer is never shared or accessed concurrently from Rust code.
unsafe impl Send for DeviceListener {}

/// RAII guard for multi-device microphone monitoring.
///
/// Registers CoreAudio property listeners on all input devices and detects
/// hot-plug/unplug events. Drop to stop monitoring and clean up.
pub struct MicMonitor {
    /// Shared state protected by a mutex (accessed from callbacks).
    inner: Arc<Mutex<MicMonitorInner>>,
    /// Hotplug listener client data (for cleanup).
    hotplug_client_data: *mut c_void,
}

// SAFETY: `MicMonitor` is `Send` because:
// - `inner` is `Arc<Mutex<..>>` which is Send+Sync.
// - `hotplug_client_data` points to a heap-allocated `HotplugContext` that
//   is only accessed from CoreAudio callbacks (thread-safe via Arc<Mutex>)
//   and during Drop (sole owner after listener removal).
unsafe impl Send for MicMonitor {}

/// Context passed to per-device property listener callbacks.
struct DeviceCallbackContext {
    sender: mpsc::Sender<SensorEvent>,
    device: MediaDevice,
}

/// Context passed to the hot-plug listener callback.
struct HotplugContext {
    inner: Arc<Mutex<MicMonitorInner>>,
}

impl MicMonitor {
    /// Start monitoring all input microphones for state changes.
    ///
    /// Returns a `MicMonitor` guard. The guard must be kept alive for
    /// monitoring to continue. Drop it to stop.
    pub fn start(sender: &mpsc::Sender<SensorEvent>) -> Result<Self, SensorError> {
        let devices = enumerate_input_devices()?;
        let mut device_listeners = Vec::with_capacity(devices.len());

        for device in &devices {
            #[allow(clippy::cast_possible_truncation)]
            let device_id = device.id as ffi::AudioObjectID;
            match register_device_listener(device_id, device.clone(), sender.clone()) {
                Ok(listener) => device_listeners.push(listener),
                Err(e) => {
                    tracing::warn!(
                        device = %device.name,
                        error = %e,
                        "failed to register listener, skipping"
                    );
                }
            }
        }

        let inner = Arc::new(Mutex::new(MicMonitorInner {
            device_listeners,
            sender: sender.clone(),
        }));

        let hotplug_ctx = Box::new(HotplugContext {
            inner: Arc::clone(&inner),
        });
        let hotplug_client_data = Box::into_raw(hotplug_ctx).cast::<c_void>();

        let address = ffi::AudioObjectPropertyAddress {
            selector: ffi::PROP_HARDWARE_DEVICES,
            scope: ffi::SCOPE_GLOBAL,
            element: ffi::ELEMENT_MAIN,
        };

        // SAFETY: AUDIO_SYSTEM_OBJECT is always valid. `address` is valid.
        // `hotplug_listener_proc` has the correct callback signature.
        // `hotplug_client_data` is a valid heap pointer freed in Drop.
        let status = unsafe {
            ffi::AudioObjectAddPropertyListener(
                ffi::AUDIO_SYSTEM_OBJECT,
                &raw const address,
                hotplug_listener_proc,
                hotplug_client_data,
            )
        };

        if status != ffi::NO_ERROR {
            // Reclaim to avoid leak.
            // SAFETY: Just created above, no callback registered.
            let _ = unsafe { Box::from_raw(hotplug_client_data.cast::<HotplugContext>()) };
            // Still return Ok — hot-plug won't work but device monitoring does.
            tracing::warn!(code = status, "failed to register hot-plug listener");
        }

        let count = inner.lock().map(|g| g.device_listeners.len()).unwrap_or(0);
        tracing::info!(device_count = count, "microphone monitor started");

        Ok(Self {
            inner,
            hotplug_client_data,
        })
    }
}

impl Drop for MicMonitor {
    fn drop(&mut self) {
        // Remove hot-plug listener.
        let address = ffi::AudioObjectPropertyAddress {
            selector: ffi::PROP_HARDWARE_DEVICES,
            scope: ffi::SCOPE_GLOBAL,
            element: ffi::ELEMENT_MAIN,
        };
        // SAFETY: Same (object, address, proc, client_data) as registration.
        let status = unsafe {
            ffi::AudioObjectRemovePropertyListener(
                ffi::AUDIO_SYSTEM_OBJECT,
                &raw const address,
                hotplug_listener_proc,
                self.hotplug_client_data,
            )
        };
        if status != ffi::NO_ERROR {
            tracing::warn!(code = status, "failed to remove hot-plug listener");
        }
        // SAFETY: Created in `start`, listener removed above.
        let _ = unsafe { Box::from_raw(self.hotplug_client_data.cast::<HotplugContext>()) };

        // Remove per-device listeners.
        if let Ok(mut guard) = self.inner.lock() {
            for dl in guard.device_listeners.drain(..) {
                remove_device_listener(dl);
            }
        }

        tracing::info!("microphone monitor stopped");
    }
}

// ---------------------------------------------------------------------------
// Per-device listener registration
// ---------------------------------------------------------------------------

/// Register a property listener for a single audio device.
fn register_device_listener(
    device_id: ffi::AudioObjectID,
    device: MediaDevice,
    sender: mpsc::Sender<SensorEvent>,
) -> Result<DeviceListener, SensorError> {
    let address = ffi::AudioObjectPropertyAddress {
        selector: ffi::PROP_DEVICE_IS_RUNNING_SOMEWHERE,
        scope: ffi::SCOPE_GLOBAL,
        element: ffi::ELEMENT_MAIN,
    };

    let ctx = Box::new(DeviceCallbackContext { sender, device });
    let client_data = Box::into_raw(ctx).cast::<c_void>();

    // SAFETY: `device_id` is valid. `address` is valid. `device_listener_proc`
    // has the correct signature. `client_data` is valid heap pointer.
    let status = unsafe {
        ffi::AudioObjectAddPropertyListener(
            device_id,
            &raw const address,
            device_listener_proc,
            client_data,
        )
    };

    if status != ffi::NO_ERROR {
        // SAFETY: Just created, no listener registered.
        let _ = unsafe { Box::from_raw(client_data.cast::<DeviceCallbackContext>()) };
        return Err(SensorError::CoreAudio {
            function: "AudioObjectAddPropertyListener(DeviceRunning)",
            code: status,
        });
    }

    Ok(DeviceListener {
        device_id,
        address,
        client_data,
    })
}

/// Remove a previously registered per-device listener and free its context.
#[allow(clippy::needless_pass_by_value)] // Takes ownership to free client_data.
fn remove_device_listener(dl: DeviceListener) {
    // SAFETY: Same (device_id, address, proc, client_data) as registration.
    let status = unsafe {
        ffi::AudioObjectRemovePropertyListener(
            dl.device_id,
            &raw const dl.address,
            device_listener_proc,
            dl.client_data,
        )
    };
    if status != ffi::NO_ERROR {
        tracing::warn!(
            device_id = dl.device_id,
            code = status,
            "failed to remove device listener"
        );
    }
    // SAFETY: Created in `register_device_listener`, listener removed above.
    let _ = unsafe { Box::from_raw(dl.client_data.cast::<DeviceCallbackContext>()) };
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Per-device property listener callback.
///
/// # Safety
///
/// Called by CoreAudio on a system thread. `client_data` must be a valid
/// pointer to a `DeviceCallbackContext` created by `Box::into_raw`.
unsafe extern "C" fn device_listener_proc(
    object_id: ffi::AudioObjectID,
    _number_addresses: u32,
    _addresses: *const ffi::AudioObjectPropertyAddress,
    client_data: *mut c_void,
) -> ffi::OSStatus {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `client_data` is a valid `DeviceCallbackContext` pointer.
        // We borrow it — no ownership transfer.
        let ctx = unsafe { &*(client_data.cast::<DeviceCallbackContext>()) };
        let active = is_device_running(object_id).unwrap_or(false);
        let event = if active {
            SensorEvent::DeviceActivated(ctx.device.clone())
        } else {
            SensorEvent::DeviceDeactivated(ctx.device.clone())
        };
        let _ = ctx.sender.send(event);
    }));
    if result.is_err() {
        tracing::error!("panic in microphone device listener callback — suppressed");
    }
    ffi::NO_ERROR
}

/// Hot-plug listener callback — fires when the system device list changes.
///
/// # Safety
///
/// Called by CoreAudio on a system thread. `client_data` must be a valid
/// pointer to a `HotplugContext` created by `Box::into_raw`.
unsafe extern "C" fn hotplug_listener_proc(
    _object_id: ffi::AudioObjectID,
    _number_addresses: u32,
    _addresses: *const ffi::AudioObjectPropertyAddress,
    client_data: *mut c_void,
) -> ffi::OSStatus {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `client_data` is a valid `HotplugContext` pointer.
        let ctx = unsafe { &*(client_data.cast::<HotplugContext>()) };
        handle_hotplug(ctx);
    }));
    if result.is_err() {
        tracing::error!("panic in microphone hot-plug callback — suppressed");
    }
    ffi::NO_ERROR
}

/// Handle a device list change: diff old vs new, emit events, update listeners.
fn handle_hotplug(ctx: &HotplugContext) {
    let new_devices = match enumerate_input_devices() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "failed to enumerate devices in hot-plug handler");
            return;
        }
    };

    let Ok(mut guard) = ctx.inner.lock() else {
        tracing::warn!("mic monitor inner lock poisoned in hot-plug handler");
        return;
    };

    let old_ids: Vec<u64> = guard
        .device_listeners
        .iter()
        .map(|dl| u64::from(dl.device_id))
        .collect();
    let new_ids: Vec<u64> = new_devices.iter().map(|d| d.id).collect();

    // Devices that disappeared.
    let removed: Vec<usize> = old_ids
        .iter()
        .enumerate()
        .filter(|(_, id)| !new_ids.contains(id))
        .map(|(i, _)| i)
        .collect();

    // Remove in reverse order to preserve indices.
    for &idx in removed.iter().rev() {
        let dl = guard.device_listeners.remove(idx);
        #[allow(clippy::cast_possible_truncation)]
        let device_id = dl.device_id;
        let name = ffi::audio_object_string_property(device_id, ffi::PROP_OBJECT_NAME)
            .unwrap_or_else(|| format!("Audio Device {device_id}"));
        remove_device_listener(dl);
        let event = SensorEvent::DeviceDisconnected(MediaDevice {
            id: u64::from(device_id),
            name,
            uid: String::new(),
            kind: MediaDeviceKind::Microphone,
        });
        let _ = guard.sender.send(event);
    }

    // Devices that appeared.
    for dev in &new_devices {
        if old_ids.contains(&dev.id) {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)]
        let device_id = dev.id as ffi::AudioObjectID;
        match register_device_listener(device_id, dev.clone(), guard.sender.clone()) {
            Ok(listener) => guard.device_listeners.push(listener),
            Err(e) => {
                tracing::warn!(
                    device = %dev.name,
                    error = %e,
                    "failed to register listener for new device"
                );
            }
        }
        let _ = guard.sender.send(SensorEvent::DeviceConnected(dev.clone()));
    }
}

#[cfg(test)]
#[path = "microphone_test.rs"]
mod microphone_test;
