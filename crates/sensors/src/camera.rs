//! Camera monitoring via IOKit notifications with ioreg polling fallback.
//!
//! Point-in-time detection uses `ioreg` to query the IOKit device tree.
//! Real-time monitoring attempts IOKit `IOServiceAddInterestNotification`
//! for instant callbacks. Falls back to polling if notifications don't fire.
//!
//! Apple Silicon: monitors `AppleH13CamIn` service.
//! Intel: monitors `IOUSBHostDevice` entries matching FaceTime/Camera.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::error::SensorError;
use crate::ffi_iokit;
use crate::{MediaDevice, MediaDeviceKind, SensorEvent};

/// Polling interval for the fallback path.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Grace period before falling back to polling if IOKit notifications don't fire.
const IOKIT_GRACE_PERIOD: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Point-in-time detection (safe, uses ioreg)
// ---------------------------------------------------------------------------

/// Check if any camera is currently active by querying IOKit.
///
/// Works on Apple Silicon (`AppleH13CamIn`) and Intel (IOUSB/FaceTime) Macs.
/// Returns `false` if the camera state cannot be determined.
pub fn is_active() -> Result<bool, SensorError> {
    if let Ok(active) = check_apple_silicon_camera() {
        return Ok(active);
    }
    check_intel_camera()
}

/// Discover camera devices and return structured `MediaDevice` info.
pub fn enumerate_cameras() -> Result<Vec<MediaDevice>, SensorError> {
    let mut cameras = Vec::new();

    if let Some(dev) = probe_apple_silicon_camera() {
        cameras.push(dev);
    }
    if let Some(dev) = probe_intel_camera() {
        cameras.push(dev);
    }

    if cameras.is_empty() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }
    Ok(cameras)
}

/// Probe Apple Silicon camera via ioreg.
fn probe_apple_silicon_camera() -> Option<MediaDevice> {
    let output = Command::new("ioreg")
        .args(["-r", "-c", "AppleH13CamIn", "-d", "1"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return None;
    }
    // Extract name from ioreg output if possible.
    let name = extract_ioreg_string(&stdout, "\"IOUserClass\"")
        .or_else(|| extract_ioreg_string(&stdout, "\"IOClass\""))
        .unwrap_or_else(|| "FaceTime HD Camera".into());

    Some(MediaDevice {
        id: 0, // ioreg doesn't give a numeric ID easily
        name,
        uid: "apple-silicon-camera".into(),
        kind: MediaDeviceKind::Camera,
    })
}

/// Probe Intel FaceTime camera via ioreg.
fn probe_intel_camera() -> Option<MediaDevice> {
    let output = Command::new("ioreg")
        .args(["-r", "-c", "IOUSBHostDevice", "-d", "3"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("FaceTime") && !stdout.contains("Camera") {
        return None;
    }
    Some(MediaDevice {
        id: 1,
        name: "FaceTime HD Camera".into(),
        uid: "intel-facetime-camera".into(),
        kind: MediaDeviceKind::Camera,
    })
}

/// Extract a value from ioreg key=value output.
fn extract_ioreg_string(output: &str, key: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix(key)
            && let Some(val) = rest.strip_prefix(" = \"")
        {
            return val.strip_suffix('"').map(String::from);
        }
    }
    None
}

/// Check Apple Silicon camera via ioreg.
fn check_apple_silicon_camera() -> Result<bool, SensorError> {
    let output = Command::new("ioreg")
        .args(["-r", "-c", "AppleH13CamIn", "-d", "1"])
        .output()
        .map_err(|_| SensorError::NoDevice { kind: "camera" })?;

    if !output.status.success() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    Ok(stdout.contains("\"DeviceInUseByAnotherApplication\" = Yes")
        || stdout.contains("\"HardwareInUse\" = Yes"))
}

/// Check Intel Mac camera via FaceTime Camera class.
fn check_intel_camera() -> Result<bool, SensorError> {
    let output = Command::new("ioreg")
        .args(["-r", "-c", "IOUSBHostDevice", "-d", "3"])
        .output()
        .map_err(|_| SensorError::NoDevice { kind: "camera" })?;

    if !output.status.success() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("FaceTime") && !stdout.contains("Camera") {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    Ok(stdout.contains("\"sessionCount\" = ") && !stdout.contains("\"sessionCount\" = 0"))
}

// ---------------------------------------------------------------------------
// Real-time monitoring
// ---------------------------------------------------------------------------

/// RAII guard for camera monitoring.
///
/// Attempts IOKit interest notifications for instant callbacks. Falls back
/// to ioreg polling (every 5s) if IOKit notifications don't fire.
pub struct CameraMonitor {
    /// Signal the monitoring thread to stop.
    stop: Arc<AtomicBool>,
    /// Join handle for the monitoring thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CameraMonitor {
    /// Start monitoring camera state changes.
    ///
    /// Tries IOKit notifications first. Falls back to polling if they
    /// don't work (detected after a 10-second grace period).
    pub fn start(sender: mpsc::Sender<SensorEvent>) -> Result<Self, SensorError> {
        let cameras = enumerate_cameras()?;
        let primary = cameras
            .into_iter()
            .next()
            .ok_or(SensorError::NoDevice { kind: "camera" })?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        let thread = std::thread::Builder::new()
            .name("camera-monitor".into())
            .spawn(move || {
                camera_monitor_thread(stop_clone, sender, primary);
            })
            .map_err(|_| SensorError::NoDevice { kind: "camera" })?;

        tracing::info!("camera monitor started");

        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for CameraMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        tracing::info!("camera monitor stopped");
    }
}

/// Main camera monitoring thread function.
///
/// Tries IOKit notifications, falls back to polling.
/// Takes ownership because it runs in a `move` closure on a spawned thread.
#[allow(clippy::needless_pass_by_value)]
fn camera_monitor_thread(
    stop: Arc<AtomicBool>,
    sender: mpsc::Sender<SensorEvent>,
    device: MediaDevice,
) {
    // Try IOKit notification path.
    if let Some(()) = try_iokit_monitor(&stop, &sender, &device) {
        return; // IOKit monitoring ran successfully until stop.
    }

    // Fallback: polling path.
    tracing::warn!("IOKit camera notifications unavailable, falling back to polling");
    poll_camera_state(&stop, &sender, &device);
}

/// Attempt IOKit interest notification monitoring.
///
/// Returns `Some(())` if IOKit monitoring ran until stop signal.
/// Returns `None` if IOKit notifications don't seem to work.
fn try_iokit_monitor(
    stop: &Arc<AtomicBool>,
    sender: &mpsc::Sender<SensorEvent>,
    device: &MediaDevice,
) -> Option<()> {
    let class_name = std::ffi::CString::new("AppleH13CamIn").ok()?;

    // SAFETY: IOServiceMatching takes a C string and returns a matching dict.
    // The dict is consumed by IOServiceGetMatchingServices (we don't release it).
    let matching = unsafe { ffi_iokit::IOServiceMatching(class_name.as_ptr()) };
    if matching.is_null() {
        return None;
    }

    let mut iterator: ffi_iokit::io_iterator_t = 0;
    // SAFETY: K_IO_MAIN_PORT_DEFAULT is always valid. `matching` is consumed.
    // `iterator` is a valid stack variable.
    let kr = unsafe {
        ffi_iokit::IOServiceGetMatchingServices(
            ffi_iokit::K_IO_MAIN_PORT_DEFAULT,
            matching,
            &raw mut iterator,
        )
    };
    if kr != ffi_iokit::KERN_SUCCESS || iterator == 0 {
        return None;
    }

    // Get the first matched service.
    // SAFETY: `iterator` is valid from successful IOServiceGetMatchingServices.
    let service = unsafe { ffi_iokit::IOIteratorNext(iterator) };
    // SAFETY: `iterator` is a valid IOKit object.
    unsafe { ffi_iokit::IOObjectRelease(iterator) };

    if service == 0 {
        return None;
    }

    // Create notification port.
    // SAFETY: K_IO_MAIN_PORT_DEFAULT is always valid.
    let notify_port =
        unsafe { ffi_iokit::IONotificationPortCreate(ffi_iokit::K_IO_MAIN_PORT_DEFAULT) };
    if notify_port.is_null() {
        // SAFETY: `service` is valid.
        unsafe { ffi_iokit::IOObjectRelease(service) };
        return None;
    }

    // Get run loop source.
    // SAFETY: `notify_port` is valid from successful creation.
    let rl_source = unsafe { ffi_iokit::IONotificationPortGetRunLoopSource(notify_port) };
    if rl_source.is_null() {
        // SAFETY: `notify_port` is valid from IONotificationPortCreate above.
        unsafe { ffi_iokit::IONotificationPortDestroy(notify_port) };
        // SAFETY: `service` is valid from IOIteratorNext above.
        unsafe { ffi_iokit::IOObjectRelease(service) };
        return None;
    }

    // Prepare callback context.
    let notification_fired = Arc::new(AtomicBool::new(false));
    let ctx = Box::new(CameraIokitContext {
        sender: sender.clone(),
        device: device.clone(),
        notification_fired: Arc::clone(&notification_fired),
    });
    let refcon = Box::into_raw(ctx).cast::<std::os::raw::c_void>();

    let mut notification: ffi_iokit::io_object_t = 0;
    // SAFETY: All parameters are valid. `refcon` is a heap pointer freed below.
    // `K_IO_GENERAL_INTEREST` is a null-terminated static byte string.
    let kr = unsafe {
        ffi_iokit::IOServiceAddInterestNotification(
            notify_port,
            service,
            ffi_iokit::K_IO_GENERAL_INTEREST.as_ptr().cast(),
            camera_iokit_callback,
            refcon,
            &raw mut notification,
        )
    };

    // SAFETY: `service` is no longer needed.
    unsafe { ffi_iokit::IOObjectRelease(service) };

    if kr != ffi_iokit::KERN_SUCCESS {
        // SAFETY: `refcon` was just created, no callback registered.
        let _ = unsafe { Box::from_raw(refcon.cast::<CameraIokitContext>()) };
        // SAFETY: `notify_port` is valid from IONotificationPortCreate.
        unsafe { ffi_iokit::IONotificationPortDestroy(notify_port) };
        return None;
    }

    // Add source to current thread's run loop.
    // SAFETY: CFRunLoopGetCurrent is always safe from the current thread.
    let run_loop = unsafe { ffi_iokit::CFRunLoopGetCurrent() };
    // SAFETY: `run_loop`, `rl_source`, and `kCFRunLoopDefaultMode` are valid.
    unsafe {
        ffi_iokit::CFRunLoopAddSource(run_loop, rl_source, ffi_iokit::kCFRunLoopDefaultMode);
    }

    // Run the loop, checking stop flag and grace period.
    let start = Instant::now();
    let mut grace_expired = false;

    while !stop.load(Ordering::Relaxed) {
        // SAFETY: `kCFRunLoopDefaultMode` is valid. Run for 1 second max.
        unsafe {
            ffi_iokit::CFRunLoopRunInMode(ffi_iokit::kCFRunLoopDefaultMode, 1.0, 1);
        }

        // After grace period, check if IOKit notifications actually work.
        if !grace_expired && start.elapsed() > IOKIT_GRACE_PERIOD {
            grace_expired = true;
            if !notification_fired.load(Ordering::Relaxed) {
                // Check if camera is actually active — if it is and we got
                // no notification, IOKit interest notifications aren't working.
                if is_active().unwrap_or(false) {
                    tracing::warn!("IOKit interest notifications did not fire during grace period");
                    // Clean up and signal caller to fall back to polling.
                    cleanup_iokit(run_loop, rl_source, notify_port, notification, refcon);
                    return None;
                }
            }
        }
    }

    cleanup_iokit(run_loop, rl_source, notify_port, notification, refcon);
    Some(())
}

/// Context for the IOKit interest notification callback.
struct CameraIokitContext {
    sender: mpsc::Sender<SensorEvent>,
    device: MediaDevice,
    notification_fired: Arc<AtomicBool>,
}

/// IOKit interest notification callback for camera state changes.
///
/// # Safety
///
/// Called by IOKit on a system thread. `refcon` must be a valid pointer to a
/// `CameraIokitContext` created by `Box::into_raw`.
unsafe extern "C" fn camera_iokit_callback(
    refcon: *mut std::os::raw::c_void,
    service: ffi_iokit::io_service_t,
    _message_type: u32,
    _message_argument: *mut std::os::raw::c_void,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `refcon` is a valid `CameraIokitContext`. We borrow only.
        let ctx = unsafe { &*(refcon.cast::<CameraIokitContext>()) };
        ctx.notification_fired.store(true, Ordering::Relaxed);

        // Check both possible property names.
        let in_use = ffi_iokit::iokit_bool_property(service, "HardwareInUse")
            .or_else(|| ffi_iokit::iokit_bool_property(service, "DeviceInUseByAnotherApplication"))
            .unwrap_or(false);

        let event = if in_use {
            SensorEvent::DeviceActivated(ctx.device.clone())
        } else {
            SensorEvent::DeviceDeactivated(ctx.device.clone())
        };
        let _ = ctx.sender.send(event);
    }));
    if result.is_err() {
        tracing::error!("panic in camera IOKit callback — suppressed");
    }
}

/// Clean up IOKit resources.
fn cleanup_iokit(
    run_loop: ffi_iokit::CFRunLoopRef,
    rl_source: ffi_iokit::CFRunLoopSourceRef,
    notify_port: ffi_iokit::IONotificationPortRef,
    notification: ffi_iokit::io_object_t,
    refcon: *mut std::os::raw::c_void,
) {
    // SAFETY: `run_loop` and `rl_source` are valid from our setup.
    unsafe {
        ffi_iokit::CFRunLoopRemoveSource(run_loop, rl_source, ffi_iokit::kCFRunLoopDefaultMode);
    }
    if notification != 0 {
        // SAFETY: `notification` is a valid IOKit object from registration.
        unsafe { ffi_iokit::IOObjectRelease(notification) };
    }
    // SAFETY: `notify_port` is valid from IONotificationPortCreate.
    unsafe { ffi_iokit::IONotificationPortDestroy(notify_port) };
    // SAFETY: `refcon` was created by Box::into_raw, all callbacks are done.
    let _ = unsafe { Box::from_raw(refcon.cast::<CameraIokitContext>()) };
}

/// Fallback: poll camera state via ioreg.
fn poll_camera_state(
    stop: &Arc<AtomicBool>,
    sender: &mpsc::Sender<SensorEvent>,
    device: &MediaDevice,
) {
    let mut last_active = false;

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(POLL_INTERVAL);

        if stop.load(Ordering::Relaxed) {
            break;
        }

        let active = is_active().unwrap_or(false);
        if active != last_active {
            let event = if active {
                SensorEvent::DeviceActivated(device.clone())
            } else {
                SensorEvent::DeviceDeactivated(device.clone())
            };
            if sender.send(event).is_err() {
                break;
            }
            last_active = active;
        }
    }
}

#[cfg(test)]
#[path = "camera_test.rs"]
mod camera_test;
