//! Safe camera monitoring.
//!
//! Point-in-time detection uses `ioreg` to query the IOKit device tree.
//! This is safe and works across all macOS versions without risk of crashes.
//!
//! Real-time monitoring via CoreMediaIO is available but experimental —
//! Apple's CMIO C API crashes (SIGSEGV) on macOS Sequoia+ without proper
//! framework initialization that may require specific entitlements.
//!
//! Future work: investigate IOKit `IOServiceAddInterestNotification` for
//! real-time camera state callbacks without CoreMediaIO dependency.

use std::process::Command;
use std::sync::mpsc;

use crate::SensorEvent;
use crate::error::SensorError;

// ---------------------------------------------------------------------------
// Point-in-time detection (safe, uses ioreg)
// ---------------------------------------------------------------------------

/// Check if any camera is currently active by querying IOKit.
///
/// Works on Apple Silicon (AppleH13CamIn) and Intel (IOUSB/FaceTime) Macs.
/// Returns `false` if the camera state cannot be determined.
pub fn is_active() -> Result<bool, SensorError> {
    // Try Apple Silicon first, then Intel.
    if let Ok(active) = check_apple_silicon_camera() {
        return Ok(active);
    }
    check_intel_camera()
}

/// Check Apple Silicon camera (AppleH13CamIn) via ioreg.
///
/// When the camera is active, the device's `"HardwareInUse"` property is set.
fn check_apple_silicon_camera() -> Result<bool, SensorError> {
    let output = Command::new("ioreg")
        .args(["-r", "-c", "AppleH13CamIn", "-d", "1"])
        .output()
        .map_err(|_| SensorError::NoDevice { kind: "camera" })?;

    if !output.status.success() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Empty output means no Apple Silicon camera exists.
    if stdout.trim().is_empty() {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    // Camera is active when IOKit reports it as in use.
    // Check for common activity indicators in the ioreg output.
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

    // Look for FaceTime camera with active state.
    if !stdout.contains("FaceTime") && !stdout.contains("Camera") {
        return Err(SensorError::NoDevice { kind: "camera" });
    }

    Ok(stdout.contains("\"sessionCount\" = ")
        && !stdout.contains("\"sessionCount\" = 0"))
}

// ---------------------------------------------------------------------------
// Real-time monitoring (placeholder — CMIO unstable on Sequoia+)
// ---------------------------------------------------------------------------

/// RAII guard for camera monitoring.
///
/// Current implementation polls via ioreg on a background thread.
/// Future: IOKit interest notifications for instant callbacks.
pub struct CameraMonitor {
    /// Signal the polling thread to stop.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Join handle for the polling thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CameraMonitor {
    /// Start monitoring camera state changes.
    ///
    /// Polls every 2 seconds via ioreg. Sends events when state changes.
    /// This is a temporary approach until IOKit notifications are implemented.
    pub fn start(sender: mpsc::Sender<SensorEvent>) -> Result<Self, SensorError> {
        // Verify we can read camera state at all.
        let _ = is_active()?;

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();

        let thread = std::thread::Builder::new()
            .name("camera-monitor".into())
            .spawn(move || {
                let mut last_active = false;

                while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    let active = is_active().unwrap_or(false);
                    if active != last_active {
                        let event = if active {
                            SensorEvent::CameraActivated
                        } else {
                            SensorEvent::CameraDeactivated
                        };
                        // Best-effort send.
                        if sender.send(event).is_err() {
                            break;
                        }
                        last_active = active;
                    }
                }
            })
            .map_err(|_| SensorError::NoDevice { kind: "camera" })?;

        tracing::info!("camera monitor started (polling every 2s)");

        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for CameraMonitor {
    fn drop(&mut self) {
        self.stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        tracing::info!("camera monitor stopped");
    }
}

#[cfg(test)]
#[path = "camera_test.rs"]
mod camera_test;
