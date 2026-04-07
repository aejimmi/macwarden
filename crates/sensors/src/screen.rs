//! Screen capture detection.
//!
//! Detects active screen recording via two signals:
//! - `CGDisplayIsBeingMirrored` (public CoreGraphics API)
//! - Process scanning for `screencaptureui` (macOS screenshot/recording UI)
//!
//! No private APIs, no TCC requirement for detection itself.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::error::SensorError;
use crate::{MediaDevice, MediaDeviceKind, SensorEvent};

/// Polling interval for screen capture detection.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// FFI — CoreGraphics display mirroring
// ---------------------------------------------------------------------------

/// CoreGraphics display ID type.
type CGDirectDisplayID = u32;

#[cfg_attr(target_os = "macos", link(name = "CoreGraphics", kind = "framework"))]
unsafe extern "C" {
    fn CGMainDisplayID() -> CGDirectDisplayID;
    fn CGDisplayMirrorsDisplay(display: CGDirectDisplayID) -> CGDirectDisplayID;
}

/// Null/invalid display constant (no mirroring).
const K_CG_NULL_DIRECT_DISPLAY: CGDirectDisplayID = 0;

// ---------------------------------------------------------------------------
// Point-in-time detection
// ---------------------------------------------------------------------------

/// Check if screen recording is currently active.
///
/// Uses two heuristics:
/// 1. Main display is being mirrored (captured) via CoreGraphics
/// 2. `screencaptureui` process is running (Cmd+Shift+5 recording)
#[must_use]
pub fn is_active() -> bool {
    if is_display_mirrored() {
        return true;
    }
    is_screencapture_running()
}

/// Check if the main display is being mirrored/captured.
fn is_display_mirrored() -> bool {
    // SAFETY: CGMainDisplayID returns a plain integer, no side effects.
    let main_display = unsafe { CGMainDisplayID() };
    // SAFETY: CGDisplayMirrorsDisplay takes and returns plain integers.
    let mirror = unsafe { CGDisplayMirrorsDisplay(main_display) };
    mirror != K_CG_NULL_DIRECT_DISPLAY
}

/// Check if `screencaptureui` is running (macOS screenshot/recording UI).
fn is_screencapture_running() -> bool {
    let output = Command::new("pgrep")
        .args(["-x", "screencaptureui"])
        .output();
    matches!(output, Ok(o) if o.status.success())
}

/// Build a `MediaDevice` representing the main screen.
fn screen_device() -> MediaDevice {
    // SAFETY: CGMainDisplayID returns a plain integer.
    let display_id = unsafe { CGMainDisplayID() };
    MediaDevice {
        id: u64::from(display_id),
        name: "Main Display".into(),
        uid: format!("display-{display_id}"),
        kind: MediaDeviceKind::Screen,
    }
}

// ---------------------------------------------------------------------------
// Real-time monitoring
// ---------------------------------------------------------------------------

/// RAII guard for screen capture monitoring.
///
/// Polls every 5 seconds for screen recording activity.
pub struct ScreenMonitor {
    /// Signal the polling thread to stop.
    stop: Arc<AtomicBool>,
    /// Join handle for the polling thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScreenMonitor {
    /// Start monitoring screen capture state.
    pub fn start(sender: mpsc::Sender<SensorEvent>) -> Result<Self, SensorError> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let device = screen_device();

        let thread = std::thread::Builder::new()
            .name("screen-monitor".into())
            .spawn(move || {
                let mut last_active = false;

                while !stop_clone.load(Ordering::Relaxed) {
                    std::thread::sleep(POLL_INTERVAL);

                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }

                    let active = is_active();
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
            })
            .map_err(|_| SensorError::DeviceEnumeration {
                reason: "failed to spawn screen monitor thread",
            })?;

        tracing::info!("screen capture monitor started (polling every 5s)");

        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ScreenMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        tracing::info!("screen capture monitor stopped");
    }
}

#[cfg(test)]
#[path = "screen_test.rs"]
mod screen_test;
