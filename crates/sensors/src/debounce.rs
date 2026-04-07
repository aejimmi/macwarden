//! Event debouncing for sensor state changes.
//!
//! Absorbs rapid on/off flicker (e.g., FaceTime startup toggling the mic)
//! by suppressing repeated state changes for the same device within a
//! configurable window.
//!
//! `DeviceConnected` and `DeviceDisconnected` events are never debounced —
//! hardware topology changes are always significant.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::{MediaDeviceKind, SensorEvent};

/// Default debounce window.
const DEFAULT_WINDOW: Duration = Duration::from_millis(500);

/// Wraps a `mpsc::Sender<SensorEvent>` with per-device debouncing.
///
/// Thread-safe — can be shared across multiple callback threads via `Arc`.
pub struct DebouncedSender {
    inner: mpsc::Sender<SensorEvent>,
    /// Last event time per device, keyed by (kind, id).
    last_event: Mutex<HashMap<(MediaDeviceKind, u64), Instant>>,
    /// Debounce window duration.
    window: Duration,
}

impl DebouncedSender {
    /// Create a new debounced sender with the default 500ms window.
    pub fn new(sender: mpsc::Sender<SensorEvent>) -> Self {
        Self::with_window(sender, DEFAULT_WINDOW)
    }

    /// Create a new debounced sender with a custom window.
    pub fn with_window(sender: mpsc::Sender<SensorEvent>, window: Duration) -> Self {
        Self {
            inner: sender,
            last_event: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Send a sensor event, applying debounce for state-change events.
    ///
    /// Returns `Err` if the underlying channel is disconnected.
    pub fn send(&self, event: SensorEvent) -> Result<(), mpsc::SendError<SensorEvent>> {
        // Connect/disconnect events are never debounced.
        if matches!(
            event,
            SensorEvent::DeviceConnected(_) | SensorEvent::DeviceDisconnected(_)
        ) {
            return self.inner.send(event);
        }

        let device = event.device();
        let key = (device.kind, device.id);
        let now = Instant::now();

        let should_send = {
            let mut guard = self
                .last_event
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(last) = guard.get(&key)
                && now.duration_since(*last) < self.window
            {
                return Ok(()); // Suppressed.
            }
            guard.insert(key, now);
            true
        };

        if should_send {
            self.inner.send(event)?;
        }
        Ok(())
    }

    /// Get a reference to the underlying sender (for non-debounced use).
    pub fn inner(&self) -> &mpsc::Sender<SensorEvent> {
        &self.inner
    }
}

#[cfg(test)]
#[path = "debounce_test.rs"]
mod debounce_test;
