// FFI crate — unsafe is expected and isolated in ffi.rs / ffi_iokit.rs.
// Every unsafe block still requires a SAFETY comment (undocumented_unsafe_blocks = deny).
#![allow(unsafe_code)]

//! Real-time camera, microphone, screen capture, and WiFi network monitoring.
//!
//! Provides safe Rust wrappers around macOS CoreAudio, IOKit, CoreGraphics,
//! and CoreWLAN frameworks for detecting hardware sensor access and network state.
//!
//! # Security design
//!
//! All FFI (`unsafe`) code is isolated in private `ffi` and `ffi_iokit` modules.
//! The public API exposes only safe types and functions. Each `unsafe` block
//! documents its safety invariants. Callbacks use `catch_unwind` to prevent
//! panics from crossing the C FFI boundary.
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  lib.rs               (safe public API)         │
//! ├─────────────────────────────────────────────────┤
//! │  camera / microphone / screen / wifi / context  │  ← safe wrappers
//! ├─────────────────────────────────────────────────┤
//! │  ffi.rs / ffi_iokit.rs / ffi_corewlan.rs        │  ← ALL unsafe here
//! ├─────────────────────────────────────────────────┤
//! │  CoreAudio / IOKit / CoreGraphics / CoreWLAN    │  ← system frameworks
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! Point-in-time check:
//! ```no_run
//! let mic_on = sensors::microphone::is_active().unwrap_or(false);
//! let cam_on = sensors::camera::is_active().unwrap_or(false);
//! ```
//!
//! Real-time monitoring:
//! ```no_run
//! use std::sync::mpsc;
//! use sensors::SensorEvent;
//!
//! let (tx, rx) = mpsc::channel();
//! let _mic = sensors::microphone::MicMonitor::start(&tx);
//! let _cam = sensors::camera::CameraMonitor::start(tx);
//!
//! for event in rx {
//!     match event {
//!         SensorEvent::DeviceActivated(ref d) => {
//!             println!("{:?} {} activated", d.kind, d.name);
//!         }
//!         SensorEvent::DeviceDeactivated(ref d) => {
//!             println!("{:?} {} deactivated", d.kind, d.name);
//!         }
//!         _ => {}
//!     }
//! }
//! ```

pub mod camera;
pub mod debounce;
pub mod error;
pub mod microphone;
pub mod network_context;
pub mod power;
pub mod screen;
pub mod wifi;

// Raw FFI bindings — internal only. Never exposed outside this crate.
pub(crate) mod ffi;
pub(crate) mod ffi_corewlan;
#[allow(non_camel_case_types)]
pub(crate) mod ffi_iokit;

pub use network_context::NetworkContext;
pub use wifi::WifiInfo;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Kind of hardware sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MediaDeviceKind {
    /// Camera (FaceTime, USB webcam, etc.).
    Camera,
    /// Microphone (built-in, AirPods, USB audio, etc.).
    Microphone,
    /// Screen capture (screen recording, mirroring).
    Screen,
}

impl std::fmt::Display for MediaDeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Camera => write!(f, "camera"),
            Self::Microphone => write!(f, "microphone"),
            Self::Screen => write!(f, "screen"),
        }
    }
}

/// A specific hardware device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MediaDevice {
    /// OS-assigned device ID (`AudioObjectID` for mic, IOKit registry ID for camera).
    pub id: u64,
    /// Human-readable name (e.g., "FaceTime HD Camera", "MacBook Pro Microphone").
    pub name: String,
    /// Stable unique identifier (persists across reboots). May be empty if unavailable.
    pub uid: String,
    /// Camera or Microphone.
    pub kind: MediaDeviceKind,
}

/// An event emitted when hardware sensor state changes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum SensorEvent {
    /// A device started being used by some process.
    DeviceActivated(MediaDevice),
    /// A device stopped being used by all processes.
    DeviceDeactivated(MediaDevice),
    /// A new device was connected (plugged in).
    DeviceConnected(MediaDevice),
    /// A device was disconnected (unplugged).
    DeviceDisconnected(MediaDevice),
}

impl SensorEvent {
    /// Get a reference to the device associated with this event.
    #[must_use]
    pub fn device(&self) -> &MediaDevice {
        match self {
            Self::DeviceActivated(d)
            | Self::DeviceDeactivated(d)
            | Self::DeviceConnected(d)
            | Self::DeviceDisconnected(d) => d,
        }
    }
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod lib_test;
