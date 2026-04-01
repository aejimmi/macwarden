// FFI crate — unsafe is expected and isolated in ffi.rs.
// Every unsafe block still requires a SAFETY comment (undocumented_unsafe_blocks = deny).
#![allow(unsafe_code)]

//! Real-time camera and microphone hardware monitoring.
//!
//! Provides safe Rust wrappers around macOS CoreAudio and CoreMediaIO
//! frameworks for detecting when camera and microphone hardware is accessed.
//!
//! # Security design
//!
//! All FFI (`unsafe`) code is isolated in the private `ffi` module. The public
//! API exposes only safe types and functions. Each `unsafe` block documents its
//! safety invariants. Callbacks use `catch_unwind` to prevent panics from
//! crossing the C FFI boundary.
//!
//! ```text
//! ┌─────────────────────────────┐
//! │  lib.rs   (safe public API) │
//! ├─────────────────────────────┤
//! │  camera.rs / microphone.rs  │  ← safe wrappers
//! ├─────────────────────────────┤
//! │  ffi.rs   (pub(crate) only) │  ← ALL unsafe lives here
//! ├─────────────────────────────┤
//! │  CoreAudio / CoreMediaIO    │  ← system frameworks
//! └─────────────────────────────┘
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
//! let _mic = sensors::microphone::MicMonitor::start(tx.clone());
//! let _cam = sensors::camera::CameraMonitor::start(tx);
//!
//! for event in rx {
//!     match event {
//!         SensorEvent::CameraActivated => println!("camera on"),
//!         SensorEvent::CameraDeactivated => println!("camera off"),
//!         SensorEvent::MicrophoneActivated => println!("mic on"),
//!         SensorEvent::MicrophoneDeactivated => println!("mic off"),
//!     }
//! }
//! ```

pub mod camera;
pub mod error;
pub mod microphone;

// Raw FFI bindings — internal only. Never exposed outside this crate.
pub(crate) mod ffi;

/// An event emitted when camera or microphone hardware state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorEvent {
    /// A camera device was activated (some process started using it).
    CameraActivated,
    /// A camera device was deactivated (all processes stopped using it).
    CameraDeactivated,
    /// A microphone was activated (some process started using it).
    MicrophoneActivated,
    /// A microphone was deactivated (all processes stopped using it).
    MicrophoneDeactivated,
}
