//! macwarden panel UI — a compact, always-ready network/privacy panel.
//!
//! The data layer ([`data`]) and view-model ([`state`]) are pure Rust and
//! compile on every target so they can be unit-tested in CI. The GPUI view and
//! the live process source are macOS-only and live behind [`run`].

pub mod data;
pub mod state;

#[cfg(target_os = "macos")]
mod ui;

/// Launch the panel window. macOS-only; the binary prints a stub elsewhere.
///
/// Pass `demo = true` for the deterministic demo stream (offline development,
/// stable screenshots); `false` runs against the real machine and daemon.
#[cfg(target_os = "macos")]
pub fn run(demo: bool) {
    ui::launch(demo);
}
