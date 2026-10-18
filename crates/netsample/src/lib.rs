//! Shared `nettop` sampling for macwarden.
//!
//! `nettop -x -J bytes_in,bytes_out -l 1` is the richest source of per-process,
//! per-connection network telemetry available without root on macOS. Both the
//! daemon's live-connection scanner and the panel's live source consume it, so
//! the parser and the subprocess spawn live here — one implementation, no drift.
//!
//! [`parse`] is deliberately platform-neutral and side-effect free so it can be
//! unit-tested on any target, including Linux CI. The impure [`sample`] that
//! spawns the subprocess is gated to macOS and returns an empty set elsewhere.

mod parse;
mod sample;

pub use parse::{Conn, ProcNet, parse};
pub use sample::sample;
