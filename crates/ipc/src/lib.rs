//! Daemon↔panel IPC protocol for macwarden.
//!
//! This crate is the frozen wire boundary between the macwarden daemon (runs as
//! **root** to hold the Endpoint Security entitlement) and the GPUI panel
//! (`macwarden-ui`, runs as the **user**). It is deliberately **pure Rust with
//! serde only** — no `gpui`, `net`, `es`, or `metrics` — so panel and daemon
//! link the same types and it unit-tests on Linux CI without a socket or root.
//! The only platform dependency is `libc::getpeereid`, isolated behind
//! `cfg(unix)` in [`server`].
//!
//! Modules:
//! - [`protocol`] — [`protocol::Request`]/[`protocol::Response`]/[`protocol::Event`]
//!   enums, the wire DTOs mirroring `macwarden-ui`'s `model.rs`,
//!   [`protocol::Capability`], error kinds, and [`protocol::PROTOCOL_VERSION`].
//! - [`codec`] — newline-delimited JSON framing over any `Read`/`Write`, with a
//!   `MAX_FRAME` bound. Pure; exercisable over a `Cursor`.
//! - [`client`] — blocking connect + `Hello`/`Welcome` handshake + socket-owner
//!   check, returning the typed [`client::Selection`] result. The decision core
//!   is pure and injectable; the real socket connect is behind `cfg(unix)`.
//! - [`server`] (`cfg(unix)`) — accept helper + `getpeereid` uid pre-gate
//!   (Layer 1 of R2), plus the typed seam where the macOS code-signature check
//!   (Layer 2) grafts in.
//! - [`validate`] — R9 boundary validators (hostname, code id, team id, expiry,
//!   rules-dir path guard) as pure functions.

pub mod client;
pub mod codec;
pub mod protocol;
pub mod validate;

#[cfg(unix)]
pub mod server;
