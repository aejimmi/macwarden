//! Daemon-side runtime modules that run alongside the enforcement monitor.
//!
//! [`ipc_server`] is the Phase 10 IPC server: it owns an `Arc`-swappable live
//! [`net::RuleSet`], fuses live connections with per-destination verdicts into
//! the frozen `ipc` wire DTOs, answers history from the metrics store, and
//! hot-reloads rules on mutation. It is started foreground via `macwarden serve`
//! and alongside the enforcement loop by `macwarden watch`.

pub mod enforcement;
pub mod ipc_server;
