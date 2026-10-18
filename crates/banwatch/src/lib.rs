//! Inbound scanner / bruteforce protection for macwarden (spec 010).
//!
//! A fail2ban-style ban-state engine, ported from `~/code/fail2ban-rs`'s
//! `src/track`, that protects **inbound** listening services from scanners and
//! bruteforce. It keeps per-IP ring-buffer failure counters (`max_retry` within
//! `find_time`), escalating temp bans (`ban_time_increment` + multipliers +
//! `maxtime`), quiet-period escalation decay (`ban_count_decay`), `ignoreip`
//! with private/loopback/self defaults, and a crash-safe etch-backed active-ban
//! store — and drives enforcement through the **existing NE path**: bans are
//! composed into the shared `net::RuleSet` as reserved-band per-IP Deny rules
//! (see `net::loader`), so a banned scanner's flow to a listening service is
//! dropped with zero extra privilege.
//!
//! The crate is **pure Rust with zero platform deps** and Linux-CI testable. The
//! platform-touching sources — the `log stream` subprocess, the BPF capture
//! feed, and the daemon's own verdict stream — live in the daemon and feed typed
//! [`record::Signal`]s into the [`engine::Engine`]; the [`detect`] analyzers are
//! the total, panic-free parse boundary over attacker-influenced input.
//!
//! # Modules
//!
//! - [`config`] — `banwatch.toml` parsing (fail-open to defaults).
//! - [`duration`] — the `1h`/`30d`/`0` duration-string parser.
//! - [`ring`] — the fixed-capacity failure-timestamp ring buffer.
//! - [`ban_calc`] — escalating ban-time calculation.
//! - [`ignore`] — `ignoreip` CIDR matching + private/loopback/self defaults.
//! - [`record`] — ban records, escalation counters, signals, and events.
//! - [`persist`] — the etch-backed active-ban store + the total read surface
//!   `net::loader` composes.
//! - [`engine`] — the single-owner ban-state engine.
//! - [`detect`] — the curated `repeat-blocked` / `auth-failure` / `port-scan`
//!   analyzers.

pub mod ban_calc;
pub mod config;
pub mod detect;
pub mod duration;
pub mod engine;
pub mod error;
pub mod ignore;
pub mod persist;
pub mod record;
pub mod ring;

pub use config::BanwatchConfig;
pub use engine::Engine;
pub use error::{BanwatchError, Result};
pub use persist::{active_ban_ips, active_ban_records};
pub use record::{BanEvent, BanRecord, BanSource, Signal};

/// Current wall-clock time in whole unix seconds.
///
/// A clock before the epoch (impossible in practice) yields `0` rather than
/// panicking.
#[must_use]
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
