//! `enforce-ne-ffi` — the C-ABI decision core for the macwarden
//! NetworkExtension content filter.
//!
//! # Why this crate exists
//!
//! macOS's official, SIP-on, no-kext network-firewall path is a
//! `NEFilterDataProvider` content-filter **system extension**. The sysext runs
//! sandboxed in its own process and must decide allow/deny for every new flow
//! in sub-millisecond time. It cannot round-trip to the macwarden daemon per
//! flow (XPC latency, and the sandbox forbids it), so the decision must happen
//! **in-process**. This crate is that in-process core: it embeds the same
//! [`net::RuleSet`] the daemon uses, loaded from the same `~/.macwarden/` files
//! via the shared [`net::loader`], and answers a verdict over a tiny C ABI the
//! Swift provider links as a static library.
//!
//! Single source of truth: every verdict comes from
//! [`net::RuleSet::decide_for`] — this crate never forks matching logic. The
//! daemon and this core compose an identical rule set from identical files, so
//! their verdicts cannot diverge.
//!
//! # Shape
//!
//! - [`decision`] — pure input mapping + [`net::RuleSet`] consultation (no I/O).
//! - [`handle`] — the opaque [`MacwardenNe`] handle with an
//!   [`arc_swap::ArcSwap`]'d rule set for lock-free reads and atomic reloads.
//! - [`ffi`] — the `extern "C"` surface, panic-guarded to fail open.
//!
//! # C ABI
//!
//! See `include/macwarden_ne.h` (hand-written; see the crate README note). The
//! functions:
//!
//! ```c
//! MacwardenNe *macwarden_ne_init(void);
//! MacwardenNe *macwarden_ne_init_at(const char *dir);
//! int32_t      macwarden_ne_decide(const MacwardenNe *h,
//!                                  const char *code_id, const char *path,
//!                                  const char *host, const char *ip,
//!                                  uint16_t port, uint8_t proto);
//! bool         macwarden_ne_reload(const MacwardenNe *h);
//! void         macwarden_ne_free(MacwardenNe *h);
//! ```
//!
//! # Safety / robustness
//!
//! - **Thread-safe.** `handleNewFlow` is called concurrently; decisions take a
//!   lock-free `ArcSwap::load`, reloads swap atomically. No lock is held across
//!   a decision.
//! - **Fail-open.** No panic ever crosses the FFI boundary: `catch_unwind`
//!   wraps every entry point and maps a caught panic to ALLOW (decisions) or
//!   null/false (lifecycle), matching the daemon's fail-open policy so a bug in
//!   enforcement cannot deny-of-service the user's connectivity.
//! - **No hot-path I/O.** `decide` performs no filesystem or network I/O; only
//!   `init`/`reload` read the snapshot files.

// This crate is the C-ABI boundary for the Swift system extension: `extern "C"`
// entry points, `#[no_mangle]` symbols, and raw-pointer handles are its entire
// reason to exist. Every `unsafe` block still carries a `// SAFETY:` note
// (`undocumented_unsafe_blocks` stays deny), but the blanket `unsafe_code`
// warning is expected here and allowed crate-wide.
#![allow(unsafe_code)]

pub mod decision;
pub mod error;
pub mod ffi;
pub mod handle;

pub use decision::{NeDecision, decide};
pub use error::NeError;
pub use ffi::{
    macwarden_ne_decide, macwarden_ne_free, macwarden_ne_init, macwarden_ne_init_at,
    macwarden_ne_reload,
};
pub use handle::MacwardenNe;
