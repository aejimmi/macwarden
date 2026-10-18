//! The `repeat-blocked` detector: bans an IP that accrues repeated **deny**
//! verdicts from the daemon's own connection stream.
//!
//! This is the no-privilege, default-on detector — it needs no root, no BPF, and
//! no unified-log access, only the `ConnectionDecided` verdicts the daemon
//! already produces. The analyzer itself is a trivial, total mapper: a denied
//! flow's remote IP becomes one failure signal; an allowed flow produces
//! nothing. The engine's ring buffer does the `max_retry`-within-`find_time`
//! counting.

use std::net::IpAddr;

use crate::record::{DETECTOR_REPEAT_BLOCKED, Signal};

/// Map one connection verdict to a failure signal.
///
/// Returns `Some` only for a **denied** flow, keyed on its remote endpoint IP;
/// an allowed flow returns `None`.
#[must_use]
pub fn on_verdict(remote_ip: IpAddr, allowed: bool) -> Option<Signal> {
    if allowed {
        return None;
    }
    Some(Signal::new(remote_ip, DETECTOR_REPEAT_BLOCKED))
}

#[cfg(test)]
#[path = "repeat_verdict_test.rs"]
mod repeat_verdict_test;
