//! Bounded capture buffering (spec R6) — a drop-oldest ring and a rate limiter.
//!
//! Both types are **pure and deterministic** (no clock, no I/O) so the R6
//! bounding logic is unit-tested without a live capture. A busy or hostile app
//! must never OOM the daemon, so the ring caps both the packet **count** and the
//! total retained **raw bytes**; on overflow the *oldest* records are evicted
//! and a monotonic `dropped` counter increments (surfaced to the UI rather than
//! silently lost). The [`RateLimiter`] bounds packets processed per unit time so
//! a flood cannot peg CPU.

use crate::parse::PacketRecord;
use std::collections::VecDeque;

/// Default retained packet count per trace.
pub const DEFAULT_MAX_PACKETS: usize = 4096;

/// Default retained raw-byte budget (64 MiB) — well above any single snaplen so
/// one packet always fits.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// A snapshot of the ring's occupancy and lifetime drop count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingStats {
    /// Records currently retained.
    pub retained: usize,
    /// Total retained raw bytes.
    pub retained_bytes: usize,
    /// Records evicted over the ring's lifetime (overflow drop-with-count).
    pub dropped: u64,
}

/// A bounded, drop-oldest ring of [`PacketRecord`]s keyed by ascending `seq`.
///
/// Invariants after every [`push`](Self::push): `retained <= max_packets` and,
/// except for the degenerate case of a single packet larger than the whole
/// budget, `retained_bytes <= max_bytes`. Records are always in ascending `seq`
/// order (the caller assigns monotonic sequence numbers), so lookup is a binary
/// search.
#[derive(Debug)]
pub struct PacketRing {
    buf: VecDeque<PacketRecord>,
    max_packets: usize,
    max_bytes: usize,
    cur_bytes: usize,
    dropped: u64,
}

impl PacketRing {
    /// Build a ring bounded by `max_packets` records and `max_bytes` raw bytes.
    /// Both bounds are clamped to at least 1 so the ring can always hold the
    /// most recent packet.
    #[must_use]
    pub fn new(max_packets: usize, max_bytes: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            max_packets: max_packets.max(1),
            max_bytes: max_bytes.max(1),
            cur_bytes: 0,
            dropped: 0,
        }
    }

    /// Build a ring with the crate defaults ([`DEFAULT_MAX_PACKETS`] /
    /// [`DEFAULT_MAX_BYTES`]).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_PACKETS, DEFAULT_MAX_BYTES)
    }

    /// Push a record, evicting the oldest entries (and bumping `dropped`) until
    /// both the count and byte budgets are satisfied. Never blocks and never
    /// grows unboundedly — this is what keeps a slow consumer from stalling
    /// capture (spec R6/R10).
    pub fn push(&mut self, record: PacketRecord) {
        self.cur_bytes = self.cur_bytes.saturating_add(record.raw.len());
        self.buf.push_back(record);
        while self.buf.len() > 1 && self.over_budget() {
            if let Some(old) = self.buf.pop_front() {
                self.cur_bytes = self.cur_bytes.saturating_sub(old.raw.len());
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }

    fn over_budget(&self) -> bool {
        self.buf.len() > self.max_packets || self.cur_bytes > self.max_bytes
    }

    /// Look up a retained record by its sequence number, or `None` if it was
    /// never captured or has been evicted (spec R6: fetching an evicted `seq`
    /// returns "not available" rather than panicking).
    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&PacketRecord> {
        let idx = self.buf.binary_search_by(|r| r.seq.cmp(&seq)).ok()?;
        self.buf.get(idx)
    }

    /// The raw bytes for a retained record, or `None` if unavailable.
    #[must_use]
    pub fn bytes(&self, seq: u64) -> Option<&[u8]> {
        self.get(seq).map(|r| r.raw.as_slice())
    }

    /// Remove and return all retained records (oldest first), resetting the
    /// byte accounting. The `dropped` counter is preserved across drains.
    pub fn drain(&mut self) -> Vec<PacketRecord> {
        self.cur_bytes = 0;
        self.buf.drain(..).collect()
    }

    /// Clone all retained records without removing them (oldest first).
    #[must_use]
    pub fn snapshot(&self) -> Vec<PacketRecord> {
        self.buf.iter().cloned().collect()
    }

    /// Records evicted over the ring's lifetime.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Number of records currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the ring holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// A snapshot of occupancy and lifetime drops.
    #[must_use]
    pub fn stats(&self) -> RingStats {
        RingStats {
            retained: self.buf.len(),
            retained_bytes: self.cur_bytes,
            dropped: self.dropped,
        }
    }
}

/// A fixed-window rate limiter: at most `max_per_window` events per one-second
/// window. Pure — the caller supplies a monotonic `now_nanos`, so behaviour is
/// deterministic and testable. `max_per_sec == 0` means **unlimited**.
#[derive(Debug)]
pub struct RateLimiter {
    max_per_window: u32,
    window_nanos: u64,
    window_start: u64,
    count: u32,
    dropped: u64,
}

impl RateLimiter {
    /// Build a limiter allowing `max_per_sec` events per second (`0` =
    /// unlimited).
    #[must_use]
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_window: max_per_sec,
            window_nanos: 1_000_000_000,
            window_start: 0,
            count: 0,
            dropped: 0,
        }
    }

    /// Record an event at `now_nanos` and report whether it is allowed. When the
    /// window budget is exhausted the event is denied and the `dropped` counter
    /// increments (the caller treats a denial as a drop-with-count).
    pub fn allow(&mut self, now_nanos: u64) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        if now_nanos.saturating_sub(self.window_start) >= self.window_nanos {
            self.window_start = now_nanos;
            self.count = 0;
        }
        if self.count < self.max_per_window {
            self.count += 1;
            true
        } else {
            self.dropped = self.dropped.saturating_add(1);
            false
        }
    }

    /// Events denied over the limiter's lifetime.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
#[path = "ring_test.rs"]
mod ring_test;
