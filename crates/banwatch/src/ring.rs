//! Fixed-capacity ring buffer of failure timestamps.
//!
//! Ported from `fail2ban-rs` `src/track/circular.rs` (`CircularTimestamps`).
//! Capacity equals a detector's `max_retry`. When the buffer is full and the
//! span from oldest to newest is within `find_time`, the ban threshold is
//! reached — an O(1) check. Memory is bounded: pushing past capacity overwrites
//! the oldest entry, the buffer never grows.

/// A fixed-capacity ring buffer of `i64` unix-second timestamps.
#[derive(Debug, Clone)]
pub struct CircularTimestamps {
    buf: Vec<i64>,
    /// Points to the next write position (also the oldest entry when full).
    head: usize,
    len: usize,
}

impl CircularTimestamps {
    /// Create a buffer with the given capacity (typically a detector's
    /// `max_retry`). A zero capacity is inert — it can never reach threshold.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            head: 0,
            len: 0,
        }
    }

    /// Push a timestamp, overwriting the oldest entry when full.
    pub fn push(&mut self, ts: i64) {
        let cap = self.buf.len();
        if cap == 0 {
            return;
        }
        let write_pos = if self.len < cap {
            self.len
        } else {
            let pos = self.head;
            self.head = (self.head + 1) % cap;
            pos
        };
        if let Some(slot) = self.buf.get_mut(write_pos) {
            *slot = ts;
        }
        if self.len < cap {
            self.len += 1;
        }
    }

    /// Clear the buffer (used after a ban fires so the next window starts fresh).
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Whether the buffer has reached its capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }

    /// The oldest timestamp, or `None` when empty.
    #[must_use]
    pub fn oldest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        self.buf.get(self.head).copied()
    }

    /// The newest timestamp, or `None` when empty.
    #[must_use]
    pub fn newest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let cap = self.buf.len();
        let idx = if self.len < cap {
            self.len - 1
        } else {
            (self.head + cap - 1) % cap
        };
        self.buf.get(idx).copied()
    }

    /// Whether the failure threshold is reached: the buffer is full and the span
    /// from oldest to newest is within `find_time` seconds (inclusive window).
    #[must_use]
    pub fn threshold_reached(&self, find_time: i64) -> bool {
        if !self.is_full() {
            return false;
        }
        match (self.oldest(), self.newest()) {
            (Some(old), Some(new)) => (new - old) <= find_time,
            _ => false,
        }
    }

    /// Number of timestamps currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The total capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
#[path = "ring_test.rs"]
mod ring_test;
