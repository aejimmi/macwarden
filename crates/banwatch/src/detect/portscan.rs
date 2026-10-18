//! The `port-scan` detector: bans an IP that touches many distinct local ports
//! or sprays SYNs within a window.
//!
//! Fed by typed `(remote_ip, local_port, is_syn)` events from the daemon's BPF
//! capture path — never raw bytes (the `capture` parse core already renders
//! attacker headers total). The detector keeps a bounded, time-evicted event
//! window per remote IP; when either the distinct-port or SYN-count threshold is
//! crossed it emits one signal and resets that IP's window, so it fires once per
//! burst rather than per packet. Memory is bounded by a per-IP event cap and a
//! total-IP cap — flooding the map cannot grow it without limit.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;

use crate::record::{DETECTOR_PORT_SCAN, Signal};

/// Hard cap on tracked source IPs. Beyond this, new IPs are not tracked until
/// the sweep prunes idle windows — bounding the map against a spray of spoofed
/// sources.
const MAX_TRACKED_IPS: usize = 4_096;

/// Hard cap on retained events per IP. A window reaching this without tripping a
/// threshold drops its oldest event (ring behavior), so a single IP's window is
/// always bounded regardless of rate.
const MAX_EVENTS_PER_IP: usize = 2_048;

/// One observed packet within a source IP's window.
#[derive(Debug, Clone, Copy)]
struct PortEvent {
    at: i64,
    port: u16,
    is_syn: bool,
}

/// A per-source-IP sliding window of recent port touches.
#[derive(Debug, Default)]
struct PortWindow {
    events: VecDeque<PortEvent>,
}

/// The windowed port-scan detector.
#[derive(Debug)]
pub struct PortScanDetector {
    enabled: bool,
    distinct_ports: u32,
    syn_rate: u32,
    find_time: i64,
    tracked: HashMap<IpAddr, PortWindow>,
}

impl PortScanDetector {
    /// Build a detector from resolved thresholds. A `distinct_ports`/`syn_rate`
    /// of `0` disables that criterion; both zero (or `enabled = false`) makes the
    /// detector inert.
    #[must_use]
    pub fn new(enabled: bool, distinct_ports: u32, syn_rate: u32, find_time: i64) -> Self {
        Self {
            enabled,
            distinct_ports,
            syn_rate,
            find_time,
            tracked: HashMap::new(),
        }
    }

    /// Whether the detector will act on events at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && (self.distinct_ports > 0 || self.syn_rate > 0)
    }

    /// Observe one packet. Returns a [`Signal`] when the source crosses a
    /// threshold within the window (and resets that source's window).
    #[must_use]
    pub fn observe(&mut self, ip: IpAddr, port: u16, is_syn: bool, now: i64) -> Option<Signal> {
        if !self.is_active() {
            return None;
        }
        if !self.tracked.contains_key(&ip) && self.tracked.len() >= MAX_TRACKED_IPS {
            return None;
        }
        let window = self.tracked.entry(ip).or_default();
        push_event(
            window,
            PortEvent {
                at: now,
                port,
                is_syn,
            },
        );
        evict_old(window, now - self.find_time);
        if !tripped(window, self.distinct_ports, self.syn_rate) {
            return None;
        }
        self.tracked.remove(&ip);
        Some(Signal::new(ip, DETECTOR_PORT_SCAN))
    }

    /// Drop windows with no event newer than `now - find_time`, bounding the map
    /// between bursts. Called from the engine sweep.
    pub fn prune(&mut self, now: i64) {
        let horizon = now - self.find_time;
        self.tracked.retain(|_, w| {
            evict_old(w, horizon);
            !w.events.is_empty()
        });
    }

    /// Number of currently-tracked source IPs (diagnostics/tests).
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.tracked.len()
    }
}

/// Append an event, dropping the oldest if the per-IP cap is reached.
fn push_event(window: &mut PortWindow, event: PortEvent) {
    if window.events.len() >= MAX_EVENTS_PER_IP {
        window.events.pop_front();
    }
    window.events.push_back(event);
}

/// Drop events at or before `horizon` (older than the window).
fn evict_old(window: &mut PortWindow, horizon: i64) {
    while let Some(front) = window.events.front() {
        if front.at < horizon {
            window.events.pop_front();
        } else {
            break;
        }
    }
}

/// Whether the window has crossed either enabled threshold.
fn tripped(window: &PortWindow, distinct_ports: u32, syn_rate: u32) -> bool {
    if syn_rate > 0 {
        let syns = window.events.iter().filter(|e| e.is_syn).count();
        if syns as u32 >= syn_rate {
            return true;
        }
    }
    if distinct_ports > 0 {
        let mut ports: Vec<u16> = window.events.iter().map(|e| e.port).collect();
        ports.sort_unstable();
        ports.dedup();
        if ports.len() as u32 >= distinct_ports {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "portscan_test.rs"]
mod portscan_test;
