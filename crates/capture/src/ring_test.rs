//! Pure unit tests for the bounded ring and rate limiter (spec R6 acceptance).

use super::*;
use crate::LinkType;
use crate::parse::PacketRecord;
use crate::types::{AppProto, Direction, L4Proto, SocketEndpoint, Timestamp};
use std::net::IpAddr;

fn addr() -> SocketEndpoint {
    let ip: IpAddr = "0.0.0.0".parse().expect("valid ip");
    SocketEndpoint::new(ip, None)
}

/// A synthetic record with a controllable `seq` and raw-byte size.
fn rec(seq: u64, raw_len: usize) -> PacketRecord {
    PacketRecord {
        seq,
        ts: Timestamp::new(0, 0),
        src: addr(),
        dst: addr(),
        proto: L4Proto::Tcp,
        length: raw_len as u32,
        direction: Direction::Inbound,
        app_proto: AppProto::Unknown,
        sni: None,
        tls: None,
        summary: String::new(),
        raw: vec![0u8; raw_len],
        link_type: LinkType::Ethernet,
    }
}

#[test]
fn test_ring_retains_newest_n_and_counts_drops() {
    let n = 8usize;
    let k = 5u64;
    let mut ring = PacketRing::new(n, usize::MAX);
    for seq in 0..(n as u64 + k) {
        ring.push(rec(seq, 10));
    }
    assert_eq!(ring.len(), n);
    assert_eq!(ring.dropped(), k);
    // The newest N are retained: seqs k..(n+k).
    let seqs: Vec<u64> = ring.snapshot().iter().map(|r| r.seq).collect();
    assert_eq!(seqs.first().copied(), Some(k));
    assert_eq!(seqs.last().copied(), Some(n as u64 + k - 1));
}

#[test]
fn test_ring_stays_under_byte_budget_evicting_extra() {
    // Budget 500 bytes, count bound high so bytes are the limiter.
    let mut ring = PacketRing::new(1000, 500);
    for seq in 0..5 {
        ring.push(rec(seq, 100));
    }
    assert_eq!(ring.stats().retained_bytes, 500);
    // A 300-byte packet forces eviction of extra 100-byte entries to fit.
    ring.push(rec(5, 300));
    assert!(ring.stats().retained_bytes <= 500);
    assert!(ring.dropped() >= 3);
}

#[test]
fn test_ring_fetch_evicted_seq_returns_none() {
    let mut ring = PacketRing::new(2, usize::MAX);
    ring.push(rec(0, 10));
    ring.push(rec(1, 10));
    ring.push(rec(2, 10)); // evicts seq 0
    assert!(ring.get(0).is_none());
    assert!(ring.bytes(0).is_none());
    assert!(ring.get(2).is_some());
    assert_eq!(ring.bytes(2).map(<[u8]>::len), Some(10));
}

#[test]
fn test_ring_drain_empties_and_resets_bytes() {
    let mut ring = PacketRing::new(16, usize::MAX);
    ring.push(rec(0, 40));
    ring.push(rec(1, 40));
    let drained = ring.drain();
    assert_eq!(drained.len(), 2);
    assert!(ring.is_empty());
    assert_eq!(ring.stats().retained_bytes, 0);
    assert!(ring.get(1).is_none());
}

#[test]
fn test_ring_single_oversized_packet_is_retained() {
    // A packet larger than the whole budget cannot go below its own size, but
    // must still be retained (the byte bound clamps to at least one packet).
    let mut ring = PacketRing::new(16, 100);
    ring.push(rec(0, 5000));
    assert_eq!(ring.len(), 1);
    assert!(ring.get(0).is_some());
}

#[test]
fn test_rate_limiter_allows_up_to_budget_then_denies() {
    let mut rl = RateLimiter::new(3);
    assert!(rl.allow(0));
    assert!(rl.allow(1));
    assert!(rl.allow(2));
    assert!(!rl.allow(3)); // 4th within the window is denied
    assert_eq!(rl.dropped(), 1);
}

#[test]
fn test_rate_limiter_resets_after_window() {
    let mut rl = RateLimiter::new(2);
    assert!(rl.allow(0));
    assert!(rl.allow(10));
    assert!(!rl.allow(20)); // over budget this window
    // Cross the 1s window boundary — budget refreshes.
    assert!(rl.allow(1_000_000_001));
    assert!(rl.allow(1_000_000_002));
    assert_eq!(rl.dropped(), 1);
}

#[test]
fn test_rate_limiter_zero_is_unlimited() {
    let mut rl = RateLimiter::new(0);
    for t in 0..10_000 {
        assert!(rl.allow(t));
    }
    assert_eq!(rl.dropped(), 0);
}
