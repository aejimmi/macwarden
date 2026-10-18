#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
}

#[test]
fn test_deny_produces_signal() {
    let sig = on_verdict(ip(), false).expect("deny -> signal");
    assert_eq!(sig.ip, ip());
    assert_eq!(sig.detector, DETECTOR_REPEAT_BLOCKED);
}

#[test]
fn test_allow_produces_nothing() {
    assert!(on_verdict(ip(), true).is_none());
}
