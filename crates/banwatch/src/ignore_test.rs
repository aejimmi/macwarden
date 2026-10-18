#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn test_loopback_and_private_ignored_by_default() {
    let set = IgnoreSet::new(&[]);
    assert!(set.contains(v4(127, 0, 0, 1)));
    assert!(set.contains(v4(10, 1, 2, 3)));
    assert!(set.contains(v4(192, 168, 0, 9)));
    assert!(set.contains(v4(172, 16, 5, 5)));
    assert!(set.contains(v4(169, 254, 1, 1)));
    assert!(set.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn test_public_ip_not_ignored() {
    let set = IgnoreSet::new(&[]);
    assert!(!set.contains(v4(203, 0, 113, 7)));
    assert!(!set.contains(v4(8, 8, 8, 8)));
}

#[test]
fn test_user_cidr_merged() {
    let set = IgnoreSet::new(&["203.0.113.0/24".to_owned()]);
    assert!(set.contains(v4(203, 0, 113, 200)));
    assert!(!set.contains(v4(203, 0, 114, 1)));
}

#[test]
fn test_user_bare_ip_as_host_route() {
    let set = IgnoreSet::new(&["8.8.8.8".to_owned()]);
    assert!(set.contains(v4(8, 8, 8, 8)));
    assert!(!set.contains(v4(8, 8, 8, 9)));
}

#[test]
fn test_malformed_entry_dropped_not_fatal() {
    let before = IgnoreSet::new(&[]).range_count();
    let set = IgnoreSet::new(&["not-an-ip".to_owned(), "203.0.113.0/24".to_owned()]);
    // The bad entry is dropped; the good one is kept (defaults + 1).
    assert_eq!(set.range_count(), before + 1);
    assert!(set.contains(v4(203, 0, 113, 1)));
}

#[test]
fn test_ignore_self_addrs() {
    let mut set = IgnoreSet::new(&[]);
    let me = v4(198, 51, 100, 42);
    assert!(!set.contains(me));
    set.set_self_addrs(vec![me]);
    assert!(set.contains(me));
}
