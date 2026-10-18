#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr};

fn ip(d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, d))
}

#[test]
fn test_distinct_ports_threshold() {
    let mut det = PortScanDetector::new(true, 5, 0, 60);
    // 4 distinct ports: below threshold.
    for port in 1000..1004u16 {
        assert!(det.observe(ip(1), port, true, 100).is_none());
    }
    // 5th distinct port trips it.
    let sig = det.observe(ip(1), 1004, true, 100).expect("port scan");
    assert_eq!(sig.ip, ip(1));
    assert_eq!(sig.detector, DETECTOR_PORT_SCAN);
}

#[test]
fn test_below_distinct_threshold_no_signal() {
    let mut det = PortScanDetector::new(true, 10, 0, 60);
    for port in 2000..2005u16 {
        assert!(det.observe(ip(1), port, true, 100).is_none());
    }
    assert!(det.tracked_ips() >= 1);
}

#[test]
fn test_repeated_same_port_not_distinct() {
    let mut det = PortScanDetector::new(true, 3, 0, 60);
    for _ in 0..10 {
        assert!(det.observe(ip(1), 22, true, 100).is_none(), "same port");
    }
}

#[test]
fn test_syn_rate_threshold() {
    let mut det = PortScanDetector::new(true, 0, 4, 60);
    for _ in 0..3 {
        assert!(det.observe(ip(2), 22, true, 100).is_none());
    }
    // A non-SYN packet does not count toward the SYN rate.
    assert!(det.observe(ip(2), 22, false, 100).is_none());
    let sig = det.observe(ip(2), 22, true, 100).expect("syn spray");
    assert_eq!(sig.ip, ip(2));
}

#[test]
fn test_window_eviction_prevents_slow_scan_ban() {
    let mut det = PortScanDetector::new(true, 3, 0, 60);
    let _ = det.observe(ip(3), 100, true, 0);
    let _ = det.observe(ip(3), 101, true, 30);
    // Third distinct port arrives long after the first left the 60s window.
    assert!(
        det.observe(ip(3), 102, true, 200).is_none(),
        "port 100 evicted"
    );
}

#[test]
fn test_resets_after_firing() {
    let mut det = PortScanDetector::new(true, 3, 0, 60);
    for port in 3000..3003u16 {
        let _ = det.observe(ip(4), port, true, 100);
    }
    // After firing, the source window is cleared — starts counting fresh.
    assert_eq!(det.tracked_ips(), 0);
}

#[test]
fn test_disabled_detector_inert() {
    let mut det = PortScanDetector::new(false, 3, 3, 60);
    assert!(!det.is_active());
    for port in 0..100u16 {
        assert!(det.observe(ip(5), port, true, 100).is_none());
    }
}

#[test]
fn test_both_thresholds_zero_inert() {
    let mut det = PortScanDetector::new(true, 0, 0, 60);
    assert!(!det.is_active());
    assert!(det.observe(ip(5), 1, true, 100).is_none());
}

#[test]
fn test_prune_drops_idle_windows() {
    let mut det = PortScanDetector::new(true, 100, 0, 60);
    let _ = det.observe(ip(6), 1, true, 100);
    assert_eq!(det.tracked_ips(), 1);
    det.prune(100_000);
    assert_eq!(det.tracked_ips(), 0, "idle window pruned");
}

#[test]
fn test_tracked_ip_cap_bounds_map() {
    let mut det = PortScanDetector::new(true, 1000, 0, 60);
    // Push well past the cap using distinct source IPs.
    for i in 0..(MAX_TRACKED_IPS + 500) {
        let addr = IpAddr::V4(Ipv4Addr::from((i as u32).wrapping_add(0x0100_0000)));
        let _ = det.observe(addr, 22, true, 100);
    }
    assert!(det.tracked_ips() <= MAX_TRACKED_IPS, "map bounded");
}
