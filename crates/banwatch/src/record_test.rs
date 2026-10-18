#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
}

#[test]
fn test_source_detector_roundtrip() {
    for src in [
        BanSource::RepeatBlocked,
        BanSource::AuthFailure,
        BanSource::PortScan,
        BanSource::Manual,
    ] {
        let det = src.detector();
        let back = BanSource::from_detector(det);
        assert_eq!(src, back);
    }
}

#[test]
fn test_unknown_detector_maps_to_manual() {
    assert_eq!(BanSource::from_detector("nope"), BanSource::Manual);
}

#[test]
fn test_source_serde_kebab() {
    let json = serde_json::to_string(&BanSource::RepeatBlocked).unwrap();
    assert_eq!(json, "\"repeat-blocked\"");
    let back: BanSource = serde_json::from_str("\"port-scan\"").unwrap();
    assert_eq!(back, BanSource::PortScan);
}

#[test]
fn test_source_unknown_variant_forward_compat() {
    let back: BanSource = serde_json::from_str("\"future-detector\"").unwrap();
    assert_eq!(back, BanSource::Unknown);
}

#[test]
fn test_record_active_at() {
    let rec = BanRecord {
        ip: ip(),
        detector: DETECTOR_REPEAT_BLOCKED.to_owned(),
        banned_at: 100,
        expires_at: Some(200),
        escalation_count: 0,
        source: BanSource::RepeatBlocked,
    };
    assert!(rec.is_active_at(150));
    assert!(!rec.is_active_at(200), "expiry is exclusive");
    assert!(!rec.is_active_at(250));
}

#[test]
fn test_permanent_ban_always_active() {
    let rec = BanRecord {
        ip: ip(),
        detector: DETECTOR_MANUAL.to_owned(),
        banned_at: 100,
        expires_at: None,
        escalation_count: 0,
        source: BanSource::Manual,
    };
    assert!(rec.is_active_at(i64::MAX));
}

#[test]
fn test_record_serde_roundtrip() {
    let rec = BanRecord {
        ip: ip(),
        detector: DETECTOR_AUTH_FAILURE.to_owned(),
        banned_at: 1,
        expires_at: Some(2),
        escalation_count: 3,
        source: BanSource::AuthFailure,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: BanRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}
