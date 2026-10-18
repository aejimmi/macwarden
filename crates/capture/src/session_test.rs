//! Pure tests for the live session's non-I/O helpers (run under
//! `--features capture-live` on macOS; no root required).

use super::*;

#[test]
fn test_map_link_type_known_dlts() {
    assert_eq!(map_link_type(Linktype(1)).ok(), Some(LinkType::Ethernet));
    assert_eq!(map_link_type(Linktype(101)).ok(), Some(LinkType::RawIp));
    assert_eq!(map_link_type(Linktype(228)).ok(), Some(LinkType::RawIp));
    assert_eq!(map_link_type(Linktype(229)).ok(), Some(LinkType::RawIp));
    assert_eq!(map_link_type(Linktype(0)).ok(), Some(LinkType::Null));
    assert_eq!(map_link_type(Linktype(108)).ok(), Some(LinkType::Null));
    assert_eq!(map_link_type(Linktype(113)).ok(), Some(LinkType::LinuxSll));
    assert_eq!(map_link_type(Linktype(276)).ok(), Some(LinkType::LinuxSll2));
}

#[test]
fn test_map_link_type_unknown_errors() {
    let result = map_link_type(Linktype(999));
    assert!(
        matches!(result, Err(CaptureError::UnsupportedLinkType(999))),
        "expected UnsupportedLinkType(999), got {result:?}"
    );
}

#[test]
fn test_capture_config_defaults() {
    let cfg = CaptureConfig::default();
    assert!(cfg.device.is_none());
    assert_eq!(cfg.snaplen, DEFAULT_SNAPLEN);
    assert_eq!(cfg.timeout_ms, DEFAULT_TIMEOUT_MS);
    assert_eq!(cfg.rate_limit_per_sec, DEFAULT_RATE_LIMIT_PER_SEC);
}
