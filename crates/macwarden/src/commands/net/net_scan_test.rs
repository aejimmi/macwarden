#![allow(clippy::indexing_slicing)]
use super::*;

// ---------------------------------------------------------------------------
// apply_filters
// ---------------------------------------------------------------------------

#[test]
fn test_apply_filters_process() {
    let mut entries = vec![
        make_entry("Safari", "ALLOW", None),
        make_entry("Chrome", "LOG", None),
    ];
    apply_filters(&mut entries, Some("safari"), false, false);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].process, "Safari");
}

#[test]
fn test_apply_filters_denied_only() {
    let mut entries = vec![
        make_entry("Safari", "ALLOW", None),
        make_entry("Chrome", "DENY", None),
    ];
    apply_filters(&mut entries, None, true, false);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "DENY");
}

#[test]
fn test_apply_filters_trackers_only() {
    let mut entries = vec![
        make_entry("Safari", "LOG", Some("analytics")),
        make_entry("Chrome", "ALLOW", None),
    ];
    apply_filters(&mut entries, None, false, true);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].tracker.is_some());
}

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

#[test]
fn test_truncate_short_string() {
    assert_eq!(truncate("hello", 10), "hello");
}

#[test]
fn test_truncate_long_string() {
    let result = truncate("a very long process name", 10);
    assert_eq!(result.len(), 10);
    assert!(result.ends_with("..."));
}

// ---------------------------------------------------------------------------
// format_code_id
// ---------------------------------------------------------------------------

#[test]
fn test_format_code_id_three_segments() {
    assert_eq!(format_code_id("com.google.Chrome"), "Chrome");
}

#[test]
fn test_format_code_id_four_segments() {
    assert_eq!(
        format_code_id("com.apple.WebKit.Networking"),
        "WebKit.Networking"
    );
}

#[test]
fn test_format_code_id_deep_segments() {
    assert_eq!(
        format_code_id("com.apple.Safari.ContentExtension"),
        "Safari.ContentExtension"
    );
}

#[test]
fn test_format_code_id_two_segments() {
    assert_eq!(format_code_id("com.apple"), "com.apple");
}

#[test]
fn test_format_code_id_single_segment() {
    assert_eq!(format_code_id("mDNSResponder"), "mDNSResponder");
}

#[test]
fn test_format_code_id_apple_daemon() {
    assert_eq!(
        format_code_id("com.apple.identityservicesd"),
        "identityservicesd"
    );
}

// ---------------------------------------------------------------------------
// display_process
// ---------------------------------------------------------------------------

#[test]
fn test_display_process_with_code_id() {
    let e = ScanEntry {
        process: "Safari".to_owned(),
        pid: 1,
        code_id: Some("com.apple.Safari".to_owned()),
        destination: "apple.com".to_owned(),
        port: 443,
        protocol: "TCP".to_owned(),
        action: "ALLOW".to_owned(),
        tracker: None,
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    };
    assert_eq!(display_process(&e), "Safari");
}

#[test]
fn test_display_process_without_code_id() {
    let e = make_entry("mDNSRespo", "ALLOW", None);
    assert_eq!(display_process(&e), "mDNSRespo");
}

// ---------------------------------------------------------------------------
// format_bytes
// ---------------------------------------------------------------------------

#[test]
fn test_format_bytes_zero() {
    assert_eq!(format_bytes(0), "-");
}

#[test]
fn test_format_bytes_small() {
    assert_eq!(format_bytes(256), "256 B");
}

#[test]
fn test_format_bytes_kilobytes() {
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1536), "1.5 KB");
}

#[test]
fn test_format_bytes_megabytes() {
    assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    assert_eq!(format_bytes(2_200_000), "2.1 MB");
}

#[test]
fn test_format_bytes_gigabytes() {
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
}

// ---------------------------------------------------------------------------
// format_port
// ---------------------------------------------------------------------------

#[test]
fn test_format_port_with_service() {
    assert_eq!(format_port(22, Some("SSH")), "22/SSH");
}

#[test]
fn test_format_port_without_service() {
    assert_eq!(format_port(443, None), "443");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn make_entry(process: &str, action: &str, tracker: Option<&str>) -> ScanEntry {
    ScanEntry {
        process: process.to_owned(),
        pid: 1,
        code_id: None,
        destination: "example.com".to_owned(),
        port: 443,
        protocol: "TCP".to_owned(),
        action: action.to_owned(),
        tracker: tracker.map(ToOwned::to_owned),
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    }
}
