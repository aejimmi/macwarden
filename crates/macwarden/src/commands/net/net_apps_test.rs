#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// compute_status
// ---------------------------------------------------------------------------

#[test]
fn test_compute_status_active() {
    assert_eq!(compute_status(5, 0), AppStatus::Active);
}

#[test]
fn test_compute_status_blocked() {
    assert_eq!(compute_status(3, 3), AppStatus::Blocked);
}

#[test]
fn test_compute_status_mixed() {
    assert_eq!(compute_status(5, 2), AppStatus::Mixed);
}

// ---------------------------------------------------------------------------
// app_key
// ---------------------------------------------------------------------------

#[test]
fn test_app_key_prefers_code_id() {
    let entry = ScanEntry {
        process: "Safari".to_owned(),
        pid: 123,
        code_id: Some("com.apple.Safari".to_owned()),
        destination: "example.com".to_owned(),
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
    assert_eq!(app_key(&entry), "com.apple.Safari");
}

#[test]
fn test_app_key_falls_back_to_process() {
    let entry = ScanEntry {
        process: "curl".to_owned(),
        pid: 456,
        code_id: None,
        destination: "example.com".to_owned(),
        port: 80,
        protocol: "TCP".to_owned(),
        action: "LOG".to_owned(),
        tracker: None,
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    };
    assert_eq!(app_key(&entry), "curl");
}

// ---------------------------------------------------------------------------
// group_by_app
// ---------------------------------------------------------------------------

#[test]
fn test_group_by_app_groups_same_code_id() {
    let entries = vec![
        ScanEntry {
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
        },
        ScanEntry {
            process: "Safari".to_owned(),
            pid: 1,
            code_id: Some("com.apple.Safari".to_owned()),
            destination: "google.com".to_owned(),
            port: 443,
            protocol: "TCP".to_owned(),
            action: "DENY".to_owned(),
            tracker: Some("analytics".to_owned()),
            country: None,
            asn_name: None,
            bytes_in: None,
            bytes_out: None,
            service: None,
        },
    ];

    let summaries = group_by_app(&entries);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].connections, 2);
    assert_eq!(summaries[0].blocked, 1);
    assert_eq!(summaries[0].trackers, 1);
    assert_eq!(summaries[0].status, AppStatus::Mixed);
}

#[test]
fn test_group_by_app_separates_different_apps() {
    let entries = vec![
        ScanEntry {
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
        },
        ScanEntry {
            process: "curl".to_owned(),
            pid: 2,
            code_id: None,
            destination: "example.com".to_owned(),
            port: 80,
            protocol: "TCP".to_owned(),
            action: "ALLOW".to_owned(),
            tracker: None,
            country: None,
            asn_name: None,
            bytes_in: None,
            bytes_out: None,
            service: None,
        },
    ];

    let summaries = group_by_app(&entries);
    assert_eq!(summaries.len(), 2);
}

// ---------------------------------------------------------------------------
// resolve_app_entries
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_app_entries_by_process_name() {
    let entries = vec![ScanEntry {
        process: "curl".to_owned(),
        pid: 1,
        code_id: None,
        destination: "example.com".to_owned(),
        port: 80,
        protocol: "TCP".to_owned(),
        action: "ALLOW".to_owned(),
        tracker: None,
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    }];

    let app_db = AppDb::from_sources(&[]).expect("empty db");
    let matched = resolve_app_entries(&entries, "curl", &app_db);
    assert_eq!(matched.len(), 1);
}

#[test]
fn test_resolve_app_entries_no_match() {
    let entries = vec![ScanEntry {
        process: "curl".to_owned(),
        pid: 1,
        code_id: None,
        destination: "example.com".to_owned(),
        port: 80,
        protocol: "TCP".to_owned(),
        action: "ALLOW".to_owned(),
        tracker: None,
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    }];

    let app_db = AppDb::from_sources(&[]).expect("empty db");
    let matched = resolve_app_entries(&entries, "firefox", &app_db);
    assert!(matched.is_empty());
}

// ---------------------------------------------------------------------------
// AppStatus::Display
// ---------------------------------------------------------------------------

#[test]
fn test_app_status_display() {
    assert_eq!(AppStatus::Active.to_string(), "Active");
    assert_eq!(AppStatus::Blocked.to_string(), "Blocked");
    assert_eq!(AppStatus::Mixed.to_string(), "Mixed");
}
