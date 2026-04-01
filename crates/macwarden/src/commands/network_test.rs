#![allow(clippy::indexing_slicing, clippy::useless_vec)]

use super::*;

// ---------------------------------------------------------------------------
// extract_app_name
// ---------------------------------------------------------------------------

#[test]
fn test_extract_app_name_spotify() {
    let label = "application.com.spotify.client.56862295.56862982";
    assert_eq!(extract_app_name(label), "Spotify");
}

#[test]
fn test_extract_app_name_raycast() {
    let label = "application.com.raycast.macos.22437190.53410052";
    assert_eq!(extract_app_name(label), "Raycast");
}

#[test]
fn test_extract_app_name_single_segment() {
    let label = "application.com";
    // Only one segment after "application." split → falls to else.
    let result = extract_app_name(label);
    assert!(!result.is_empty());
}

#[test]
fn test_extract_app_name_capitalizes() {
    let label = "application.org.firefox.nightly.12345";
    assert_eq!(extract_app_name(label), "Firefox");
}

// ---------------------------------------------------------------------------
// classify_connection
// ---------------------------------------------------------------------------

#[test]
fn test_classify_connection_established() {
    assert_eq!(classify_connection("TCP", "ESTABLISHED"), "ESTABLISHED");
}

#[test]
fn test_classify_connection_listen() {
    assert_eq!(classify_connection("TCP", "LISTEN"), "LISTEN");
}

#[test]
fn test_classify_connection_udp() {
    assert_eq!(classify_connection("UDP", ""), "UDP");
}

#[test]
fn test_classify_connection_other() {
    assert_eq!(classify_connection("TCP", "CLOSE_WAIT"), "CLOSE_WAIT");
}

// ---------------------------------------------------------------------------
// classify_process
// ---------------------------------------------------------------------------

#[test]
fn test_classify_process_known_group() {
    let groups = catalog::load_builtin_groups();
    let label = "com.apple.Siri.agent".to_owned();
    let (service, group) = classify_process(Some(&label), "Siri", &groups);
    assert_eq!(service, "com.apple.Siri.agent");
    assert!(group.is_some(), "Siri should match a known group");
}

#[test]
fn test_classify_process_application_label() {
    let groups = vec![];
    let label = "application.com.spotify.client.123.456".to_owned();
    let (service, group) = classify_process(Some(&label), "Spotify", &groups);
    assert_eq!(service, "Spotify");
    assert_eq!(group, Some("applications".to_owned()));
}

#[test]
fn test_classify_process_known_service_no_group() {
    let groups = vec![];
    let label = "com.example.unknown".to_owned();
    let (service, group) = classify_process(Some(&label), "unknown", &groups);
    assert_eq!(service, "com.example.unknown");
    assert!(group.is_none());
}

#[test]
fn test_classify_process_no_label() {
    let groups = vec![];
    let (service, group) = classify_process(None, "Firefox", &groups);
    assert_eq!(service, "Firefox");
    assert_eq!(group, Some("applications".to_owned()));
}

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

#[test]
fn test_truncate_short_string_unchanged() {
    assert_eq!(truncate("hello", 10), "hello");
}

#[test]
fn test_truncate_exact_length_unchanged() {
    assert_eq!(truncate("hello", 5), "hello");
}

#[test]
fn test_truncate_long_string_ellipsis() {
    let result = truncate("hello world", 6);
    assert_eq!(result, "hello…");
    assert!(result.len() <= 10); // 5 ASCII + 3-byte ellipsis
}

// ---------------------------------------------------------------------------
// NetEntry sorting
// ---------------------------------------------------------------------------

#[test]
fn test_net_entry_sort_grouped_first() {
    let mut entries = vec![
        NetEntry {
            pid: 1,
            process: "b".to_owned(),
            service: Some("svc".to_owned()),
            group: None,
            connection: "1.2.3.4:443".to_owned(),
            conn_type: "ESTABLISHED".to_owned(),
        },
        NetEntry {
            pid: 2,
            process: "a".to_owned(),
            service: Some("svc".to_owned()),
            group: Some("telemetry".to_owned()),
            connection: "5.6.7.8:443".to_owned(),
            conn_type: "ESTABLISHED".to_owned(),
        },
    ];

    entries.sort_by(|a, b| {
        let rank = |e: &NetEntry| -> u8 {
            if e.group.is_some() {
                0
            } else if e.service.is_some() {
                1
            } else {
                2
            }
        };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.group.cmp(&b.group))
            .then_with(|| a.process.cmp(&b.process))
    });

    assert_eq!(entries[0].pid, 2, "grouped entry should sort first");
}

#[test]
fn test_net_entry_dedup_same_pid_and_connection() {
    let mut entries = vec![
        NetEntry {
            pid: 1,
            process: "p".to_owned(),
            service: None,
            group: None,
            connection: "1.2.3.4:443".to_owned(),
            conn_type: "ESTABLISHED".to_owned(),
        },
        NetEntry {
            pid: 1,
            process: "p".to_owned(),
            service: None,
            group: None,
            connection: "1.2.3.4:443".to_owned(),
            conn_type: "ESTABLISHED".to_owned(),
        },
    ];

    entries.dedup_by(|a, b| a.pid == b.pid && a.connection == b.connection);
    assert_eq!(entries.len(), 1);
}
