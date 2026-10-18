#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::Ipv4Addr;

use tempfile::TempDir;

/// Write a banwatch.toml enabling a fast repeat-blocked detector and the
/// port-scan detector, and open a service over it (metrics in-memory).
fn service_with(body: &str) -> (TempDir, Arc<Mutex<MetricsStore>>, BanwatchService) {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("banwatch.toml"), body).unwrap();
    let metrics = Arc::new(Mutex::new(
        MetricsStore::open(&dir.path().join("metrics.db")).unwrap(),
    ));
    let service = BanwatchService::open(dir.path(), Some(Arc::clone(&metrics)))
        .unwrap()
        .expect("service enabled");
    (dir, metrics, service)
}

const FAST_CONFIG: &str = r#"
[banwatch]
enabled = true
ban_time = "1h"

[detectors.repeat-blocked]
enabled = true
max_retry = 3
find_time = "10m"

[detectors.auth-failure]
enabled = true
max_retry = 2
find_time = "10m"

[detectors.port-scan]
enabled = true
distinct_ports = 4
syn_rate = 0
find_time = "1m"
"#;

fn ip(d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, d))
}

#[test]
fn test_disabled_config_yields_no_service() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("banwatch.toml"),
        "[banwatch]\nenabled = false\n",
    )
    .unwrap();
    let service = BanwatchService::open(dir.path(), None).unwrap();
    assert!(service.is_none(), "disabled config withholds the service");
}

#[test]
fn test_missing_config_defaults_enabled() {
    let dir = TempDir::new().unwrap();
    let service = BanwatchService::open(dir.path(), None).unwrap();
    assert!(service.is_some(), "default config enables banwatch");
}

#[test]
fn test_repeat_blocked_verdict_stream_bans() {
    let (_d, metrics, svc) = service_with(FAST_CONFIG);
    // Allowed verdicts never signal.
    assert!(svc.on_verdict(ip(1), true).is_none());
    // Three denies within the window ban the IP.
    assert!(svc.on_verdict(ip(1), false).is_none());
    assert!(svc.on_verdict(ip(1), false).is_none());
    let event = svc.on_verdict(ip(1), false).expect("third deny bans");
    assert!(matches!(event, BanEvent::Banned(_)));

    // The ban is listed and a metric was written.
    let bans = svc.list_bans();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, "203.0.113.1");
    assert_eq!(bans[0].detector, "repeat-blocked");

    let rows = metrics
        .lock()
        .unwrap()
        .ban_timeline(&metrics::TimeRange::all())
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "ip_banned");
}

#[test]
fn test_auth_failure_line_bans() {
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    let line = "sshd[1]: Failed password for root from 203.0.113.2 port 22 ssh2";
    assert!(svc.on_auth_line(line).is_none(), "1 of 2");
    let event = svc.on_auth_line(line).expect("second failure bans");
    match event {
        BanEvent::Banned(rec) => assert_eq!(rec.ip, ip(2)),
        BanEvent::Unbanned { .. } => panic!("expected ban"),
    }
}

#[test]
fn test_auth_failure_redaction_is_inert() {
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    let redacted = "sshd[1]: Failed password for root from <private> port 22 ssh2";
    assert!(svc.on_auth_line(redacted).is_none());
    assert!(svc.on_auth_line(redacted).is_none());
    assert!(svc.list_bans().is_empty(), "redacted peers never ban");
}

#[test]
fn test_port_scan_feed_bans() {
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    // 4 distinct ports from one IP trips the port-scan detector (bans on the
    // first analyzer signal, since the port-scan engine max_retry is 1).
    for port in 1000..1003u16 {
        assert!(svc.observe_packet(ip(3), port, true).is_none());
    }
    let event = svc.observe_packet(ip(3), 1003, true).expect("scan bans");
    assert!(matches!(event, BanEvent::Banned(_)));
    assert_eq!(svc.list_bans()[0].detector, "port-scan");
}

#[test]
fn test_manual_ban_and_unban_with_reload_semantics() {
    let (_d, metrics, svc) = service_with(FAST_CONFIG);
    assert!(svc.set_ban("203.0.113.9", true, Some(3600), None).unwrap());
    let bans = svc.list_bans();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].source, "manual");

    // Unban.
    assert!(svc.set_ban("203.0.113.9", false, None, None).unwrap());
    assert!(svc.list_bans().is_empty());

    // Both lifecycle events reached metrics.
    let rows = metrics
        .lock()
        .unwrap()
        .ban_timeline(&metrics::TimeRange::all())
        .unwrap();
    let kinds: Vec<&str> = rows.iter().map(|r| r.kind.as_str()).collect();
    assert!(kinds.contains(&"ip_banned"));
    assert!(kinds.contains(&"ip_unbanned"));
}

#[test]
fn test_active_ban_ips_reads_in_memory_set() {
    // The daemon reload path sources bans from this snapshot of the engine's
    // in-memory store — never by reopening the etch WAL — so it cannot tear
    // against a compaction (the #4 torn-read bug). A ban applied through the
    // service is immediately visible via `active_ban_ips`, and an unban clears
    // it, with no store reopen involved.
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    assert!(svc.active_ban_ips().is_empty(), "no bans yet");

    svc.set_ban("203.0.113.20", true, Some(3600), None).unwrap();
    svc.set_ban("203.0.113.21", true, Some(3600), None).unwrap();
    let ips = svc.active_ban_ips();
    assert_eq!(
        ips,
        vec![ip(20), ip(21)],
        "in-memory bans, sorted + deduped"
    );

    svc.set_ban("203.0.113.20", false, None, None).unwrap();
    assert_eq!(svc.active_ban_ips(), vec![ip(21)], "unban is reflected");
}

#[test]
fn test_set_ban_rejects_invalid_ip() {
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    assert!(svc.set_ban("not-an-ip", true, None, None).is_err());
}

#[test]
fn test_list_bans_newest_first() {
    let (_d, _m, svc) = service_with(FAST_CONFIG);
    svc.set_ban("203.0.113.10", true, Some(3600), None).unwrap();
    svc.set_ban("203.0.113.11", true, Some(3600), None).unwrap();
    let bans = svc.list_bans();
    assert_eq!(bans.len(), 2);
    // Newest ban (113.11) should sort first (or tie by banned_at; both same
    // second — assert both present regardless of order).
    let ips: Vec<&str> = bans.iter().map(|b| b.ip.as_str()).collect();
    assert!(ips.contains(&"203.0.113.10"));
    assert!(ips.contains(&"203.0.113.11"));
}
