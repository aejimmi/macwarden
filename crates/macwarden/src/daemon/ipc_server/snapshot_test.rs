#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::float_cmp
)]

use net::{
    BreakageRisk, DestMatcher, HostPattern, NetworkAction, NetworkRule, ProcessMatcher,
    RuleDuration, RuleId, RuleSet, TrackerRule,
};

use super::*;

fn deny_rule(code_id: &str) -> NetworkRule {
    NetworkRule {
        id: RuleId(1),
        name: "block".to_owned(),
        process: ProcessMatcher::code_id(code_id).unwrap(),
        destination: DestMatcher::default(),
        action: NetworkAction::Deny,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: None,
    }
}

fn tracker_rule(pattern: &str) -> TrackerRule {
    TrackerRule {
        pattern: HostPattern::new(pattern).unwrap(),
        category: "advertising".to_owned(),
        breakage_risk: BreakageRisk::None,
        description: "test tracker".to_owned(),
    }
}

fn ruleset(user: Vec<NetworkRule>, trackers: Vec<TrackerRule>) -> RuleSet {
    let mut rs = RuleSet::default();
    rs.user_rules = user;
    rs.tracker_rules = trackers;
    rs.sort_user_rules();
    rs
}

fn conn(code_id: &str, host: &str) -> LiveConn {
    LiveConn {
        code_id: Some(code_id.to_owned()),
        process: "proc".to_owned(),
        pid: 1,
        path: Some("/Applications/App.app".to_owned()),
        host: Some(host.to_owned()),
        ip: "1.2.3.4".parse().ok(),
        port: 443,
        protocol: "TCP".to_owned(),
        bytes_in: 100,
        bytes_out: 40,
        is_apple_signed: None,
        cpu: 0.0,
        mem_bytes: 0,
        ..LiveConn::default()
    }
}

#[test]
fn test_build_snapshot_default_allow() {
    let rs = ruleset(vec![], vec![]);
    let conns = vec![conn("com.example.app", "example.test")];
    let data = build_snapshot(&conns, &rs, false);

    assert_eq!(data.apps.len(), 1);
    let app = &data.apps[0];
    assert!(app.allowed);
    assert_eq!(app.domains.len(), 1);
    assert_eq!(app.domains[0].verdict, WireVerdict::Allow);
    assert!(app.domains[0].allowed);
    assert_eq!(data.totals.connections, 1);
    assert_eq!(data.totals.trackers_blocked, 0);
}

#[test]
fn test_build_snapshot_user_deny_is_blocked() {
    let rs = ruleset(vec![deny_rule("com.example.app")], vec![]);
    let conns = vec![conn("com.example.app", "example.test")];
    let data = build_snapshot(&conns, &rs, false);

    let app = &data.apps[0];
    assert_eq!(app.domains[0].verdict, WireVerdict::Blocked);
    assert!(!app.domains[0].allowed);
    assert!(!app.allowed, "app with only blocked domains is not allowed");
}

#[test]
fn test_build_snapshot_tracker_tier_is_tracker() {
    let rs = ruleset(vec![], vec![tracker_rule("tracker.example")]);
    let conns = vec![conn("com.example.app", "tracker.example")];
    let data = build_snapshot(&conns, &rs, false);

    assert_eq!(data.apps[0].domains[0].verdict, WireVerdict::Tracker);
    assert_eq!(
        data.totals.trackers_blocked, 1,
        "trackers_blocked counts tracker-tier denials"
    );
}

#[test]
fn test_totals_sum_bytes_and_dedupe_pid() {
    let rs = ruleset(vec![], vec![]);
    // Same pid across two destinations: process bytes must not double-count.
    let mut a = conn("com.example.app", "one.test");
    let mut b = conn("com.example.app", "two.test");
    a.pid = 7;
    b.pid = 7;
    let data = build_snapshot(&[a, b], &rs, false);

    assert_eq!(data.apps[0].down_bytes, 100);
    assert_eq!(data.apps[0].up_bytes, 40);
    assert_eq!(data.totals.down_bytes, 100);
    assert_eq!(data.totals.up_bytes, 40);
    assert_eq!(data.apps[0].domains.len(), 2);
}

#[test]
fn test_net_rows_and_procs_built() {
    let rs = ruleset(vec![], vec![]);
    let mut a = conn("com.a.one", "a.test");
    let mut b = conn("com.b.two", "b.test");
    a.pid = 1;
    b.pid = 2;
    let data = build_snapshot(&[a, b], &rs, false);

    assert_eq!(data.net_rows.len(), 2);
    assert_eq!(data.procs.len(), 2, "two distinct pids");
    assert_eq!(data.proc_groups.len(), 2, "two distinct app groups");
}

#[test]
fn test_proc_rows_carry_cpu_and_mem_from_conn() {
    let rs = ruleset(vec![], vec![]);
    let mut c = conn("com.example.app", "one.test");
    c.pid = 9;
    c.cpu = 12.5;
    c.mem_bytes = 4_000_000;
    let data = build_snapshot(&[c], &rs, false);

    assert_eq!(data.procs.len(), 1);
    assert_eq!(data.procs[0].cpu, 12.5, "proc row carries real cpu");
    assert_eq!(
        data.procs[0].mem_bytes, 4_000_000,
        "proc row carries real mem"
    );
}

#[test]
fn test_display_name_strips_hash_from_bare_binary_code_id() {
    let mut c = conn("cargo-9b434e75c9a9c27f", "crates.io");
    c.code_id = Some("cargo-9b434e75c9a9c27f".to_owned());
    let data = build_snapshot(&[c], &ruleset(vec![], vec![]), false);
    assert_eq!(data.apps[0].name, "cargo", "display name is clean");
    assert_eq!(
        data.apps[0].id, "cargo-9b434e75c9a9c27f",
        "group key keeps the full code id for uniqueness"
    );
}

#[test]
fn test_is_system_binary_requires_apple_signed_and_system_path() {
    assert!(is_system_binary(Some(true), Some("/usr/libexec/trustd")));
    assert!(is_system_binary(Some(true), Some("/System/Library/x")));
    assert!(is_system_binary(
        Some(true),
        Some("/usr/sbin/mDNSResponder")
    ));
    // Apple-signed but a third-party app path → not system.
    assert!(!is_system_binary(
        Some(true),
        Some("/Applications/Xcode.app")
    ));
    // System path but not Apple-signed → not system.
    assert!(!is_system_binary(Some(false), Some("/usr/bin/x")));
    assert!(!is_system_binary(None, Some("/usr/bin/x")));
    assert!(!is_system_binary(Some(true), None));
}

#[test]
fn test_build_snapshot_marks_apple_system_daemon() {
    let mut c = conn("com.apple.trustd", "ocsp.apple.com");
    c.is_apple_signed = Some(true);
    c.path = Some("/usr/libexec/trustd".to_owned());
    let data = build_snapshot(&[c], &ruleset(vec![], vec![]), false);
    assert!(data.apps[0].is_system, "apple system daemon flagged");
    assert!(data.procs[0].is_system);
}

#[test]
fn test_build_snapshot_live_rates_populate_flow_and_net() {
    let mut c = conn("com.example.app", "one.test");
    c.pid = 42;
    c.rate_in_bps = 3000;
    c.rate_out_bps = 1000;
    let data = build_snapshot(&[c], &ruleset(vec![], vec![]), false);
    // App flow reflects the live rate, not the session buffer.
    assert_eq!(data.apps[0].flow, WireFlow::Active(4000));
    // Domain carries its per-connection rate.
    assert_eq!(data.apps[0].domains[0].rate_bps, 4000);
    // Proc NET column and totals reflect the same live rate.
    assert_eq!(data.procs[0].net_bps, 4000);
    assert_eq!(data.proc_groups[0].net_bps, 4000);
    assert_eq!(data.totals.down_bps, 3000);
    assert_eq!(data.totals.up_bps, 1000);
}

#[test]
fn test_build_snapshot_idle_app_keeps_session_flow() {
    // No live rate but retained session bytes → Session, not Active.
    let data = build_snapshot(
        &[conn("com.example.app", "one.test")],
        &ruleset(vec![], vec![]),
        false,
    );
    assert_eq!(data.apps[0].flow, WireFlow::Session(140));
    assert_eq!(data.totals.down_bps, 0);
}

#[test]
fn test_proc_group_sums_member_cpu_and_mem() {
    let rs = ruleset(vec![], vec![]);
    // Two pids under the same app id: the group must sum their cpu and mem.
    let mut a = conn("com.example.app", "one.test");
    let mut b = conn("com.example.app", "two.test");
    a.pid = 1;
    a.cpu = 10.0;
    a.mem_bytes = 1_000;
    b.pid = 2;
    b.cpu = 5.0;
    b.mem_bytes = 3_000;
    let data = build_snapshot(&[a, b], &rs, false);

    assert_eq!(data.proc_groups.len(), 1, "same app id groups both pids");
    let group = &data.proc_groups[0];
    assert_eq!(group.cpu, 15.0, "group cpu is the sum of members");
    assert_eq!(group.mem_bytes, 4_000, "group mem is the sum of members");
    assert_eq!(group.procs.len(), 2);
}
