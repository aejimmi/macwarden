#![allow(clippy::indexing_slicing, clippy::panic)]

use std::path::PathBuf;

use super::*;

#[test]
fn test_format_bytes_scales_units() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1 KB");
    assert_eq!(format_bytes(406_000_000), "387 MB");
    assert_eq!(format_bytes(1_610_612_736), "1.5 GB");
}

#[test]
fn test_format_rate_zero_is_dash() {
    assert_eq!(format_rate(0), "—");
    assert!(format_rate(1_500_000).ends_with("/s"));
}

#[test]
fn test_format_scoped_picks_totals_or_rate() {
    // Totals scope → accumulated bytes, never a per-second unit.
    let totals = format_scoped(true, 6_400_000, 406_000_000);
    assert_eq!(totals, "387 MB");
    assert!(!totals.contains("/s"));
    // Real-time scope → live rate.
    assert!(format_scoped(false, 1_500_000, 406_000_000).ends_with("/s"));
    assert_eq!(format_scoped(false, 0, 999), "—");
}

#[test]
fn test_proc_group_singleton_and_group() {
    let single = ProcGroup::singleton(ProcRow {
        id: "1".into(),
        name: "trustd".into(),
        bundle_path: None,
        cpu: 1.0,
        mem_bytes: 10,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
    });
    assert!(!single.is_group());
    assert_eq!(single.procs.len(), 1);
    assert_eq!(single.monogram(), 'T');
}

#[test]
fn test_flow_label_variants() {
    assert!(Flow::Active(2_100_000).label().ends_with("/s"));
    assert_eq!(Flow::Session(4_200_000).label(), "4.0 MB");
    assert_eq!(Flow::Zero.label(), "0 B");
    assert_eq!(Flow::Idle.label(), "—");
}

#[test]
fn test_verdict_labels() {
    assert_eq!(Verdict::Allow.label(), "allowed");
    assert_eq!(Verdict::Blocked.label(), "blocked");
    assert_eq!(Verdict::Tracker.label(), "tracker");
}

#[test]
fn test_signature_describe() {
    assert_eq!(Signature::Apple.describe(), "Apple");
    assert_eq!(
        Signature::DevId("TEAM123".into()).describe(),
        "Developer ID · TEAM123"
    );
    assert_eq!(Signature::Unsigned.describe(), "unsigned");
}

#[test]
fn test_app_monogram_uppercases_first_char() {
    let app = AppRow {
        id: "x".into(),
        name: "spotify".into(),
        bundle_path: None,
        allowed: true,
        known_bad: false,
        is_system: false,
        down_bytes: 0,
        up_bytes: 0,
        flow: Flow::Idle,
        domains: vec![],
    };
    assert_eq!(app.monogram(), 'S');
}

#[test]
fn test_monogram_empty_name_is_question_mark() {
    let p = ProcRow {
        id: "1".into(),
        name: String::new(),
        bundle_path: None,
        cpu: 0.0,
        mem_bytes: 0,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
    };
    assert_eq!(p.monogram(), '?');
}

fn proc(stats_known: bool, cpu: f32, mem: u64) -> ProcRow {
    ProcRow {
        id: "1".into(),
        name: "p".into(),
        bundle_path: None,
        cpu,
        mem_bytes: mem,
        net_bps: 0,
        net_bytes: 0,
        stats_known,
    }
}

#[test]
fn test_proc_labels_known_show_values() {
    let p = proc(true, 12.34, 100_000_000);
    assert_eq!(p.cpu_label(), "12.3%");
    assert_eq!(p.mem_label(), format_bytes(100_000_000));
}

#[test]
fn test_proc_labels_unknown_show_dash() {
    // An unreadable process (stats_known == false) must render "—", not a zero.
    let p = proc(false, 0.0, 0);
    assert_eq!(p.cpu_label(), "—");
    assert_eq!(p.mem_label(), "—");
}

#[test]
fn test_proc_group_labels_follow_known_flag() {
    let known = ProcGroup::singleton(proc(true, 5.0, 2048));
    assert_eq!(known.cpu_label(), "5.0%");
    assert_eq!(known.mem_label(), format_bytes(2048));

    let unknown = ProcGroup::singleton(proc(false, 0.0, 0));
    assert_eq!(unknown.cpu_label(), "—");
    assert_eq!(unknown.mem_label(), "—");
}

fn domain(host: &str, allowed: bool) -> DomainRow {
    DomainRow {
        host: host.into(),
        country: None,
        verdict: if allowed {
            Verdict::Allow
        } else {
            Verdict::Blocked
        },
        rate_bps: 0,
        total_bytes: 100,
        sockets: 1,
        allowed,
    }
}

#[test]
fn test_detail_from_app_row_seeds_identity_bytes_and_domains() {
    let app = AppRow {
        id: "com.example.App".into(),
        name: "Example".into(),
        bundle_path: Some(PathBuf::from("/Applications/Example.app")),
        allowed: true,
        known_bad: false,
        is_system: false,
        down_bytes: 4096,
        up_bytes: 1024,
        flow: Flow::Idle,
        domains: vec![domain("a.example", true), domain("b.example", false)],
    };
    let d = Detail::from_app_row(&app);
    assert_eq!(d.name, "Example");
    assert_eq!(d.bundle_id, "com.example.App");
    assert_eq!(
        d.bundle_path,
        Some(PathBuf::from("/Applications/Example.app"))
    );
    assert_eq!(d.in_bytes, 4096);
    assert_eq!(d.out_bytes, 1024);
    assert!(d.allowed);
    assert_eq!(d.allowed_count, 1);
    assert_eq!(d.denied_count, 1);
    assert_eq!(d.hostnames, vec!["a.example", "b.example"]);
    // Fields the row cannot know are left as placeholders for the daemon merge.
    assert_eq!(d.user, "—");
    assert_eq!(d.openbinary, "—");
    assert!(d.ips.is_empty());
    assert!(d.ports.is_empty());
}

#[test]
fn test_detail_from_net_row_seeds_from_destination() {
    let row = NetRow {
        app_name: "Example".into(),
        app_path: None,
        domain: domain("tracker.example", false),
    };
    let d = Detail::from_net_row(&row);
    assert_eq!(d.name, "tracker.example");
    assert_eq!(d.hostnames, vec!["tracker.example"]);
    assert!(!d.allowed);
    assert_eq!(d.denied_count, 1);
    assert_eq!(d.allowed_count, 0);
}

#[test]
fn test_detail_from_proc_row_seeds_identity() {
    let proc = ProcRow {
        id: "4321".into(),
        name: "helper".into(),
        bundle_path: None,
        cpu: 1.0,
        mem_bytes: 2048,
        net_bps: 0,
        net_bytes: 555,
        stats_known: true,
    };
    let d = Detail::from_proc_row(&proc);
    assert_eq!(d.name, "helper");
    assert_eq!(d.bundle_id, "4321");
    assert_eq!(d.in_bytes, 555);
}
