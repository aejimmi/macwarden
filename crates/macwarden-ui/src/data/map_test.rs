#![allow(clippy::indexing_slicing, clippy::panic)]

use std::path::PathBuf;

use ipc::protocol::{
    WireAppRow, WireDetail, WireDomainRow, WireFlow, WireNetRow, WireProcGroup, WireProcRow,
    WireSignature, WireTotals, WireVerdict,
};

use super::*;
use crate::data::model::{Flow, Signature, Verdict};

fn wire_domain() -> WireDomainRow {
    WireDomainRow {
        host: "googlevideo.com".to_string(),
        country: Some("US".to_string()),
        verdict: WireVerdict::Tracker,
        rate_bps: 4096,
        total_bytes: 1_048_576,
        sockets: 3,
        allowed: false,
    }
}

#[test]
fn test_verdict_maps_every_variant() {
    assert_eq!(verdict(WireVerdict::Allow), Verdict::Allow);
    assert_eq!(verdict(WireVerdict::Blocked), Verdict::Blocked);
    assert_eq!(verdict(WireVerdict::Tracker), Verdict::Tracker);
}

#[test]
fn test_signature_maps_every_variant() {
    assert_eq!(signature(WireSignature::Apple), Signature::Apple);
    assert_eq!(
        signature(WireSignature::DevId("TEAM123456".to_string())),
        Signature::DevId("TEAM123456".to_string())
    );
    assert_eq!(signature(WireSignature::Unsigned), Signature::Unsigned);
}

#[test]
fn test_flow_maps_every_variant() {
    assert_eq!(flow(WireFlow::Active(2048)), Flow::Active(2048));
    assert_eq!(flow(WireFlow::Session(4096)), Flow::Session(4096));
    assert_eq!(flow(WireFlow::Zero), Flow::Zero);
    assert_eq!(flow(WireFlow::Idle), Flow::Idle);
}

#[test]
fn test_domain_row_maps_every_field() {
    let row = domain_row(wire_domain());
    assert_eq!(row.host, "googlevideo.com");
    assert_eq!(row.country.as_deref(), Some("US"));
    assert_eq!(row.verdict, Verdict::Tracker);
    assert_eq!(row.rate_bps, 4096);
    assert_eq!(row.total_bytes, 1_048_576);
    assert_eq!(row.sockets, 3);
    assert!(!row.allowed);
}

#[test]
fn test_app_row_maps_every_field_and_converts_path() {
    let wire = WireAppRow {
        id: "com.example.app".to_string(),
        name: "Example".to_string(),
        bundle_path: Some("/Applications/Example.app".to_string()),
        allowed: true,
        known_bad: true,
        down_bytes: 100,
        up_bytes: 200,
        flow: WireFlow::Active(512),
        is_system: false,
        domains: vec![wire_domain()],
    };
    let row = app_row(wire);
    assert_eq!(row.id, "com.example.app");
    assert_eq!(row.name, "Example");
    assert_eq!(
        row.bundle_path,
        Some(PathBuf::from("/Applications/Example.app"))
    );
    assert!(row.allowed);
    assert!(row.known_bad);
    assert_eq!(row.down_bytes, 100);
    assert_eq!(row.up_bytes, 200);
    assert_eq!(row.flow, Flow::Active(512));
    assert_eq!(row.domains.len(), 1);
    assert_eq!(row.domains[0].host, "googlevideo.com");
}

#[test]
fn test_app_row_none_path_stays_none() {
    let wire = WireAppRow {
        id: "x".to_string(),
        name: "X".to_string(),
        bundle_path: None,
        allowed: true,
        known_bad: false,
        down_bytes: 0,
        up_bytes: 0,
        flow: WireFlow::Idle,
        is_system: false,
        domains: Vec::new(),
    };
    assert_eq!(app_row(wire).bundle_path, None);
}

#[test]
fn test_net_row_maps_every_field() {
    let wire = WireNetRow {
        app_name: "Example".to_string(),
        app_path: Some("/Applications/Example.app".to_string()),
        domain: wire_domain(),
    };
    let row = net_row(wire);
    assert_eq!(row.app_name, "Example");
    assert_eq!(
        row.app_path,
        Some(PathBuf::from("/Applications/Example.app"))
    );
    assert_eq!(row.domain.host, "googlevideo.com");
}

#[test]
fn test_proc_row_maps_every_field() {
    let wire = WireProcRow {
        id: "1234".to_string(),
        name: "helper".to_string(),
        bundle_path: Some("/usr/bin/helper".to_string()),
        cpu: 12.5,
        mem_bytes: 4096,
        net_bps: 128,
        net_bytes: 8192,
        stats_known: true,
        is_system: false,
    };
    let row = proc_row(wire);
    assert_eq!(row.id, "1234");
    assert_eq!(row.name, "helper");
    assert_eq!(row.bundle_path, Some(PathBuf::from("/usr/bin/helper")));
    assert!((row.cpu - 12.5).abs() < f32::EPSILON);
    assert_eq!(row.mem_bytes, 4096);
    assert_eq!(row.net_bps, 128);
    assert_eq!(row.net_bytes, 8192);
}

#[test]
fn test_proc_group_maps_every_field_and_members() {
    let member = WireProcRow {
        id: "1234".to_string(),
        name: "helper".to_string(),
        bundle_path: None,
        cpu: 1.0,
        mem_bytes: 1,
        net_bps: 1,
        net_bytes: 1,
        stats_known: true,
        is_system: false,
    };
    let wire = WireProcGroup {
        id: "com.example.app".to_string(),
        name: "Example".to_string(),
        bundle_path: Some("/Applications/Example.app".to_string()),
        cpu: 25.0,
        mem_bytes: 8192,
        net_bps: 256,
        net_bytes: 16384,
        stats_known: true,
        procs: vec![member],
    };
    let group = proc_group(wire);
    assert_eq!(group.id, "com.example.app");
    assert_eq!(group.name, "Example");
    assert_eq!(
        group.bundle_path,
        Some(PathBuf::from("/Applications/Example.app"))
    );
    assert!((group.cpu - 25.0).abs() < f32::EPSILON);
    assert_eq!(group.mem_bytes, 8192);
    assert_eq!(group.net_bps, 256);
    assert_eq!(group.net_bytes, 16384);
    assert_eq!(group.procs.len(), 1);
    assert_eq!(group.procs[0].id, "1234");
}

#[test]
fn test_detail_maps_every_field() {
    let wire = WireDetail {
        name: "Example".to_string(),
        bundle_id: "com.example.app".to_string(),
        bundle_path: Some("/Applications/Example.app".to_string()),
        in_bytes: 10,
        out_bytes: 20,
        path: "/Applications/Example.app/Contents/MacOS/Example".to_string(),
        user: "kingkong".to_string(),
        signature: WireSignature::DevId("TEAM123456".to_string()),
        openbinary: "known good".to_string(),
        hostnames: vec!["a.com".to_string()],
        ips: vec!["1.2.3.4".to_string()],
        ports: vec!["443/tcp".to_string()],
        allowed_count: 5,
        denied_count: 2,
        allowed: true,
    };
    let d = detail(wire);
    assert_eq!(d.name, "Example");
    assert_eq!(d.bundle_id, "com.example.app");
    assert_eq!(
        d.bundle_path,
        Some(PathBuf::from("/Applications/Example.app"))
    );
    assert_eq!(d.in_bytes, 10);
    assert_eq!(d.out_bytes, 20);
    assert_eq!(d.path, "/Applications/Example.app/Contents/MacOS/Example");
    assert_eq!(d.user, "kingkong");
    assert_eq!(d.signature, Signature::DevId("TEAM123456".to_string()));
    assert_eq!(d.openbinary, "known good");
    assert_eq!(d.hostnames, vec!["a.com".to_string()]);
    assert_eq!(d.ips, vec!["1.2.3.4".to_string()]);
    assert_eq!(d.ports, vec!["443/tcp".to_string()]);
    assert_eq!(d.allowed_count, 5);
    assert_eq!(d.denied_count, 2);
    assert!(d.allowed);
}

#[test]
fn test_totals_maps_every_field() {
    let wire = WireTotals {
        down_bytes: 1,
        up_bytes: 2,
        trackers_blocked: 3,
        connections: 4,
        down_bps: 5,
        up_bps: 6,
    };
    let t = totals(wire);
    assert_eq!(t.down_bytes, 1);
    assert_eq!(t.up_bytes, 2);
    assert_eq!(t.trackers_blocked, 3);
    assert_eq!(t.connections, 4);
    assert_eq!(t.down_bps, 5);
    assert_eq!(t.up_bps, 6);
}
