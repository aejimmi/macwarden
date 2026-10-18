#![allow(clippy::unwrap_used, clippy::panic)]

use ipc::protocol::WireSignature;
use net::RuleSet;

use super::super::snapshot::LiveConn;
use super::*;

fn conn(code_id: &str, host: &str, pid: u32) -> LiveConn {
    LiveConn {
        code_id: Some(code_id.to_owned()),
        process: "proc".to_owned(),
        pid,
        path: Some("/Applications/App.app".to_owned()),
        host: Some(host.to_owned()),
        ip: "9.9.9.9".parse().ok(),
        port: 443,
        protocol: "TCP".to_owned(),
        bytes_in: 100,
        bytes_out: 25,
        is_apple_signed: None,
        cpu: 0.0,
        mem_bytes: 0,
        ..LiveConn::default()
    }
}

#[test]
fn test_assemble_detail_aggregates_hosts_and_counts() {
    let rs = RuleSet::default(); // default allow
    let a = conn("com.example.app", "one.test", 5);
    let b = conn("com.example.app", "two.test", 5); // same pid: bytes dedupe
    let matched = vec![&a, &b];

    let detail = assemble_detail(
        "com.example.app",
        &matched,
        &rs,
        WireSignature::Apple,
        "cached line".to_owned(),
        false,
    );

    assert_eq!(detail.bundle_id, "com.example.app");
    assert_eq!(detail.signature, WireSignature::Apple);
    assert_eq!(detail.openbinary, "cached line");
    assert_eq!(detail.hostnames, vec!["one.test", "two.test"]);
    assert_eq!(detail.in_bytes, 100, "pid-deduped");
    assert_eq!(detail.out_bytes, 25);
    assert_eq!(detail.allowed_count, 2);
    assert_eq!(detail.denied_count, 0);
    assert!(detail.allowed);
}

#[test]
fn test_assemble_detail_shows_destination_multiplicity() {
    // Two connections to the same ip:port from the same pid: the deduped IP/port
    // lists carry a ×2 multiplier so they reconcile with the "2 allowed" tally.
    let rs = RuleSet::default();
    let a = conn("com.example.app", "one.test", 5);
    let b = conn("com.example.app", "one.test", 5); // identical ip 9.9.9.9:443
    let matched = vec![&a, &b];

    let detail = assemble_detail(
        "com.example.app",
        &matched,
        &rs,
        WireSignature::Apple,
        "line".to_owned(),
        false,
    );

    assert_eq!(detail.allowed_count, 2);
    assert_eq!(detail.ips, vec!["9.9.9.9 \u{d7}2"]);
    assert_eq!(detail.ports, vec!["443/tcp \u{d7}2"]);
    assert_eq!(detail.hostnames, vec!["one.test \u{d7}2"]);
}

#[test]
fn test_assemble_detail_resolves_user() {
    let rs = RuleSet::default();
    let mut c = conn("com.example.app", "one.test", 5);
    c.user = Some("kingkong".to_owned());
    let matched = vec![&c];
    let detail = assemble_detail(
        "com.example.app",
        &matched,
        &rs,
        WireSignature::Apple,
        "line".to_owned(),
        false,
    );
    assert_eq!(detail.user, "kingkong");
}

#[test]
fn test_assemble_detail_user_dash_when_unresolved() {
    let rs = RuleSet::default();
    let c = conn("com.example.app", "one.test", 5); // user defaults to None
    let matched = vec![&c];
    let detail = assemble_detail(
        "com.example.app",
        &matched,
        &rs,
        WireSignature::Apple,
        "line".to_owned(),
        false,
    );
    assert_eq!(detail.user, "—");
}

#[test]
fn test_openbinary_summary_variants() {
    let both = serde_json::json!({ "title": "T", "summary": "S" });
    assert_eq!(openbinary_summary(&both), Some("T — S".to_owned()));

    let title_only = serde_json::json!({ "title": "T" });
    assert_eq!(openbinary_summary(&title_only), Some("T".to_owned()));

    let empty = serde_json::json!({});
    assert_eq!(openbinary_summary(&empty), None);
}

#[test]
fn test_signature_from_info_mapping() {
    assert_eq!(signature_from_info(true, None), WireSignature::Apple);
    assert_eq!(
        signature_from_info(false, Some("EQHXZ8M8AV".to_owned())),
        WireSignature::DevId("EQHXZ8M8AV".to_owned())
    );
    assert_eq!(signature_from_info(false, None), WireSignature::Unsigned);
}
