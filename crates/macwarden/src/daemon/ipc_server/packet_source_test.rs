#![allow(clippy::unwrap_used, clippy::panic)]

use capture::{AppProto, Direction, L4Proto, decode_tree};

use super::*;

/// Drain the demo source `n` times, flattening the emitted records.
fn drain_n(source: &mut DemoSource, n: usize) -> Vec<PacketRecord> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend(source.drain());
    }
    out
}

#[test]
fn test_demo_source_emits_monotonic_varied_stream() {
    let mut source = DemoSource::new(&[]);
    let records = drain_n(&mut source, 12);

    assert!(records.len() >= 10, "demo emits one packet per drain");
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.seq, i as u64, "sequence numbers are monotonic from 0");
    }
    // A realistic mix: TLS with an SNI, a DNS query, both directions.
    assert!(
        records
            .iter()
            .any(|r| r.sni.as_deref() == Some("example.com")),
        "a TLS Client Hello carries the synthetic SNI"
    );
    assert!(
        records.iter().any(|r| r.app_proto == AppProto::Dns),
        "a DNS query appears in the stream"
    );
    assert!(records.iter().any(|r| r.direction == Direction::Outbound));
    assert!(records.iter().any(|r| r.direction == Direction::Inbound));
    assert!(records.iter().any(|r| r.proto == L4Proto::Udp));
    assert!(records.iter().any(|r| r.proto == L4Proto::Tcp));
}

#[test]
fn test_demo_client_hello_is_a_real_parseable_frame() {
    let mut source = DemoSource::new(&[]);
    let records = drain_n(&mut source, 5);
    let hello = records
        .iter()
        .find(|r| r.sni.as_deref() == Some("example.com"))
        .expect("a Client Hello frame");

    // The synthetic frame parses through the exact stage-1 path, so its decode
    // tree is a real Frame → Ethernet → IPv4 → TCP → TLS tree.
    let tree = decode_tree(hello);
    assert_eq!(tree.root.label, "Frame");
    let labels: Vec<&str> = tree
        .root
        .children
        .iter()
        .map(|c| c.label.as_str())
        .collect();
    assert!(labels.contains(&"Ethernet"));
    assert!(labels.contains(&"IPv4"));
    assert!(labels.contains(&"TCP"));
    assert!(labels.contains(&"TLS"));
    assert!(!hello.raw.is_empty());
}

#[test]
fn test_demo_app_data_record_is_opaque() {
    let mut source = DemoSource::new(&[]);
    let records = drain_n(&mut source, 6);
    // The application-data record parses to a length only — never a body (R1).
    let app_data = records
        .iter()
        .filter_map(|r| r.tls.as_ref())
        .find_map(|t| t.app_data_len);
    assert!(
        app_data.is_some(),
        "a TLS application-data record appears, carrying a length only"
    );
}

// Without the live backend compiled in (default build), selection always yields
// the demo source, which drains packets immediately. When the live feature is
// on, selection may instead return a live capture (empty until packets arrive),
// so this fallback assertion is scoped to the demo-only build.
#[cfg(not(all(feature = "capture-live", target_os = "macos")))]
#[test]
fn test_select_source_falls_back_to_demo_without_capture() {
    let mut source = select_source(&[]);
    assert!(
        !source.drain().is_empty(),
        "the selected source produces packets"
    );
}

#[test]
fn test_select_source_reports_demo_kind_under_forced_demo() {
    // With the test default (FORCE_DEMO_SOURCE on), selection is the synthetic
    // stream and its reported source is honestly non-live.
    let (source, kind) = select_source(&[]);
    assert_eq!(source.device(), "demo0", "demo device selected");
    assert!(!kind.is_live(), "a demo selection never reports live");
    assert!(matches!(
        kind,
        ipc::protocol::WireTraceSource::DemoNoAccess
            | ipc::protocol::WireTraceSource::DemoNoCapture
    ));
}
