#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use ipc::protocol::{WireAppProto, WireDirection, WireL4Proto, WirePacketBytes, WirePacketRecord};

/// Build a light record with the given transport / app protocol and sequence.
fn rec(seq: u64, proto: WireL4Proto, app: WireAppProto, sni: Option<&str>) -> WirePacketRecord {
    WirePacketRecord {
        seq,
        timestamp_ms: 1_000 + seq,
        src: "192.168.1.42:50000".into(),
        dst: "1.2.3.4:443".into(),
        proto,
        length: 100,
        direction: WireDirection::Out,
        app_proto: app,
        sni: sni.map(str::to_string),
        tls_version: None,
        summary: "test".into(),
    }
}

#[test]
fn test_push_builds_list_in_order() {
    let mut m = TraceModel::new();
    m.push(rec(0, WireL4Proto::Tcp, WireAppProto::Tls, Some("a.com")));
    m.push(rec(1, WireL4Proto::Udp, WireAppProto::Dns, Some("b.com")));
    let visible = m.visible();
    assert_eq!(visible.len(), 2);
    assert_eq!(visible[0].seq, 0);
    assert_eq!(visible[1].seq, 1);
    assert_eq!(m.total(), 2);
    assert_eq!(m.dropped(), 0);
}

#[test]
fn test_ring_evicts_oldest_and_counts_drops() {
    let mut m = TraceModel::new();
    let over = 5;
    for seq in 0..(RING_CAP as u64 + over) {
        m.push(rec(seq, WireL4Proto::Tcp, WireAppProto::Unknown, None));
    }
    assert_eq!(m.retained(), RING_CAP);
    assert_eq!(m.dropped(), over);
    assert_eq!(m.total(), RING_CAP as u64 + over);
    // The newest are kept: the front is the (over)th sequence.
    assert_eq!(m.first_seq(), Some(over));
}

#[test]
fn test_filter_selects_subset_per_tab() {
    let mut m = TraceModel::new();
    m.push(rec(0, WireL4Proto::Tcp, WireAppProto::Tls, Some("tls.com")));
    m.push(rec(1, WireL4Proto::Udp, WireAppProto::Dns, Some("dns.com")));
    m.push(rec(
        2,
        WireL4Proto::Tcp,
        WireAppProto::Http,
        Some("http.com"),
    ));
    m.push(rec(3, WireL4Proto::Icmp, WireAppProto::Unknown, None));

    m.set_filter(ProtoFilter::Tls);
    assert_eq!(
        m.visible().iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![0]
    );
    m.set_filter(ProtoFilter::Dns);
    assert_eq!(
        m.visible().iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1]
    );
    m.set_filter(ProtoFilter::Http);
    assert_eq!(
        m.visible().iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![2]
    );
    m.set_filter(ProtoFilter::Udp);
    assert_eq!(
        m.visible().iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1]
    );
    m.set_filter(ProtoFilter::Errors);
    assert_eq!(
        m.visible().iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![3]
    );
    m.set_filter(ProtoFilter::All);
    assert_eq!(m.visible().len(), 4);
}

#[test]
fn test_select_marks_loading_then_stores_bytes() {
    let mut m = TraceModel::new();
    m.push(rec(7, WireL4Proto::Tcp, WireAppProto::Tls, Some("x.com")));
    m.select(7);
    assert_eq!(m.selected(), Some(7));
    assert!(m.bytes_loading());
    assert!(m.bytes().is_none());

    m.set_bytes(WirePacketBytes {
        seq: 7,
        available: true,
        raw: vec![1, 2, 3],
        tree: None,
    });
    assert!(!m.bytes_loading());
    assert_eq!(m.bytes().map(|b| b.raw.len()), Some(3));
}

#[test]
fn test_selecting_a_new_packet_clears_prior_bytes() {
    let mut m = TraceModel::new();
    m.select(1);
    m.set_bytes(WirePacketBytes {
        seq: 1,
        available: true,
        raw: vec![9],
        tree: None,
    });
    m.select(2);
    assert_eq!(m.selected(), Some(2));
    assert!(m.bytes_loading());
    assert!(m.bytes().is_none());
}

#[test]
fn test_toggle_highlight_sets_and_clears() {
    let mut m = TraceModel::new();
    assert!(m.highlight().is_none());
    m.toggle_highlight(0..14);
    assert_eq!(m.highlight(), Some(&(0..14)));
    m.toggle_highlight(0..14);
    assert!(m.highlight().is_none());
    m.toggle_highlight(14..34);
    assert_eq!(m.highlight(), Some(&(14..34)));
}

#[test]
fn test_clear_resets_list_but_not_capture() {
    let mut m = TraceModel::new();
    for seq in 0..10 {
        m.push(rec(seq, WireL4Proto::Tcp, WireAppProto::Unknown, None));
    }
    m.select(3);
    m.clear();
    assert_eq!(m.retained(), 0);
    assert_eq!(m.total(), 0);
    assert_eq!(m.dropped(), 0);
    assert!(m.selected().is_none());
    assert!(m.bytes().is_none());
}

#[test]
fn test_chip_proto_prefers_app_protocol() {
    let tls = rec(0, WireL4Proto::Tcp, WireAppProto::Tls, None);
    assert_eq!(ChipProto::of(&tls), ChipProto::Tls);
    let plain = rec(1, WireL4Proto::Tcp, WireAppProto::Unknown, None);
    assert_eq!(ChipProto::of(&plain), ChipProto::Tcp);
    let quic = rec(2, WireL4Proto::Udp, WireAppProto::Quic, None);
    assert_eq!(ChipProto::of(&quic), ChipProto::Quic);
    assert_eq!(ChipProto::Tls.label(), "TLS");
}

#[test]
fn test_hex_rows_format_offset_hex_ascii() {
    let raw: Vec<u8> = (0..18).collect();
    let rows = hex_rows(&raw);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].offset, 0);
    assert_eq!(rows[0].range, 0..16);
    assert_eq!(rows[1].offset, 16);
    assert_eq!(rows[1].range, 16..18);
    // First row starts 00 01 02 …; ASCII gutter maps control bytes to '.'.
    assert!(rows[0].hex.starts_with("00 01 02 03"));
    assert_eq!(rows[0].ascii.len(), 16);
    // The short final row's hex column is right-padded so gutters stay aligned.
    assert_eq!(rows[1].ascii.len(), 2);
}

#[test]
fn test_hex_rows_are_capped() {
    let raw = vec![0u8; HEX_MAX * 4];
    let rows = hex_rows(&raw);
    assert_eq!(rows.len(), HEX_MAX / 16);
}

#[test]
fn test_hex_ascii_gutter_prints_printable() {
    let rows = hex_rows(b"AB\x00~");
    assert_eq!(&rows[0].ascii, "AB.~");
}

#[test]
fn test_select_marks_loading_not_failed() {
    let mut m = TraceModel::new();
    m.select(7);
    assert!(m.bytes_loading());
    assert!(!m.bytes_failed());
    assert!(m.bytes().is_none());
}

#[test]
fn test_fail_bytes_is_terminal_not_loading() {
    // A failed fetch (worker gone / timed out) must leave a terminal state, never
    // stuck "loading" — so the detail pane can render a clear message.
    let mut m = TraceModel::new();
    m.select(7);
    m.fail_bytes();
    assert!(!m.bytes_loading(), "no longer loading after a failed fetch");
    assert!(m.bytes_failed(), "failed state is set");
    assert!(m.bytes().is_none());
}

#[test]
fn test_set_bytes_clears_failed() {
    let mut m = TraceModel::new();
    m.select(7);
    m.fail_bytes();
    m.set_bytes(WirePacketBytes {
        seq: 7,
        available: true,
        raw: vec![1, 2, 3],
        tree: None,
    });
    assert!(!m.bytes_failed());
    assert!(!m.bytes_loading());
    assert!(m.bytes().is_some());
}

#[test]
fn test_reselect_after_failure_resets_to_loading() {
    let mut m = TraceModel::new();
    m.select(7);
    m.fail_bytes();
    m.select(7); // retry
    assert!(m.bytes_loading());
    assert!(!m.bytes_failed());
}
