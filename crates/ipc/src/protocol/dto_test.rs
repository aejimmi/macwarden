#![allow(clippy::float_cmp)]

use super::*;

/// Construct a fully-populated `WireAppRow` — every field set — mirroring
/// `macwarden-ui`'s `AppRow`. This is the DTO↔model coverage assertion: if a
/// field is added to `AppRow`, its DTO counterpart must appear here (see the
/// mapping table in `dto.rs`).
#[test]
fn test_full_app_row_covers_every_model_field() {
    let app = WireAppRow {
        id: "com.google.Chrome".into(),     // AppRow::id
        name: "Chrome".into(),              // AppRow::name
        bundle_path: Some("/A.app".into()), // AppRow::bundle_path (PathBuf→String)
        allowed: true,                      // AppRow::allowed
        known_bad: false,                   // AppRow::known_bad
        down_bytes: 10,                     // AppRow::down_bytes
        up_bytes: 20,                       // AppRow::up_bytes
        flow: WireFlow::Active(1),          // AppRow::flow
        is_system: false,                   // AppRow::is_system
        domains: vec![full_domain_row()],   // AppRow::domains
    };
    // Round-trips through JSON identically.
    let json = serde_json::to_string(&app).expect("serialize");
    let back: WireAppRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, app);
}

fn full_domain_row() -> WireDomainRow {
    WireDomainRow {
        host: "a.com".into(),        // DomainRow::host
        country: Some("US".into()),  // DomainRow::country
        verdict: WireVerdict::Allow, // DomainRow::verdict
        rate_bps: 1,                 // DomainRow::rate_bps
        total_bytes: 2,              // DomainRow::total_bytes
        sockets: 3,                  // DomainRow::sockets
        allowed: true,               // DomainRow::allowed
    }
}

#[test]
fn test_full_detail_covers_every_model_field() {
    let detail = WireDetail {
        name: "Chrome".into(),                 // Detail::name
        bundle_id: "com.google.Chrome".into(), // Detail::bundle_id
        bundle_path: Some("/A.app".into()),    // Detail::bundle_path
        in_bytes: 1,                           // Detail::in_bytes
        out_bytes: 2,                          // Detail::out_bytes
        path: "/A".into(),                     // Detail::path
        user: "kingkong".into(),               // Detail::user
        signature: WireSignature::Apple,       // Detail::signature
        openbinary: "not yet analyzed".into(), // Detail::openbinary
        hostnames: vec!["a.com".into()],       // Detail::hostnames
        ips: vec!["1.2.3.4".into()],           // Detail::ips
        ports: vec!["443/tcp".into()],         // Detail::ports
        allowed_count: 4,                      // Detail::allowed_count
        denied_count: 1,                       // Detail::denied_count
        allowed: true,                         // Detail::allowed
    };
    let json = serde_json::to_string(&detail).expect("serialize");
    let back: WireDetail = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, detail);
}

#[test]
fn test_full_totals_covers_every_model_field() {
    let totals = WireTotals {
        down_bytes: 1,       // Totals::down_bytes
        up_bytes: 2,         // Totals::up_bytes
        trackers_blocked: 3, // Totals::trackers_blocked
        connections: 4,      // Totals::connections
        down_bps: 5,         // Totals::down_bps
        up_bps: 6,           // Totals::up_bps
    };
    let json = serde_json::to_string(&totals).expect("serialize");
    let back: WireTotals = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, totals);
}

#[test]
fn test_proc_row_and_group_cover_every_model_field() {
    let proc = WireProcRow {
        id: "1".into(),    // ProcRow::id
        name: "p".into(),  // ProcRow::name
        bundle_path: None, // ProcRow::bundle_path
        cpu: 1.0,          // ProcRow::cpu
        mem_bytes: 2,      // ProcRow::mem_bytes
        net_bps: 3,        // ProcRow::net_bps
        net_bytes: 4,      // ProcRow::net_bytes
        is_system: false,  // ProcRow::is_system
        stats_known: true, // ProcRow::stats_known
    };
    let group = WireProcGroup {
        id: "1".into(),            // ProcGroup::id
        name: "p".into(),          // ProcGroup::name
        bundle_path: None,         // ProcGroup::bundle_path
        cpu: 1.0,                  // ProcGroup::cpu
        mem_bytes: 2,              // ProcGroup::mem_bytes
        net_bps: 3,                // ProcGroup::net_bps
        net_bytes: 4,              // ProcGroup::net_bytes
        procs: vec![proc.clone()], // ProcGroup::procs
        stats_known: true,         // ProcGroup::stats_known
    };
    assert_eq!(group.procs.first(), Some(&proc));
}

#[test]
fn test_proc_row_stats_known_defaults_true_for_old_daemon() {
    // An old daemon's JSON has no `stats_known` field. A new panel must read it
    // as `true` — the old daemon only ever reported real (or already-zeroed)
    // numbers, so absence of the flag means "known".
    let json = r#"{"id":"1","name":"p","cpu":1.0,"mem_bytes":2,"net_bps":3,"net_bytes":4}"#;
    let row: WireProcRow = serde_json::from_str(json).expect("old-daemon proc row");
    assert!(row.stats_known, "missing stats_known must default to true");
}

#[test]
fn test_proc_row_unknown_stats_roundtrip_and_old_panel_compat() {
    // A new daemon emits stats_known=false. It round-trips, and an old-shaped
    // panel struct (no stats_known field) still deserializes it — serde ignores
    // the unknown field, so new daemon → old panel stays compatible.
    let row = WireProcRow {
        id: "1".into(),
        name: "p".into(),
        bundle_path: None,
        cpu: 0.0,
        mem_bytes: 0,
        net_bps: 0,
        net_bytes: 0,
        is_system: false,
        stats_known: false,
    };
    let json = serde_json::to_string(&row).expect("serialize");
    let back: WireProcRow = serde_json::from_str(&json).expect("roundtrip");
    assert!(!back.stats_known);

    #[derive(serde::Deserialize)]
    struct OldProcRow {
        cpu: f32,
        mem_bytes: u64,
    }
    let old: OldProcRow = serde_json::from_str(&json).expect("old panel ignores new field");
    assert_eq!(old.cpu, 0.0);
    assert_eq!(old.mem_bytes, 0);
}

#[test]
fn test_serde_default_absorbs_additive_field_drift() {
    // A DomainRow JSON missing the optional `country` field (as an older daemon
    // would omit) deserializes via `#[serde(default)]` rather than failing.
    let json = r#"{"host":"a.com","verdict":"allow","rate_bps":0,"total_bytes":0,"sockets":0,"allowed":true}"#;
    let row: WireDomainRow = serde_json::from_str(json).expect("deserialize");
    assert_eq!(row.country, None);
    assert_eq!(row.host, "a.com");
}

#[test]
fn test_wire_signature_devid_carries_team() {
    let sig = WireSignature::DevId("EQHXZ8M8AV".into());
    let json = serde_json::to_string(&sig).expect("serialize");
    let back: WireSignature = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, sig);
}

#[test]
fn test_wire_duration_until_carries_expiry() {
    let d = WireDuration::Until { expiry_ms: 42 };
    let json = serde_json::to_string(&d).expect("serialize");
    let back: WireDuration = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, d);
}

// ---------------------------------------------------------------------------
// R7 policy DTOs
// ---------------------------------------------------------------------------

#[test]
fn test_wire_mode_round_trips() {
    for mode in [WireMode::AllowAll, WireMode::BlockAll] {
        let json = serde_json::to_string(&mode).expect("serialize");
        let back: WireMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, mode);
    }
}

#[test]
fn test_wire_allow_entry_round_trips() {
    let entry = WireAllowEntry {
        app: Some("com.google.Chrome".into()),
        team_id: None,
        host: Some("*.googleapis.com".into()),
        ip: Some("140.82.112.0/20".into()),
        note: Some("work".into()),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let back: WireAllowEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, entry);
}

#[test]
fn test_wire_allow_entry_defaults_absorb_missing_fields() {
    let entry: WireAllowEntry = serde_json::from_str(r#"{"host":"a.com"}"#).expect("deserialize");
    assert_eq!(entry.host.as_deref(), Some("a.com"));
    assert!(entry.app.is_none());
    assert!(entry.ip.is_none());
}

#[test]
fn test_wire_group_state_round_trips() {
    let g = WireGroupState {
        name: "location-services".into(),
        description: "loc".into(),
        enabled: true,
        default_enabled: false,
        domain_count: 12,
    };
    let json = serde_json::to_string(&g).expect("serialize");
    let back: WireGroupState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, g);
}

#[test]
fn test_wire_profile_round_trips() {
    let profile = WireProfile {
        mode: WireMode::BlockAll,
        allow_apple_programs: true,
        allow_dns_traffic: false,
        groups: vec![WireGroupState {
            name: "gaming".into(),
            description: "g".into(),
            enabled: false,
            default_enabled: false,
            domain_count: 3,
        }],
        allowlist: vec![WireAllowEntry {
            app: None,
            team_id: Some("EQHXZ8M8AV".into()),
            host: None,
            ip: None,
            note: None,
        }],
    };
    let json = serde_json::to_string(&profile).expect("serialize");
    let back: WireProfile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, profile);
}

// ---------------------------------------------------------------------------
// R8 packet-trace DTOs
// ---------------------------------------------------------------------------

/// A fully-populated light stream record — every field set — mirroring
/// `capture`'s `PacketRecord` (minus raw bytes / decode tree).
fn full_packet_record() -> WirePacketRecord {
    WirePacketRecord {
        seq: 42,                             // PacketRecord::seq
        timestamp_ms: 1_700_000_000_123,     // PacketRecord::ts
        src: "10.0.0.2:52344".into(),        // PacketRecord::src
        dst: "1.1.1.1:443".into(),           // PacketRecord::dst
        proto: WireL4Proto::Tcp,             // PacketRecord::proto
        length: 517,                         // PacketRecord::length
        direction: WireDirection::Out,       // PacketRecord::direction
        app_proto: WireAppProto::Tls,        // PacketRecord::app_proto
        sni: Some("example.com".into()),     // PacketRecord::sni
        tls_version: Some("TLS 1.3".into()), // TlsInfo::version
        summary: "TCP 10.0.0.2:52344 -> 1.1.1.1:443 TLS (example.com)".into(),
    }
}

#[test]
fn test_wire_packet_record_round_trips() {
    let rec = full_packet_record();
    let json = serde_json::to_string(&rec).expect("serialize");
    let back: WirePacketRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, rec);
}

#[test]
fn test_wire_packet_record_carries_no_raw_bytes() {
    // R8: the light stream record must never carry raw bytes (kept for the heavy
    // GetPacketBytes fetch). The serialized JSON has no `raw` key.
    let json = serde_json::to_string(&full_packet_record()).expect("serialize");
    assert!(
        !json.contains("\"raw\""),
        "light record leaked raw bytes: {json}"
    );
}

#[test]
fn test_wire_packet_record_absent_optionals_default() {
    // A record from a non-TLS packet omits `sni`/`tls_version`; `#[serde(default)]`
    // absorbs the missing fields rather than failing.
    let json = r#"{"seq":1,"timestamp_ms":0,"src":"a","dst":"b","proto":"udp","length":60,"direction":"in","app_proto":"dns","summary":"DNS"}"#;
    let rec: WirePacketRecord = serde_json::from_str(json).expect("deserialize");
    assert_eq!(rec.sni, None);
    assert_eq!(rec.tls_version, None);
    assert_eq!(rec.proto, WireL4Proto::Udp);
    assert_eq!(rec.direction, WireDirection::In);
}

#[test]
fn test_wire_l4_proto_and_app_proto_variants_round_trip() {
    for p in [
        WireL4Proto::Tcp,
        WireL4Proto::Udp,
        WireL4Proto::Icmp,
        WireL4Proto::Arp,
        WireL4Proto::Other,
    ] {
        let json = serde_json::to_string(&p).expect("serialize");
        let back: WireL4Proto = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, p);
    }
    for a in [
        WireAppProto::Tls,
        WireAppProto::Dns,
        WireAppProto::Http,
        WireAppProto::Quic,
        WireAppProto::Unknown,
    ] {
        let json = serde_json::to_string(&a).expect("serialize");
        let back: WireAppProto = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, a);
    }
    for d in [
        WireDirection::In,
        WireDirection::Out,
        WireDirection::Unknown,
    ] {
        let json = serde_json::to_string(&d).expect("serialize");
        let back: WireDirection = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, d);
    }
}

/// A nested decode tree with child ranges contained in their parent's range,
/// mirroring `capture`'s `DecodeTree` (Frame → Ethernet → IPv4 → TCP).
fn full_decode_tree() -> WireDecodeTree {
    WireDecodeTree {
        root: WireDecodeNode {
            label: "Frame".into(),
            summary: "60 bytes on wire, Ethernet".into(),
            byte_range: 0..60,
            fields: vec![("Length".into(), "60".into())],
            children: vec![
                WireDecodeNode {
                    label: "Ethernet".into(),
                    summary: "14-byte link header".into(),
                    byte_range: 0..14,
                    fields: Vec::new(),
                    children: Vec::new(),
                },
                WireDecodeNode {
                    label: "IPv4".into(),
                    summary: "10.0.0.2 → 1.1.1.1".into(),
                    byte_range: 14..34,
                    fields: vec![("Source".into(), "10.0.0.2".into())],
                    children: Vec::new(),
                },
            ],
        },
    }
}

#[test]
fn test_wire_decode_tree_round_trips() {
    let tree = full_decode_tree();
    let json = serde_json::to_string(&tree).expect("serialize");
    let back: WireDecodeTree = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, tree);
}

#[test]
fn test_wire_decode_node_defaults_absorb_empty_fields_children() {
    // A leaf node omitting `fields`/`children` deserializes via `#[serde(default)]`.
    let json = r#"{"label":"TLS","summary":"ClientHello","byte_range":{"start":34,"end":60}}"#;
    let node: WireDecodeNode = serde_json::from_str(json).expect("deserialize");
    assert_eq!(node.byte_range, 34..60);
    assert!(node.fields.is_empty());
    assert!(node.children.is_empty());
}

#[test]
fn test_wire_packet_bytes_available_round_trips() {
    let bytes = WirePacketBytes {
        seq: 42,
        available: true,
        raw: vec![0xde, 0xad, 0xbe, 0xef],
        tree: Some(full_decode_tree()),
    };
    let json = serde_json::to_string(&bytes).expect("serialize");
    let back: WirePacketBytes = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, bytes);
}

#[test]
fn test_wire_packet_bytes_aged_out_round_trips() {
    // R6: an evicted `seq` returns `available == false` with empty raw/tree —
    // a graceful "not available", not an error.
    let bytes = WirePacketBytes {
        seq: 7,
        available: false,
        raw: Vec::new(),
        tree: None,
    };
    let json = serde_json::to_string(&bytes).expect("serialize");
    let back: WirePacketBytes = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, bytes);
    assert!(!back.available);
    assert!(back.raw.is_empty());
    assert!(back.tree.is_none());
}
