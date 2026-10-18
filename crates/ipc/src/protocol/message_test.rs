#![allow(clippy::panic)]

use super::*;

#[test]
fn test_request_hello_serializes_snake_case_tag() {
    let hello = Request::Hello {
        protocol_version: 1,
        client_version: "0.1.0".into(),
    };
    let json = serde_json::to_string(&hello).expect("serialize");
    assert!(json.contains("\"hello\""));
    let back: Request = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, hello);
}

#[test]
fn test_unit_request_variants_serialize_as_bare_strings() {
    // Unit variants serialize as bare tag strings under external tagging.
    assert_eq!(
        serde_json::to_string(&Request::GetSnapshot).expect("serialize"),
        "\"get_snapshot\""
    );
    assert_eq!(
        serde_json::to_string(&Request::Unsubscribe).expect("serialize"),
        "\"unsubscribe\""
    );
}

#[test]
fn test_response_error_message_defaults_when_absent() {
    // An Error frame from an older daemon that omits `message` deserializes with
    // an empty string via `#[serde(default)]`.
    let json = r#"{"error":{"kind":"bad_request"}}"#;
    let resp: Response = serde_json::from_str(json).expect("deserialize");
    match resp {
        Response::Error { kind, message } => {
            assert_eq!(kind, ErrorKind::BadRequest);
            assert!(message.is_empty());
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn test_event_connection_decided_round_trips() {
    let ev = Event::ConnectionDecided {
        app_id: "com.a".into(),
        host: "a.com".into(),
        verdict: WireVerdict::Blocked,
        allowed: false,
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let back: Event = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, ev);
}

#[test]
fn test_event_kind_round_trips() {
    for kind in [EventKind::ConnectionDecided, EventKind::RateTick] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let back: EventKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, kind);
    }
}

// ---------------------------------------------------------------------------
// R7 profile requests/responses
// ---------------------------------------------------------------------------

#[test]
fn test_get_profile_serializes_snake_case() {
    let json = serde_json::to_string(&Request::GetProfile).expect("serialize");
    assert!(json.contains("get_profile"), "got {json}");
    let back: Request = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, Request::GetProfile);
}

#[test]
fn test_set_mode_round_trips() {
    let req = Request::SetMode {
        mode: super::WireMode::BlockAll,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let back: Request = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, req);
}

#[test]
fn test_profile_mutation_requests_round_trip() {
    let reqs = vec![
        Request::SetAppleAllow { allow: true },
        Request::SetDnsAllow { allow: false },
        Request::SetGroupEnabled {
            group: "location-services".into(),
            enabled: true,
        },
        Request::AddAllowListEntry {
            entry: super::WireAllowEntry {
                app: Some("com.google.Chrome".into()),
                team_id: None,
                host: Some("x.com".into()),
                ip: None,
                note: None,
            },
        },
        Request::RemoveAllowListEntry {
            entry: super::WireAllowEntry {
                app: None,
                team_id: None,
                host: Some("x.com".into()),
                ip: None,
                note: None,
            },
        },
    ];
    for req in reqs {
        let json = serde_json::to_string(&req).expect("serialize");
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }
}

#[test]
fn test_profile_responses_round_trip() {
    let profile = super::WireProfile {
        mode: super::WireMode::AllowAll,
        allow_apple_programs: false,
        allow_dns_traffic: true,
        groups: Vec::new(),
        allowlist: Vec::new(),
    };
    let resp = Response::Profile {
        profile: profile.clone(),
    };
    let json = serde_json::to_string(&resp).expect("serialize");
    let back: Response = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, resp);

    let ack = Response::ProfileAck {
        generation: 7,
        profile,
    };
    let json = serde_json::to_string(&ack).expect("serialize");
    let back: Response = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, ack);
}

#[test]
fn test_policy_capability_round_trips() {
    let json = serde_json::to_string(&super::Capability::Policy).expect("serialize");
    assert!(json.contains("policy"), "got {json}");
    let back: super::Capability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, super::Capability::Policy);
}

// ---------------------------------------------------------------------------
// R8 packet-trace requests / responses / events / capability / ServerFrame
// ---------------------------------------------------------------------------

fn sample_packet_record() -> WirePacketRecord {
    WirePacketRecord {
        seq: 3,
        timestamp_ms: 1_700_000_000_000,
        src: "10.0.0.2:52344".into(),
        dst: "1.1.1.1:443".into(),
        proto: crate::protocol::WireL4Proto::Tcp,
        length: 517,
        direction: crate::protocol::WireDirection::Out,
        app_proto: crate::protocol::WireAppProto::Tls,
        sni: Some("example.com".into()),
        tls_version: Some("TLS 1.2".into()),
        summary: "TLS (example.com)".into(),
    }
}

fn sample_packet_bytes() -> WirePacketBytes {
    WirePacketBytes {
        seq: 3,
        available: true,
        raw: vec![0x16, 0x03, 0x01],
        tree: None,
    }
}

#[test]
fn test_trace_requests_round_trip() {
    let reqs = vec![
        Request::StartTrace {
            app_id: "com.google.Chrome".into(),
        },
        Request::StopTrace,
        Request::GetPacketBytes { seq: 99 },
    ];
    for req in reqs {
        let json = serde_json::to_string(&req).expect("serialize");
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }
}

#[test]
fn test_start_trace_serializes_snake_case_tag() {
    let json = serde_json::to_string(&Request::StartTrace {
        app_id: "com.a".into(),
    })
    .expect("serialize");
    assert!(json.contains("start_trace"), "got {json}");
}

#[test]
fn test_trace_responses_round_trip() {
    let resps = vec![
        Response::TraceStarted {
            session_ok: true,
            source: super::super::WireTraceSource::Live,
        },
        Response::PacketBytes(sample_packet_bytes()),
    ];
    for resp in resps {
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }
}

#[test]
fn test_event_packet_round_trips_and_carries_no_raw() {
    let ev = Event::Packet(sample_packet_record());
    let json = serde_json::to_string(&ev).expect("serialize");
    let back: Event = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, ev);
    // R8: the live event stream carries the light record only — no raw bytes.
    assert!(
        !json.contains("\"raw\""),
        "Event::Packet leaked raw bytes: {json}"
    );
}

#[test]
fn test_event_kind_packet_round_trips() {
    let json = serde_json::to_string(&EventKind::Packet).expect("serialize");
    assert!(json.contains("packet"), "got {json}");
    let back: EventKind = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, EventKind::Packet);
}

#[test]
fn test_trace_capability_round_trips() {
    let json = serde_json::to_string(&Capability::Trace).expect("serialize");
    assert!(json.contains("trace"), "got {json}");
    let back: Capability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, Capability::Trace);
}

#[test]
fn test_server_frame_disambiguates_response_from_event() {
    // R8: a serialized Event::Packet reads back as ServerFrame::Event, and a
    // serialized Response::PacketBytes as ServerFrame::Response, on the same
    // stream — the external tag makes them unambiguous.
    let event_frame = ServerFrame::Event(Event::Packet(sample_packet_record()));
    let json = serde_json::to_string(&event_frame).expect("serialize");
    let back: ServerFrame = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, event_frame);
    assert!(matches!(back, ServerFrame::Event(_)));

    let resp_frame = ServerFrame::Response(Box::new(Response::PacketBytes(sample_packet_bytes())));
    let json = serde_json::to_string(&resp_frame).expect("serialize");
    let back: ServerFrame = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, resp_frame);
    assert!(matches!(back, ServerFrame::Response(_)));
}

#[test]
fn test_server_frame_round_trips_through_codec() {
    // ServerFrame travels over the real newline-delimited codec unchanged.
    let frame = ServerFrame::Event(Event::RateTick {
        down_bps: 10,
        up_bps: 20,
    });
    let mut buf = Vec::new();
    crate::codec::write_message(&mut buf, &frame).expect("write");
    let mut cursor = std::io::Cursor::new(buf);
    let back: ServerFrame = crate::codec::read_message(&mut cursor).expect("read");
    assert_eq!(back, frame);
}

#[test]
fn test_trace_started_source_defaults_unknown_for_old_daemon() {
    // An older daemon's TraceStarted has no `source` field; a new panel must read
    // it as `Unknown` — treated as non-live so demo is never shown as real.
    let json = r#"{"trace_started":{"session_ok":true}}"#;
    let resp: Response = serde_json::from_str(json).expect("old-daemon trace_started");
    match resp {
        Response::TraceStarted { session_ok, source } => {
            assert!(session_ok);
            assert_eq!(source, super::super::WireTraceSource::Unknown);
            assert!(!source.is_live());
        }
        other => panic!("expected TraceStarted, got {other:?}"),
    }
}

#[test]
fn test_trace_started_source_round_trips() {
    use super::super::WireTraceSource;
    for source in [
        WireTraceSource::Live,
        WireTraceSource::DemoNoAccess,
        WireTraceSource::DemoNoCapture,
        WireTraceSource::Unknown,
    ] {
        let resp = Response::TraceStarted {
            session_ok: true,
            source,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(back, resp);
    }
}

#[test]
fn test_unknown_trace_source_label_maps_to_unknown() {
    // A newer daemon reporting a source the panel doesn't recognize is treated as
    // Unknown (non-live), never accidentally shown as live capture.
    let json = r#"{"trace_started":{"session_ok":true,"source":"some_future_source"}}"#;
    let resp: Response = serde_json::from_str(json).expect("forward-compatible");
    match resp {
        Response::TraceStarted { source, .. } => {
            assert_eq!(source, super::super::WireTraceSource::Unknown);
        }
        other => panic!("expected TraceStarted, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// banwatch protocol additions (spec 010 R8)
// ---------------------------------------------------------------------------

#[test]
fn test_banwatch_requests_round_trip() {
    let requests = [
        Request::GetBans,
        Request::SetBan {
            ip: "203.0.113.7".to_owned(),
            ban: true,
            ban_secs: Some(3600),
            detector: Some("manual".to_owned()),
        },
        Request::SetBan {
            ip: "203.0.113.7".to_owned(),
            ban: false,
            ban_secs: None,
            detector: None,
        },
    ];
    for req in requests {
        let json = serde_json::to_string(&req).expect("serialize");
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req, "round-trip {json}");
    }
}

#[test]
fn test_set_ban_optional_fields_default() {
    // An older panel omits ban_secs/detector; the daemon still parses it.
    let json = r#"{"set_ban":{"ip":"203.0.113.7","ban":true}}"#;
    let back: Request = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        back,
        Request::SetBan {
            ip: "203.0.113.7".to_owned(),
            ban: true,
            ban_secs: None,
            detector: None,
        }
    );
}

#[test]
fn test_banwatch_responses_round_trip() {
    let responses = [
        Response::Bans {
            bans: vec![WireBan {
                ip: "203.0.113.7".to_owned(),
                detector: "port-scan".to_owned(),
                banned_at_ms: 1_700_000_000_000,
                expires_at_ms: Some(1_700_000_600_000),
                escalation_count: 1,
                source: "port-scan".to_owned(),
            }],
        },
        Response::BanAck {
            applied: true,
            generation: 42,
        },
    ];
    for resp in responses {
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp, "round-trip {json}");
    }
}

#[test]
fn test_wire_ban_tolerates_missing_fields() {
    // Forward-compat: an older panel receives a WireBan with only the fields it
    // knows; every field defaults, so deserialization never fails.
    let json = r#"{"ip":"203.0.113.7","detector":"manual"}"#;
    let back: WireBan = serde_json::from_str(json).expect("deserialize");
    assert_eq!(back.ip, "203.0.113.7");
    assert_eq!(back.expires_at_ms, None);
    assert_eq!(back.escalation_count, 0);
}

#[test]
fn test_ban_events_round_trip() {
    let events = [
        Event::IpBanned {
            ip: "203.0.113.7".to_owned(),
            detector: "repeat-blocked".to_owned(),
            expires_at_ms: Some(1_700_000_600_000),
        },
        Event::IpUnbanned {
            ip: "203.0.113.7".to_owned(),
        },
    ];
    for ev in events {
        let json = serde_json::to_string(&ev).expect("serialize");
        let back: Event = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ev, "round-trip {json}");
    }
}

#[test]
fn test_ban_changed_event_kind_round_trips() {
    let json = serde_json::to_string(&EventKind::BanChanged).expect("serialize");
    assert!(json.contains("ban_changed"), "got {json}");
    let back: EventKind = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, EventKind::BanChanged);
}

#[test]
fn test_banwatch_capability_round_trips() {
    let json = serde_json::to_string(&Capability::BanWatch).expect("serialize");
    assert!(json.contains("ban_watch"), "got {json}");
    let back: Capability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, Capability::BanWatch);
}

#[test]
fn test_unknown_capability_from_newer_daemon_degrades() {
    // Spec 010 R8 forward-compat: a capability the panel does not know
    // deserializes to Unknown rather than failing the handshake.
    let back: Capability = serde_json::from_str("\"some_future_capability\"").expect("deserialize");
    assert_eq!(back, Capability::Unknown);
}
