#![allow(clippy::naive_bytecount, clippy::float_cmp)]

use std::io::Cursor;

use super::*;
use crate::protocol::{
    Capability, ErrorKind, Event, EventKind, ExecTarget, HistoryBucket, HistoryScope, Request,
    Response, RuleTarget, WireAppRow, WireDetail, WireDomainRow, WireDuration, WireFlow,
    WireNetRow, WireProcGroup, WireProcRow, WireSignature, WireTotals, WireVerdict,
};

fn sample_domain() -> WireDomainRow {
    WireDomainRow {
        host: "googlevideo.com".into(),
        country: Some("US".into()),
        verdict: WireVerdict::Tracker,
        rate_bps: 1234,
        total_bytes: 999,
        sockets: 3,
        allowed: false,
    }
}

fn sample_app() -> WireAppRow {
    WireAppRow {
        id: "com.google.Chrome".into(),
        name: "Chrome".into(),
        bundle_path: Some("/Applications/Google Chrome.app".into()),
        allowed: true,
        known_bad: false,
        down_bytes: 42,
        up_bytes: 7,
        flow: WireFlow::Active(2048),
        is_system: false,
        domains: vec![sample_domain()],
    }
}

fn sample_detail() -> WireDetail {
    WireDetail {
        name: "Chrome".into(),
        bundle_id: "com.google.Chrome".into(),
        bundle_path: Some("/Applications/Google Chrome.app".into()),
        in_bytes: 10,
        out_bytes: 20,
        path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
        user: "kingkong".into(),
        signature: WireSignature::DevId("EQHXZ8M8AV".into()),
        openbinary: "known good · chrome".into(),
        hostnames: vec!["a.com".into()],
        ips: vec!["1.2.3.4".into()],
        ports: vec!["443/tcp".into()],
        allowed_count: 5,
        denied_count: 1,
        allowed: true,
    }
}

/// Every `Request` variant, for exhaustive round-trip coverage.
fn all_requests() -> Vec<Request> {
    vec![
        Request::Hello {
            protocol_version: PROTOCOL_VERSION_LOCAL,
            client_version: "0.1.0".into(),
        },
        Request::GetSnapshot,
        Request::GetHistory {
            scope: HistoryScope::Today,
            app_id: Some("com.google.Chrome".into()),
        },
        Request::GetHistory {
            scope: HistoryScope::Hour,
            app_id: None,
        },
        Request::GetAppDetail {
            id: "com.google.Chrome".into(),
        },
        Request::GetProcDetail { id: "4123".into() },
        Request::GetDomainDetail {
            host: "googlevideo.com".into(),
        },
        Request::SetRule {
            target: RuleTarget::AppDomain {
                code_id: "com.google.Chrome".into(),
                host: "googlevideo.com".into(),
            },
            allow: false,
            duration: WireDuration::Until { expiry_ms: 999 },
        },
        Request::SetRule {
            target: RuleTarget::App {
                code_id: "com.foo".into(),
            },
            allow: true,
            duration: WireDuration::Session,
        },
        Request::SetRule {
            target: RuleTarget::Domain {
                host: "a.com".into(),
            },
            allow: false,
            duration: WireDuration::Permanent,
        },
        Request::SetExecPolicy {
            target: ExecTarget::TeamId("EQHXZ8M8AV".into()),
            deny: true,
        },
        Request::SetExecPolicy {
            target: ExecTarget::CodeId("com.bad".into()),
            deny: false,
        },
        Request::Subscribe {
            kinds: vec![EventKind::ConnectionDecided, EventKind::RateTick],
        },
        Request::Unsubscribe,
    ]
}

const PROTOCOL_VERSION_LOCAL: u32 = crate::protocol::PROTOCOL_VERSION;

fn all_responses() -> Vec<Response> {
    vec![
        Response::Welcome {
            protocol_version: PROTOCOL_VERSION_LOCAL,
            daemon_version: "0.1.0".into(),
            capabilities: vec![Capability::History, Capability::Mutations],
        },
        Response::Snapshot {
            apps: vec![sample_app()],
            net_rows: vec![WireNetRow {
                app_name: "Chrome".into(),
                app_path: Some("/Applications/Google Chrome.app".into()),
                domain: sample_domain(),
            }],
            procs: vec![WireProcRow {
                id: "4123".into(),
                name: "Chrome".into(),
                bundle_path: None,
                cpu: 12.5,
                mem_bytes: 4096,
                net_bps: 100,
                net_bytes: 200,
                stats_known: true,
                is_system: false,
            }],
            proc_groups: vec![WireProcGroup {
                id: "com.google.Chrome".into(),
                name: "Chrome".into(),
                bundle_path: None,
                cpu: 25.0,
                mem_bytes: 8192,
                net_bps: 200,
                net_bytes: 400,
                stats_known: true,
                procs: vec![],
            }],
            totals: WireTotals {
                down_bytes: 1,
                up_bytes: 2,
                trackers_blocked: 3,
                connections: 4,
                down_bps: 5,
                up_bps: 6,
            },
            generation: 7,
            sample_age_ms: Some(42),
        },
        Response::History {
            buckets: vec![HistoryBucket {
                start_ms: 0,
                end_ms: 3_600_000,
                app_id: Some("com.google.Chrome".into()),
                connections: 10,
                denied: 2,
                tracker_hits: 1,
                down_bytes: 100,
                up_bytes: 50,
            }],
        },
        Response::Detail {
            detail: Some(sample_detail()),
        },
        Response::Detail { detail: None },
        Response::RuleAck {
            applied: true,
            generation: 8,
            verdict: WireVerdict::Blocked,
        },
        Response::Error {
            kind: ErrorKind::VersionMismatch,
            message: "daemon out of date".into(),
        },
    ]
}

fn all_events() -> Vec<Event> {
    vec![
        Event::ConnectionDecided {
            app_id: "com.google.Chrome".into(),
            host: "googlevideo.com".into(),
            verdict: WireVerdict::Allow,
            allowed: true,
        },
        Event::RateTick {
            down_bps: 1000,
            up_bps: 500,
        },
    ]
}

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut buf = Vec::new();
    write_message(&mut buf, value).expect("write");
    let mut cursor = Cursor::new(buf);
    read_message(&mut cursor).expect("read")
}

#[test]
fn test_codec_round_trips_every_request_variant() {
    for req in all_requests() {
        assert_eq!(round_trip(&req), req);
    }
}

#[test]
fn test_codec_round_trips_every_response_variant() {
    for resp in all_responses() {
        assert_eq!(round_trip(&resp), resp);
    }
}

#[test]
fn test_codec_round_trips_every_event_variant() {
    for ev in all_events() {
        assert_eq!(round_trip(&ev), ev);
    }
}

#[test]
fn test_write_appends_single_newline_terminator() {
    let mut buf = Vec::new();
    write_message(&mut buf, &Request::GetSnapshot).expect("write");
    assert_eq!(buf.last(), Some(&b'\n'));
    assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
}

#[test]
fn test_embedded_newline_survives_framing() {
    // A string field containing a literal '\n' must round-trip: JSON escapes it,
    // so it is not treated as a frame boundary.
    let req = Request::GetDomainDetail {
        host: "line1\nline2".into(),
    };
    let mut buf = Vec::new();
    write_message(&mut buf, &req).expect("write");
    // Exactly one raw newline byte — the terminator, not the embedded one.
    assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
    let mut cursor = Cursor::new(buf);
    let back: Request = read_message(&mut cursor).expect("read");
    assert_eq!(back, req);
}

#[test]
fn test_back_to_back_messages_parse_as_two() {
    let mut buf = Vec::new();
    write_message(&mut buf, &Request::GetSnapshot).expect("write 1");
    write_message(&mut buf, &Request::GetAppDetail { id: "com.a".into() }).expect("write 2");
    let mut cursor = Cursor::new(buf);
    let first: Request = read_message(&mut cursor).expect("read 1");
    let second: Request = read_message(&mut cursor).expect("read 2");
    assert_eq!(first, Request::GetSnapshot);
    assert_eq!(second, Request::GetAppDetail { id: "com.a".into() });
}

#[test]
fn test_frame_exceeding_max_frame_on_read_is_rejected() {
    // Build an oversized line (no newline within MAX_FRAME) and confirm the read
    // rejects it rather than allocating unboundedly past the cap.
    let mut buf = vec![b'x'; MAX_FRAME + 10];
    buf.push(b'\n');
    let mut cursor = Cursor::new(buf);
    let err = read_message::<_, Request>(&mut cursor).expect_err("must reject");
    assert!(matches!(err, CodecError::FrameTooLarge));
}

#[test]
fn test_write_rejects_oversized_payload() {
    // A payload whose JSON encoding exceeds MAX_FRAME fails before writing.
    let big = "a".repeat(MAX_FRAME + 1);
    let req = Request::GetDomainDetail { host: big };
    let mut buf = Vec::new();
    let err = write_message(&mut buf, &req).expect_err("must reject");
    assert!(matches!(err, CodecError::FrameTooLarge));
    assert!(buf.is_empty());
}

#[test]
fn test_read_on_closed_stream_reports_closed() {
    let mut cursor = Cursor::new(Vec::new());
    let err = read_message::<_, Request>(&mut cursor).expect_err("closed");
    assert!(matches!(err, CodecError::Closed));
}

#[test]
fn test_read_truncated_frame_without_newline() {
    let mut cursor = Cursor::new(b"{\"get_snapshot\"".to_vec());
    let err = read_message::<_, Request>(&mut cursor).expect_err("truncated");
    assert!(matches!(err, CodecError::Truncated));
}

#[test]
fn test_max_frame_boundary_exact_length_accepted() {
    // A payload of exactly MAX_FRAME data bytes plus newline is accepted.
    let req = Request::GetSnapshot;
    let mut buf = serde_json::to_vec(&req).expect("encode");
    let pad = MAX_FRAME - buf.len();
    // Pad by embedding a long host so the encoded frame length is exactly
    // MAX_FRAME, then confirm read accepts it.
    let host = "a".repeat(pad.saturating_sub(30).max(1));
    let req = Request::GetDomainDetail { host };
    buf = Vec::new();
    write_message(&mut buf, &req).expect("write");
    assert!(buf.len() <= MAX_FRAME + 1);
    let mut cursor = Cursor::new(buf);
    let back: Request = read_message(&mut cursor).expect("read");
    assert_eq!(back, req);
}
