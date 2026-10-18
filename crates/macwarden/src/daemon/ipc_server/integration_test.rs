#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use ipc::codec::{read_message, write_message};
use ipc::protocol::{
    Capability, Event, PROTOCOL_VERSION, Request, Response, RuleTarget, ServerFrame, WireDuration,
    WireVerdict,
};
use net::{AddressFamily, Destination, NetworkAction, ProcessIdentity};

use super::banwatch_svc::BanwatchService;
use super::conn::serve_connection;
use super::error::Result;
use super::snapshot::{ConnectionScanner, LiveConn};
use super::state::ServerState;

struct StubScanner(Vec<LiveConn>);

impl ConnectionScanner for StubScanner {
    fn scan(&self) -> Result<Vec<LiveConn>> {
        Ok(self.0.clone())
    }
}

fn conn() -> LiveConn {
    LiveConn {
        code_id: Some("com.example.app".to_owned()),
        process: "proc".to_owned(),
        pid: 1,
        path: Some("/Applications/App.app".to_owned()),
        host: Some("example.test".to_owned()),
        ip: "1.2.3.4".parse().ok(),
        port: 443,
        protocol: "TCP".to_owned(),
        bytes_in: 10,
        bytes_out: 5,
        is_apple_signed: None,
        cpu: 0.0,
        mem_bytes: 0,
        ..LiveConn::default()
    }
}

/// Extract `(generation, first-domain verdict)` from a `Snapshot` response.
fn snapshot_verdict(response: &Response) -> (u64, WireVerdict) {
    match response {
        Response::Snapshot {
            apps, generation, ..
        } => {
            let verdict = apps
                .first()
                .and_then(|a| a.domains.first())
                .map(|d| d.verdict)
                .expect("one app with one domain");
            (*generation, verdict)
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn test_reload_folds_in_ban_from_in_memory_engine_without_store_reopen() {
    // Regression test for the WAL torn-read bug (#4): the daemon reload path must
    // compose ban Deny rules from the banwatch engine's authoritative in-memory
    // set, never by reopening the etch store. Here we ban an IP through the
    // service (which mutates only the in-memory engine + its own WAL), then call
    // `ServerState::reload` and assert the live rule set denies that IP. The
    // ruleset composition reads the ban from the engine snapshot, not a fresh
    // store handle — so no compaction race can drop it.
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path();
    let rules_dir = base_dir.join("net-rules");
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(StubScanner(vec![]));

    let service = BanwatchService::open(base_dir, None)
        .unwrap()
        .expect("default config enables banwatch");
    let banned = "203.0.113.200";
    assert!(service.set_ban(banned, true, Some(3600), None).unwrap());

    let state = ServerState::new(
        "test".to_owned(),
        vec![Capability::Mutations],
        rules_dir,
        scanner,
        None,
        None,
    )
    .unwrap()
    .with_banwatch(Some(Arc::new(service)));

    // The initial rule set (built before banwatch attached) carries no ban.
    let banned_ip: std::net::IpAddr = banned.parse().unwrap();
    assert_eq!(
        state
            .ruleset()
            .decide_for(&ban_proc(), &ban_dest(banned_ip))
            .action,
        NetworkAction::Log,
        "no ban composed before reload",
    );

    // Reload sources the ban from the in-memory engine snapshot.
    state.reload().unwrap();
    assert_eq!(
        state
            .ruleset()
            .decide_for(&ban_proc(), &ban_dest(banned_ip))
            .action,
        NetworkAction::Deny,
        "reload must fold in the in-memory engine ban and deny the IP",
    );
}

/// A process identity for ban-composition assertions (bans are process-blind).
fn ban_proc() -> ProcessIdentity {
    ProcessIdentity {
        pid: 1,
        uid: 501,
        path: "/x".into(),
        code_id: None,
        team_id: None,
        is_valid_signature: None,
        is_apple_signed: None,
    }
}

/// A destination whose remote IP is `ip` (the ban match key).
fn ban_dest(ip: std::net::IpAddr) -> Destination {
    Destination {
        host: None,
        ip,
        port: Some(443),
        protocol: None,
        address_family: AddressFamily::Inet,
    }
}

#[test]
fn test_socketpair_handshake_snapshot_and_mutation_flip() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("net-rules");
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(StubScanner(vec![conn()]));
    let state = Arc::new(
        ServerState::new(
            "test".to_owned(),
            vec![Capability::Mutations],
            rules_dir.clone(),
            scanner,
            None,
            None,
        )
        .unwrap(),
    );
    // Seed the cached sample the way the background sampler would, so the
    // snapshot handler reads it (it no longer scans inline).
    state.store_conns(vec![conn()]);

    // Same-uid socketpair — no listener, no root.
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_state = Arc::clone(&state);
    let handle = thread::spawn(move || serve_connection(server, &server_state));

    let mut reader = BufReader::new(client.try_clone().unwrap());

    // R3: Hello → Welcome.
    write_message(
        &mut client,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
        },
    )
    .unwrap();
    let welcome: Response = read_message(&mut reader).unwrap();
    match welcome {
        Response::Welcome {
            protocol_version,
            capabilities,
            ..
        } => {
            assert_eq!(protocol_version, PROTOCOL_VERSION);
            assert!(capabilities.contains(&Capability::Mutations));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }

    // R4: snapshot before the mutation — default profile allows.
    write_message(&mut client, &Request::GetSnapshot).unwrap();
    let before: Response = read_message(&mut reader).unwrap();
    let (gen_before, verdict_before) = snapshot_verdict(&before);
    assert_eq!(gen_before, 0);
    assert_eq!(verdict_before, WireVerdict::Allow);

    // R7: block the app, expect an ack with a bumped generation and Blocked.
    write_message(
        &mut client,
        &Request::SetRule {
            target: RuleTarget::App {
                code_id: "com.example.app".to_owned(),
            },
            allow: false,
            duration: WireDuration::Permanent,
        },
    )
    .unwrap();
    let ack: Response = read_message(&mut reader).unwrap();
    match ack {
        Response::RuleAck {
            applied,
            generation,
            verdict,
        } => {
            assert!(applied);
            assert_eq!(generation, 1);
            assert_eq!(verdict, WireVerdict::Blocked);
        }
        other => panic!("expected RuleAck, got {other:?}"),
    }

    // R4 again: the next snapshot reflects the just-applied block with gen 1.
    write_message(&mut client, &Request::GetSnapshot).unwrap();
    let after: Response = read_message(&mut reader).unwrap();
    let (gen_after, verdict_after) = snapshot_verdict(&after);
    assert!(gen_after > gen_before);
    assert_eq!(verdict_after, WireVerdict::Blocked);

    // The rule file was written in the `net block` format.
    let rule_file = rules_dir.join("block-com-example-app.toml");
    assert!(rule_file.exists(), "the deny rule file must be written");

    // The live Arc<RuleSet> reflects the mutation (a real hot-reload).
    let ruleset = state.ruleset();
    let process = ProcessIdentity {
        pid: 1,
        uid: 0,
        path: "/Applications/App.app".into(),
        code_id: Some("com.example.app".to_owned()),
        team_id: None,
        is_valid_signature: None,
        is_apple_signed: None,
    };
    let destination = Destination {
        host: Some("example.test".to_owned()),
        ip: "1.2.3.4".parse().unwrap(),
        port: Some(443),
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    assert_eq!(
        ruleset.decide_for(&process, &destination).action,
        NetworkAction::Deny,
        "the live ruleset must deny the blocked app"
    );

    // Close both client fds so the server sees EOF and the thread exits.
    drop(reader);
    drop(client);
    handle.join().unwrap();
}

/// R9/R10 end-to-end over a socketpair (no root — the demo packet source):
/// Hello → StartTrace → interleaved `Event::Packet` pushes → `GetPacketBytes` →
/// `StopTrace`, with the daemon writing `ServerFrame`s after the trace begins.
#[test]
fn test_trace_start_stream_get_bytes_and_stop() {
    let dir = tempfile::tempdir().unwrap();
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(StubScanner(vec![conn()]));
    let state = Arc::new(
        ServerState::new(
            "test".to_owned(),
            vec![Capability::Trace],
            dir.path().join("net-rules"),
            scanner,
            None,
            None,
        )
        .unwrap(),
    );

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_state = Arc::clone(&state);
    let handle = thread::spawn(move || serve_connection(server, &server_state));
    let mut reader = BufReader::new(client.try_clone().unwrap());

    // Handshake — the daemon advertises Trace.
    write_message(
        &mut client,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
        },
    )
    .unwrap();
    let welcome: Response = read_message(&mut reader).unwrap();
    match welcome {
        Response::Welcome { capabilities, .. } => {
            assert!(capabilities.contains(&Capability::Trace));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }

    // StartTrace — from here the client reads ServerFrames.
    write_message(
        &mut client,
        &Request::StartTrace {
            app_id: "com.example.app".to_owned(),
        },
    )
    .unwrap();

    // The first ServerFrame is the TraceStarted ack, ahead of any pushed event.
    match read_message::<_, ServerFrame>(&mut reader).unwrap() {
        ServerFrame::Response(resp) => {
            assert!(matches!(
                *resp,
                Response::TraceStarted {
                    session_ok: true,
                    ..
                }
            ));
        }
        ServerFrame::Event(event) => panic!("expected TraceStarted, got event {event:?}"),
    }

    // Collect pushed packets until the synthetic TLS Client Hello (with SNI)
    // arrives, then select its seq.
    let mut sni_seq = None;
    for _ in 0..40 {
        if let ServerFrame::Event(Event::Packet(p)) = read_message(&mut reader).unwrap()
            && p.sni.as_deref() == Some("example.com")
        {
            sni_seq = Some(p.seq);
            break;
        }
    }
    let seq = sni_seq.expect("a TLS packet carrying an SNI was pushed");

    // GetPacketBytes for that packet — the reply interleaves with more events.
    write_message(&mut client, &Request::GetPacketBytes { seq }).unwrap();
    let bytes = loop {
        match read_message::<_, ServerFrame>(&mut reader).unwrap() {
            ServerFrame::Response(resp) => match *resp {
                Response::PacketBytes(bytes) => break bytes,
                other => panic!("expected PacketBytes, got {other:?}"),
            },
            ServerFrame::Event(_) => {}
        }
    };
    assert_eq!(bytes.seq, seq);
    assert!(bytes.available, "the selected packet is still in the ring");
    assert!(!bytes.raw.is_empty(), "raw frame bytes are returned");
    let tree = bytes.tree.expect("a decode tree");
    assert_eq!(tree.root.label, "Frame");

    // StopTrace — the session tears down and reports inactive.
    write_message(&mut client, &Request::StopTrace).unwrap();
    let stopped = loop {
        match read_message::<_, ServerFrame>(&mut reader).unwrap() {
            ServerFrame::Response(resp) => break *resp,
            ServerFrame::Event(_) => {}
        }
    };
    assert!(matches!(
        stopped,
        Response::TraceStarted {
            session_ok: false,
            ..
        }
    ));

    drop(reader);
    drop(client);
    handle.join().unwrap();
}
