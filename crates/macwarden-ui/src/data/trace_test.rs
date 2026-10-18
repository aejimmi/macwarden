#![allow(clippy::indexing_slicing, clippy::panic)]

use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ipc::codec::{CodecError, read_message, write_message};
use ipc::protocol::{
    Event, PROTOCOL_VERSION, Request, Response, ServerFrame, WirePacketBytes, WirePacketRecord,
    WireTraceSource,
};

use super::*;

/// A stub daemon speaking the subscribed-connection protocol: it completes the
/// handshake, then — after `StartTrace` — pushes `Event::Packet` frames as
/// `ServerFrame::Event` while answering `GetPacketBytes` with
/// `ServerFrame::Response`, exercising the client's demux.
fn spawn_trace_stub(server: UnixStream, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = server.set_read_timeout(Some(Duration::from_millis(40)));
        let mut writer = server.try_clone().expect("clone server");
        let mut reader = BufReader::new(server);
        // Handshake: the client sends Hello, expects a plain Welcome.
        let hello: Request = match read_message(&mut reader) {
            Ok(r) => r,
            Err(_) => return,
        };
        assert!(matches!(hello, Request::Hello { .. }));
        let welcome = Response::Welcome {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "trace-stub".into(),
            capabilities: vec![ipc::protocol::Capability::Trace],
        };
        if write_message(&mut writer, &welcome).is_err() {
            return;
        }

        let mut started = false;
        let mut seq = 0u64;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match read_message::<_, Request>(&mut reader) {
                Ok(Request::StartTrace { .. }) => {
                    started = true;
                    // The daemon acks StartTrace with a TraceStarted response
                    // before streaming events; the client's reader ignores it.
                    let ack = ServerFrame::Response(Box::new(Response::TraceStarted {
                        session_ok: true,
                        source: WireTraceSource::Live,
                    }));
                    if write_message(&mut writer, &ack).is_err() {
                        break;
                    }
                }
                Ok(Request::GetPacketBytes { seq: want }) => {
                    let frame =
                        ServerFrame::Response(Box::new(Response::PacketBytes(WirePacketBytes {
                            seq: want,
                            available: true,
                            raw: vec![want as u8; 8],
                            tree: None,
                        })));
                    if write_message(&mut writer, &frame).is_err() {
                        break;
                    }
                }
                Ok(Request::StopTrace) => break,
                Ok(_) => {}
                Err(CodecError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
            if started {
                let frame = ServerFrame::Event(Event::Packet(stub_record(seq)));
                if write_message(&mut writer, &frame).is_err() {
                    break;
                }
                seq += 1;
            }
        }
    })
}

/// A minimal streamed record for the stub.
fn stub_record(seq: u64) -> WirePacketRecord {
    let mut rec = synthetic_record(seq, 1_000 + seq);
    rec.seq = seq;
    rec
}

/// Build a [`TraceConnector`] over a handshake-completed socketpair to the stub.
fn stub_connector() -> (Arc<TraceConnector>, Arc<AtomicBool>) {
    let (client, server) = UnixStream::pair().expect("socketpair");
    let stop = Arc::new(AtomicBool::new(false));
    spawn_trace_stub(server, Arc::clone(&stop));

    // Run the handshake by hand, as `ipc::client::connect` would.
    let mut writer = client.try_clone().expect("clone client");
    write_message(
        &mut writer,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".into(),
        },
    )
    .expect("hello");
    let mut reader = BufReader::new(client.try_clone().expect("clone read half"));
    let welcome: Response = read_message(&mut reader).expect("welcome");
    assert!(matches!(welcome, Response::Welcome { .. }));

    let mut slot = Some(client);
    let connector = TraceConnector::new(Box::new(move || slot.take()));
    (Arc::new(connector), stop)
}

/// Poll `session.drain` until at least `want` packets accumulate or time out.
fn collect(session: &TraceSession, want: usize) -> Vec<WirePacketRecord> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut acc = Vec::new();
    while acc.len() < want && Instant::now() < deadline {
        acc.extend(session.drain(64));
        if acc.len() < want {
            thread::sleep(Duration::from_millis(20));
        }
    }
    acc
}

#[test]
fn test_socket_worker_demuxes_pushed_packets() {
    let (connector, _stop) = stub_connector();
    let session = connect_trace(&connector, "com.example.app").expect("session");
    let packets = collect(&session, 5);
    assert!(packets.len() >= 5, "got {}", packets.len());
    // Sequence numbers arrive monotonically from the push stream.
    assert_eq!(packets[0].seq, 0);
    assert_eq!(packets[1].seq, 1);
}

#[test]
fn test_get_packet_bytes_correlates_amid_event_stream() {
    let (connector, _stop) = stub_connector();
    let session = connect_trace(&connector, "com.example.app").expect("session");
    // Let some packets flow so the byte reply is genuinely interleaved.
    let _ = collect(&session, 3);
    let bytes = session.query().get_packet_bytes(42).expect("bytes");
    assert_eq!(bytes.seq, 42);
    assert!(bytes.available);
    assert_eq!(bytes.raw, vec![42u8; 8]);
}

#[test]
fn test_dropping_session_sets_stop_flag() {
    let (connector, _stop) = stub_connector();
    let session = connect_trace(&connector, "com.example.app").expect("session");
    let _ = collect(&session, 2);
    // Dropping the session signals the worker to stop and send StopTrace.
    drop(session);
    // The connector is exhausted (single-shot), so a second start yields nothing.
    assert!(connect_trace(&connector, "com.example.app").is_none());
}

#[test]
fn test_demo_backend_streams_and_answers_bytes() {
    let backend = DemoTraceBackend;
    let session = backend
        .start_trace("com.example.app")
        .expect("demo session");
    let packets = collect(&session, 10);
    assert!(packets.len() >= 10, "got {}", packets.len());

    let bytes = session.query().get_packet_bytes(0).expect("demo bytes");
    assert!(bytes.available);
    assert!(bytes.tree.is_some());
    let tree = bytes.tree.expect("tree");
    assert_eq!(tree.root.label, "Frame");
    // The frame decodes into ordered layers.
    let labels: Vec<&str> = tree
        .root
        .children
        .iter()
        .map(|c| c.label.as_str())
        .collect();
    assert!(labels.contains(&"Ethernet II"));
    assert!(labels.contains(&"IPv4"));
}

#[test]
fn test_synthetic_bytes_ranges_are_within_frame() {
    let bytes = synthetic_bytes(0);
    let tree = bytes.tree.expect("tree");
    assert_eq!(tree.root.byte_range, 0..bytes.raw.len());
    for child in &tree.root.children {
        assert!(child.byte_range.end <= bytes.raw.len());
        assert!(child.byte_range.start >= tree.root.byte_range.start);
    }
}
