#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::io::{self, BufReader, Cursor, Write};
use std::sync::{Arc, Mutex};

use ipc::codec::read_message;
use ipc::protocol::{Capability, ErrorKind, Event, Response, ServerFrame};

use super::super::error::Result as ServerResult;
use super::super::push::spawn_writer;
use super::super::snapshot::{ConnectionScanner, LiveConn};
use super::super::state::ServerState;
use super::*;

// --- R7: the pure `app_tuples` tuple selector -------------------------------

fn conn(app: &str, ip: &str, port: u16, proto: &str) -> LiveConn {
    let mut c = LiveConn::default();
    c.code_id = Some(app.to_owned());
    c.process = "proc".to_owned();
    c.ip = ip.parse().ok();
    c.port = port;
    c.protocol = proto.to_owned();
    c
}

#[test]
fn test_app_tuples_selects_only_the_target_app() {
    let conns = vec![
        conn("com.a", "1.2.3.4", 443, "TCP"),
        conn("com.b", "5.6.7.8", 53, "UDP"),
    ];
    let tuples = app_tuples("com.a", &conns);
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].ip, "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(tuples[0].port, 443);
    assert_eq!(tuples[0].proto, L4Proto::Tcp);
}

#[test]
fn test_app_tuples_dedups_identical_flows() {
    let conns = vec![
        conn("com.a", "1.2.3.4", 443, "TCP"),
        conn("com.a", "1.2.3.4", 443, "TCP"),
    ];
    assert_eq!(app_tuples("com.a", &conns).len(), 1);
}

#[test]
fn test_app_tuples_is_monotonic_when_a_flow_is_added() {
    let base = vec![conn("com.a", "1.2.3.4", 443, "TCP")];
    let grown = vec![
        conn("com.a", "1.2.3.4", 443, "TCP"),
        conn("com.a", "9.9.9.9", 853, "UDP"),
    ];
    let base_set = app_tuples("com.a", &base);
    let grown_set = app_tuples("com.a", &grown);
    for t in &base_set {
        assert!(grown_set.contains(t), "the grown set is a superset");
    }
    assert_eq!(grown_set.len(), base_set.len() + 1);
}

#[test]
fn test_app_tuples_skips_conns_without_ip_or_port() {
    let mut no_ip = conn("com.a", "1.2.3.4", 443, "TCP");
    no_ip.ip = None;
    let conns = vec![no_ip, conn("com.a", "1.2.3.4", 0, "TCP")];
    assert!(app_tuples("com.a", &conns).is_empty());
}

// --- R9: gating + lifecycle --------------------------------------------------

struct StubScanner(Vec<LiveConn>);

impl ConnectionScanner for StubScanner {
    fn scan(&self) -> ServerResult<Vec<LiveConn>> {
        Ok(self.0.clone())
    }
}

fn state_with(caps: Vec<Capability>) -> Arc<ServerState> {
    let dir = tempfile::tempdir().unwrap();
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(StubScanner(vec![conn(
        "com.example.app",
        "1.2.3.4",
        443,
        "TCP",
    )]));
    Arc::new(
        ServerState::new(
            "test".to_owned(),
            caps,
            dir.path().join("net-rules"),
            scanner,
            None,
            None,
        )
        .unwrap(),
    )
}

/// Extract the error response (`PreparedTrace` is not `Debug`, so `unwrap_err`
/// is unavailable).
fn err_of(result: std::result::Result<PreparedTrace, Box<Response>>) -> Response {
    match result {
        Ok(_) => panic!("expected a gating error, got a prepared trace"),
        Err(response) => *response,
    }
}

#[test]
fn test_start_trace_requires_capability() {
    let state = state_with(vec![]);
    let err = err_of(start_trace(&state, "com.example.app"));
    assert!(matches!(
        err,
        Response::Error {
            kind: ErrorKind::Unsupported,
            ..
        }
    ));
}

#[test]
fn test_start_trace_rejects_bad_app_id() {
    let state = state_with(vec![Capability::Trace]);
    let err = err_of(start_trace(&state, "../etc/passwd"));
    assert!(matches!(
        err,
        Response::Error {
            kind: ErrorKind::BadRequest,
            ..
        }
    ));
}

#[test]
fn test_start_trace_bounds_concurrent_sessions() {
    let state = state_with(vec![Capability::Trace]);
    // Hold the max number of prepared traces (each keeps its slot), then the
    // next start must be refused rather than spawning another capture.
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_TRACES {
        held.push(start_trace(&state, "com.example.app").expect("under the cap"));
    }
    let err = err_of(start_trace(&state, "com.example.app"));
    assert!(matches!(
        err,
        Response::Error {
            kind: ErrorKind::Refused,
            ..
        }
    ));
    // Dropping one releases a slot so a new trace can start again.
    held.pop();
    assert!(start_trace(&state, "com.example.app").is_ok());
}

#[test]
fn test_trace_lifecycle_pushes_packets_then_stops_on_drop() {
    let state = state_with(vec![Capability::Trace]);
    let buf = Arc::new(Mutex::new(Vec::new()));
    let (sink, handle) = spawn_writer(BufWriter(Arc::clone(&buf)));

    let prepared = start_trace(&state, "com.example.app").unwrap();
    sink.send_response(Response::TraceStarted {
        session_ok: true,
        source: ipc::protocol::WireTraceSource::Live,
    });
    let session = prepared.spawn(&sink);

    // Let the pump emit a few packets, then stop via RAII drop (this joins the
    // pump thread — a hang here would mean the stop flag was not observed).
    std::thread::sleep(std::time::Duration::from_millis(700));
    drop(session);
    sink.close();
    handle.join().unwrap();

    let bytes = buf.lock().unwrap().clone();
    let mut reader = BufReader::new(Cursor::new(bytes));
    let frames: Vec<ServerFrame> = std::iter::from_fn(|| read_message(&mut reader).ok()).collect();

    assert!(
        matches!(frames.first(), Some(ServerFrame::Response(_))),
        "TraceStarted is the first frame, ahead of any pushed event"
    );
    let packets: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            ServerFrame::Event(Event::Packet(p)) => Some(p),
            _ => None,
        })
        .collect();
    assert!(!packets.is_empty(), "the pump pushed Event::Packet frames");
    assert!(
        packets
            .iter()
            .any(|p| p.sni.as_deref() == Some("example.com")),
        "the synthetic TLS packet carries its SNI on the wire"
    );
}

#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
