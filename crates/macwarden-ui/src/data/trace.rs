//! The packet-trace subscription — the panel's first streaming/push consumer.
//!
//! A trace runs over a **dedicated** `ipc` connection (separate from the
//! snapshot [`super::daemon::DaemonSource`] worker), opened via a `connect`
//! factory that re-runs the handshake and yields a fresh post-handshake
//! [`UnixStream`]. Sending [`Request::StartTrace`] switches *that* connection
//! into trace mode: the daemon replies with a first
//! [`ServerFrame::Response`]`(TraceStarted)` ack and then interleaves
//! [`ServerFrame::Event`] pushes (`Event::Packet`) with [`ServerFrame::Response`]
//! answers to `GetPacketBytes`. A single reader thread owns the socket and
//! **demuxes** those frames: `Event::Packet` records go to the packet channel the
//! view drains each render, while `GetPacketBytes` requests posted over a command
//! channel are answered inline by reading forward until the matching
//! `Response::PacketBytes` (buffering any packets seen along the way). The
//! existing request/reply `DaemonSource` path is untouched — the demux lives only
//! on this trace connection. (There is no `Subscribe` — `StartTrace` alone
//! subscribes the connection.)
//!
//! A [`DemoTraceBackend`] mirror emits synthetic packets with no socket or root,
//! so the whole trace view is provable from `--demo`.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ipc::codec::{CodecError, read_message, write_message};
use ipc::protocol::{
    Event, Request, Response, ServerFrame, WirePacketBytes, WirePacketRecord, WireTraceSource,
};

use super::source::TraceBackend;

mod demo;

pub use demo::{DemoTraceBackend, synthetic_bytes, synthetic_record};

/// Per-read socket timeout so the reader loop can observe the stop flag and
/// service commands even while no packets are arriving.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a `GetPacketBytes` fetch waits for its reply before giving up.
const BYTES_TIMEOUT: Duration = Duration::from_secs(3);

/// A command posted to the trace worker over its command channel.
enum TraceCmd {
    /// Fetch the raw bytes + decode tree for one selected packet (R8).
    GetBytes {
        /// The packet's per-trace sequence number.
        seq: u64,
        /// Where to send the answer.
        reply: Sender<WirePacketBytes>,
    },
}

/// A cloneable, `Send` handle for fetching a selected packet's bytes off the
/// render thread. The panel clones this onto its background executor so the
/// blocking round-trip never pins the UI.
#[derive(Clone)]
pub struct TraceQuery {
    cmd_tx: Sender<TraceCmd>,
}

impl TraceQuery {
    /// Fetch the raw bytes + decode tree for `seq` (R8). Returns `None` if the
    /// worker is gone or the reply times out; an aged-out packet comes back as
    /// [`WirePacketBytes::available`] `= false` (R6), not `None`.
    #[must_use]
    pub fn get_packet_bytes(&self, seq: u64) -> Option<WirePacketBytes> {
        let (reply, rx) = channel();
        self.cmd_tx.send(TraceCmd::GetBytes { seq, reply }).ok()?;
        rx.recv_timeout(BYTES_TIMEOUT).ok()
    }
}

/// A live trace session: the packet stream the view drains, a [`TraceQuery`] for
/// on-demand byte fetches, and the worker that owns the connection. Dropping it
/// signals the worker to send `StopTrace` and exit (R9 disconnect-stop).
pub struct TraceSession {
    packets_rx: Receiver<WirePacketRecord>,
    query: TraceQuery,
    stop: Arc<AtomicBool>,
    /// The source the daemon reported (from the `TraceStarted` ack) — live BPF
    /// capture vs. the synthetic demo stream. Shared so the reader thread can set
    /// it once the ack arrives; the panel reads it for the honest capture badge.
    source: Arc<Mutex<WireTraceSource>>,
    _worker: Option<JoinHandle<()>>,
}

impl TraceSession {
    /// The reported packet source (live vs. demo). `Unknown` until the daemon's
    /// `TraceStarted` ack lands (typically the first frame).
    #[must_use]
    pub fn source(&self) -> WireTraceSource {
        self.source.lock().map(|s| *s).unwrap_or_default()
    }

    /// Drain up to `max` newly-arrived packets (non-blocking).
    #[must_use]
    pub fn drain(&self, max: usize) -> Vec<WirePacketRecord> {
        let mut out = Vec::new();
        for _ in 0..max {
            match self.packets_rx.try_recv() {
                Ok(rec) => out.push(rec),
                Err(_) => break,
            }
        }
        out
    }

    /// A cloneable query handle for off-thread byte fetches.
    #[must_use]
    pub fn query(&self) -> TraceQuery {
        self.query.clone()
    }

    /// Signal the worker to stop (also happens on drop).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A factory that yields fresh post-handshake trace connections. Held by the
/// [`super::daemon::DaemonSource`]; `start_trace` locks it to open a dedicated
/// connection for a new session.
pub struct TraceConnector {
    connect: Mutex<Box<dyn FnMut() -> Option<UnixStream> + Send>>,
}

impl TraceConnector {
    /// Wrap a connect closure (typically the same one the reconnect path uses).
    #[must_use]
    pub fn new(connect: Box<dyn FnMut() -> Option<UnixStream> + Send>) -> Self {
        Self {
            connect: Mutex::new(connect),
        }
    }

    /// Open one fresh, handshake-completed stream.
    fn fresh(&self) -> Option<UnixStream> {
        let mut guard = self.connect.lock().ok()?;
        (*guard)()
    }
}

/// A [`TraceBackend`] over a real daemon connection: `start_trace` opens a fresh
/// trace connection and spawns the demuxing reader.
pub struct DaemonTraceBackend {
    connector: Arc<TraceConnector>,
}

impl DaemonTraceBackend {
    /// Build the backend from the daemon source's connector.
    #[must_use]
    pub fn new(connector: Arc<TraceConnector>) -> Self {
        Self { connector }
    }
}

impl TraceBackend for DaemonTraceBackend {
    fn start_trace(&self, app_id: &str) -> Option<TraceSession> {
        connect_trace(&self.connector, app_id)
    }
}

/// Open a fresh trace connection, send `StartTrace` (which subscribes the
/// connection), and spawn the demuxing reader thread. The daemon's first frame
/// on the trace connection is a `ServerFrame::Response(TraceStarted)` ack, which
/// the reader loop harmlessly ignores like any non-`PacketBytes` response.
fn connect_trace(connector: &TraceConnector, app_id: &str) -> Option<TraceSession> {
    let stream = connector.fresh()?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok()?;
    let mut writer = stream.try_clone().ok()?;
    write_message(
        &mut writer,
        &Request::StartTrace {
            app_id: app_id.to_string(),
        },
    )
    .ok()?;

    let (packets_tx, packets_rx) = channel();
    let (cmd_tx, cmd_rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let source = Arc::new(Mutex::new(WireTraceSource::Unknown));
    let worker_source = Arc::clone(&source);
    let worker = thread::Builder::new()
        .name("ui-trace".into())
        .spawn(move || {
            run_socket_worker(
                stream,
                writer,
                &packets_tx,
                &cmd_rx,
                &worker_stop,
                &worker_source,
            );
        })
        .ok()?;

    Some(TraceSession {
        packets_rx,
        query: TraceQuery { cmd_tx },
        stop,
        source,
        _worker: Some(worker),
    })
}

/// The demuxing reader: publish `Event::Packet` frames to `packets_tx`, service
/// `GetBytes` commands inline, record the trace source from the `TraceStarted`
/// ack, and send `StopTrace` on shutdown.
fn run_socket_worker(
    stream: UnixStream,
    mut writer: UnixStream,
    packets_tx: &Sender<WirePacketRecord>,
    cmd_rx: &Receiver<TraceCmd>,
    stop: &AtomicBool,
    source: &Mutex<WireTraceSource>,
) {
    let mut reader = BufReader::new(stream);
    loop {
        if stop.load(Ordering::Relaxed) {
            let _ = write_message(&mut writer, &Request::StopTrace);
            break;
        }
        match cmd_rx.try_recv() {
            Ok(TraceCmd::GetBytes { seq, reply }) => {
                let bytes = request_bytes(&mut writer, &mut reader, seq, packets_tx, stop);
                let _ = reply.send(bytes);
                continue;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        match read_message::<_, ServerFrame>(&mut reader) {
            Ok(ServerFrame::Event(Event::Packet(rec))) => {
                if packets_tx.send(rec).is_err() {
                    break;
                }
            }
            // The `TraceStarted` ack carries the honest source kind — record it so
            // the panel's capture badge tells the truth (live vs. demo).
            Ok(ServerFrame::Response(resp)) => {
                if let Response::TraceStarted { source: kind, .. } = *resp
                    && let Ok(mut slot) = source.lock()
                {
                    *slot = kind;
                }
            }
            // Other events — ignore.
            Ok(_) => {}
            Err(CodecError::Io(e)) if would_block(&e) => {}
            Err(_) => break,
        }
    }
}

/// Send `GetPacketBytes{seq}` and read forward until the matching
/// `Response::PacketBytes`, routing any interleaved packets to `packets_tx`.
fn request_bytes(
    writer: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    seq: u64,
    packets_tx: &Sender<WirePacketRecord>,
    stop: &AtomicBool,
) -> WirePacketBytes {
    if write_message(writer, &Request::GetPacketBytes { seq }).is_err() {
        return unavailable(seq);
    }
    let deadline = Instant::now() + BYTES_TIMEOUT;
    loop {
        if stop.load(Ordering::Relaxed) || Instant::now() > deadline {
            return unavailable(seq);
        }
        match read_message::<_, ServerFrame>(reader) {
            Ok(ServerFrame::Response(resp)) => {
                if let Response::PacketBytes(bytes) = *resp {
                    return bytes;
                }
            }
            Ok(ServerFrame::Event(Event::Packet(rec))) => {
                let _ = packets_tx.send(rec);
            }
            Ok(ServerFrame::Event(_)) => {}
            Err(CodecError::Io(e)) if would_block(&e) => {}
            Err(_) => return unavailable(seq),
        }
    }
}

/// The "aged out / unreachable" byte payload (R6): `available = false`, empty.
fn unavailable(seq: u64) -> WirePacketBytes {
    WirePacketBytes {
        seq,
        available: false,
        raw: Vec::new(),
        tree: None,
    }
}

/// Whether an I/O error is a read timeout (the reader should loop, not fail).
fn would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Build a [`TraceSession`] from pre-wired channels, a worker handle, and the
/// reported source. Shared by [`connect_trace`] and the demo backend so both
/// present one session shape.
fn session_from_parts(
    packets_rx: Receiver<WirePacketRecord>,
    cmd_tx: Sender<TraceCmd>,
    stop: Arc<AtomicBool>,
    worker: JoinHandle<()>,
    source: WireTraceSource,
) -> TraceSession {
    TraceSession {
        packets_rx,
        query: TraceQuery { cmd_tx },
        stop,
        source: Arc::new(Mutex::new(source)),
        _worker: Some(worker),
    }
}

#[cfg(test)]
#[path = "trace_test.rs"]
mod trace_test;
