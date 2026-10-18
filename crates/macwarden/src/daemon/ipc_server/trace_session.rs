//! The daemon-side [`TraceSession`] lifecycle (spec R9).
//!
//! A trace ties three things together: the R7 connection scanner (which maps the
//! selected app → its live 5-tuples), a [`PacketSource`] (the real BPF capture
//! under root, else the [`DemoSource`](super::packet_source::DemoSource)), and a
//! bounded ring buffer keyed by `seq` (R6, for on-demand `GetPacketBytes`).
//!
//! [`start_trace`] gates the request (capability, boundary validation, a bounded
//! session count), seeds the filter from the app's current tuples, and spawns a
//! **pump thread** that drains the source on a cadence, retains raw bytes in the
//! ring, refreshes the filter as the app opens new flows, and pushes each packet
//! as a light [`Event::Packet`] over the connection's [`FrameSink`] (R10).
//!
//! Teardown is RAII: dropping the [`TraceSession`] sets the stop flag and joins
//! the pump, and the pump's owned source drops with it — releasing the BPF
//! handle. So `StopTrace`, the connection closing, and the client disconnecting
//! all tear the capture down through the same path (R9).

use std::collections::HashSet;
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use capture::{FlowTuple, L4Proto, PacketRecord, PacketRing};
use ipc::protocol::{Capability, ErrorKind, Event, Response, WireTraceSource};
use ipc::validate::validate_app_id;
use tracing::{debug, warn};

use super::packet_source::{PacketSource, select_source};
use super::push::FrameSink;
use super::snapshot::{ConnectionScanner, LiveConn};
use super::state::ServerState;

/// Maximum concurrent trace sessions across all connections (R9). Small so
/// panels cannot spawn unbounded captures.
const MAX_CONCURRENT_TRACES: usize = 4;

/// How often the pump drains the source and emits packets.
const POLL_INTERVAL: Duration = Duration::from_millis(180);

/// Refresh the capture filter from the scanner every this many pump ticks
/// (~1.8 s), picking up flows the app opened after the trace began (R2/R7).
const REFRESH_TICKS: u64 = 10;

/// A live per-app packet trace on one connection. Dropping it stops the pump and
/// releases the underlying capture (RAII, R9).
pub struct TraceSession {
    ring: Arc<Mutex<PacketRing>>,
    stop: Arc<AtomicBool>,
    pump: Option<JoinHandle<()>>,
    _slot: TraceSlot,
}

impl TraceSession {
    /// Answer [`ipc::protocol::Request::GetPacketBytes`] from the ring (R6/R8):
    /// the raw frame + decode tree for a retained `seq`, or a graceful
    /// "not available" when it has aged out.
    #[must_use]
    pub fn packet_bytes(&self, seq: u64) -> Response {
        let bytes = match self.ring.lock() {
            Ok(ring) => ring.get(seq).map(super::trace_map::wire_bytes),
            Err(poisoned) => poisoned
                .into_inner()
                .get(seq)
                .map(super::trace_map::wire_bytes),
        };
        Response::PacketBytes(bytes.unwrap_or_else(|| super::trace_map::unavailable_bytes(seq)))
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.pump.take()
            && handle.join().is_err()
        {
            warn!("trace pump thread terminated abnormally");
        }
    }
}

/// A gated, resourced-but-not-yet-running trace (spec R9). Splitting "prepare"
/// from "spawn" lets the connection layer enqueue the `TraceStarted` response
/// **before** the pump starts, so that response is always the first frame the
/// client sees — pushed events can only follow it, never race ahead of it.
pub struct PreparedTrace {
    source: Box<dyn PacketSource>,
    ring: Arc<Mutex<PacketRing>>,
    stop: Arc<AtomicBool>,
    scanner: Arc<dyn ConnectionScanner>,
    app_id: String,
    slot: TraceSlot,
    device: String,
    source_kind: WireTraceSource,
}

impl PreparedTrace {
    /// Which source backs this trace (live capture vs. demo stream), for the
    /// `TraceStarted` ack — surfaced so the panel never presents demo as real.
    #[must_use]
    pub fn source_kind(&self) -> WireTraceSource {
        self.source_kind
    }

    /// Spawn the pump thread bound to `sink` and hand back the live session.
    ///
    /// A failure to spawn the pump is non-fatal: the session is returned with no
    /// pump (it simply emits nothing) so the connection stays consistent; the
    /// stop/RAII teardown path is unchanged.
    #[must_use]
    pub fn spawn(self, sink: &FrameSink) -> TraceSession {
        let ctx = PumpCtx {
            source: self.source,
            ring: Arc::clone(&self.ring),
            stop: Arc::clone(&self.stop),
            scanner: self.scanner,
            app_id: self.app_id,
            sink: sink.clone(),
        };
        let pump = thread::Builder::new()
            .name("mw-trace-pump".to_string())
            .spawn(move || run_pump(ctx))
            .map_or_else(
                |e| {
                    warn!(error = %e, "failed to spawn trace pump; trace will be empty");
                    None
                },
                Some,
            );
        debug!(device = %self.device, "trace session started");
        TraceSession {
            ring: self.ring,
            stop: self.stop,
            pump,
            _slot: self.slot,
        }
    }
}

/// Gate and resource a trace for `app_id` (spec R9) without starting it yet.
///
/// Returns a [`PreparedTrace`] on success, or a ready-to-send [`Response`] error
/// on any gating failure — missing [`Capability::Trace`], a malformed `app_id`,
/// or the concurrent-session cap — never a panic. Call [`PreparedTrace::spawn`]
/// after enqueuing the `TraceStarted` response to begin the packet stream.
pub fn start_trace(state: &ServerState, app_id: &str) -> Result<PreparedTrace, Box<Response>> {
    if !state.capabilities.contains(&Capability::Trace) {
        return Err(error(
            ErrorKind::Unsupported,
            "packet trace is not supported",
        ));
    }
    if let Err(e) = validate_app_id(app_id) {
        return Err(error(ErrorKind::BadRequest, &e.to_string()));
    }
    let slot = TraceSlot::try_acquire(Arc::clone(state.active_traces()))
        .ok_or_else(|| error(ErrorKind::Refused, "too many concurrent traces"))?;

    let tuples = resolve_tuples(state, app_id);
    let (source, source_kind) = select_source(&tuples);
    let device = source.device().to_owned();
    debug!(app_id, device = %device, tuples = tuples.len(), ?source_kind, "trace prepared");
    Ok(PreparedTrace {
        source,
        ring: Arc::new(Mutex::new(PacketRing::with_defaults())),
        stop: Arc::new(AtomicBool::new(false)),
        scanner: Arc::clone(state.scanner()),
        app_id: app_id.to_owned(),
        slot,
        device,
        source_kind,
    })
}

/// Resolve the app's current 5-tuples via the scanner (R7). A scan failure or an
/// app with no live flows yields an empty set — the demo source still emits and
/// the live source captures nothing until a refresh finds a flow.
fn resolve_tuples(state: &ServerState, app_id: &str) -> Vec<FlowTuple> {
    match state.scanner().scan() {
        Ok(conns) => app_tuples(app_id, &conns),
        Err(e) => {
            debug!(error = %e, "trace tuple scan failed; starting with empty filter");
            Vec::new()
        }
    }
}

/// Select the target app's connections and reduce them to a de-duplicated
/// `(ip, port, proto)` flow-tuple set (spec R7).
///
/// A connection matches when its app grouping key ([`LiveConn::app_id`], the code
/// id else the process name) equals `app_id`. Connections without a resolved IP
/// or port are skipped (no tuple to build); the scanner has already dropped
/// local-noise destinations. Adding a flow is monotonic — a superset of
/// connections yields a superset of tuples.
#[must_use]
pub fn app_tuples(app_id: &str, conns: &[LiveConn]) -> Vec<FlowTuple> {
    let mut seen: HashSet<(IpAddr, u16, u8)> = HashSet::new();
    let mut tuples = Vec::new();
    for conn in conns {
        if conn.app_id() != app_id {
            continue;
        }
        let (Some(ip), port) = (conn.ip, conn.port) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let proto = if conn.protocol.eq_ignore_ascii_case("UDP") {
            L4Proto::Udp
        } else {
            L4Proto::Tcp
        };
        if seen.insert((ip, port, proto_key(proto))) {
            tuples.push(FlowTuple::new(ip, port, proto));
        }
    }
    tuples
}

/// A stable discriminant for the tuple dedup set.
fn proto_key(proto: L4Proto) -> u8 {
    match proto {
        L4Proto::Tcp => 0,
        L4Proto::Udp => 1,
        L4Proto::Icmp => 2,
        L4Proto::Arp => 3,
        L4Proto::Other => 4,
    }
}

/// A ready-to-send typed error response, boxed so the `start_trace` result keeps
/// its large error variant off the stack (clippy `result_large_err`).
fn error(kind: ErrorKind, message: &str) -> Box<Response> {
    Box::new(Response::Error {
        kind,
        message: message.to_owned(),
    })
}

/// An RAII guard for one concurrent-trace slot; decrements the shared counter on
/// drop so a dropped [`TraceSession`] always releases its slot (R9).
struct TraceSlot(Arc<AtomicUsize>);

impl TraceSlot {
    /// Reserve a slot if the cap is not yet reached, else `None`.
    fn try_acquire(counter: Arc<AtomicUsize>) -> Option<Self> {
        let acquired = counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CONCURRENT_TRACES).then_some(n + 1)
            })
            .is_ok();
        acquired.then_some(Self(counter))
    }
}

impl Drop for TraceSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Everything the pump thread owns for the trace's lifetime.
struct PumpCtx {
    source: Box<dyn PacketSource>,
    ring: Arc<Mutex<PacketRing>>,
    stop: Arc<AtomicBool>,
    scanner: Arc<dyn ConnectionScanner>,
    app_id: String,
    sink: FrameSink,
}

/// The pump entry point, wrapped in `catch_unwind` so a panic anywhere in the
/// drain/parse path tears the thread down cleanly instead of unwinding across a
/// thread boundary (per the project's Rayon/thread-boundary rule).
fn run_pump(mut ctx: PumpCtx) {
    if catch_unwind(AssertUnwindSafe(|| pump_loop(&mut ctx))).is_err() {
        warn!("trace pump panicked; trace stopped");
    }
}

/// Drain → retain → push, refreshing the filter periodically, until stopped.
fn pump_loop(ctx: &mut PumpCtx) {
    let mut ticks: u64 = 0;
    while !ctx.stop.load(Ordering::Relaxed) {
        if ticks > 0 && ticks.is_multiple_of(REFRESH_TICKS) {
            refresh_filter(ctx);
        }
        for record in ctx.source.drain() {
            let wire = super::trace_map::wire_record(&record);
            retain(&ctx.ring, record);
            ctx.sink.send_event(Event::Packet(wire));
        }
        thread::sleep(POLL_INTERVAL);
        ticks = ticks.wrapping_add(1);
    }
}

/// Re-scan the app's flows and re-apply the capture filter (R2/R7).
fn refresh_filter(ctx: &mut PumpCtx) {
    match ctx.scanner.scan() {
        Ok(conns) => {
            let tuples = app_tuples(&ctx.app_id, &conns);
            ctx.source.update_filter(&tuples);
        }
        Err(e) => debug!(error = %e, "trace filter refresh scan failed"),
    }
}

/// Retain a record's raw bytes in the ring for on-demand `GetPacketBytes` (R6).
fn retain(ring: &Mutex<PacketRing>, record: PacketRecord) {
    match ring.lock() {
        Ok(mut ring) => ring.push(record),
        Err(poisoned) => poisoned.into_inner().push(record),
    }
}

#[cfg(test)]
#[path = "trace_session_test.rs"]
mod trace_session_test;
