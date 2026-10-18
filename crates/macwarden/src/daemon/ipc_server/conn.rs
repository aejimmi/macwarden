//! Per-connection handling: handshake, version gate, rate limit (R3, R9), and
//! the packet-trace server-push path (R10).
//!
//! Each connection runs a synchronous read → handle → write loop on its own
//! thread. Before a trace it is strict request/response: the handler computes a
//! [`Response`] and writes it inline. When a [`Request::StartTrace`] arrives the
//! connection switches into **trace mode** ([`serve_trace`]): a single writer
//! thread ([`super::push`]) takes the stream and serializes both the pushed
//! [`ipc::protocol::Event::Packet`] frames and the interleaved [`Response`]s as
//! [`ipc::protocol::ServerFrame`]s, while this reader thread keeps handling
//! `GetPacketBytes` / `StopTrace` and any other verb. A per-read idle timeout
//! bounds a wedged client, and mutation frames are rate limited so churn cannot
//! thrash disk/CPU.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use ipc::codec::{read_message, write_message};
use ipc::protocol::{ErrorKind, PROTOCOL_VERSION, Request, Response, WireTraceSource};
use tracing::debug;

use super::handlers::handle_request;
use super::state::ServerState;
use super::trace_session::TraceSession;
use super::{push, trace_map, trace_session};

/// Per-read idle timeout — a wedged client cannot pin a connection slot (R1).
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Mutation rate-limit window (R9).
const RATE_WINDOW: Duration = Duration::from_secs(10);

/// Maximum mutations per [`RATE_WINDOW`] (R9); further ones get `RateLimited`.
const RATE_MAX: usize = 20;

/// Serve one authenticated connection to completion (R3–R9).
pub fn serve_connection(stream: UnixStream, state: &ServerState) {
    if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
        debug!(error = %e, "failed to set read timeout");
        return;
    }
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);

    let Ok(version_ok) = handshake(&mut reader, &mut writer, state) else {
        return;
    };

    let mut mutation_times: Vec<Instant> = Vec::new();
    while let Ok(request) = read_message::<_, Request>(&mut reader) {
        // `StartTrace` switches the connection into server-push trace mode; from
        // there the client reads `ServerFrame`s (R8/R10) and this function ends.
        if let Request::StartTrace { app_id } = request {
            serve_trace(reader, writer, state, &app_id, version_ok, mutation_times);
            return;
        }
        let response = respond(state, &request, version_ok, &mut mutation_times);
        if write_message(&mut writer, &response).is_err() {
            break;
        }
    }
}

/// Serve a connection in trace mode (R9/R10): spawn the writer thread, start the
/// [`TraceSession`], and keep reading requests — answering `GetPacketBytes` /
/// `StopTrace` and routing any other verb — until the client stops the trace or
/// disconnects. Every outbound frame is a [`ipc::protocol::ServerFrame`]; the
/// pushed [`ipc::protocol::Event::Packet`]s interleave with these responses.
fn serve_trace(
    mut reader: BufReader<UnixStream>,
    writer: UnixStream,
    state: &ServerState,
    app_id: &str,
    version_ok: bool,
    mut mutation_times: Vec<Instant>,
) {
    let (sink, handle) = push::spawn_writer(writer);
    let mut session: Option<TraceSession> = None;

    if version_ok {
        match trace_session::start_trace(state, app_id) {
            Ok(prepared) => {
                // Enqueue `TraceStarted` (carrying the honest source kind) before
                // the pump starts so it is always the first frame; only then spawn
                // the packet stream (R10).
                let source = prepared.source_kind();
                sink.send_response(Response::TraceStarted {
                    session_ok: true,
                    source,
                });
                session = Some(prepared.spawn(&sink));
            }
            Err(response) => sink.send_response(*response),
        }
    } else {
        sink.send_response(error(
            ErrorKind::VersionMismatch,
            "protocol version mismatch",
        ));
    }

    while let Ok(request) = read_message::<_, Request>(&mut reader) {
        match request {
            Request::StopTrace => {
                // Drop the session (RAII stop) and report the trace inactive.
                session = None;
                sink.send_response(Response::TraceStarted {
                    session_ok: false,
                    source: WireTraceSource::Unknown,
                });
            }
            Request::GetPacketBytes { seq } => {
                let response = session.as_ref().map_or_else(
                    || Response::PacketBytes(trace_map::unavailable_bytes(seq)),
                    |s| s.packet_bytes(seq),
                );
                sink.send_response(response);
            }
            Request::StartTrace { .. } => {
                sink.send_response(error(
                    ErrorKind::Unsupported,
                    "a trace is already active on this connection",
                ));
            }
            other => {
                let response = respond(state, &other, version_ok, &mut mutation_times);
                sink.send_response(response);
            }
        }
    }

    // Client disconnected or the loop ended: stop the capture before tearing the
    // writer down so no further events are pushed, then join the writer thread.
    drop(session);
    debug!(dropped_events = sink.dropped(), "trace connection closing");
    sink.close();
    let _ = handle.join();
}

/// Compute the response for one request, applying the version gate and mutation
/// rate limit (R3/R9).
fn respond(
    state: &ServerState,
    request: &Request,
    version_ok: bool,
    mutation_times: &mut Vec<Instant>,
) -> Response {
    if let Request::Hello { .. } = request {
        // A repeat Hello just re-announces the daemon.
        return welcome(state);
    }
    if !version_ok {
        return error(ErrorKind::VersionMismatch, "protocol version mismatch");
    }
    if is_mutation(request) && rate_limited(mutation_times) {
        return error(ErrorKind::RateLimited, "mutation rate limit exceeded");
    }
    handle_request(state, request)
}

/// Perform the R3 handshake. Replies `Welcome` (even on version mismatch so the
/// panel learns the daemon's version) and returns whether versions match.
fn handshake(
    reader: &mut BufReader<UnixStream>,
    writer: &mut UnixStream,
    state: &ServerState,
) -> std::result::Result<bool, ()> {
    let first: Request = read_message(reader).map_err(|_| ())?;
    let Request::Hello {
        protocol_version, ..
    } = first
    else {
        let _ = write_message(
            writer,
            &error(ErrorKind::BadRequest, "first frame must be Hello"),
        );
        return Err(());
    };
    write_message(writer, &welcome(state)).map_err(|_| ())?;
    Ok(protocol_version == PROTOCOL_VERSION)
}

/// Build the `Welcome` response from the daemon's advertised identity.
fn welcome(state: &ServerState) -> Response {
    Response::Welcome {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: state.daemon_version.clone(),
        capabilities: state.capabilities.clone(),
    }
}

/// Build a typed error response.
fn error(kind: ErrorKind, message: &str) -> Response {
    Response::Error {
        kind,
        message: message.to_owned(),
    }
}

/// Whether a request is a heavier-gated mutation verb (R7/R9).
fn is_mutation(request: &Request) -> bool {
    matches!(
        request,
        Request::SetRule { .. }
            | Request::SetRules { .. }
            | Request::SetExecPolicy { .. }
            | Request::SetMode { .. }
            | Request::SetAppleAllow { .. }
            | Request::SetDnsAllow { .. }
            | Request::SetGroupEnabled { .. }
            | Request::AddAllowListEntry { .. }
            | Request::RemoveAllowListEntry { .. }
    )
}

/// Sliding-window mutation rate limiter (R9). Returns `true` when over budget.
fn rate_limited(times: &mut Vec<Instant>) -> bool {
    let now = Instant::now();
    times.retain(|t| now.duration_since(*t) < RATE_WINDOW);
    if times.len() >= RATE_MAX {
        return true;
    }
    times.push(now);
    false
}

#[cfg(test)]
#[path = "conn_test.rs"]
mod conn_test;
