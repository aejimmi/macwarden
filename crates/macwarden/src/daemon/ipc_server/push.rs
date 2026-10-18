//! Server-push writer machinery (spec R10) — the first real `Event` push path.
//!
//! The daemon is otherwise strict request/response ([`super::conn`] writes each
//! [`Response`] inline). A packet trace, however, interleaves pushed
//! [`Event::Packet`] frames with the [`Response`]s to `GetPacketBytes` /
//! `StopTrace` on the same stream. Because the codec deserializes one line into
//! a single type, both are wrapped in a [`ServerFrame`] and a **single writer
//! thread** owns the stream and serializes every outbound frame — the reader
//! thread and the trace pump both hand frames to it over one mailbox, so no
//! write ever races another.
//!
//! # Backpressure (never block the daemon)
//!
//! The mailbox is a bounded, **drop-oldest** queue for events. When a slow client
//! lets pushed events pile up past [`MAX_QUEUED_EVENTS`], the *oldest* event is
//! evicted and a monotonic counter bumped rather than blocking the trace pump.
//! The writer thread blocks on the socket, not the daemon: capture keeps running
//! and simply drops-oldest into this queue, mirroring the ring's R6 policy.
//!
//! [`Response`]s are normally never dropped — a well-behaved client has only a
//! handful in flight. But a hostile peer that floods requests (`GetPacketBytes`)
//! without draining its socket would otherwise grow the response queue without
//! bound. So responses are capped at [`MAX_QUEUED_RESPONSES`]: crossing it is
//! treated as a protocol abuse — a final typed `Refused` frame is enqueued and
//! the connection is closed, so the queue can never grow unbounded.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use ipc::codec::write_message;
use ipc::protocol::{ErrorKind, Event, Response, ServerFrame};
use tracing::{debug, warn};

/// Maximum pushed events buffered for a slow client before the oldest is dropped
/// (spec R6/R10). Small enough that a stalled writer cannot grow memory, large
/// enough to ride out a brief render hitch on the panel.
const MAX_QUEUED_EVENTS: usize = 1024;

/// Maximum outstanding [`Response`] frames before the peer is treated as abusive
/// and the connection closed. A well-behaved client keeps only a couple in
/// flight (answers to `GetPacketBytes` / `StopTrace`), so this ceiling is only
/// ever reached by a peer flooding requests without draining its socket.
const MAX_QUEUED_RESPONSES: usize = 256;

/// The shared mailbox drained by the writer thread. Events are drop-oldest past
/// [`MAX_QUEUED_EVENTS`]; responses are capped at [`MAX_QUEUED_RESPONSES`], and
/// crossing that cap closes the connection.
struct Mailbox {
    state: Mutex<MailboxState>,
    signal: Condvar,
    dropped: AtomicU64,
    max_events: usize,
    max_responses: usize,
}

/// The mutable half of the mailbox, guarded by one lock.
struct MailboxState {
    frames: VecDeque<ServerFrame>,
    /// Count of `Event` frames currently queued, tracked so the drop-oldest
    /// check is O(1) and only the eviction scan touches the deque.
    events: usize,
    /// Count of `Response` frames currently queued, tracked so the overflow
    /// check is O(1).
    responses: usize,
    closed: bool,
}

/// A cheap, cloneable handle used by the reader thread and the trace pump to
/// enqueue outbound frames for the writer thread (spec R10).
#[derive(Clone)]
pub struct FrameSink {
    inner: Arc<Mailbox>,
}

impl FrameSink {
    /// Enqueue a [`Response`] frame. Never dropped — at most a handful are ever
    /// in flight (answers to `GetPacketBytes` / `StopTrace`).
    pub fn send_response(&self, response: Response) {
        self.push(ServerFrame::Response(Box::new(response)), false);
    }

    /// Enqueue a pushed [`Event`] frame. Drop-oldest when the queue is full so
    /// the caller (the trace pump) never blocks (spec R10 backpressure).
    pub fn send_event(&self, event: Event) {
        self.push(ServerFrame::Event(event), true);
    }

    /// Number of events dropped to a slow client over this connection's life.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Signal the writer thread to flush and exit once the queue drains.
    pub fn close(&self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.closed = true;
        }
        self.inner.signal.notify_all();
    }

    /// Push one frame, evicting the oldest event first when an event would push
    /// the queue past its bound, or closing the connection when responses
    /// overflow their cap (a flooding, non-draining peer).
    fn push(&self, frame: ServerFrame, is_event: bool) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        if state.closed {
            return;
        }
        if is_event {
            if state.events >= self.inner.max_events {
                evict_oldest_event(&mut state);
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            state.events += 1;
        } else {
            if state.responses >= self.inner.max_responses {
                self.overflow_close(&mut state);
                return;
            }
            state.responses += 1;
        }
        state.frames.push_back(frame);
        drop(state);
        self.inner.signal.notify_one();
    }

    /// Handle a response-queue overflow: enqueue one final typed `Refused` frame
    /// and close the connection so the queue can never grow unbounded. Called
    /// with the mailbox lock held.
    fn overflow_close(&self, state: &mut MailboxState) {
        warn!(
            cap = self.inner.max_responses,
            "IPC response backlog exceeded; closing connection to a non-draining peer"
        );
        state
            .frames
            .push_back(ServerFrame::Response(Box::new(Response::Error {
                kind: ErrorKind::Refused,
                message: "response backlog exceeded; connection closed".to_owned(),
            })));
        state.responses += 1;
        state.closed = true;
        self.inner.signal.notify_all();
    }
}

/// Remove the oldest queued `Event`, keeping responses intact. The front is
/// almost always an event, so this is O(1) in practice.
fn evict_oldest_event(state: &mut MailboxState) {
    if let Some(pos) = state
        .frames
        .iter()
        .position(|f| matches!(f, ServerFrame::Event(_)))
    {
        state.frames.remove(pos);
        state.events = state.events.saturating_sub(1);
    }
}

/// Spawn the single writer thread that owns `writer` and drains the mailbox,
/// serializing every outbound [`ServerFrame`] (spec R10). Returns the sink the
/// reader/pump enqueue into and the thread handle to join at teardown.
pub fn spawn_writer<W>(mut writer: W) -> (FrameSink, JoinHandle<()>)
where
    W: Write + Send + 'static,
{
    let inner = Arc::new(Mailbox {
        state: Mutex::new(MailboxState {
            frames: VecDeque::new(),
            events: 0,
            responses: 0,
            closed: false,
        }),
        signal: Condvar::new(),
        dropped: AtomicU64::new(0),
        max_events: MAX_QUEUED_EVENTS,
        max_responses: MAX_QUEUED_RESPONSES,
    });
    let sink = FrameSink {
        inner: Arc::clone(&inner),
    };
    let handle = std::thread::Builder::new()
        .name("mw-ipc-writer".to_string())
        .spawn(move || writer_loop(&inner, &mut writer))
        .unwrap_or_else(|e| {
            debug!(error = %e, "failed to spawn IPC writer thread");
            // Fall back to a no-op joined handle so callers still get one.
            std::thread::spawn(|| {})
        });
    (sink, handle)
}

/// The writer thread body: wait for frames, drain the queue under one lock, then
/// write each frame outside the lock so a blocked socket never stalls enqueues.
fn writer_loop<W: Write>(inner: &Arc<Mailbox>, writer: &mut W) {
    while let Some(batch) = wait_batch(inner) {
        for frame in batch {
            if write_message(writer, &frame).is_err() {
                // Client gone or wedged: mark closed so enqueues stop and exit.
                if let Ok(mut state) = inner.state.lock() {
                    state.closed = true;
                }
                return;
            }
        }
    }
}

/// Block until frames are available (or the mailbox closes), then take the whole
/// batch. Returns `None` only when closed with an empty queue — the exit signal.
fn wait_batch(inner: &Arc<Mailbox>) -> Option<Vec<ServerFrame>> {
    let mut state = inner.state.lock().ok()?;
    loop {
        if !state.frames.is_empty() {
            state.events = 0;
            state.responses = 0;
            return Some(state.frames.drain(..).collect());
        }
        if state.closed {
            return None;
        }
        state = inner.signal.wait(state).ok()?;
    }
}

#[cfg(test)]
#[path = "push_test.rs"]
mod push_test;
