#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{self, BufReader, Cursor, Write};
use std::sync::{Arc, Condvar, Mutex};

use ipc::codec::read_message;
use ipc::protocol::{Event, Response, ServerFrame, WireVerdict};

use super::*;

/// A writer that buffers every write into a shared `Vec`, never blocking.
#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer that blocks inside `write` until its gate is released — models a
/// slow client so the mailbox's drop-oldest path is exercised deterministically.
struct BlockingWriter {
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl Write for BlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.gate;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn rate_event() -> Event {
    Event::RateTick {
        down_bps: 1,
        up_bps: 2,
    }
}

fn decided_event() -> Event {
    Event::ConnectionDecided {
        app_id: "com.example".to_owned(),
        host: "example.test".to_owned(),
        verdict: WireVerdict::Allow,
        allowed: true,
    }
}

#[test]
fn test_writer_serializes_responses_and_events_as_server_frames() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let (sink, handle) = spawn_writer(SharedWriter(Arc::clone(&buf)));

    sink.send_response(Response::TraceStarted {
        session_ok: true,
        source: ipc::protocol::WireTraceSource::Live,
    });
    sink.send_event(rate_event());
    sink.send_event(decided_event());
    sink.send_response(Response::TraceStarted {
        session_ok: false,
        source: ipc::protocol::WireTraceSource::Unknown,
    });

    sink.close();
    handle.join().unwrap();

    let bytes = buf.lock().unwrap().clone();
    let mut reader = BufReader::new(Cursor::new(bytes));
    let frames: Vec<ServerFrame> = std::iter::from_fn(|| read_message(&mut reader).ok()).collect();

    assert_eq!(frames.len(), 4, "all four frames must be written");
    assert!(matches!(frames[0], ServerFrame::Response(_)));
    assert!(matches!(
        frames[1],
        ServerFrame::Event(Event::RateTick { .. })
    ));
    assert!(matches!(
        frames[2],
        ServerFrame::Event(Event::ConnectionDecided { .. })
    ));
    assert!(matches!(frames[3], ServerFrame::Response(_)));
    assert_eq!(sink.dropped(), 0, "a fast client drops nothing");
}

#[test]
fn test_backpressure_drops_oldest_events_never_responses() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (sink, handle) = spawn_writer(BlockingWriter {
        gate: Arc::clone(&gate),
    });

    // The writer picks up the response and blocks writing it; give it a moment.
    sink.send_response(Response::TraceStarted {
        session_ok: true,
        source: ipc::protocol::WireTraceSource::Live,
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    // With the writer wedged, overfill the event queue: the first MAX fill it,
    // the extra K each evict the oldest event → exactly K drops.
    let extra = 10;
    for _ in 0..(MAX_QUEUED_EVENTS + extra) {
        sink.send_event(rate_event());
    }
    assert_eq!(
        sink.dropped(),
        extra as u64,
        "a slow client drops exactly the overflow, oldest-first"
    );

    // Release the writer and tear down cleanly.
    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    sink.close();
    handle.join().unwrap();
}

fn a_response() -> Response {
    Response::TraceStarted {
        session_ok: true,
        source: ipc::protocol::WireTraceSource::Live,
    }
}

#[test]
fn test_response_backlog_is_bounded_and_closes_connection() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (sink, handle) = spawn_writer(BlockingWriter {
        gate: Arc::clone(&gate),
    });

    // The writer picks up the first response, drains it (resetting the response
    // counter), then blocks writing it — so the flood below accumulates in the
    // deque with the writer wedged.
    sink.send_response(a_response());
    std::thread::sleep(std::time::Duration::from_millis(50));

    // A non-draining peer floods responses far past the cap.
    for _ in 0..(MAX_QUEUED_RESPONSES + 50) {
        sink.send_response(a_response());
    }

    {
        let state = sink.inner.state.lock().unwrap();
        assert!(
            state.closed,
            "crossing the response cap must close the connection"
        );
        // Bounded: at most the cap plus the single final `Refused` frame — never
        // the full flood.
        assert!(
            state.frames.len() <= MAX_QUEUED_RESPONSES + 1,
            "response queue must stay bounded, got {}",
            state.frames.len()
        );
        // The last enqueued frame is the typed refusal.
        assert!(matches!(
            state.frames.back(),
            Some(ServerFrame::Response(_))
        ));
    }

    // Further sends after close are silently dropped (no growth, no panic).
    sink.send_response(a_response());
    assert!(sink.inner.state.lock().unwrap().frames.len() <= MAX_QUEUED_RESPONSES + 1);

    // Release the writer and tear down cleanly.
    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    sink.close();
    handle.join().unwrap();
}
