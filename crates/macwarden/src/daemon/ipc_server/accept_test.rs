#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::BufReader;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ipc::codec::read_message;

use super::*;

#[test]
fn test_bind_socket_refuses_when_daemon_already_running() {
    // A live listener accepting on the path means a daemon is already running:
    // a second bind must refuse rather than unlink and steal the socket.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("macwarden.sock");
    let _live = UnixListener::bind(&path).unwrap();

    match bind_socket(&path) {
        Err(ServerError::AlreadyRunning(_)) => {}
        other => panic!("expected AlreadyRunning, got {other:?}"),
    }
    // The original listener's socket file is untouched (not stolen).
    assert!(path.exists(), "live socket must not be unlinked");
}

#[test]
fn test_bind_socket_unlinks_stale_socket_and_binds() {
    // A leftover socket file with no live listener (connect refused) is stale:
    // bind_socket must unlink it and bind fresh.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("macwarden.sock");
    let stale = UnixListener::bind(&path).unwrap();
    drop(stale); // std leaves the socket file on disk but nothing accepts on it.

    let listener = bind_socket(&path).expect("stale socket should be reclaimed");
    // The reclaimed listener now accepts connections on the path.
    assert!(UnixStream::connect(&path).is_ok());
    drop(listener);
}

#[test]
fn test_busy_writes_unavailable_error_frame() {
    let (client, server) = UnixStream::pair().unwrap();
    busy(server);
    let mut reader = BufReader::new(client);
    match read_message::<_, Response>(&mut reader).unwrap() {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unavailable),
        other => panic!("expected Unavailable error, got {other:?}"),
    }
}

#[test]
fn test_slot_guard_decrements_on_drop() {
    let active = Arc::new(AtomicUsize::new(0));
    active.fetch_add(1, Ordering::AcqRel);
    {
        let _guard = SlotGuard(Arc::clone(&active));
        assert_eq!(active.load(Ordering::Acquire), 1);
    }
    assert_eq!(active.load(Ordering::Acquire), 0, "slot reclaimed on drop");
}

#[test]
fn test_slot_guard_reclaims_slot_on_handler_panic() {
    // Mirrors accept_one: the guard is created, then a panicking handler runs
    // under catch_unwind. The slot must be reclaimed even though it panicked.
    let active = Arc::new(AtomicUsize::new(0));
    active.fetch_add(1, Ordering::AcqRel);
    let handler_active = Arc::clone(&active);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _guard = SlotGuard(handler_active);
        panic!("handler boom");
    }));
    assert!(result.is_err(), "panic must be caught, not propagated");
    assert_eq!(
        active.load(Ordering::Acquire),
        0,
        "slot reclaimed despite panic"
    );
}
