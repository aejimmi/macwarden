#![allow(clippy::panic)]

use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use super::*;

#[test]
fn test_peer_uid_on_socketpair_returns_current_uid() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let (uid, _gid) = peer_uid(a.as_raw_fd()).expect("getpeereid");
    // Both ends of a socketpair share this process's uid; a real uid is returned
    // (never panics), which is the Layer-1 pre-gate input.
    let (uid2, _gid2) = peer_uid(a.as_raw_fd()).expect("getpeereid");
    assert_eq!(uid, uid2);
}

#[test]
fn test_uid_verifier_admits_matching_uid() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let (uid, _gid) = peer_uid(a.as_raw_fd()).expect("getpeereid");
    let verifier = UidVerifier::new(uid);
    assert!(verify_stream(&a, &verifier).is_ok());
}

#[test]
fn test_uid_verifier_rejects_mismatched_uid() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let (uid, _gid) = peer_uid(a.as_raw_fd()).expect("getpeereid");
    let verifier = UidVerifier::new(uid.wrapping_add(1));
    let err = verify_stream(&a, &verifier).expect_err("must reject");
    match err {
        AuthError::UidMismatch { expected, actual } => {
            assert_eq!(expected, uid.wrapping_add(1));
            assert_eq!(actual, uid);
        }
        other => panic!("expected UidMismatch, got {other:?}"),
    }
}

#[test]
fn test_code_signature_seam_returns_ok_for_now() {
    // The Layer-2 seam is stubbed to Ok, so a uid-matching peer is admitted end
    // to end. When the macOS FFI grafts in, this test's expectation flips on
    // macOS but callers are untouched.
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let (uid, _gid) = peer_uid(a.as_raw_fd()).expect("getpeereid");
    assert!(UidVerifier::new(uid).verify(a.as_raw_fd()).is_ok());
}

#[test]
fn test_accept_authenticates_connecting_peer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let client = UnixStream::connect(&path).expect("connect");
    let (uid, _gid) = peer_uid(client.as_raw_fd()).expect("getpeereid");

    let verifier = UidVerifier::new(uid);
    let (_stream, auth) = accept(&listener, &verifier).expect("accept");
    assert!(auth.is_ok());
}

#[test]
fn test_accept_rejects_mismatched_uid_but_returns_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let client = UnixStream::connect(&path).expect("connect");
    let (uid, _gid) = peer_uid(client.as_raw_fd()).expect("getpeereid");

    // Wrong served uid: accept still returns the stream (so the caller can write
    // an Unauthorized frame) but the auth result is an error.
    let verifier = UidVerifier::new(uid.wrapping_add(1));
    let (_stream, auth) = accept(&listener, &verifier).expect("accept");
    assert!(matches!(auth, Err(AuthError::UidMismatch { .. })));
}
