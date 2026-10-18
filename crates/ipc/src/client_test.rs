#![allow(clippy::panic)]

use super::*;
use crate::protocol::{Capability, PROTOCOL_VERSION, Response};

/// A [`Connector`] whose every step is a preset outcome, so each [`Selection`]
/// branch is exercised without a socket.
struct MockConnector {
    exists: bool,
    connect_ok: bool,
    owner_ok: bool,
    handshake: Option<Welcome>,
}

impl MockConnector {
    /// The happy path: exists, connects, owner ok, compatible handshake.
    fn healthy() -> Self {
        Self {
            exists: true,
            connect_ok: true,
            owner_ok: true,
            handshake: Some(Welcome {
                protocol_version: PROTOCOL_VERSION,
                daemon_version: "0.1.0".into(),
                capabilities: vec![Capability::History, Capability::Mutations],
            }),
        }
    }
}

impl Connector for MockConnector {
    type Conn = ();

    fn socket_exists(&self) -> bool {
        self.exists
    }

    fn connect(&self) -> std::io::Result<()> {
        if self.connect_ok {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            ))
        }
    }

    fn owner_ok(&self, _conn: &()) -> bool {
        self.owner_ok
    }

    fn handshake(&self, _conn: &mut ()) -> Result<Welcome, HandshakeError> {
        self.handshake.clone().ok_or(HandshakeError::NotWelcome)
    }
}

#[test]
fn test_select_returns_client_on_healthy_path() {
    let selection = select(&MockConnector::healthy());
    match selection {
        Selection::Client(handle) => {
            assert_eq!(handle.daemon_version(), "0.1.0");
            assert!(handle.has_capability(Capability::History));
            assert!(!handle.has_capability(Capability::ExecPolicy));
        }
        other => panic!("expected Client, got {other:?}"),
    }
}

#[test]
fn test_select_unavailable_when_socket_absent() {
    let mut c = MockConnector::healthy();
    c.exists = false;
    assert!(matches!(select(&c), Selection::Unavailable));
}

#[test]
fn test_select_unavailable_when_connect_refused() {
    let mut c = MockConnector::healthy();
    c.connect_ok = false;
    assert!(matches!(select(&c), Selection::Unavailable));
}

#[test]
fn test_select_untrusted_when_owner_check_fails() {
    let mut c = MockConnector::healthy();
    c.owner_ok = false;
    assert!(matches!(select(&c), Selection::Untrusted));
}

#[test]
fn test_select_unavailable_when_handshake_fails() {
    let mut c = MockConnector::healthy();
    c.handshake = None;
    assert!(matches!(select(&c), Selection::Unavailable));
}

#[test]
fn test_select_incompatible_on_version_mismatch() {
    let mut c = MockConnector::healthy();
    c.handshake = Some(Welcome {
        protocol_version: PROTOCOL_VERSION + 1,
        daemon_version: "2.0.0".into(),
        capabilities: vec![],
    });
    match select(&c) {
        Selection::Incompatible { daemon_version } => assert_eq!(daemon_version, "2.0.0"),
        other => panic!("expected Incompatible, got {other:?}"),
    }
}

#[test]
fn test_owner_matches_root_path() {
    assert!(owner_matches(0, ExpectedOwner::Root));
    assert!(!owner_matches(501, ExpectedOwner::Root));
}

#[test]
fn test_owner_matches_uid_path() {
    assert!(owner_matches(501, ExpectedOwner::Uid(501)));
    assert!(!owner_matches(0, ExpectedOwner::Uid(501)));
}

#[test]
fn test_parent_mode_rejects_group_or_world_writable() {
    assert!(parent_mode_ok(0o755));
    assert!(parent_mode_ok(0o700));
    assert!(!parent_mode_ok(0o775)); // group-writable
    assert!(!parent_mode_ok(0o757)); // world-writable
    assert!(!parent_mode_ok(0o777));
}

#[test]
fn test_welcome_from_welcome_response_extracts_fields() {
    let welcome = Welcome::from_response(Response::Welcome {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: "0.1.0".into(),
        capabilities: vec![Capability::PushEvents],
    })
    .expect("welcome");
    assert_eq!(welcome.protocol_version, PROTOCOL_VERSION);
    assert_eq!(welcome.capabilities, vec![Capability::PushEvents]);
}

#[test]
fn test_welcome_from_non_welcome_response_is_none() {
    // A non-Welcome first reply is rejected by the handshake extractor.
    assert!(Welcome::from_response(Response::Detail { detail: None }).is_none());
}
