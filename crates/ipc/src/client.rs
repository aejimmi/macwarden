//! Blocking connect + handshake + socket-owner check, returning the typed R8
//! [`Selection`] result.
//!
//! The **decision core** ([`select`], [`owner_matches`], [`parent_mode_ok`]) is
//! pure and injectable: it drives a [`Connector`] whose fallible steps a test
//! can stub, so every selection outcome is unit-testable without a socket or
//! root. The real socket connect ([`connect`]) lives behind `cfg(unix)` and
//! wires a [`UnixConnector`] into the same pure decision.

use crate::protocol::{Capability, PROTOCOL_VERSION, Response};

/// The daemon's advertised identity, extracted from [`Response::Welcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// The daemon's protocol version.
    pub protocol_version: u32,
    /// The daemon's human-readable build version.
    pub daemon_version: String,
    /// The daemon's advertised capabilities.
    pub capabilities: Vec<Capability>,
}

impl Welcome {
    /// Extract the welcome fields from a [`Response`], or `None` if the daemon
    /// replied with something other than [`Response::Welcome`] to the handshake.
    #[must_use]
    pub fn from_response(response: Response) -> Option<Self> {
        match response {
            Response::Welcome {
                protocol_version,
                daemon_version,
                capabilities,
            } => Some(Self {
                protocol_version,
                daemon_version,
                capabilities,
            }),
            _ => None,
        }
    }
}

/// A live, handshake-completed connection to the daemon.
#[derive(Debug)]
pub struct ClientHandle<C> {
    conn: C,
    capabilities: Vec<Capability>,
    daemon_version: String,
}

impl<C> ClientHandle<C> {
    /// The daemon's advertised build version.
    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    /// Whether the daemon advertised a given capability.
    #[must_use]
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// The daemon's full capability list.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Borrow the underlying connection (e.g. to issue further requests).
    pub fn connection(&mut self) -> &mut C {
        &mut self.conn
    }

    /// Consume the handle, yielding the underlying connection.
    pub fn into_connection(self) -> C {
        self.conn
    }
}

/// The outcome of selecting a daemon source (R8). The panel maps this to either
/// a live `DaemonSource` or a fallback `LiveSource` with the right affordance.
#[derive(Debug)]
pub enum Selection<C> {
    /// Daemon reachable and version-compatible — use the live client.
    Client(ClientHandle<C>),
    /// No socket, or connect refused, or the handshake failed — daemon absent.
    Unavailable,
    /// The socket exists but failed the owner check — do not trust it.
    Untrusted,
    /// Daemon reachable but protocol-incompatible — fall back read-only.
    Incompatible {
        /// The daemon's build version, for the "out of date" affordance.
        daemon_version: String,
    },
}

/// The fallible steps of establishing a daemon connection. Real transport wires
/// filesystem/socket calls here; tests inject stubbed outcomes to exercise every
/// [`Selection`] branch.
pub trait Connector {
    /// The connection type produced on success.
    type Conn;

    /// Whether the socket path exists. `false` → [`Selection::Unavailable`].
    fn socket_exists(&self) -> bool;

    /// Connect to the socket. `Err` → [`Selection::Unavailable`].
    fn connect(&self) -> std::io::Result<Self::Conn>;

    /// Verify the socket owner and parent permissions (client authenticates the
    /// daemon, R2). `false` → [`Selection::Untrusted`].
    fn owner_ok(&self, conn: &Self::Conn) -> bool;

    /// Perform the `Hello`/`Welcome` handshake. `Err` → [`Selection::Unavailable`].
    fn handshake(&self, conn: &mut Self::Conn) -> Result<Welcome, HandshakeError>;
}

/// A handshake failure (I/O, codec, or a non-`Welcome` first reply).
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The framing or (de)serialization failed.
    #[error("handshake codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),
    /// The daemon's first reply was not a [`Response::Welcome`].
    #[error("expected Welcome, got a different response")]
    NotWelcome,
}

/// Pure selection decision (R8). Drives the [`Connector`] steps in order and
/// maps each failure to the corresponding typed [`Selection`]:
///
/// - socket absent or connect error → [`Selection::Unavailable`];
/// - owner check fails → [`Selection::Untrusted`];
/// - handshake error → [`Selection::Unavailable`];
/// - version mismatch → [`Selection::Incompatible`];
/// - otherwise → [`Selection::Client`].
pub fn select<T: Connector>(connector: &T) -> Selection<T::Conn> {
    if !connector.socket_exists() {
        return Selection::Unavailable;
    }
    let Ok(mut conn) = connector.connect() else {
        return Selection::Unavailable;
    };
    if !connector.owner_ok(&conn) {
        return Selection::Untrusted;
    }
    let Ok(welcome) = connector.handshake(&mut conn) else {
        return Selection::Unavailable;
    };
    if welcome.protocol_version != PROTOCOL_VERSION {
        return Selection::Incompatible {
            daemon_version: welcome.daemon_version,
        };
    }
    Selection::Client(ClientHandle {
        conn,
        capabilities: welcome.capabilities,
        daemon_version: welcome.daemon_version,
    })
}

/// The expected owner uid of a trusted daemon socket, by socket path (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedOwner {
    /// The `/var/run/macwarden` root-daemon socket — must be root-owned.
    Root,
    /// The `~/.macwarden` user-agent socket — must be owned by this uid.
    Uid(u32),
}

/// Whether a socket's `stat` owner uid matches the expected owner for its path
/// (client authenticates the daemon, R2). Pure — no filesystem access.
#[must_use]
pub fn owner_matches(stat_uid: u32, expected: ExpectedOwner) -> bool {
    match expected {
        ExpectedOwner::Root => stat_uid == 0,
        ExpectedOwner::Uid(uid) => stat_uid == uid,
    }
}

/// Whether a parent directory's permission bits are safe — not group- or
/// world-writable (R2 path-squatting defense). Pure — no filesystem access.
#[must_use]
pub fn parent_mode_ok(mode: u32) -> bool {
    // Reject if either the group-write (0o020) or other-write (0o002) bit is set.
    mode & 0o022 == 0
}

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::{UnixConnector, connect};

#[cfg(test)]
#[path = "client_test.rs"]
mod client_test;
