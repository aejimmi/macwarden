//! The real `cfg(unix)` transport for the client: connect over a
//! [`UnixStream`], verify the socket owner via `fstat`, and run the handshake
//! through [`crate::codec`]. All decision logic lives in the pure
//! [`super::select`]; this module only supplies the fallible steps.

use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::{
    Connector, ExpectedOwner, HandshakeError, Selection, Welcome, owner_matches, parent_mode_ok,
    select,
};
use crate::codec::{read_message, write_message};
use crate::protocol::{PROTOCOL_VERSION, Request, Response};

/// The real Unix-domain-socket [`Connector`]: connect, `fstat` owner check, and
/// codec handshake against a socket at `path`.
#[derive(Debug, Clone)]
pub struct UnixConnector {
    path: PathBuf,
    expected_owner: ExpectedOwner,
    client_version: String,
}

impl UnixConnector {
    /// Build a connector for a socket `path`, trusting only an owner matching
    /// `expected_owner`, announcing `client_version` in the handshake.
    pub fn new(
        path: impl Into<PathBuf>,
        expected_owner: ExpectedOwner,
        client_version: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            expected_owner,
            client_version: client_version.into(),
        }
    }
}

/// Read the owner uid of an open socket fd via `fstat` (R2: check the connected
/// socket, not the path, to avoid a TOCTOU swap).
#[allow(unsafe_code)]
fn socket_owner_uid(stream: &UnixStream) -> std::io::Result<u32> {
    // SAFETY: `libc::stat` is a plain-old-data C struct for which an all-zero
    // bit pattern is a valid (empty) initial value; we overwrite it via fstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stream` owns a valid open socket fd for the duration of the call,
    // and `st` is an exclusively-owned, correctly-sized `stat` out-param.
    let rc = unsafe { libc::fstat(stream.as_raw_fd(), &raw mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.st_uid)
}

/// Whether the socket's parent directory is not group/world-writable (R2
/// path-squatting defense).
fn parent_dir_safe(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    match std::fs::symlink_metadata(parent) {
        Ok(meta) => parent_mode_ok(meta.mode()),
        Err(_) => false,
    }
}

impl Connector for UnixConnector {
    type Conn = UnixStream;

    fn socket_exists(&self) -> bool {
        self.path.exists()
    }

    fn connect(&self) -> std::io::Result<Self::Conn> {
        UnixStream::connect(&self.path)
    }

    fn owner_ok(&self, conn: &Self::Conn) -> bool {
        let Ok(uid) = socket_owner_uid(conn) else {
            return false;
        };
        owner_matches(uid, self.expected_owner) && parent_dir_safe(&self.path)
    }

    fn handshake(&self, conn: &mut Self::Conn) -> Result<Welcome, HandshakeError> {
        let hello = Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: self.client_version.clone(),
        };
        write_message(conn, &hello)?;
        let reader_half = conn.try_clone().map_err(crate::codec::CodecError::Io)?;
        let mut reader = BufReader::new(reader_half);
        let response: Response = read_message(&mut reader)?;
        Welcome::from_response(response).ok_or(HandshakeError::NotWelcome)
    }
}

/// Connect to the daemon socket at `path` and run the R8 selection: returns a
/// live [`Selection::Client`], or a typed
/// [`Selection::Unavailable`]/[`Selection::Untrusted`]/[`Selection::Incompatible`]
/// reason. This is the one function the panel calls to pick its source.
pub fn connect(
    path: impl Into<PathBuf>,
    expected_owner: ExpectedOwner,
    client_version: impl Into<String>,
) -> Selection<UnixStream> {
    let connector = UnixConnector::new(path, expected_owner, client_version);
    select(&connector)
}
