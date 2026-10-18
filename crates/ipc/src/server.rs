//! `cfg(unix)` daemon-side helpers: accept a connection and authenticate the
//! peer (Layer 1 of R2), plus the typed seam where the macOS code-signature
//! check (Layer 2) grafts in.
//!
//! Layer 1 — the uid pre-gate — is implemented here via `getpeereid` and is
//! Linux-CI testable over a `socketpair` ([`UnixStream::pair`]) without root.
//! Layer 2 — the audit-token code-signature check — is a macOS-only seam left
//! stubbed to `Ok(())`; see [`verify_code_signature`].

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(target_os = "macos")]
mod codesign;

#[cfg(target_os = "macos")]
pub use codesign::{CodesignVerifier, MACWARDEN_PANEL_REQUIREMENT, OSStatus, PeerTokenError};

/// A peer-authentication failure (R2).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// `getpeereid` (or an underlying syscall) failed.
    #[error("peer credential lookup failed: {0}")]
    Io(#[from] std::io::Error),
    /// The peer's uid is not the served user's uid (Layer 1).
    #[error("peer uid {actual} does not match served uid {expected}")]
    UidMismatch {
        /// The served user's uid.
        expected: u32,
        /// The connecting peer's uid.
        actual: u32,
    },
    /// The peer's code signature did not satisfy the panel's designated
    /// requirement (Layer 2, macOS).
    #[error("peer code-signature verification failed")]
    CodeSignature,
}

/// Read the peer's effective `(uid, gid)` from a connected socket fd via
/// `getpeereid` (R2 Layer 1). Works on Linux and macOS, so it is exercisable
/// over a `socketpair` without root.
#[allow(unsafe_code)]
pub fn peer_uid(fd: RawFd) -> std::io::Result<(u32, u32)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a valid connected socket fd; `uid`/`gid` are exclusively
    // owned out-params of the correct type that `getpeereid` writes on success.
    let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((uid, gid))
}

/// Authenticates a freshly accepted peer (R2). Layer 1 (uid pre-gate) is
/// implemented by [`UidVerifier`]; Layer 2 (code signature) grafts in behind the
/// same interface without touching callers — the accept loop only sees this
/// trait.
pub trait PeerVerifier {
    /// Verify the peer connected on `fd`. `Ok(())` admits the connection; any
    /// `Err` closes it with an `Unauthorized` frame.
    fn verify(&self, fd: RawFd) -> Result<(), AuthError>;
}

/// The default verifier: uid pre-gate (Layer 1 of R2), then the Layer 2
/// code-signature seam. Admits only connections from the served uid.
#[derive(Debug, Clone, Copy)]
pub struct UidVerifier {
    /// The served user's uid (daemon's own uid for a user agent; the console
    /// user's uid for the root daemon).
    pub expected_uid: u32,
}

impl UidVerifier {
    /// Build a verifier that admits only `expected_uid`.
    #[must_use]
    pub fn new(expected_uid: u32) -> Self {
        Self { expected_uid }
    }
}

impl PeerVerifier for UidVerifier {
    fn verify(&self, fd: RawFd) -> Result<(), AuthError> {
        let (uid, _gid) = peer_uid(fd)?;
        if uid != self.expected_uid {
            return Err(AuthError::UidMismatch {
                expected: self.expected_uid,
                actual: uid,
            });
        }
        // R2 Layer 2: code-signature check lands here (macOS,
        // cfg(target_os = "macos")) — see security validation.
        verify_code_signature(fd)?;
        Ok(())
    }
}

/// R2 Layer 2 seam for [`UidVerifier`]: a no-op on every platform.
///
/// The real audit-token code-signature check lives in the macOS-only
/// [`codesign`] module and is exposed as [`CodesignVerifier`] — the daemon's
/// choice on macOS. [`UidVerifier`] deliberately keeps this seam a no-op so it
/// stays the pure Layer-1 uid gate for the Linux/CI and fallback paths (a
/// uid-matching socketpair peer is admitted end to end without a signing check).
#[allow(clippy::unnecessary_wraps)]
fn verify_code_signature(_fd: RawFd) -> Result<(), AuthError> {
    Ok(())
}

/// Accept one connection and authenticate its peer with `verifier` (R2). Returns
/// the stream paired with the auth result: on `Err`, the caller writes an
/// `Unauthorized` frame and drops the stream; the accept loop keeps serving.
pub fn accept<V: PeerVerifier>(
    listener: &UnixListener,
    verifier: &V,
) -> std::io::Result<(UnixStream, Result<(), AuthError>)> {
    let (stream, _addr) = listener.accept()?;
    let auth = verifier.verify(stream.as_raw_fd());
    Ok((stream, auth))
}

/// Authenticate an already-accepted `stream` with `verifier` (R2 Layer 1+seam).
pub fn verify_stream<V: PeerVerifier>(stream: &UnixStream, verifier: &V) -> Result<(), AuthError> {
    verifier.verify(stream.as_raw_fd())
}

#[cfg(test)]
#[path = "server_test.rs"]
mod server_test;
