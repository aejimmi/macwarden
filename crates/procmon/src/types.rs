//! Cross-platform types for process monitoring.
//!
//! These types compile on all platforms and can be tested in CI
//! without macOS. The FFI modules populate them on macOS.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ProcessInfo
// ---------------------------------------------------------------------------

/// Process identity with code signing information.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Path to the executable.
    pub path: PathBuf,
    /// Code signing identifier (e.g. "com.apple.Safari").
    pub code_id: Option<String>,
    /// Team identifier (e.g. "ABCDEF1234").
    pub team_id: Option<String>,
    /// Whether the binary is signed by Apple.
    pub is_apple_signed: bool,
    /// Whether the signature is currently valid.
    pub is_valid_signature: bool,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref id) = self.code_id {
            write!(f, "{id} (pid {})", self.pid)?;
        } else {
            write!(f, "{} (pid {})", self.path.display(), self.pid)?;
        }
        if self.is_apple_signed {
            write!(f, " [Apple]")?;
        }
        if let Some(ref team) = self.team_id {
            write!(f, " [team {team}]")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ResponsibleProcess
// ---------------------------------------------------------------------------

/// The responsible (parent) app for a helper process.
///
/// For example, `com.apple.WebKit.Networking` is a helper whose
/// responsible process is Safari.
#[derive(Debug, Clone)]
pub struct ResponsibleProcess {
    /// PID of the responsible process.
    pub pid: u32,
    /// Path to the responsible process executable.
    pub path: PathBuf,
    /// Code signing identifier, if available.
    pub code_id: Option<String>,
}

impl fmt::Display for ResponsibleProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref id) = self.code_id {
            write!(f, "{id} (pid {})", self.pid)
        } else {
            write!(f, "{} (pid {})", self.path.display(), self.pid)
        }
    }
}

// ---------------------------------------------------------------------------
// SocketInfo
// ---------------------------------------------------------------------------

/// An open network socket for a process.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// Local IP address.
    pub local_addr: IpAddr,
    /// Local port number.
    pub local_port: u16,
    /// Remote IP address.
    pub remote_addr: IpAddr,
    /// Remote port number.
    pub remote_port: u16,
    /// Transport protocol (TCP or UDP).
    pub protocol: SocketProtocol,
    /// Current connection state.
    pub state: SocketState,
}

impl fmt::Display for SocketInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{} -> {}:{} [{}]",
            self.protocol,
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port,
            self.state,
        )
    }
}

// ---------------------------------------------------------------------------
// SocketProtocol
// ---------------------------------------------------------------------------

/// Transport protocol for a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

// ---------------------------------------------------------------------------
// SocketState
// ---------------------------------------------------------------------------

/// TCP connection state (or pseudo-state for UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Connection established and data can flow.
    Established,
    /// Listening for incoming connections.
    Listen,
    /// Waiting for enough time to pass after close.
    TimeWait,
    /// Remote side has shut down, waiting for local close.
    CloseWait,
    /// SYN sent, waiting for SYN-ACK.
    SynSent,
    /// SYN received, waiting for ACK.
    SynReceived,
    /// Connection is fully closed.
    Closed,
    /// Any state not explicitly modeled.
    Other,
}

impl fmt::Display for SocketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Established => write!(f, "ESTABLISHED"),
            Self::Listen => write!(f, "LISTEN"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Other => write!(f, "OTHER"),
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkUsage
// ---------------------------------------------------------------------------

/// Per-process network usage statistics.
#[derive(Debug, Clone)]
pub struct NetworkUsage {
    /// Process ID.
    pub pid: u32,
    /// Total bytes received by this process.
    pub bytes_in: u64,
    /// Total bytes sent by this process.
    pub bytes_out: u64,
}

impl fmt::Display for NetworkUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pid {} : {} bytes in, {} bytes out",
            self.pid, self.bytes_in, self.bytes_out,
        )
    }
}

// ---------------------------------------------------------------------------
// CodeSigningInfo
// ---------------------------------------------------------------------------

/// Code signing verification result.
#[derive(Debug, Clone)]
pub struct CodeSigningInfo {
    /// Bundle identifier (e.g. "com.apple.Safari").
    pub code_id: Option<String>,
    /// Team identifier (e.g. "ABCDEF1234").
    pub team_id: Option<String>,
    /// Whether the binary is signed by Apple.
    pub is_apple_signed: bool,
    /// Whether the signature is currently valid.
    pub is_valid: bool,
}

impl fmt::Display for CodeSigningInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref id) = self.code_id {
            write!(f, "{id}")?;
        } else {
            write!(f, "<unsigned>")?;
        }
        if self.is_apple_signed {
            write!(f, " [Apple]")?;
        }
        if let Some(ref team) = self.team_id {
            write!(f, " [team {team}]")?;
        }
        if !self.is_valid {
            write!(f, " [INVALID]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;
