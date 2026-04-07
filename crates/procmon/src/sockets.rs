//! Socket enumeration via `proc_pidinfo` / `proc_pidfdinfo`.
//!
//! Lists all open network sockets for a process by:
//! 1. Calling `proc_pidinfo(PROC_PIDLISTFDS)` to list file descriptors.
//! 2. Filtering for `PROX_FDTYPE_SOCKET` entries.
//! 3. Calling `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` for each socket fd.
//! 4. Extracting address, port, protocol, and state from the result.
//!
//! # Platform
//!
//! This module only compiles on macOS (`cfg(target_os = "macos")`).

#![cfg(target_os = "macos")]

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::debug;

use crate::error::ProcmonError;
use crate::ffi;
use crate::types::{SocketInfo, SocketProtocol, SocketState};

/// List all open network sockets (TCP and UDP) for a process.
///
/// Only returns IPv4 and IPv6 sockets. Unix domain sockets, kernel
/// control sockets, and other non-IP sockets are skipped.
///
/// # Errors
///
/// Returns `ProcmonError::SocketEnum` if `proc_pidinfo` fails.
pub fn list_sockets(pid: u32) -> Result<Vec<SocketInfo>, ProcmonError> {
    let fds = list_fds(pid)?;
    let socket_fds: Vec<_> = fds
        .iter()
        .filter(|fd| fd.proc_fdtype == ffi::PROX_FDTYPE_SOCKET)
        .collect();

    debug!(
        pid,
        total_fds = fds.len(),
        socket_fds = socket_fds.len(),
        "enumerating sockets"
    );

    let mut sockets = Vec::new();
    for fd in &socket_fds {
        match get_socket_info(pid, fd.proc_fd) {
            Ok(Some(si)) => sockets.push(si),
            Ok(None) => {} // non-IP socket, skip
            Err(e) => {
                debug!(pid, fd = fd.proc_fd, %e, "skipping fd");
            }
        }
    }

    Ok(sockets)
}

/// List all file descriptors for a process.
fn list_fds(pid: u32) -> Result<Vec<ffi::proc_fdinfo>, ProcmonError> {
    // First call with empty buffer to get the required size
    // SAFETY: Passing null buffer with size 0 to get required buffer size.
    #[allow(unsafe_code)]
    let size =
        unsafe { ffi::proc_pidinfo(pid as i32, ffi::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };

    if size <= 0 {
        return Err(ProcmonError::SocketEnum {
            pid,
            message: format!("proc_pidinfo(PROC_PIDLISTFDS) returned {size}"),
        });
    }

    let fd_size = mem::size_of::<ffi::proc_fdinfo>();
    let count = size as usize / fd_size;
    // Allocate extra space in case new fds appear between calls
    let buf_count = count + 16;
    let mut buf: Vec<ffi::proc_fdinfo> = vec![
        ffi::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        buf_count
    ];

    // SAFETY: buf is a valid, correctly-sized buffer of proc_fdinfo structs.
    #[allow(unsafe_code)]
    let actual_size = unsafe {
        ffi::proc_pidinfo(
            pid as i32,
            ffi::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            (buf_count * fd_size) as i32,
        )
    };

    if actual_size <= 0 {
        return Err(ProcmonError::SocketEnum {
            pid,
            message: format!("proc_pidinfo(PROC_PIDLISTFDS) second call returned {actual_size}"),
        });
    }

    let actual_count = actual_size as usize / fd_size;
    buf.truncate(actual_count);
    Ok(buf)
}

/// Get socket info for a specific file descriptor.
///
/// Returns `None` for non-IP sockets (Unix domain, etc.).
fn get_socket_info(pid: u32, fd: i32) -> Result<Option<SocketInfo>, ProcmonError> {
    let mut info = mem::MaybeUninit::<ffi::socket_fdinfo>::uninit();

    // SAFETY: info is a valid MaybeUninit buffer of the correct size.
    // proc_pidfdinfo will write the full socket_fdinfo struct into it.
    #[allow(unsafe_code)]
    let ret = unsafe {
        ffi::proc_pidfdinfo(
            pid as i32,
            fd,
            ffi::PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast(),
            mem::size_of::<ffi::socket_fdinfo>() as i32,
        )
    };

    if ret <= 0 {
        return Err(ProcmonError::SocketEnum {
            pid,
            message: format!("proc_pidfdinfo(fd={fd}) returned {ret}"),
        });
    }

    // SAFETY: proc_pidfdinfo returned > 0, meaning it wrote valid data.
    #[allow(unsafe_code)]
    let info = unsafe { info.assume_init() };
    let si = &info.psi;

    // Only handle IPv4 and IPv6
    if si.soi_family != ffi::AF_INET && si.soi_family != ffi::AF_INET6 {
        return Ok(None);
    }

    let protocol = match si.soi_protocol {
        ffi::IPPROTO_TCP => SocketProtocol::Tcp,
        ffi::IPPROTO_UDP => SocketProtocol::Udp,
        _ => return Ok(None),
    };

    // Extract addresses and ports from the protocol-specific union
    let (local_addr, local_port, remote_addr, remote_port, state) = extract_addresses(si, protocol);

    Ok(Some(SocketInfo {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        protocol,
        state,
    }))
}

/// Extract addresses, ports, and state from the socket_info union.
#[allow(unsafe_code)]
fn extract_addresses(
    si: &ffi::socket_info,
    protocol: SocketProtocol,
) -> (IpAddr, u16, IpAddr, u16, SocketState) {
    // For TCP sockets, use pri_tcp which contains in_sockinfo + state
    // For UDP/other, use pri_in which is just in_sockinfo
    let (ini, tcp_state) = if protocol == SocketProtocol::Tcp && si.soi_kind == ffi::SOCKINFO_TCP {
        // SAFETY: soi_kind == SOCKINFO_TCP confirms the pri_tcp variant
        // is active. The union was populated by the kernel.
        let tcp = unsafe { &si.soi_proto.pri_tcp };
        (&tcp.tcpsi_ini, Some(tcp.tcpsi_state))
    } else {
        // SAFETY: For non-TCP IP sockets, pri_in is the correct variant.
        // The union was populated by the kernel.
        let ins = unsafe { &si.soi_proto.pri_in };
        (ins, None)
    };

    let is_v6 = (ini.insi_vflag & ffi::INI_IPV6) != 0;

    // SAFETY: The in_addr_union was populated by the kernel. We access
    // the correct variant based on insi_vflag.
    let local_addr = unsafe { parse_addr(&ini.insi_laddr, is_v6) };
    // SAFETY: Same as local_addr -- insi_faddr uses the same layout.
    let remote_addr = unsafe { parse_addr(&ini.insi_faddr, is_v6) };

    let local_port = ini.insi_lport as u16;
    let remote_port = ini.insi_fport as u16;

    let state = match tcp_state {
        Some(s) => map_tcp_state(s),
        None => SocketState::Other,
    };

    (local_addr, local_port, remote_addr, remote_port, state)
}

/// Parse an IP address from the kernel's `in_addr_union`.
///
/// # Safety
///
/// The union must have been populated by the kernel via `proc_pidfdinfo`.
/// `is_v6` must match the `insi_vflag` of the containing `in_sockinfo`.
#[allow(unsafe_code)]
unsafe fn parse_addr(addr: &ffi::in_addr_union, is_v6: bool) -> IpAddr {
    if is_v6 {
        // SAFETY: Caller verified insi_vflag has INI_IPV6 set, so the
        // ina_6 variant is the active union member.
        let bytes = unsafe { addr.ina_6.bytes };
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        // SAFETY: Caller verified insi_vflag does not have INI_IPV6,
        // so the ina_46 variant is the active union member.
        let octets = unsafe { addr.ina_46.i46a_addr4 };
        IpAddr::V4(Ipv4Addr::from(octets))
    }
}

/// Map a TSI_S_* TCP state constant to our `SocketState` enum.
fn map_tcp_state(state: i32) -> SocketState {
    match state {
        ffi::TSI_S_CLOSED => SocketState::Closed,
        ffi::TSI_S_LISTEN => SocketState::Listen,
        ffi::TSI_S_SYN_SENT => SocketState::SynSent,
        ffi::TSI_S_SYN_RECEIVED => SocketState::SynReceived,
        ffi::TSI_S_ESTABLISHED => SocketState::Established,
        ffi::TSI_S_CLOSE_WAIT => SocketState::CloseWait,
        ffi::TSI_S_TIME_WAIT => SocketState::TimeWait,
        _ => SocketState::Other,
    }
}

#[cfg(test)]
#[path = "sockets_test.rs"]
mod sockets_test;
