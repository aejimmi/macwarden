//! Per-process resource usage via `proc_pid_rusage`.
//!
//! Uses `RUSAGE_INFO_V4` to get disk I/O byte counters. Network-specific
//! byte counters are not available in the public `rusage_info_v4` struct,
//! so we report disk I/O as a proxy (which includes network-backed
//! filesystem operations). For true per-process network bytes, use
//! the `NetworkStatisticsManager` private API or `nettop` output.
//!
//! # Platform
//!
//! This module only compiles on macOS (`cfg(target_os = "macos")`).

#![cfg(target_os = "macos")]

use std::mem;

use tracing::debug;

use crate::error::ProcmonError;
use crate::ffi;
use crate::types::NetworkUsage;

/// Get resource usage statistics for a process.
///
/// Returns disk I/O bytes read/written as a proxy for network usage.
/// The `rusage_info_v4` struct does not expose per-process network
/// byte counters in the public SDK.
///
/// # Errors
///
/// Returns `ProcmonError::ResourceUsage` if `proc_pid_rusage` fails.
pub fn get_network_usage(pid: u32) -> Result<NetworkUsage, ProcmonError> {
    let mut info = mem::MaybeUninit::<ffi::rusage_info_v4>::uninit();

    // SAFETY: info is a valid MaybeUninit buffer of the correct size
    // (296 bytes, verified). proc_pid_rusage writes the full struct.
    #[allow(unsafe_code)]
    let ret =
        unsafe { ffi::proc_pid_rusage(pid as i32, ffi::RUSAGE_INFO_V4, info.as_mut_ptr().cast()) };

    if ret != 0 {
        debug!(pid, ret, "proc_pid_rusage failed");
        return Err(ProcmonError::ResourceUsage {
            pid,
            message: format!("proc_pid_rusage returned {ret}"),
        });
    }

    // SAFETY: proc_pid_rusage returned 0 (success), so the struct is valid.
    #[allow(unsafe_code)]
    let info = unsafe { info.assume_init() };

    Ok(NetworkUsage {
        pid,
        bytes_in: info.ri_diskio_bytesread,
        bytes_out: info.ri_diskio_byteswritten,
    })
}

#[cfg(test)]
#[path = "rusage_test.rs"]
mod rusage_test;
