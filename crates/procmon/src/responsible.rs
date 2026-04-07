//! Responsible process lookup via `responsibility_get_pid_responsible_for_pid`.
//!
//! On macOS, helper processes (XPC services, WebKit networking, etc.) have
//! a "responsible" parent app. This module resolves that relationship.
//!
//! # Platform
//!
//! This module only compiles on macOS (`cfg(target_os = "macos")`).

#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

use tracing::debug;

use crate::error::ProcmonError;
use crate::ffi;
use crate::types::ResponsibleProcess;

/// Get the responsible (parent app) PID for a helper process.
///
/// Returns `None` if the process IS the responsible process (i.e., it
/// is not a helper launched on behalf of another app).
///
/// # Errors
///
/// Returns `ProcmonError::ResponsiblePid` if the lookup fails.
pub fn get_responsible_pid(pid: u32) -> Result<Option<u32>, ProcmonError> {
    // SAFETY: responsibility_get_pid_responsible_for_pid is a simple
    // function that takes and returns an integer. No pointers involved.
    #[allow(unsafe_code)]
    let responsible = unsafe { ffi::responsibility_get_pid_responsible_for_pid(pid as i32) };

    if responsible < 0 {
        return Err(ProcmonError::ResponsiblePid {
            pid,
            message: format!("returned negative pid: {responsible}"),
        });
    }

    let responsible_u32 = responsible as u32;
    if responsible_u32 == pid {
        Ok(None)
    } else {
        Ok(Some(responsible_u32))
    }
}

/// Build a full `ResponsibleProcess` for the responsible parent of `pid`.
///
/// Returns `None` if the process is its own responsible process.
///
/// # Errors
///
/// Returns `ProcmonError` if the responsible PID lookup or path
/// resolution fails.
pub fn get_responsible_process(pid: u32) -> Result<Option<ResponsibleProcess>, ProcmonError> {
    let Some(responsible_pid) = get_responsible_pid(pid)? else {
        return Ok(None);
    };

    let path = get_process_path(responsible_pid)?;

    // Try to get code signing info -- best effort
    let code_id = crate::code_signing::get_code_signing_info(responsible_pid, &path)
        .ok()
        .and_then(|info| info.code_id);

    Ok(Some(ResponsibleProcess {
        pid: responsible_pid,
        path,
        code_id,
    }))
}

/// Get the executable path for a process by PID.
///
/// # Errors
///
/// Returns `ProcmonError::PathLookup` if `proc_pidpath` fails.
pub(crate) fn get_process_path(pid: u32) -> Result<PathBuf, ProcmonError> {
    let mut buf = vec![0u8; ffi::PROC_PIDPATHINFO_MAXSIZE as usize];

    // SAFETY: buf is a valid, correctly-sized buffer. proc_pidpath
    // writes a null-terminated C string into it.
    #[allow(unsafe_code)]
    let ret = unsafe {
        ffi::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr().cast::<c_char>(),
            ffi::PROC_PIDPATHINFO_MAXSIZE,
        )
    };

    if ret <= 0 {
        debug!(pid, ret, "proc_pidpath failed");
        return Err(ProcmonError::PathLookup {
            pid,
            message: format!("proc_pidpath returned {ret}"),
        });
    }

    // SAFETY: proc_pidpath returned > 0, meaning it wrote a valid
    // null-terminated C string into buf.
    #[allow(unsafe_code)]
    let path_str = unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) };

    Ok(PathBuf::from(path_str.to_str().map_err(|e| {
        ProcmonError::PathLookup {
            pid,
            message: format!("path is not valid UTF-8: {e}"),
        }
    })?))
}

#[cfg(test)]
#[path = "responsible_test.rs"]
mod responsible_test;
