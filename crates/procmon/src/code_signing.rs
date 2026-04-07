//! Code signing verification via Security.framework.
//!
//! Uses `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation`
//! to extract the signing identity and team ID from a process executable,
//! and `SecStaticCodeCheckValidity` to verify signature validity.
//!
//! # Platform
//!
//! This module only compiles on macOS (`cfg(target_os = "macos")`).

#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use tracing::debug;

use crate::error::ProcmonError;
use crate::ffi;
use crate::types::CodeSigningInfo;

/// Get the code signing identity for an executable at the given path.
///
/// This uses `SecStaticCodeCreateWithPath` rather than looking up by PID,
/// which avoids the need for an audit token and works for any path on disk.
///
/// # Errors
///
/// Returns `ProcmonError::CodeSigning` if the Security.framework calls fail.
#[allow(unsafe_code)]
pub fn get_code_signing_info(pid: u32, path: &Path) -> Result<CodeSigningInfo, ProcmonError> {
    let path_str = path.to_str().ok_or_else(|| ProcmonError::CodeSigning {
        pid,
        message: "path is not valid UTF-8".to_string(),
    })?;

    // SAFETY: create_cfstring validates the input and returns None on failure.
    let path_cfstr =
        unsafe { create_cfstring(path_str) }.ok_or_else(|| ProcmonError::CodeSigning {
            pid,
            message: "failed to create CFString from path".to_string(),
        })?;

    // SAFETY: path_cfstr is a valid CFStringRef. allocator=null uses default.
    let url = unsafe {
        ffi::CFURLCreateWithFileSystemPath(
            std::ptr::null(),
            path_cfstr,
            ffi::K_CF_URL_POSIX_PATH_STYLE,
            false,
        )
    };
    // SAFETY: path_cfstr is a valid CF object obtained from create_cfstring.
    unsafe { ffi::CFRelease(path_cfstr) };

    if url.is_null() {
        return Err(ProcmonError::CodeSigning {
            pid,
            message: "failed to create CFURL from path".to_string(),
        });
    }

    let mut static_code: ffi::SecCodeRef = std::ptr::null_mut();
    // SAFETY: url is a valid CFURL. static_code is a valid output pointer.
    let status = unsafe { ffi::SecStaticCodeCreateWithPath(url, 0, &raw mut static_code) };
    // SAFETY: url is a valid CF object obtained from CFURLCreateWithFileSystemPath.
    unsafe { ffi::CFRelease(url) };

    if status != ffi::ERR_SEC_SUCCESS || static_code.is_null() {
        debug!(pid, ?path, status, "SecStaticCodeCreateWithPath failed");
        return Ok(CodeSigningInfo {
            code_id: None,
            team_id: None,
            is_apple_signed: false,
            is_valid: false,
        });
    }

    let result = extract_signing_info(pid, path, static_code);

    // SAFETY: static_code is a valid SecStaticCodeRef from the successful call above.
    unsafe { ffi::CFRelease(static_code.cast()) };

    result
}

/// Extract signing info from a valid `SecStaticCodeRef`.
///
/// The caller is responsible for releasing `static_code`.
#[allow(unsafe_code, clippy::unnecessary_wraps)]
fn extract_signing_info(
    pid: u32,
    path: &Path,
    static_code: ffi::SecCodeRef,
) -> Result<CodeSigningInfo, ProcmonError> {
    // SAFETY: static_code is a valid SecStaticCodeRef. requirement=null
    // means "accept any valid signature".
    let validity_status =
        unsafe { ffi::SecStaticCodeCheckValidity(static_code, 0, std::ptr::null()) };
    let is_valid = validity_status == ffi::ERR_SEC_SUCCESS;

    let mut info_dict: ffi::CFDictionaryRef = std::ptr::null();
    // SAFETY: static_code is valid. info_dict is a valid output pointer.
    let info_status = unsafe {
        ffi::SecCodeCopySigningInformation(
            static_code,
            ffi::K_SEC_CS_SIGNING_INFORMATION,
            &raw mut info_dict,
        )
    };

    if info_status != ffi::ERR_SEC_SUCCESS || info_dict.is_null() {
        debug!(
            pid,
            ?path,
            info_status,
            "SecCodeCopySigningInformation failed"
        );
        return Ok(CodeSigningInfo {
            code_id: None,
            team_id: None,
            is_apple_signed: false,
            is_valid,
        });
    }

    // SAFETY: info_dict is a valid CFDictionaryRef. The kSecCodeInfo*
    // keys are framework-provided global CFStringRef constants.
    let code_id = unsafe { extract_string_from_dict(info_dict, ffi::kSecCodeInfoIdentifier) };
    // SAFETY: same as above.
    let team_id = unsafe { extract_string_from_dict(info_dict, ffi::kSecCodeInfoTeamIdentifier) };

    // SAFETY: info_dict is a valid CF object from SecCodeCopySigningInformation.
    unsafe { ffi::CFRelease(info_dict) };

    let is_apple_signed = code_id
        .as_ref()
        .is_some_and(|id| id.starts_with("com.apple."));

    Ok(CodeSigningInfo {
        code_id,
        team_id,
        is_apple_signed,
        is_valid,
    })
}

/// Create a `CFString` from a Rust string. Returns `None` on failure.
///
/// # Safety
///
/// The returned `CFStringRef` must be released with `CFRelease`.
#[allow(unsafe_code)]
unsafe fn create_cfstring(s: &str) -> Option<ffi::CFStringRef> {
    let c_str = std::ffi::CString::new(s).ok()?;
    // SAFETY: c_str is a valid null-terminated C string. The allocator
    // is null (use default). The encoding constant is correct.
    let cf = unsafe {
        ffi::CFStringCreateWithCString(
            std::ptr::null(),
            c_str.as_ptr(),
            ffi::K_CF_STRING_ENCODING_UTF8,
        )
    };
    if cf.is_null() { None } else { Some(cf) }
}

/// Extract a string value from a `CFDictionary` by key.
///
/// # Safety
///
/// `dict` must be a valid `CFDictionaryRef`. `key` must be a valid
/// `CFStringRef` (typically a framework-provided constant).
#[allow(unsafe_code)]
unsafe fn extract_string_from_dict(
    dict: ffi::CFDictionaryRef,
    key: ffi::CFStringRef,
) -> Option<String> {
    // SAFETY: dict and key are valid CF objects. CFDictionaryGetValue
    // returns null if the key is not present (which we check).
    let value = unsafe { ffi::CFDictionaryGetValue(dict, key) };
    if value.is_null() {
        return None;
    }

    // SAFETY: value is a valid CFStringRef obtained from the dictionary.
    let len = unsafe { ffi::CFStringGetLength(value.cast()) };
    if len <= 0 {
        return None;
    }

    // UTF-8 can be up to 4 bytes per UTF-16 code unit
    let buf_size = (len * 4 + 1) as usize;
    let mut buf: Vec<u8> = vec![0u8; buf_size];
    // SAFETY: buf is a valid buffer of sufficient size. The encoding
    // constant is correct. value is a valid CFStringRef.
    let ok = unsafe {
        ffi::CFStringGetCString(
            value.cast(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf_size as isize,
            ffi::K_CF_STRING_ENCODING_UTF8,
        )
    };

    if !ok {
        return None;
    }

    // SAFETY: CFStringGetCString wrote a null-terminated C string into buf.
    unsafe {
        CStr::from_ptr(buf.as_ptr().cast::<c_char>())
            .to_str()
            .ok()
            .map(String::from)
    }
}

#[cfg(test)]
#[path = "code_signing_test.rs"]
mod code_signing_test;
