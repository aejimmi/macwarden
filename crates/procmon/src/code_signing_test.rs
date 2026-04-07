use super::*;
use std::path::PathBuf;

#[test]
#[cfg(target_os = "macos")]
fn test_get_code_signing_info_apple_binary() {
    // /usr/bin/curl is Apple-signed on all macOS versions
    let path = PathBuf::from("/usr/bin/curl");
    let info = get_code_signing_info(0, &path).expect("should succeed for /usr/bin/curl");
    assert!(
        info.code_id.is_some(),
        "curl should have a code signing identity"
    );
    assert!(info.is_apple_signed, "curl should be Apple-signed");
    assert!(info.is_valid, "curl should have a valid signature");
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_code_signing_info_nonexistent_path() {
    let path = PathBuf::from("/nonexistent/binary");
    let info = get_code_signing_info(0, &path).expect("should return unsigned info, not error");
    assert!(info.code_id.is_none());
    assert!(!info.is_apple_signed);
    assert!(!info.is_valid);
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_code_signing_info_launchd() {
    // launchd (pid 1) is always Apple-signed
    let path = PathBuf::from("/sbin/launchd");
    let info = get_code_signing_info(1, &path).expect("should succeed for launchd");
    assert!(info.is_apple_signed, "launchd should be Apple-signed");
    assert!(info.is_valid, "launchd should have a valid signature");
}
