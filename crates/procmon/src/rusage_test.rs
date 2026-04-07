use super::*;

#[test]
#[cfg(target_os = "macos")]
fn test_get_network_usage_current_process() {
    let pid = std::process::id();
    let usage = get_network_usage(pid).expect("should succeed for current process");
    assert_eq!(usage.pid, pid);
    // The call succeeded and returned a valid struct. Byte counters
    // may be zero for short-lived test processes -- that is fine as
    // long as the FFI call itself works without error.
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_network_usage_nonexistent_pid() {
    let result = get_network_usage(99_999_999);
    assert!(result.is_err(), "should fail for nonexistent PID");
}
