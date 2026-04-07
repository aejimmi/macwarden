use super::*;

#[test]
#[cfg(target_os = "macos")]
fn test_get_responsible_pid_self() {
    let pid = std::process::id();
    // Should not error -- the current process always has a responsible PID
    let result = get_responsible_pid(pid);
    assert!(
        result.is_ok(),
        "get_responsible_pid should succeed for current process"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_responsible_pid_launchd() {
    // launchd (pid 1) is its own responsible process
    let result = get_responsible_pid(1);
    // May fail without root, so just check it doesn't panic
    if let Ok(rpid) = result {
        assert!(
            rpid.is_none(),
            "launchd should be its own responsible process"
        );
    }
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_process_path_self() {
    let pid = std::process::id();
    let path = get_process_path(pid).expect("should resolve path for current process");
    assert!(
        path.exists(),
        "resolved path should exist on disk: {path:?}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_process_path_nonexistent_pid() {
    // PID 99999999 almost certainly doesn't exist
    let result = get_process_path(99_999_999);
    assert!(result.is_err(), "should fail for nonexistent PID");
}

#[test]
#[cfg(target_os = "macos")]
fn test_get_responsible_process_self() {
    let pid = std::process::id();
    let result = get_responsible_process(pid);
    assert!(
        result.is_ok(),
        "get_responsible_process should succeed for current process"
    );
    // Result may be None (we ARE the responsible process) or Some
}
