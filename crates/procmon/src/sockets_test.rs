use super::*;

#[test]
fn test_map_tcp_state_all_known() {
    assert_eq!(map_tcp_state(ffi::TSI_S_CLOSED), SocketState::Closed);
    assert_eq!(map_tcp_state(ffi::TSI_S_LISTEN), SocketState::Listen);
    assert_eq!(map_tcp_state(ffi::TSI_S_SYN_SENT), SocketState::SynSent);
    assert_eq!(
        map_tcp_state(ffi::TSI_S_SYN_RECEIVED),
        SocketState::SynReceived
    );
    assert_eq!(
        map_tcp_state(ffi::TSI_S_ESTABLISHED),
        SocketState::Established
    );
    assert_eq!(map_tcp_state(ffi::TSI_S_CLOSE_WAIT), SocketState::CloseWait);
    assert_eq!(map_tcp_state(ffi::TSI_S_TIME_WAIT), SocketState::TimeWait);
}

#[test]
fn test_map_tcp_state_unknown() {
    assert_eq!(map_tcp_state(99), SocketState::Other);
    assert_eq!(map_tcp_state(-1), SocketState::Other);
}

#[test]
#[cfg(target_os = "macos")]
fn test_list_sockets_current_process() {
    let pid = std::process::id();
    let result = list_sockets(pid);
    // Should succeed -- current process always exists
    assert!(
        result.is_ok(),
        "list_sockets should succeed for current process"
    );
    // We may or may not have open sockets, but the call shouldn't crash
}

#[test]
#[cfg(target_os = "macos")]
fn test_list_sockets_nonexistent_pid() {
    let result = list_sockets(99_999_999);
    assert!(result.is_err(), "should fail for nonexistent PID");
}
