use super::*;

#[test]
fn test_display_process_not_found() {
    let err = ProcmonError::ProcessNotFound { pid: 42 };
    assert_eq!(err.to_string(), "process 42 not found");
}

#[test]
fn test_display_path_lookup() {
    let err = ProcmonError::PathLookup {
        pid: 100,
        message: "permission denied".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "failed to get process path for pid 100: permission denied"
    );
}

#[test]
fn test_display_code_signing() {
    let err = ProcmonError::CodeSigning {
        pid: 200,
        message: "invalid signature".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "code signing lookup failed for pid 200: invalid signature"
    );
}

#[test]
fn test_display_responsible_pid() {
    let err = ProcmonError::ResponsiblePid {
        pid: 300,
        message: "not available".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "responsible pid lookup failed for pid 300: not available"
    );
}

#[test]
fn test_display_socket_enum() {
    let err = ProcmonError::SocketEnum {
        pid: 400,
        message: "EPERM".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "socket enumeration failed for pid 400: EPERM"
    );
}

#[test]
fn test_display_resource_usage() {
    let err = ProcmonError::ResourceUsage {
        pid: 500,
        message: "flavor unsupported".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "resource usage lookup failed for pid 500: flavor unsupported"
    );
}
