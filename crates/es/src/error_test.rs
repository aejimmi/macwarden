use super::*;

#[test]
fn test_error_display_client_create() {
    let err = EsError::ClientCreate { code: 42 };
    assert_eq!(err.to_string(), "failed to create ES client: 42");
}

#[test]
fn test_error_display_subscribe() {
    let err = EsError::Subscribe { code: 7 };
    assert_eq!(err.to_string(), "failed to subscribe to events: 7");
}

#[test]
fn test_error_display_respond() {
    let err = EsError::Respond { code: 3 };
    assert_eq!(err.to_string(), "failed to respond to event: 3");
}

#[test]
fn test_error_display_not_available() {
    let err = EsError::NotAvailable;
    assert_eq!(err.to_string(), "ES not available on this platform");
}

#[test]
fn test_error_display_unsafe_event_type() {
    let err = EsError::UnsafeEventType { event_type: 999 };
    assert_eq!(
        err.to_string(),
        "event type 999 may not be safe to subscribe (past safety threshold)"
    );
}

#[test]
fn test_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(EsError::NotAvailable);
    assert!(!err.to_string().is_empty());
}
