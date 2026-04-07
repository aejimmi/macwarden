use super::*;

#[test]
fn test_event_type_constants() {
    assert_eq!(ES_EVENT_TYPE_AUTH_EXEC, 0);
    assert_eq!(ES_EVENT_TYPE_RESERVED_5, 153);
    assert_eq!(ES_EVENT_TYPE_RESERVED_6, 154);
}

#[test]
fn test_result_constants() {
    assert_eq!(ES_NEW_CLIENT_RESULT_SUCCESS, 0);
    assert_eq!(ES_RETURN_SUCCESS, 0);
    assert_eq!(ES_RESPOND_RESULT_SUCCESS, 0);
}

#[test]
fn test_auth_result_constants() {
    assert_eq!(ES_AUTH_RESULT_ALLOW, 0);
    assert_eq!(ES_AUTH_RESULT_DENY, 1);
}

#[test]
fn test_audit_token_size() {
    assert_eq!(
        std::mem::size_of::<AuditToken>(),
        32,
        "AuditToken must be 8 x u32 = 32 bytes"
    );
}

#[test]
fn test_audit_token_clone() {
    let token = AuditToken {
        val: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let cloned = token;
    assert_eq!(token.val, cloned.val);
}

#[test]
fn test_block_literal_size() {
    // Block literal: isa (8) + flags (4) + reserved (4) + invoke (8) + descriptor (8) = 32
    assert_eq!(
        std::mem::size_of::<BlockLiteral>(),
        32,
        "BlockLiteral must be 32 bytes on 64-bit"
    );
}

#[test]
fn test_block_descriptor_size() {
    // BlockDescriptor: reserved (8) + size (8) = 16
    assert_eq!(
        std::mem::size_of::<BlockDescriptor>(),
        16,
        "BlockDescriptor must be 16 bytes"
    );
}
