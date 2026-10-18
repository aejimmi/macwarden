use super::*;

use openbinary_agent_core::SipStatus;

#[test]
fn test_sealed_fastpath_ok_sip_enabled() {
    // SIP on: the sealed volume is protected, so the fast-path is trusted.
    assert!(sealed_fastpath_ok(SipStatus::Enabled));
}

#[test]
fn test_sealed_fastpath_ok_sip_disabled() {
    // SIP off: sealed-path binaries could be tampered with — force a real check.
    assert!(!sealed_fastpath_ok(SipStatus::Disabled));
}

#[test]
fn test_sealed_fastpath_ok_sip_unknown() {
    // Unknown state is treated conservatively — no fast-path.
    assert!(!sealed_fastpath_ok(SipStatus::Unknown));
}

#[test]
fn test_is_sealed_path_matches_prefixes() {
    assert!(is_sealed_path("/usr/bin/ssh"));
    assert!(is_sealed_path("/usr/sbin/foo"));
    assert!(is_sealed_path("/usr/libexec/bar"));
    assert!(is_sealed_path("/System/Library/CoreServices/baz"));
}

#[test]
fn test_is_sealed_path_rejects_non_sealed() {
    assert!(!is_sealed_path("/Applications/Foo.app/Contents/MacOS/Foo"));
    assert!(!is_sealed_path("/opt/homebrew/bin/rg"));
    assert!(!is_sealed_path("/usr/local/bin/thing"));
}
