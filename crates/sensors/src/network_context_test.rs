use super::*;

/// `NetworkContext::detect()` should return without panicking.
/// We cannot assert specific values since CI has unknown network state.
#[test]
fn test_detect_returns_context() {
    let ctx = NetworkContext::detect();
    // Just verify it returns a valid struct without panicking.
    let _ = format!("{ctx:?}");
}

/// Construct a context with no WiFi.
#[test]
fn test_context_with_no_wifi() {
    let ctx = NetworkContext {
        wifi: None,
        is_vpn: false,
    };
    assert!(ctx.wifi.is_none());
    assert!(!ctx.is_vpn);
}

/// Construct a context with WiFi and VPN.
#[test]
fn test_context_with_wifi_and_vpn() {
    let ctx = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "CoffeeShop".into(),
            is_captive: false,
        }),
        is_vpn: true,
    };
    assert_eq!(
        ctx.wifi.as_ref().map(|w| w.ssid.as_str()),
        Some("CoffeeShop")
    );
    assert!(ctx.is_vpn);
}

/// Two identical contexts are equal.
#[test]
fn test_context_equality() {
    let a = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "Home".into(),
            is_captive: false,
        }),
        is_vpn: false,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

/// Contexts with different WiFi are not equal.
#[test]
fn test_context_not_equal_different_wifi() {
    let a = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "Home".into(),
            is_captive: false,
        }),
        is_vpn: false,
    };
    let b = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "Office".into(),
            is_captive: false,
        }),
        is_vpn: false,
    };
    assert_ne!(a, b);
}

/// Contexts with different VPN state are not equal.
#[test]
fn test_context_not_equal_different_vpn() {
    let a = NetworkContext {
        wifi: None,
        is_vpn: false,
    };
    let b = NetworkContext {
        wifi: None,
        is_vpn: true,
    };
    assert_ne!(a, b);
}

/// Debug output is readable and contains field names.
#[test]
fn test_context_debug() {
    let ctx = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "TestSSID".into(),
            is_captive: false,
        }),
        is_vpn: true,
    };
    let debug = format!("{ctx:?}");
    assert!(debug.contains("TestSSID"), "Debug should contain SSID");
    assert!(debug.contains("is_vpn"), "Debug should contain is_vpn");
}

/// NetworkContext serializes to JSON correctly.
#[test]
fn test_context_serialize() {
    let ctx = NetworkContext {
        wifi: Some(WifiInfo {
            ssid: "SerNet".into(),
            is_captive: false,
        }),
        is_vpn: true,
    };
    let json = serde_json::to_string(&ctx).expect("should serialize");
    assert!(json.contains("SerNet"));
    assert!(json.contains("is_vpn"));
}

/// `is_vpn_active()` returns without panicking.
#[test]
fn test_is_vpn_active_no_panic() {
    let _ = is_vpn_active();
}

/// `is_vpn_interface` correctly identifies VPN interfaces.
#[test]
fn test_is_vpn_interface() {
    // utun0 is iCloud Private Relay -- skip it.
    assert!(!is_vpn_interface("utun0"));
    // utun1+ are likely user VPNs.
    assert!(is_vpn_interface("utun1"));
    assert!(is_vpn_interface("utun2"));
    assert!(is_vpn_interface("utun99"));
    // Non-utun interfaces are not VPNs.
    assert!(!is_vpn_interface("en0"));
    assert!(!is_vpn_interface("lo0"));
    assert!(!is_vpn_interface("bridge0"));
    // Edge cases.
    assert!(!is_vpn_interface("utun"));
    assert!(!is_vpn_interface("utunX"));
    assert!(!is_vpn_interface(""));
}
