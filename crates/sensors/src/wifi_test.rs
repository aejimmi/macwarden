use super::*;

/// `current_wifi()` should return `Some` or `None` without panicking.
/// We cannot assert a specific SSID since CI may not have WiFi.
#[test]
fn test_current_wifi_returns_option() {
    let result = current_wifi();
    // Just verify it doesn't panic. If WiFi is connected, we get Some.
    if let Some(ref info) = result {
        assert!(!info.ssid.is_empty(), "SSID should not be empty if Some");
    }
}

/// Debug formatting includes the SSID field.
#[test]
fn test_wifi_info_debug() {
    let info = WifiInfo {
        ssid: "TestNetwork".into(),
        is_captive: false,
    };
    let debug = format!("{info:?}");
    assert!(debug.contains("TestNetwork"), "Debug should contain SSID");
    assert!(
        debug.contains("is_captive"),
        "Debug should contain is_captive"
    );
}

/// Clone and PartialEq work correctly.
#[test]
fn test_wifi_info_clone_eq() {
    let info = WifiInfo {
        ssid: "MyWiFi".into(),
        is_captive: false,
    };
    let cloned = info.clone();
    assert_eq!(info, cloned);
}

/// Two WifiInfo with different SSIDs are not equal.
#[test]
fn test_wifi_info_not_equal_different_ssid() {
    let a = WifiInfo {
        ssid: "NetworkA".into(),
        is_captive: false,
    };
    let b = WifiInfo {
        ssid: "NetworkB".into(),
        is_captive: false,
    };
    assert_ne!(a, b);
}

/// WifiInfo with captive flag differs from non-captive.
#[test]
fn test_wifi_info_captive_flag() {
    let normal = WifiInfo {
        ssid: "Hotel".into(),
        is_captive: false,
    };
    let captive = WifiInfo {
        ssid: "Hotel".into(),
        is_captive: true,
    };
    assert_ne!(normal, captive);
}

/// WifiInfo serializes to JSON correctly.
#[test]
fn test_wifi_info_serialize() {
    let info = WifiInfo {
        ssid: "TestNet".into(),
        is_captive: false,
    };
    let json = serde_json::to_string(&info).expect("should serialize");
    assert!(json.contains("TestNet"));
    assert!(json.contains("is_captive"));
}
