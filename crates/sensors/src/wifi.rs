//! WiFi network detection via CoreWLAN.
//!
//! Provides a safe Rust interface to detect the current WiFi connection
//! using macOS CoreWLAN framework (`CWWiFiClient` -> `CWInterface` -> `ssid()`).
//!
//! All Objective-C FFI is isolated in [`crate::ffi_corewlan`]. This module
//! only calls the safe helpers defined there.
//!
//! # Platform
//!
//! macOS only. The CoreWLAN framework is not available on other platforms.
//!
//! # Example
//!
//! ```no_run
//! if let Some(info) = sensors::wifi::current_wifi() {
//!     println!("Connected to: {}", info.ssid);
//! } else {
//!     println!("WiFi disconnected");
//! }
//! ```

use crate::ffi_corewlan;

/// Information about the current WiFi connection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WifiInfo {
    /// The SSID of the connected WiFi network.
    pub ssid: String,
    /// Whether this is a captive network (e.g., hotel/airport WiFi).
    ///
    /// TODO: Implement captive portal detection. Currently always `false`.
    /// Possible approaches: check `CWInterface.serviceActive()` or attempt
    /// a connection to a known URL (e.g., Apple's captive portal check).
    pub is_captive: bool,
}

/// Returns information about the current WiFi connection, if connected.
///
/// Uses CoreWLAN framework: `[CWWiFiClient sharedWiFiClient]` ->
/// `[client interface]` -> `[interface ssid]`.
///
/// Returns `None` if:
/// - WiFi is disconnected or unavailable
/// - No WiFi interface exists on this Mac
/// - The CoreWLAN framework is not loaded
/// - The SSID cannot be read (permissions, etc.)
pub fn current_wifi() -> Option<WifiInfo> {
    // Step 1: Get CWWiFiClient class.
    // SAFETY: c"CWWiFiClient" is a valid null-terminated class name.
    // Returns null if CoreWLAN is not linked (but we link it in ffi_corewlan.rs).
    let class = unsafe { ffi_corewlan::objc_getClass(c"CWWiFiClient".as_ptr()) };
    if class.is_null() {
        tracing::debug!("CWWiFiClient class not found — CoreWLAN unavailable");
        return None;
    }

    // Step 2: Get shared WiFi client: [CWWiFiClient sharedWiFiClient]
    // SAFETY: c"sharedWiFiClient" is a valid selector name.
    let sel_shared = unsafe { ffi_corewlan::sel_registerName(c"sharedWiFiClient".as_ptr()) };
    // SAFETY: class is a valid CWWiFiClient class, sharedWiFiClient is a
    // class method that returns a singleton CWWiFiClient*.
    let client = unsafe { ffi_corewlan::msg_send_id(class.cast_mut(), sel_shared) }?;

    // Step 3: Get default interface: [client interface]
    // SAFETY: c"interface" is a valid selector on CWWiFiClient.
    let sel_interface = unsafe { ffi_corewlan::sel_registerName(c"interface".as_ptr()) };
    // SAFETY: client is a valid CWWiFiClient*, interface returns CWInterface* or nil.
    let interface = unsafe { ffi_corewlan::msg_send_id(client, sel_interface) }?;

    // Step 4: Get SSID: [interface ssid]
    // SAFETY: interface is a valid CWInterface*.
    let ssid = unsafe { ffi_corewlan::cw_interface_ssid(interface) }?;

    if ssid.is_empty() {
        tracing::debug!("WiFi SSID is empty — likely disconnected");
        return None;
    }

    Some(WifiInfo {
        ssid,
        // TODO: Implement captive portal detection (see WifiInfo doc comment).
        is_captive: false,
    })
}

#[cfg(test)]
#[path = "wifi_test.rs"]
mod wifi_test;
