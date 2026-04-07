//! Network context detection combining WiFi and VPN state.
//!
//! `NetworkContext` is a point-in-time snapshot of the network environment.
//! It is an orthogonal axis to service-group profiles (privacy, developer) --
//! both dimensions are independent and compose.
//!
//! # Example
//!
//! ```no_run
//! let ctx = sensors::network_context::NetworkContext::detect();
//! if let Some(ref wifi) = ctx.wifi {
//!     println!("WiFi: {}", wifi.ssid);
//! }
//! if ctx.is_vpn {
//!     println!("VPN is active");
//! }
//! ```

use crate::wifi::{self, WifiInfo};

/// Current network environment.
///
/// Combines WiFi state and VPN detection into a single snapshot
/// that can be used for profile selection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NetworkContext {
    /// Current WiFi connection, if any.
    pub wifi: Option<WifiInfo>,
    /// Whether a VPN tunnel is active.
    pub is_vpn: bool,
}

impl NetworkContext {
    /// Detect the current network context.
    ///
    /// Checks WiFi via CoreWLAN and VPN via utun interface detection.
    pub fn detect() -> Self {
        Self {
            wifi: wifi::current_wifi(),
            is_vpn: is_vpn_active(),
        }
    }
}

/// Check whether a VPN tunnel appears to be active.
///
/// Enumerates network interfaces via `getifaddrs()` and looks for `utun`
/// interfaces (beyond `utun0`, which is typically iCloud Private Relay)
/// that have an assigned IP address.
///
/// Returns `false` if `getifaddrs` fails (with a warning log).
pub fn is_vpn_active() -> bool {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `addrs` is a valid out-pointer on the stack. `getifaddrs`
    // writes a valid linked-list pointer on success (rc == 0).
    // We call `freeifaddrs` after walking the list.
    let rc = unsafe { libc::getifaddrs(&raw mut addrs) };
    if rc != 0 {
        tracing::warn!("getifaddrs failed (rc={rc}) — assuming no VPN");
        return false;
    }

    let found = walk_ifaddrs_for_vpn(addrs);

    // SAFETY: addrs is the pointer returned by a successful getifaddrs call.
    unsafe { libc::freeifaddrs(addrs) };

    found
}

/// Walk the ifaddrs linked list looking for VPN-indicative utun interfaces.
///
/// Checks for `utun` interfaces with index > 0 (skip utun0 = iCloud Private
/// Relay) that have an assigned address (AF_INET or AF_INET6).
fn walk_ifaddrs_for_vpn(mut current: *mut libc::ifaddrs) -> bool {
    while !current.is_null() {
        // SAFETY: current is either the head from getifaddrs or a valid
        // ifa_next pointer. We only read fields, never write.
        let ifa = unsafe { &*current };

        if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_name is a valid null-terminated C string from getifaddrs.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            if let Ok(name_str) = name.to_str()
                && is_vpn_interface(name_str)
            {
                // Check that it has an assigned IP address.
                // SAFETY: ifa_addr is non-null (checked above).
                let family = unsafe { (*ifa.ifa_addr).sa_family };
                let family_i32 = i32::from(family);
                if family_i32 == libc::AF_INET || family_i32 == libc::AF_INET6 {
                    tracing::debug!(interface = name_str, "VPN tunnel detected");
                    return true;
                }
            }
        }

        current = ifa.ifa_next;
    }
    false
}

/// Determine whether an interface name indicates a user VPN tunnel.
///
/// `utun0` is typically iCloud Private Relay infrastructure.
/// `utun1`, `utun2`, etc. with assigned addresses are likely user VPNs
/// (WireGuard, OpenVPN, IKEv2, etc.).
fn is_vpn_interface(name: &str) -> bool {
    if let Some(suffix) = name.strip_prefix("utun") {
        // Parse the numeric suffix. Skip utun0 (iCloud Private Relay).
        suffix.parse::<u32>().is_ok_and(|n| n > 0)
    } else {
        false
    }
}

#[cfg(test)]
#[path = "network_context_test.rs"]
mod network_context_test;
