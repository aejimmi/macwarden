//! `ignoreip` CIDR matching with private / loopback / self defaults.
//!
//! A matched source IP is never counted and never banned — the first guard on
//! the ban path, and the mitigation for the log-injection "ban a victim" threat
//! (an attacker who can influence log content still cannot get a trusted range
//! banned). Defaults cover loopback, RFC1918 / ULA / link-local private ranges,
//! and, when enabled, the host's own interface addresses.

use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

/// Loopback, private, and link-local ranges merged into every ignore set.
///
/// Covers IPv4 loopback / RFC1918 / link-local and IPv6 loopback / ULA /
/// link-local. A scanner from any of these is treated as trusted-local.
const DEFAULT_RANGES: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// A set of CIDR ranges an IP is checked against before it can be counted.
#[derive(Debug, Clone, Default)]
pub struct IgnoreSet {
    nets: Vec<IpNet>,
    self_addrs: Vec<IpAddr>,
}

impl IgnoreSet {
    /// Build an ignore set from user `ignoreip` entries merged with the
    /// built-in private/loopback defaults.
    ///
    /// A malformed user entry is dropped with a `warn!` (fail-open, like
    /// `net::policy::PolicyConfig`) rather than rejecting the whole set. The
    /// built-in defaults are parsed from known-good constants and always load.
    #[must_use]
    pub fn new(user_entries: &[String]) -> Self {
        let mut nets: Vec<IpNet> = DEFAULT_RANGES
            .iter()
            .filter_map(|r| r.parse().ok())
            .collect();
        for entry in user_entries {
            match entry.parse::<IpNet>() {
                Ok(net) => nets.push(net),
                // A bare IP is treated as a host route (`/32` or `/128`).
                Err(_) => match entry.parse::<IpAddr>().ok().and_then(host_net) {
                    Some(net) => nets.push(net),
                    None => {
                        warn!(entry = %entry, "dropping malformed ignoreip entry");
                    }
                },
            }
        }
        Self {
            nets,
            self_addrs: Vec::new(),
        }
    }

    /// Register the host's own interface addresses (`ignore_self`). These are
    /// resolved by the platform layer and injected here so the engine core
    /// stays platform-dependency-free.
    pub fn set_self_addrs(&mut self, addrs: Vec<IpAddr>) {
        self.self_addrs = addrs;
    }

    /// Whether `ip` is trusted and must never be counted or banned.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.self_addrs.contains(&ip) {
            return true;
        }
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// Number of CIDR ranges (built-in + user), for diagnostics/tests.
    #[must_use]
    pub fn range_count(&self) -> usize {
        self.nets.len()
    }
}

/// Build the host-route `IpNet` (`/32` or `/128`) for a single address.
///
/// The prefix is valid for the family by construction, so this only returns
/// `None` on a theoretically-impossible error path — handled totally either way.
#[must_use]
fn host_net(ip: IpAddr) -> Option<IpNet> {
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNet::new(ip, prefix).ok()
}

#[cfg(test)]
#[path = "ignore_test.rs"]
mod ignore_test;
