//! Essential domain safe-list for the network firewall.
//!
//! Domains on this list are NEVER blocked, regardless of user rules,
//! tracker databases, or blocklists. Blocking these domains can break
//! certificate validation, time synchronization, system updates, or
//! iCloud activation -- causing system-level failures that are hard
//! to diagnose.
//!
//! This list is compiled in and not user-overridable. It is checked
//! before any other matching tier.

/// Essential Apple infrastructure domains that must never be blocked.
///
/// Each entry is a bare domain. Subdomains are also considered essential
/// via domain-boundary decomposition (same pattern as blocklist matching).
const ESSENTIAL_DOMAINS: &[&str] = &[
    "ocsp.apple.com",
    "time.apple.com",
    "gateway.icloud.com",
    "captive.apple.com",
    "swscan.apple.com",
    "swdist.apple.com",
    "crl.apple.com",
    "valid.apple.com",
    "ocsp2.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
];

/// Returns `true` if the hostname is an essential domain that must
/// never be blocked.
///
/// Uses domain-boundary decomposition: `"cdn.ocsp.apple.com"` matches
/// because `"ocsp.apple.com"` is in the safe-list and `"cdn"` is a
/// subdomain. But `"evil-ocsp.apple.com"` does NOT match because
/// `"evil-ocsp.apple.com"` is not a subdomain of any listed domain.
///
/// Matching is case-insensitive.
///
/// # Examples
///
/// ```
/// use net::safelist::is_essential_domain;
///
/// assert!(is_essential_domain("ocsp.apple.com"));
/// assert!(is_essential_domain("cdn.ocsp.apple.com"));
/// assert!(!is_essential_domain("tracking.apple.com"));
/// ```
pub fn is_essential_domain(hostname: &str) -> bool {
    let lower = hostname.to_ascii_lowercase();
    let mut candidate: &str = &lower;
    loop {
        if ESSENTIAL_DOMAINS.contains(&candidate) {
            return true;
        }
        match candidate.find('.') {
            Some(pos) => candidate = &candidate[pos + 1..],
            None => return false,
        }
    }
}

/// Returns the number of entries in the essential domain safe-list.
///
/// Useful for CLI summary output.
pub fn count() -> usize {
    ESSENTIAL_DOMAINS.len()
}

#[cfg(test)]
#[path = "safelist_test.rs"]
mod safelist_test;
