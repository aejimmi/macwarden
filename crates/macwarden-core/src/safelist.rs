//! Critical service safe-list.
//!
//! Hardcoded list of services that must NEVER be disabled, regardless of any
//! profile or user request. Checked at two enforcement points: profile
//! validation and action execution.

use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::error::SafelistError;
use crate::types::Action;

/// Service label patterns for critical system services.
///
/// These are glob patterns — entries ending in `*` match any suffix.
/// Services matching any of these patterns cannot be disabled or killed.
pub const CRITICAL_SERVICES: &[&str] = &[
    "com.apple.launchd*",
    "com.apple.WindowServer",
    "com.apple.opendirectoryd",
    "com.apple.securityd",
    "com.apple.configd",
    "com.apple.diskarbitrationd",
    "com.apple.logd",
    "com.apple.notifyd",
    "com.apple.coreservicesd",
    "com.apple.loginwindow*",
    "com.apple.SystemStarter",
    "com.apple.xpc.*",
    "com.apple.kernelmanagerd",
    "com.apple.IOKit*",
    "com.apple.fseventsd",
    "com.apple.distnoted",
];

/// Compiled glob set for efficient matching against [`CRITICAL_SERVICES`].
static CRITICAL_GLOB_SET: LazyLock<GlobSet> = LazyLock::new(|| {
    let mut builder = GlobSetBuilder::new();
    for pattern in CRITICAL_SERVICES {
        // These patterns are hardcoded constants — compilation cannot fail.
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder
        .build()
        .expect("critical service glob set must compile")
});

/// Returns `true` if the given label matches any critical service pattern.
///
/// Uses a compiled [`GlobSet`] for efficient matching.
///
/// # Examples
///
/// ```
/// use macwarden_core::safelist::is_critical;
///
/// assert!(is_critical("com.apple.launchd"));
/// assert!(is_critical("com.apple.WindowServer"));
/// assert!(!is_critical("com.apple.Siri.agent"));
/// ```
pub fn is_critical(label: &str) -> bool {
    CRITICAL_GLOB_SET.is_match(label)
}

/// Validates a list of actions against the critical service safe-list.
///
/// Returns `Ok(actions)` unchanged if no action targets a critical service.
/// Returns `Err(SafelistError)` listing the rejected labels if any do.
pub fn validate_actions(actions: &[Action]) -> Result<Vec<Action>, SafelistError> {
    let rejected: Vec<String> = actions
        .iter()
        .filter(|a| is_critical(a.label()))
        .map(|a| a.label().to_owned())
        .collect();

    if rejected.is_empty() {
        Ok(actions.to_vec())
    } else {
        Err(SafelistError { rejected })
    }
}

#[cfg(test)]
#[path = "safelist_test.rs"]
mod safelist_test;
