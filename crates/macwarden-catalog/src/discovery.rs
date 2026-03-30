//! Service discovery — enumerate plists and combine with annotations.
//!
//! This module walks the canonical launchd plist directories, parses each
//! `.plist` file, and merges the results with the annotation database to
//! produce fully qualified [`ServiceInfo`] records.

use std::path::{Path, PathBuf};

use macwarden_core::{Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};

use crate::annotation::AnnotationDb;
use crate::plist_parser::{PlistInfo, parse_plist};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The five canonical directories where macOS stores launchd plist files.
pub const DEFAULT_PLIST_DIRS: &[&str] = &[
    "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    // Note: `~/Library/LaunchAgents` must be expanded by the caller before use.
    // This constant uses the literal path for documentation purposes.
    "~/Library/LaunchAgents",
];

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Enumerate all `.plist` files in the given directories and parse each one.
///
/// Files that fail to parse are logged as warnings and skipped. The returned
/// vector contains only successfully parsed entries.
pub fn discover_plists(dirs: &[PathBuf]) -> Vec<PlistInfo> {
    let mut results = Vec::new();

    for dir in dirs {
        if !dir.is_dir() {
            tracing::debug!(path = %dir.display(), "skipping non-existent plist directory");
            continue;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(path = %dir.display(), error = %e, "failed to read plist directory");
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read directory entry");
                    continue;
                }
            };

            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }

            match parse_plist(&path) {
                Ok(info) => results.push(info),
                Err(e) => {
                    // Not all .plist files in launch directories are service
                    // definitions (e.g. jetsamproperties, keystone configs).
                    // This is expected, not actionable — log at debug.
                    tracing::debug!(path = %path.display(), error = %e, "skipping non-service plist");
                }
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Annotation
// ---------------------------------------------------------------------------

/// Combine parsed plist info with annotations to produce full service records.
///
/// For each plist, the annotation database is consulted. If no annotation
/// matches, the service gets `Unknown` category and `Optional` safety, unless
/// the label suggests telemetry (contains "analytic", "diagnostic", "telemetry",
/// "crash", or "report").
pub fn annotate_services(plists: &[PlistInfo], db: &AnnotationDb) -> Vec<ServiceInfo> {
    plists
        .iter()
        .map(|plist| {
            let (category, safety, description) = match db.lookup(&plist.label) {
                Some(ann) => (ann.category, ann.safety, Some(ann.description.clone())),
                None => infer_unknown(&plist.label),
            };

            let domain = infer_domain(&plist.path);
            let state = if plist.disabled {
                ServiceState::Disabled
            } else {
                ServiceState::Unknown
            };

            ServiceInfo {
                label: plist.label.clone(),
                domain,
                plist_path: Some(plist.path.clone()),
                state,
                category,
                safety,
                description,
                pid: None,
            }
        })
        .collect()
}

/// Infer category and safety for an unknown service based on label heuristics.
///
/// Checks keyword patterns in priority order. More specific patterns (telemetry,
/// security) are checked before broad ones (unknown fallback).
fn infer_unknown(label: &str) -> (ServiceCategory, SafetyLevel, Option<String>) {
    let lower = label.to_ascii_lowercase();

    // Telemetry patterns
    if contains_any(
        &lower,
        &[
            "diagnostic",
            "analytics",
            "analytic",
            "crash",
            "report",
            "symptom",
            "spindump",
            "telemetry",
        ],
    ) {
        return (
            ServiceCategory::Telemetry,
            SafetyLevel::Telemetry,
            Some("Auto-detected telemetry service".into()),
        );
    }
    // Audio/Video
    if contains_any(
        &lower,
        &[
            "audio",
            "sound",
            "coreaudio",
            "camera",
            "cmio",
            "vdc",
            "video",
        ],
    ) {
        return (
            ServiceCategory::Media,
            SafetyLevel::Important,
            Some("Auto-detected media service".into()),
        );
    }
    // Bluetooth
    if contains_any(&lower, &["bluetooth", "btserver"]) {
        return (
            ServiceCategory::Networking,
            SafetyLevel::Optional,
            Some("Auto-detected Bluetooth service".into()),
        );
    }
    // Notifications
    if contains_any(&lower, &["notification", "usernot"]) {
        return (
            ServiceCategory::Unknown,
            SafetyLevel::Optional,
            Some("Auto-detected notification service".into()),
        );
    }
    // Printing
    if contains_any(&lower, &["print", "cups"]) {
        return (
            ServiceCategory::Unknown,
            SafetyLevel::Optional,
            Some("Auto-detected printing service".into()),
        );
    }
    // Location
    if contains_any(&lower, &["location", "geod", "geoservices"]) {
        return (
            ServiceCategory::Networking,
            SafetyLevel::Optional,
            Some("Auto-detected location service".into()),
        );
    }
    // Security
    if contains_any(
        &lower,
        &["security", "securityd", "keychain", "cryptotoken"],
    ) {
        return (
            ServiceCategory::Security,
            SafetyLevel::Important,
            Some("Auto-detected security service".into()),
        );
    }
    // File system
    if contains_any(&lower, &["fsevent", "diskimage", "filesystem", "diskutil"]) {
        return (
            ServiceCategory::CoreOs,
            SafetyLevel::Important,
            Some("Auto-detected filesystem service".into()),
        );
    }
    // Safari
    if contains_any(&lower, &["safari", "webkit"]) {
        return (
            ServiceCategory::Unknown,
            SafetyLevel::Optional,
            Some("Auto-detected Safari service".into()),
        );
    }
    // Accessibility
    if contains_any(&lower, &["accessibility", "voiceover", "universalaccess"]) {
        return (
            ServiceCategory::Accessibility,
            SafetyLevel::Important,
            Some("Auto-detected accessibility service".into()),
        );
    }

    // Apple system services — known vendor, unknown function.
    if lower.starts_with("com.apple.") {
        return (
            ServiceCategory::Unknown,
            SafetyLevel::Optional,
            Some("Apple service — not yet researched".into()),
        );
    }

    // Third-party services
    if !lower.starts_with("com.apple.") && lower.contains('.') {
        return (
            ServiceCategory::ThirdParty,
            SafetyLevel::Optional,
            Some("Third-party service".into()),
        );
    }

    (ServiceCategory::Unknown, SafetyLevel::Optional, None)
}

/// Check if a string contains any of the given keywords.
fn contains_any(s: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|k| s.contains(k))
}

/// Infer the launchd domain from the plist file path.
fn infer_domain(path: &Path) -> Domain {
    let path_str = path.to_string_lossy();

    if path_str.contains("LaunchDaemons") {
        Domain::System
    } else if path_str.contains("/System/Library/LaunchAgents") {
        Domain::Global
    } else {
        // ~/Library/LaunchAgents and /Library/LaunchAgents are user-domain.
        Domain::User
    }
}

#[cfg(test)]
#[path = "discovery_test.rs"]
mod discovery_test;
