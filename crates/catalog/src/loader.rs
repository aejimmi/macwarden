//! Loads built-in annotations, groups, and profiles from embedded TOML data.
//!
//! Data files live in `knowledge/services/` at the workspace root and are
//! embedded at compile time via `include_str!`. Contributors edit TOML, not Rust.
//!
//! Groups are one file per group under `knowledge/services/groups/`. To add a
//! new group, create `knowledge/services/groups/<name>.toml` and add an
//! `include_str!` line to `GROUP_SOURCES` below.

use policy::artifact::{ArtifactDomain, parse_artifact_file, validate_artifact_catalog};
use policy::group::{ServiceGroup, parse_group_file};
use policy::profile::{Profile, parse_profile_toml};

use crate::annotation::AnnotationDb;

// ---------------------------------------------------------------------------
// Embedded data
// ---------------------------------------------------------------------------

const ANNOTATIONS_TOML: &str = include_str!("../../../knowledge/services/annotations.toml");

/// One entry per group file in `data/groups/`.
const GROUP_SOURCES: &[&str] = &[
    include_str!("../../../knowledge/services/groups/airdrop.toml"),
    include_str!("../../../knowledge/services/groups/airplay.toml"),
    include_str!("../../../knowledge/services/groups/apple-intelligence.toml"),
    include_str!("../../../knowledge/services/groups/applemusic.toml"),
    include_str!("../../../knowledge/services/groups/audit-logs.toml"),
    include_str!("../../../knowledge/services/groups/backup.toml"),
    include_str!("../../../knowledge/services/groups/bluetooth.toml"),
    include_str!("../../../knowledge/services/groups/cloudkit.toml"),
    include_str!("../../../knowledge/services/groups/continuity.toml"),
    include_str!("../../../knowledge/services/groups/crash-reports.toml"),
    include_str!("../../../knowledge/services/groups/document-versions.toml"),
    include_str!("../../../knowledge/services/groups/fmf.toml"),
    include_str!("../../../knowledge/services/groups/fsevents.toml"),
    include_str!("../../../knowledge/services/groups/gamekit.toml"),
    include_str!("../../../knowledge/services/groups/gatekeeper.toml"),
    include_str!("../../../knowledge/services/groups/hang-detection.toml"),
    include_str!("../../../knowledge/services/groups/icloud-sync.toml"),
    include_str!("../../../knowledge/services/groups/install-history.toml"),
    include_str!("../../../knowledge/services/groups/keychain-sync.toml"),
    include_str!("../../../knowledge/services/groups/location.toml"),
    include_str!("../../../knowledge/services/groups/mail.toml"),
    include_str!("../../../knowledge/services/groups/maps.toml"),
    include_str!("../../../knowledge/services/groups/media-analysis.toml"),
    include_str!("../../../knowledge/services/groups/messages.toml"),
    include_str!("../../../knowledge/services/groups/network-quality.toml"),
    include_str!("../../../knowledge/services/groups/network-usage.toml"),
    include_str!("../../../knowledge/services/groups/notifications.toml"),
    include_str!("../../../knowledge/services/groups/photos.toml"),
    include_str!("../../../knowledge/services/groups/print-logs.toml"),
    include_str!("../../../knowledge/services/groups/profiling.toml"),
    include_str!("../../../knowledge/services/groups/quarantine.toml"),
    include_str!("../../../knowledge/services/groups/quicklook.toml"),
    include_str!("../../../knowledge/services/groups/recent-items.toml"),
    include_str!("../../../knowledge/services/groups/remote-access.toml"),
    include_str!("../../../knowledge/services/groups/safari.toml"),
    include_str!("../../../knowledge/services/groups/saved-state.toml"),
    include_str!("../../../knowledge/services/groups/screentime.toml"),
    include_str!("../../../knowledge/services/groups/shell-history.toml"),
    include_str!("../../../knowledge/services/groups/siri.toml"),
    include_str!("../../../knowledge/services/groups/spotlight.toml"),
    include_str!("../../../knowledge/services/groups/system-logging.toml"),
    include_str!("../../../knowledge/services/groups/tcc.toml"),
    include_str!("../../../knowledge/services/groups/telemetry.toml"),
    include_str!("../../../knowledge/services/groups/updates.toml"),
    include_str!("../../../knowledge/services/groups/wallet.toml"),
    include_str!("../../../knowledge/services/groups/widgets.toml"),
    include_str!("../../../knowledge/services/groups/wifi.toml"),
    include_str!("../../../knowledge/services/groups/xcode.toml"),
];

/// One entry per artifact domain file in `knowledge/services/artifacts/`.
const ARTIFACT_SOURCES: &[&str] = &[
    include_str!("../../../knowledge/services/artifacts/app-caches.toml"),
    include_str!("../../../knowledge/services/artifacts/browser-traces.toml"),
    include_str!("../../../knowledge/services/artifacts/cloudkit-cache.toml"),
    include_str!("../../../knowledge/services/artifacts/mail.toml"),
    include_str!("../../../knowledge/services/artifacts/quarantine.toml"),
    include_str!("../../../knowledge/services/artifacts/quicklook.toml"),
    include_str!("../../../knowledge/services/artifacts/recent-items.toml"),
    include_str!("../../../knowledge/services/artifacts/safari.toml"),
    include_str!("../../../knowledge/services/artifacts/saved-state.toml"),
    include_str!("../../../knowledge/services/artifacts/spotlight.toml"),
    include_str!("../../../knowledge/services/artifacts/system-logs.toml"),
    include_str!("../../../knowledge/services/artifacts/telemetry.toml"),
];

const PROFILE_SOURCES: &[&str] = &[include_str!(
    "../../../knowledge/services/profiles/privacy.toml"
)];

// ---------------------------------------------------------------------------
// Public loaders
// ---------------------------------------------------------------------------

/// Load the built-in annotation database from embedded TOML.
pub fn load_builtin_annotations() -> AnnotationDb {
    AnnotationDb::load_from_toml(ANNOTATIONS_TOML).expect("built-in annotations.toml must be valid")
}

/// Load all built-in service groups from per-group TOML files.
pub fn load_builtin_groups() -> Vec<ServiceGroup> {
    GROUP_SOURCES
        .iter()
        .map(|src| parse_group_file(src).expect("built-in group file must be valid"))
        .collect()
}

/// Load all built-in artifact domains from embedded TOML files.
///
/// Panics if any embedded artifact file is invalid or if names collide,
/// since built-in data is always valid.
pub fn load_builtin_artifacts() -> Vec<ArtifactDomain> {
    let domains: Vec<ArtifactDomain> = ARTIFACT_SOURCES
        .iter()
        .map(|src| parse_artifact_file(src).expect("built-in artifact file must be valid"))
        .collect();

    validate_artifact_catalog(&domains).expect("built-in artifact catalog must be valid");
    domains
}

/// Load all built-in profiles from embedded TOML files.
pub fn load_builtin_profiles() -> Vec<Profile> {
    PROFILE_SOURCES
        .iter()
        .map(|s| parse_profile_toml(s).expect("built-in profile TOML must be valid"))
        .collect()
}

#[cfg(test)]
#[path = "loader_test.rs"]
mod loader_test;
