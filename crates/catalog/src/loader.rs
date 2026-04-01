//! Loads built-in annotations, groups, and profiles from embedded TOML data.
//!
//! Data files live in `data/` and are embedded at compile time via
//! `include_str!`. Contributors edit TOML, not Rust.
//!
//! Groups are one file per group under `data/groups/`. To add a new group,
//! create `data/groups/<name>.toml` and add an `include_str!` line to
//! `GROUP_SOURCES` below.

use policy::group::{ServiceGroup, parse_group_file};
use policy::profile::{Profile, parse_profile_toml};

use crate::annotation::AnnotationDb;

// ---------------------------------------------------------------------------
// Embedded data
// ---------------------------------------------------------------------------

const ANNOTATIONS_TOML: &str = include_str!("../data/annotations.toml");

/// One entry per group file in `data/groups/`.
const GROUP_SOURCES: &[&str] = &[
    include_str!("../data/groups/airdrop.toml"),
    include_str!("../data/groups/airplay.toml"),
    include_str!("../data/groups/apple-intelligence.toml"),
    include_str!("../data/groups/applemusic.toml"),
    include_str!("../data/groups/backup.toml"),
    include_str!("../data/groups/bluetooth.toml"),
    include_str!("../data/groups/cloudkit.toml"),
    include_str!("../data/groups/continuity.toml"),
    include_str!("../data/groups/crash-reports.toml"),
    include_str!("../data/groups/fmf.toml"),
    include_str!("../data/groups/gamekit.toml"),
    include_str!("../data/groups/hang-detection.toml"),
    include_str!("../data/groups/icloud-sync.toml"),
    include_str!("../data/groups/keychain-sync.toml"),
    include_str!("../data/groups/location.toml"),
    include_str!("../data/groups/mail.toml"),
    include_str!("../data/groups/maps.toml"),
    include_str!("../data/groups/media-analysis.toml"),
    include_str!("../data/groups/messages.toml"),
    include_str!("../data/groups/network-quality.toml"),
    include_str!("../data/groups/notifications.toml"),
    include_str!("../data/groups/photos.toml"),
    include_str!("../data/groups/profiling.toml"),
    include_str!("../data/groups/remote-access.toml"),
    include_str!("../data/groups/safari.toml"),
    include_str!("../data/groups/screentime.toml"),
    include_str!("../data/groups/siri.toml"),
    include_str!("../data/groups/spotlight.toml"),
    include_str!("../data/groups/system-logging.toml"),
    include_str!("../data/groups/telemetry.toml"),
    include_str!("../data/groups/updates.toml"),
    include_str!("../data/groups/wallet.toml"),
    include_str!("../data/groups/widgets.toml"),
    include_str!("../data/groups/xcode.toml"),
];

const PROFILE_SOURCES: &[&str] = &[include_str!("../data/profiles/privacy.toml")];

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
