//! Loads built-in annotations, groups, and profiles from embedded TOML data.
//!
//! Data files live in `data/` and are embedded at compile time via
//! `include_str!`. Contributors edit TOML, not Rust.

use macwarden_core::group::{ServiceGroup, parse_groups_toml};
use macwarden_core::profile::{Profile, parse_profile_toml};

use crate::annotation::AnnotationDb;

// ---------------------------------------------------------------------------
// Embedded data
// ---------------------------------------------------------------------------

const ANNOTATIONS_TOML: &str = include_str!("../data/annotations.toml");
const GROUPS_TOML: &str = include_str!("../data/groups.toml");

const PROFILE_SOURCES: &[&str] = &[
    include_str!("../data/profiles/base.toml"),
    include_str!("../data/profiles/minimal.toml"),
    include_str!("../data/profiles/developer.toml"),
    include_str!("../data/profiles/airgapped.toml"),
    include_str!("../data/profiles/studio.toml"),
    include_str!("../data/profiles/paranoid.toml"),
    include_str!("../data/profiles/privacy.toml"),
];

// ---------------------------------------------------------------------------
// Public loaders
// ---------------------------------------------------------------------------

/// Load the built-in annotation database from embedded TOML.
pub fn load_builtin_annotations() -> AnnotationDb {
    AnnotationDb::load_from_toml(ANNOTATIONS_TOML).expect("built-in annotations.toml must be valid")
}

/// Load all built-in service groups from embedded TOML.
pub fn load_builtin_groups() -> Vec<ServiceGroup> {
    parse_groups_toml(GROUPS_TOML).expect("built-in groups.toml must be valid")
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
