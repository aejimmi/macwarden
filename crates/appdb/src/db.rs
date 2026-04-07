//! App database — loads and indexes [`AppProfile`] entries.
//!
//! The database is built from embedded TOML files at compile time.
//! It provides fast lookup by `code_id` and category expansion for
//! use by both the network firewall and execution gating subsystems.

use std::collections::HashMap;

use crate::error::AppDbError;
use crate::profile::{AppCategory, AppProfile};

// ---------------------------------------------------------------------------
// AppDb
// ---------------------------------------------------------------------------

/// Database of app profiles, indexed by code signing identity.
#[derive(Debug, Clone)]
pub struct AppDb {
    /// All loaded profiles.
    profiles: Vec<AppProfile>,
    /// Index from code_id to position in `profiles`.
    index: HashMap<String, usize>,
}

impl AppDb {
    /// Build a database from a slice of TOML source strings.
    ///
    /// Each string is the content of a single per-app TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`AppDbError::ProfileParse`] if any TOML file is malformed.
    pub fn from_sources(sources: &[&str]) -> Result<Self, AppDbError> {
        let mut profiles = Vec::with_capacity(sources.len());
        for src in sources {
            let profile: AppProfile =
                toml::from_str(src).map_err(|e| AppDbError::ProfileParse {
                    message: e.to_string(),
                })?;
            profiles.push(profile);
        }
        let index = profiles
            .iter()
            .enumerate()
            .map(|(i, p)| (p.code_id.clone(), i))
            .collect();
        Ok(Self { profiles, index })
    }

    /// Load the built-in app database from compiled-in TOML data.
    ///
    /// # Errors
    ///
    /// Returns [`AppDbError::ProfileParse`] if any embedded TOML is malformed.
    pub fn load_builtin() -> Result<Self, AppDbError> {
        Self::from_sources(crate::loader::APP_PROFILE_SOURCES)
    }

    /// Look up an app profile by exact code signing identity.
    pub fn lookup(&self, code_id: &str) -> Option<&AppProfile> {
        self.index.get(code_id).and_then(|&i| self.profiles.get(i))
    }

    /// Look up which category an app belongs to by exact `code_id` match.
    pub fn categorize(&self, code_id: &str) -> Option<AppCategory> {
        self.lookup(code_id).and_then(|p| p.category)
    }

    /// Get all profiles in a given category.
    pub fn apps_in(&self, category: AppCategory) -> Vec<&AppProfile> {
        self.profiles
            .iter()
            .filter(|p| p.category == Some(category))
            .collect()
    }

    /// All loaded profiles in the database.
    pub fn entries(&self) -> &[AppProfile] {
        &self.profiles
    }

    /// Expand a category into a list of code_id strings.
    ///
    /// Used at profile load time to expand `process = { category = "browser" }`
    /// into individual `ProcessMatcher::CodeId` rules.
    pub fn expand_category(&self, category: AppCategory) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|p| p.category == Some(category))
            .map(|p| p.code_id.clone())
            .collect()
    }

    /// Returns the number of profiles in the database.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Returns `true` if the database contains no profiles.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
#[path = "db_test.rs"]
mod db_test;
