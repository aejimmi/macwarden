//! The opaque handle: an atomically-swappable embedded [`net::RuleSet`].
//!
//! `NEFilterDataProvider` calls `handleNewFlow` concurrently, so decisions must
//! take a cheap, lock-free read of the current rule set while a reload swaps in
//! a fresh one atomically. [`arc_swap::ArcSwap`] gives exactly that: `decide`
//! loads the current `Arc<RuleSet>` with no lock held across matching, and
//! `reload` rebuilds off to the side then stores the new pointer in one step.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use net::RuleSet;

use crate::decision::{self, NeDecision};
use crate::error::NeError;

/// Opaque handle owned by the caller (Swift) as `*mut MacwardenNe`.
pub struct MacwardenNe {
    base_dir: PathBuf,
    ruleset: ArcSwap<RuleSet>,
}

impl MacwardenNe {
    /// Load the initial rule set from `base_dir` (`~/.macwarden/`).
    ///
    /// # Errors
    ///
    /// Returns [`NeError::Load`] if the ruleset cannot be composed. Note the
    /// composition itself fails open for missing/malformed config files; an
    /// error here means a built-in data file failed to load.
    pub fn load(base_dir: PathBuf) -> Result<Self, NeError> {
        let ruleset = build(&base_dir)?;
        Ok(Self {
            base_dir,
            ruleset: ArcSwap::from_pointee(ruleset),
        })
    }

    /// Rebuild the rule set from disk and swap it in atomically.
    ///
    /// On failure the previous rule set is retained (fail-safe: a bad reload
    /// never wipes enforcement) and the error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`NeError::Load`] if the fresh ruleset cannot be composed.
    pub fn reload(&self) -> Result<(), NeError> {
        let fresh = build(&self.base_dir)?;
        self.ruleset.store(Arc::new(fresh));
        Ok(())
    }

    /// Decide a flow against the current rule set snapshot.
    #[must_use]
    pub fn decide(
        &self,
        code_id: Option<&str>,
        path: Option<&str>,
        host: Option<&str>,
        ip: Option<&str>,
        port: u16,
        proto: u8,
    ) -> NeDecision {
        let rules = self.ruleset.load();
        decision::decide(&rules, code_id, path, host, ip, port, proto)
    }

    /// The base directory this handle loads from.
    #[must_use]
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

/// Compose the live rule set from the shared loader (single source of truth).
///
/// The NE decision core is a separate, sandboxed process with no in-memory
/// banwatch engine, so it reads the active-ban IP set from the on-disk store
/// here at the call site and hands it to the loader as an explicit input (the
/// loader itself is source-agnostic). The read is total: a missing or corrupt
/// store composes zero bans rather than erroring.
fn build(base_dir: &Path) -> Result<RuleSet, NeError> {
    let banned_ips = banwatch::active_ban_ips(base_dir);
    net::load_live_ruleset(base_dir, &[], &banned_ips).map_err(|e| NeError::Load(e.to_string()))
}

/// Resolve the default `~/.macwarden/` base directory.
///
/// Honors `MACWARDEN_HOME` (an explicit override) first, then `$HOME`. Returns
/// [`NeError::NoBaseDir`] when neither is set.
pub fn default_base_dir() -> Result<PathBuf, NeError> {
    if let Some(dir) = std::env::var_os("MACWARDEN_HOME") {
        return Ok(PathBuf::from(dir));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".macwarden"))
        .ok_or(NeError::NoBaseDir)
}

#[cfg(test)]
#[path = "handle_test.rs"]
mod handle_test;
