//! Building the daemon's live [`net::RuleSet`] from all rule sources (R7).
//!
//! The live rule set fuses the base profile (trackers, groups, blocklists,
//! default action, synthetic allow-list), the persisted user-rule files in
//! `~/.macwarden/net-rules/` (what `net block` writes), and the daemon's
//! in-memory session rules. Composition itself lives in [`net::loader`] so the
//! daemon and the NetworkExtension decision core (`enforce-ne-ffi`) produce one
//! identical rule set from the same files; this module is a thin adapter that
//! maps the daemon's `net-rules/` directory onto that shared loader.

use std::net::IpAddr;
use std::path::Path;

use net::{NetworkRule, RuleSet};

use super::error::{Result, ServerError};

/// Build the live rule set: base profile + persisted user rules + session rules.
///
/// `rules_dir` is the daemon's `net-rules/` directory; its parent is the
/// `~/.macwarden/` base directory the shared loader reads `net-profile.toml`
/// and `net-shield.toml` from. `session_rules` are the daemon's in-memory
/// `Session`-duration rules, appended after the on-disk user rules.
///
/// `banned_ips` is the active-ban IP set the daemon has **already snapshotted**
/// from its in-memory banwatch engine (see
/// [`super::banwatch_svc::BanwatchService::active_ban_ips`]). It is passed as an
/// explicit input so the reload path never reopens the etch ban store — the fix
/// for the WAL torn-read bug.
pub fn build_live_ruleset(
    rules_dir: &Path,
    session_rules: &[NetworkRule],
    banned_ips: &[IpAddr],
) -> Result<RuleSet> {
    let base_dir = rules_dir.parent().unwrap_or(rules_dir);
    net::load_live_ruleset(base_dir, session_rules, banned_ips)
        .map_err(|e| ServerError::Reload(e.to_string()))
}

#[cfg(test)]
#[path = "ruleset_test.rs"]
mod ruleset_test;
