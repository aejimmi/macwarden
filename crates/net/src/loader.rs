//! Composing a live [`RuleSet`] from the persisted `~/.macwarden/` files.
//!
//! This is the single source of truth for how a rule set is fused from disk,
//! shared by the daemon (which owns the live set and serves it over IPC) and
//! the NetworkExtension decision core (`enforce-ne-ffi`, which embeds a
//! `RuleSet` inside the sandboxed content-filter process). Both must produce
//! byte-for-byte the same verdicts from the same files, so both call these
//! functions rather than re-implementing composition.
//!
//! The fusion, in the tier order the matcher expects:
//! 1. the built-in tracker DB, network groups, and app-category DB;
//! 2. the base profile derived from `net-profile.toml` ([`PolicyConfig`]) and
//!    `net-shield.toml` ([`ShieldConfig`]);
//! 3. the synthetic allow-list + DNS carve-outs the policy compiles;
//! 4. the persisted user-rule files in `net-rules/` ([`load_user_rules`]);
//! 5. caller-supplied in-memory session rules.
//!
//! Every path is derived from a single `base_dir` argument so the loader is
//! fully test-overridable (point it at a `tempfile::TempDir`) and never has to
//! hard-code `$HOME`.

use std::net::IpAddr;
use std::path::Path;

use appdb::AppDb;
use ipnet::IpNet;

use crate::error::NetError;
use crate::group::NetworkGroups;
use crate::matcher::RuleSet;
use crate::policy::PolicyConfig;
use crate::profile::{BlocklistSettings, GroupSettings, NetworkProfile, TrackerSettings};
use crate::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};
use crate::shield::{SHIELD_FILENAME, ShieldConfig};
use crate::tracker::TrackerDatabase;
use crate::user_rule::load_user_rules;

/// Canonical filename of the policy config within `~/.macwarden/`.
pub const NET_PROFILE_FILENAME: &str = "net-profile.toml";

/// Canonical directory (within `~/.macwarden/`) holding persisted user rules.
pub const NET_RULES_DIRNAME: &str = "net-rules";

/// Base id for synthetic banwatch Deny rules (spec 010 R6).
///
/// Sits above the allow-list band ([`crate::policy::ALLOWLIST_RULE_ID_BASE`] =
/// `800_000`) and below session rules (`900_000`), so ban rules never collide
/// with either. Allow-list entries are Tier-1 Allow and still evaluate first;
/// a banwatch ban only ever reaches an IP that `ignoreip` did not exempt, so
/// there is no allow/deny ambiguity for trusted ranges.
pub const BAN_RULE_ID_BASE: u64 = 850_000;

/// Build the base [`NetworkProfile`] from a policy config and shield state.
///
/// When the shield is enabled, tracker categories configured as `"deny"`
/// upgrade the corresponding [`TrackerSettings`] field from `Log` to `Deny`.
/// The [`PolicyConfig`] then sets the Tier-5 default action from the global
/// mode and merges group enable/disable overrides.
#[must_use]
pub fn base_profile(config: &PolicyConfig, shield: &ShieldConfig) -> NetworkProfile {
    let trackers = if shield.enabled {
        TrackerSettings {
            advertising: shield.category_action("advertising"),
            analytics: shield.category_action("analytics"),
            fingerprinting: shield.category_action("fingerprinting"),
            social: shield.category_action("social"),
            ..TrackerSettings::default()
        }
    } else {
        TrackerSettings::default()
    };

    let mut profile = NetworkProfile {
        default: NetworkAction::Log,
        trackers,
        groups: GroupSettings::default(),
        blocklists: BlocklistSettings::default(),
        rules: Vec::new(),
    };
    config.apply_to(&mut profile);
    profile
}

/// Build the base rule set: builtins + base profile + synthetic allow-list.
///
/// Reads `net-profile.toml` and `net-shield.toml` from `base_dir` (both fail
/// open to their disabled/allow-all defaults if absent or malformed). Does
/// **not** include the persisted user-rule files or session rules -- use
/// [`load_live_ruleset`] for the complete live set.
///
/// # Errors
///
/// Returns [`NetError`] only when a built-in data file (tracker DB, network
/// groups, app categories) or the profile resolution fails -- never for a
/// missing or malformed on-disk config, which fails open.
pub fn build_base_ruleset(base_dir: &Path, banned_ips: &[IpAddr]) -> Result<RuleSet, NetError> {
    let config = PolicyConfig::load(&base_dir.join(NET_PROFILE_FILENAME));
    let shield = ShieldConfig::load(&base_dir.join(SHIELD_FILENAME));

    let tracker_db = TrackerDatabase::load_builtin()?;
    let groups = NetworkGroups::load_builtin()?;
    let category_db = AppDb::load_builtin().map_err(|e| NetError::CategoryParse {
        message: e.to_string(),
    })?;

    let profile = base_profile(&config, &shield);
    let mut ruleset = profile.resolve(&groups, &tracker_db, &category_db, &[])?;

    let allow_rules = config.to_allow_rules()?;
    ruleset.user_rules.extend(allow_rules);
    ruleset.user_rules.extend(ban_deny_rules(banned_ips));
    ruleset.sort_user_rules();
    Ok(ruleset)
}

/// Compose synthetic **Deny** rules from a caller-supplied active-ban IP set
/// (spec 010 R6). The IP list is an explicit **input** — the loader never
/// reopens the etch ban store itself, so it cannot tear against an etch WAL
/// compaction (the daemon supplies its authoritative in-memory set; the NE core
/// and CLI read the store at their own call sites and pass the slice in). This
/// keeps composition source-agnostic and forward-compatible with the spec-009
/// `RuleSources` refactor (bans as an explicit rule source).
///
/// Each ban becomes a process-blind `NetworkRule` that denies a flow whose
/// **remote** endpoint IP is the banned address (`process = Any`,
/// `dest.ip = <ip>/32|/128`, `action = Deny`) — so a banned scanner's flow to a
/// listening service is dropped, inbound or outbound. Given the same IP set,
/// every caller composes byte-identical ban rules (the parity invariant).
#[must_use]
pub fn ban_deny_rules(banned_ips: &[IpAddr]) -> Vec<NetworkRule> {
    banned_ips
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, ip)| ban_rule(idx, ip))
        .collect()
}

/// Build one banwatch Deny rule for `ip` at `idx` within the reserved band.
fn ban_rule(idx: usize, ip: IpAddr) -> NetworkRule {
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    // `new_assert` is infallible for a `/32`|`/128` host route on its family.
    let net = IpNet::new_assert(ip, prefix);
    NetworkRule {
        id: RuleId(BAN_RULE_ID_BASE + idx as u64),
        name: format!("banwatch: deny {ip}"),
        process: ProcessMatcher::Any,
        destination: DestMatcher {
            ip: Some(net),
            ..Default::default()
        },
        action: NetworkAction::Deny,
        duration: RuleDuration::Session,
        enabled: true,
        note: Some("auto-composed from the banwatch active-ban set".to_owned()),
    }
}

/// Build the complete live rule set: base + persisted user rules + session.
///
/// Composes [`build_base_ruleset`] (which folds in the caller-supplied
/// `banned_ips`), then appends the persisted user-rule files in
/// `base_dir/net-rules/` (what `net block` writes) and the caller's in-memory
/// `session_rules`, re-sorting so specificity ordering holds. A missing
/// `net-rules/` directory is not an error -- it just means no user rules yet.
///
/// # Errors
///
/// Returns [`NetError`] only when the base set fails to build (see
/// [`build_base_ruleset`]) or the `net-rules/` directory exists but cannot be
/// read at all. Individual user-rule files that are malformed, oversized,
/// symlinked, or otherwise unreadable are **skipped with a warning** — the
/// fail-safe behavior — never propagated as an error, so one bad file cannot
/// wedge the whole live rule set. Do not "restore" an error-out-on-malformed
/// path here: skipping is the security-correct semantics ([`load_user_rules`]).
pub fn load_live_ruleset(
    base_dir: &Path,
    session_rules: &[NetworkRule],
    banned_ips: &[IpAddr],
) -> Result<RuleSet, NetError> {
    let mut ruleset = build_base_ruleset(base_dir, banned_ips)?;

    let rules_dir = base_dir.join(NET_RULES_DIRNAME);
    if rules_dir.is_dir() {
        let user = load_user_rules(&rules_dir)?;
        ruleset.user_rules.extend(user);
    }

    ruleset.user_rules.extend(session_rules.iter().cloned());
    ruleset.sort_user_rules();
    Ok(ruleset)
}

#[cfg(test)]
#[path = "loader_test.rs"]
mod loader_test;
