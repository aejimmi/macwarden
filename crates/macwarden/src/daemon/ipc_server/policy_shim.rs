//! Decide-time policy shim (R4): the "Allow Apple Programs" floor.
//!
//! The pure `net` matcher is I/O-free and cannot know a process's live signing
//! state, so the Apple carve-out is applied *here*, in the daemon, around
//! [`net::RuleSet::decide_for_via`]. It is a **floor only**: it lifts the
//! Block-All profile-default Deny for an Apple-signed, non-graylisted process,
//! but it never overrides an explicit user/group Deny, a tracker/blocklist
//! Deny, or the Tier-0 safelist Allow.
//!
//! Ordering (mirrors the spec):
//! 1. Run `decide_for_via` (Tier 0 safelist + Tiers 1–5).
//! 2. If it returned anything other than the *profile-default* Deny
//!    (i.e. an explicit matched rule, or an Allow/Log), honor it verbatim.
//! 3. Only the profile-default Deny (`action == Deny && matched_rule == None`)
//!    is liftable: if `allow_apple_programs` and the process is Apple-signed
//!    and its path is **not** graylisted, override to Allow.
//! 4. Otherwise return the matcher's decision unchanged.
//!
//! Graylisted Apple binaries (`/bin/bash`, `/usr/bin/curl`, …) therefore fall
//! through to the default Deny under Block-All -- exactly the intended
//! hardening against using Apple-signed tools as an exfiltration lane.

use net::{
    Destination, MatchTier, MatchedRule, NetworkAction, NetworkDecision, ProcessIdentity, RuleId,
    RuleSet, graylist,
};

/// Synthetic rule id for a decision produced by the Apple-programs floor.
const APPLE_FLOOR_RULE_ID: u64 = 810_000;

/// Evaluate a connection against the rule set, then apply the Apple-programs
/// floor when `apple_allow` is set.
#[must_use]
pub fn decide_with_policy(
    ruleset: &RuleSet,
    process: &ProcessIdentity,
    via: Option<&ProcessIdentity>,
    dest: &Destination,
    apple_allow: bool,
) -> NetworkDecision {
    let decision = ruleset.decide_for_via(process, via, dest);
    if !apple_allow || !is_liftable_default_deny(&decision) {
        return decision;
    }
    if !is_apple_carveout_eligible(process) {
        return decision;
    }
    apple_allow_decision(process)
}

/// Whether a decision is the liftable profile-default Deny (no rule matched).
fn is_liftable_default_deny(decision: &NetworkDecision) -> bool {
    decision.action == NetworkAction::Deny && decision.matched_rule.is_none()
}

/// Whether the process qualifies for the Apple carve-out: Apple-signed and not
/// graylisted.
fn is_apple_carveout_eligible(process: &ProcessIdentity) -> bool {
    if process.is_apple_signed != Some(true) {
        return false;
    }
    !graylist::is_graylisted(&process.path.to_string_lossy())
}

/// Build the Allow decision the floor produces.
fn apple_allow_decision(process: &ProcessIdentity) -> NetworkDecision {
    NetworkDecision {
        action: NetworkAction::Allow,
        matched_rule: Some(MatchedRule {
            rule_id: RuleId(APPLE_FLOOR_RULE_ID),
            rule_name: "Allow Apple Programs".to_owned(),
            tier: MatchTier::UserRule,
        }),
        explanation: format!(
            "ALLOWED by Apple-programs floor -- {process} is Apple-signed and not graylisted",
        ),
    }
}

#[cfg(test)]
#[path = "policy_shim_test.rs"]
mod policy_shim_test;
