//! Five-tier rule matching engine.
//!
//! Evaluates connection events against a prioritized rule set:
//! 1. User rules (sorted by specificity)
//! 2. Group rules (ordered by group priority)
//! 3. Tracker rules (category-based domain blocking)
//! 4. Blocklist entries (exact domain match + subdomain walking)
//! 5. Profile default action
//!
//! First match wins within and across tiers. User rules always beat
//! community/curated rules.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::connection::{
    ConnectionEvent, Destination, MatchTier, MatchedRule, NetworkDecision, ProcessIdentity,
};
use crate::domain_trie::DomainTrie;
use crate::rule::{HostPattern, NetworkAction, NetworkRule, ProcessMatcher, RuleId};
use crate::safelist;

// ---------------------------------------------------------------------------
// BreakageRisk
// ---------------------------------------------------------------------------

/// How much breakage blocking a tracker domain may cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreakageRisk {
    /// Blocking has zero side effects.
    None,
    /// App works but loses a feature.
    Degraded,
    /// App may fail to start or lose core function.
    Critical,
}

impl fmt::Display for BreakageRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Degraded => write!(f, "degraded"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// GroupedRule
// ---------------------------------------------------------------------------

/// A network rule with group provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedRule {
    /// The underlying network rule.
    pub rule: NetworkRule,
    /// Name of the group this rule belongs to.
    pub group_name: String,
    /// Priority of the group (lower = higher priority).
    pub group_priority: u32,
}

// ---------------------------------------------------------------------------
// TrackerRule
// ---------------------------------------------------------------------------

/// A tracker domain pattern with category and breakage info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerRule {
    /// Domain pattern to match.
    pub pattern: HostPattern,
    /// Tracker category (e.g. "advertising", "analytics").
    pub category: String,
    /// Risk of breakage if this domain is blocked.
    pub breakage_risk: BreakageRisk,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// BlocklistEntry
// ---------------------------------------------------------------------------

/// A domain from an external blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Normalized domain string.
    pub domain: String,
    /// Name of the blocklist this domain came from.
    pub list_name: String,
}

// ---------------------------------------------------------------------------
// RuleSet
// ---------------------------------------------------------------------------

/// The complete rule set used by the matching engine.
///
/// Rules are organized into five tiers, evaluated in order.
/// First match across all tiers wins.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Tier 1: user-defined rules, pre-sorted by specificity.
    pub user_rules: Vec<NetworkRule>,
    /// Tier 2: group rules, ordered by group priority.
    pub group_rules: Vec<GroupedRule>,
    /// Tier 3: tracker rules.
    pub tracker_rules: Vec<TrackerRule>,
    /// Tier 4: blocklist domains (kept for iteration / listing).
    pub blocklist_domains: Vec<BlocklistEntry>,
    /// Tier 4 acceleration: reverse-label trie for O(k) blocklist lookup.
    pub blocklist_trie: DomainTrie<BlocklistEntry>,
    /// Tier 5: default action when nothing matches.
    pub default_action: NetworkAction,
}

impl RuleSet {
    /// Sort user rules by specificity (most specific first).
    ///
    /// Call this after adding rules. The matcher assumes user rules are sorted.
    pub fn sort_user_rules(&mut self) {
        self.user_rules.sort_by(|a, b| {
            let sa = a.specificity();
            let sb = b.specificity();
            // Higher specificity first: reverse order.
            sb.cmp(&sa)
        });
    }

    /// Rebuild the blocklist trie from `blocklist_domains`.
    ///
    /// Call this after populating or modifying `blocklist_domains`.
    /// Each entry is inserted as a domain match (self + subdomains),
    /// matching the semantics of the previous linear-scan approach.
    pub fn rebuild_blocklist_trie(&mut self) {
        let mut trie = DomainTrie::new();
        for entry in &self.blocklist_domains {
            trie.insert_domain(&entry.domain, entry.clone());
        }
        self.blocklist_trie = trie;
    }

    /// Evaluate a connection event against the rule set.
    ///
    /// Returns a [`NetworkDecision`] with the action, matched rule, and explanation.
    pub fn decide(&self, event: &ConnectionEvent) -> NetworkDecision {
        self.decide_for_via(
            &event.process,
            event.via_process.as_ref(),
            &event.destination,
        )
    }

    /// Evaluate a process + destination pair against the rule set.
    ///
    /// Same as [`decide`](Self::decide) but takes components directly.
    /// Does not consider a via process -- use [`decide_for_via`](Self::decide_for_via)
    /// when a responsible process is available.
    ///
    /// The safelist is checked first -- essential domains (OCSP, NTP,
    /// iCloud activation, etc.) are always allowed regardless of rules.
    pub fn decide_for(&self, process: &ProcessIdentity, dest: &Destination) -> NetworkDecision {
        self.decide_for_via(process, None, dest)
    }

    /// Evaluate a process + via process + destination against the rule set.
    ///
    /// When a helper process (e.g. `com.apple.WebKit.Networking`) makes a
    /// connection on behalf of an app (e.g. Safari), pass the app as `via`.
    /// Rules targeting either process will match.
    pub fn decide_for_via(
        &self,
        process: &ProcessIdentity,
        via: Option<&ProcessIdentity>,
        dest: &Destination,
    ) -> NetworkDecision {
        if let Some(d) = self.check_safelist(dest) {
            return d;
        }
        if let Some(d) = self.check_user_rules(process, via, dest) {
            return d;
        }
        if let Some(d) = self.check_group_rules(process, via, dest) {
            return d;
        }
        if let Some(d) = self.check_tracker_rules(dest) {
            return d;
        }
        if let Some(d) = self.check_blocklist(dest) {
            return d;
        }
        self.default_decision(process, dest)
    }

    /// Produce a human-readable explanation of why a decision was made.
    pub fn explain(&self, process: &ProcessIdentity, dest: &Destination) -> String {
        let decision = self.decide_for(process, dest);
        decision.explanation
    }
}

// ---------------------------------------------------------------------------
// Tier implementations (private)
// ---------------------------------------------------------------------------

impl RuleSet {
    /// Tier 0: check the essential domain safe-list.
    ///
    /// Essential domains (OCSP, NTP, iCloud activation) are always
    /// allowed before any other tier is consulted.
    #[allow(clippy::unused_self)]
    fn check_safelist(&self, dest: &Destination) -> Option<NetworkDecision> {
        let host = dest.host.as_deref()?;
        if !safelist::is_essential_domain(host) {
            return None;
        }
        Some(NetworkDecision {
            action: NetworkAction::Allow,
            matched_rule: Some(MatchedRule {
                rule_id: RuleId(0),
                rule_name: host.to_owned(),
                tier: MatchTier::SafeList,
            }),
            explanation: format!(
                "ALLOWED by safe-list -- {host} is an essential domain (never blocked)",
            ),
        })
    }

    /// Tier 1: check user rules (pre-sorted by specificity).
    fn check_user_rules(
        &self,
        process: &ProcessIdentity,
        via: Option<&ProcessIdentity>,
        dest: &Destination,
    ) -> Option<NetworkDecision> {
        let rule = self
            .user_rules
            .iter()
            .find(|r| r.matches_with_via(process, via, dest))?;
        Some(build_decision(
            rule,
            &MatchTier::UserRule,
            process,
            via,
            dest,
        ))
    }

    /// Tier 2: check group rules (ordered by group priority).
    fn check_group_rules(
        &self,
        process: &ProcessIdentity,
        via: Option<&ProcessIdentity>,
        dest: &Destination,
    ) -> Option<NetworkDecision> {
        let gr = self
            .group_rules
            .iter()
            .find(|gr| gr.rule.matches_with_via(process, via, dest))?;
        let tier = MatchTier::RuleGroup {
            group_name: gr.group_name.clone(),
        };
        Some(build_decision(&gr.rule, &tier, process, via, dest))
    }

    /// Tier 3: check tracker rules.
    ///
    /// Critical breakage risk domains are skipped (auto-allowed).
    fn check_tracker_rules(&self, dest: &Destination) -> Option<NetworkDecision> {
        let host = dest.host.as_deref()?;
        let tracker = self
            .tracker_rules
            .iter()
            .find(|t| t.pattern.matches(host))?;
        // Critical breakage: skip this tracker rule (don't deny).
        if tracker.breakage_risk == BreakageRisk::Critical {
            return None;
        }
        Some(NetworkDecision {
            action: NetworkAction::Deny,
            matched_rule: Some(MatchedRule {
                rule_id: RuleId(0),
                rule_name: tracker.description.clone(),
                tier: MatchTier::Tracker {
                    category: tracker.category.clone(),
                },
            }),
            explanation: format!(
                "DENIED by tracker-shield/{} -- destination {host} matches pattern {} -- {}",
                tracker.category, tracker.pattern, tracker.description,
            ),
        })
    }

    /// Tier 4: check blocklist domains via reverse-label trie (O(k) lookup).
    ///
    /// Falls back to linear scan if the trie is empty but the vec is not,
    /// which can happen if `rebuild_blocklist_trie()` was not called.
    fn check_blocklist(&self, dest: &Destination) -> Option<NetworkDecision> {
        let host = dest.host.as_deref()?;
        let lower = host.to_ascii_lowercase();

        let entry = if self.blocklist_trie.is_empty() {
            // Fallback: linear scan for backwards compatibility.
            self.blocklist_domains
                .iter()
                .find(|e| blocklist_matches(&e.domain, &lower))?
        } else {
            self.blocklist_trie.lookup(&lower)?
        };

        Some(NetworkDecision {
            action: NetworkAction::Deny,
            matched_rule: Some(MatchedRule {
                rule_id: RuleId(0),
                rule_name: entry.domain.clone(),
                tier: MatchTier::Blocklist {
                    list_name: entry.list_name.clone(),
                },
            }),
            explanation: format!(
                "DENIED by blocklist/{} -- domain {} matches blocklist entry {}",
                entry.list_name, lower, entry.domain,
            ),
        })
    }

    /// Tier 5: return the profile default action.
    fn default_decision(&self, process: &ProcessIdentity, dest: &Destination) -> NetworkDecision {
        NetworkDecision {
            action: self.default_action,
            matched_rule: None,
            explanation: format!(
                "{} by profile-default -- no rule matched for {} -> {}",
                action_verb(self.default_action),
                process,
                dest,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `NetworkDecision` from rule match details.
///
/// When the rule matched on the via process (not the direct process),
/// the explanation notes this: "Matched via responsible process ...".
fn build_decision(
    rule: &NetworkRule,
    tier: &MatchTier,
    process: &ProcessIdentity,
    via: Option<&ProcessIdentity>,
    dest: &Destination,
) -> NetworkDecision {
    let via_note = via_match_note(&rule.process, process, via);
    NetworkDecision {
        action: rule.action,
        matched_rule: Some(MatchedRule {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            tier: tier.clone(),
        }),
        explanation: format!(
            "{} by {} rule `{}` -- process {} -> {}{via_note}",
            action_verb(rule.action),
            tier,
            rule.name,
            process,
            dest,
        ),
    }
}

/// Produce the via-process annotation for an explanation string.
///
/// Returns an empty string when the direct process matched, or a note
/// like " -- Matched via responsible process Safari (direct: WebKit.Networking)".
fn via_match_note(
    matcher: &ProcessMatcher,
    process: &ProcessIdentity,
    via: Option<&ProcessIdentity>,
) -> String {
    match via {
        Some(via_proc) if !matcher.matches(process) => {
            format!(" -- Matched via responsible process {via_proc} (direct: {process})")
        }
        _ => String::new(),
    }
}

/// Human-readable past-tense verb for an action.
fn action_verb(action: NetworkAction) -> &'static str {
    match action {
        NetworkAction::Allow => "ALLOWED",
        NetworkAction::Deny => "DENIED",
        NetworkAction::Log => "LOGGED",
    }
}

/// Check if a blocklist domain matches via exact match or subdomain walking.
///
/// `"tracker.com"` matches `"tracker.com"` and `"x.tracker.com"` but NOT
/// `"eviltracker.com"`.
fn blocklist_matches(blocklist_domain: &str, host: &str) -> bool {
    if host == blocklist_domain {
        return true;
    }
    // Subdomain walking: check if host ends with ".{domain}".
    host.strip_suffix(blocklist_domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
#[path = "matcher_test.rs"]
mod matcher_test;
