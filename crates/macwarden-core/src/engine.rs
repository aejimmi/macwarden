//! Policy decision engine.
//!
//! Evaluates services against a profile to produce allow/deny decisions,
//! compute diffs (actions needed to reach desired state), and generate
//! human-readable explanations.

use globset::Glob;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::profile::{CategoryAction, Profile};
use crate::types::{Action, ServiceInfo, ServiceState};

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The result of evaluating a service against a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    /// The service is allowed to run.
    Allow {
        /// Why the service is allowed.
        reason: String,
    },
    /// The service should be disabled/killed.
    Deny {
        /// Why the service is denied.
        reason: String,
    },
    /// The service is logged but no action is taken.
    LogOnly {
        /// Why the service is in log-only mode.
        reason: String,
    },
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow { reason } => write!(f, "ALLOWED: {reason}"),
            Self::Deny { reason } => write!(f, "DENIED: {reason}"),
            Self::LogOnly { reason } => write!(f, "LOG-ONLY: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal decision detail (carries provenance for explain)
// ---------------------------------------------------------------------------

/// Internal struct carrying the full context of a decision for explain output.
struct DecisionDetail {
    decision: Decision,
    matched_rule: Option<String>,
    source: RuleSource,
}

/// Where the matching rule came from.
enum RuleSource {
    ExplicitLabel,
    GlobPattern,
    CategoryRule { category: String },
    DefaultAllow,
}

// ---------------------------------------------------------------------------
// decide
// ---------------------------------------------------------------------------

/// Evaluate a service against a profile and return a decision.
///
/// Precedence (first match wins):
/// 1. Explicit label match in deny list
/// 2. Explicit label match in allow list
/// 3. Glob pattern match in deny list
/// 4. Glob pattern match in allow list
/// 5. Category-level rules
/// 6. Default: allow
pub fn decide(service: &ServiceInfo, profile: &Profile) -> Decision {
    decide_detailed(service, profile).decision
}

/// Internal detailed decision that carries rule provenance.
fn decide_detailed(service: &ServiceInfo, profile: &Profile) -> DecisionDetail {
    let label = &service.label;
    let category_str = service.category.to_string();

    // 1. Explicit label in deny list.
    if profile.rules.deny.iter().any(|r| r == label) {
        return DecisionDetail {
            decision: Decision::Deny {
                reason: format!("explicit deny rule: {label}"),
            },
            matched_rule: Some(label.clone()),
            source: RuleSource::ExplicitLabel,
        };
    }

    // 2. Explicit label in allow list.
    if profile.rules.allow.iter().any(|r| r == label) {
        return DecisionDetail {
            decision: Decision::Allow {
                reason: format!("explicit allow rule: {label}"),
            },
            matched_rule: Some(label.clone()),
            source: RuleSource::ExplicitLabel,
        };
    }

    // 3. Glob pattern in deny list.
    if let Some(pattern) = find_glob_match(&profile.rules.deny, label) {
        return DecisionDetail {
            decision: Decision::Deny {
                reason: format!("deny glob pattern: {pattern}"),
            },
            matched_rule: Some(pattern),
            source: RuleSource::GlobPattern,
        };
    }

    // 4. Glob pattern in allow list.
    if let Some(pattern) = find_glob_match(&profile.rules.allow, label) {
        return DecisionDetail {
            decision: Decision::Allow {
                reason: format!("allow glob pattern: {pattern}"),
            },
            matched_rule: Some(pattern),
            source: RuleSource::GlobPattern,
        };
    }

    // 5. Category-level rules.
    if let Some(action) = profile.rules.categories.get(&category_str) {
        let detail = match action {
            CategoryAction::Allow => DecisionDetail {
                decision: Decision::Allow {
                    reason: format!("category rule: {category_str} = allow"),
                },
                matched_rule: None,
                source: RuleSource::CategoryRule {
                    category: category_str,
                },
            },
            CategoryAction::Deny => DecisionDetail {
                decision: Decision::Deny {
                    reason: format!("category rule: {category_str} = deny"),
                },
                matched_rule: None,
                source: RuleSource::CategoryRule {
                    category: category_str,
                },
            },
            CategoryAction::LogOnly => DecisionDetail {
                decision: Decision::LogOnly {
                    reason: format!("category rule: {category_str} = log-only"),
                },
                matched_rule: None,
                source: RuleSource::CategoryRule {
                    category: category_str,
                },
            },
        };
        return detail;
    }

    // 6. Default: allow.
    DecisionDetail {
        decision: Decision::Allow {
            reason: "no matching rule, default allow".to_owned(),
        },
        matched_rule: None,
        source: RuleSource::DefaultAllow,
    }
}

/// Find the first glob pattern in `patterns` that matches `label`.
///
/// Only tests patterns that contain glob meta-characters (`*`, `?`, `[`).
fn find_glob_match(patterns: &[String], label: &str) -> Option<String> {
    for pattern in patterns {
        if !is_glob_pattern(pattern) {
            continue;
        }
        if let Ok(glob) = Glob::new(pattern)
            && glob.compile_matcher().is_match(label)
        {
            return Some(pattern.clone());
        }
    }
    None
}

/// Returns `true` if the string contains glob metacharacters.
fn is_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

/// Compute the set of actions needed to bring services into compliance with a profile.
///
/// - Running services that are denied: `Action::Disable` + `Action::Kill` (if pid known).
/// - Disabled services that are allowed: `Action::Enable`.
/// - Services already in desired state: no action.
pub fn diff(services: &[ServiceInfo], profile: &Profile) -> Vec<(ServiceInfo, Action)> {
    let mut actions = Vec::new();

    for service in services {
        let decision = decide(service, profile);

        match decision {
            Decision::Deny { .. } => {
                if service.state == ServiceState::Running || service.state == ServiceState::Stopped
                {
                    actions.push((
                        service.clone(),
                        Action::Disable {
                            label: service.label.clone(),
                        },
                    ));
                }
                if let Some(pid) = service.pid
                    && service.state == ServiceState::Running
                {
                    actions.push((
                        service.clone(),
                        Action::Kill {
                            label: service.label.clone(),
                            pid,
                        },
                    ));
                }
            }
            Decision::Allow { .. } => {
                // Don't auto-enable disabled services. A service may be
                // disabled by the user outside of macwarden — we should not
                // undo that. Enable actions should only come from explicit
                // `rollback` operations using a snapshot.
            }
            Decision::LogOnly { .. } => {
                // No action — log-only mode.
            }
        }
    }

    actions
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

/// Produce a human-readable explanation of why a service is allowed or denied.
///
/// Format example:
/// `"DENIED by rule com.apple.Siri.* in profile privacy, category: telemetry, safety: optional"`
pub fn explain(service_label: &str, profile: &Profile, services: &[ServiceInfo]) -> String {
    let service = services.iter().find(|s| s.label == service_label);

    let Some(svc) = service else {
        return format!("service {service_label} not found in service list");
    };

    let detail = decide_detailed(svc, profile);
    let profile_name = &profile.profile.name;
    let category = svc.category.to_string();
    let safety = svc.safety.to_string();

    let decision_word = match &detail.decision {
        Decision::Allow { .. } => "ALLOWED",
        Decision::Deny { .. } => "DENIED",
        Decision::LogOnly { .. } => "LOG-ONLY",
    };

    let rule_desc = match &detail.source {
        RuleSource::ExplicitLabel => {
            let rule = detail.matched_rule.as_deref().unwrap_or("unknown");
            format!("by rule {rule}")
        }
        RuleSource::GlobPattern => {
            let rule = detail.matched_rule.as_deref().unwrap_or("unknown");
            format!("by rule {rule}")
        }
        RuleSource::CategoryRule { category: cat } => {
            format!("by category rule {cat}")
        }
        RuleSource::DefaultAllow => "by default (no matching rule)".to_owned(),
    };

    let extends_note = if profile.profile.extends.is_empty() {
        String::new()
    } else {
        format!(" (inherited from {})", profile.profile.extends.join(", "))
    };

    format!(
        "{decision_word} {rule_desc} in profile {profile_name}{extends_note}, \
         category: {category}, safety: {safety}"
    )
}

#[cfg(test)]
#[path = "engine_test.rs"]
mod engine_test;
