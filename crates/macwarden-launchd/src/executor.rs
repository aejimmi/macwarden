//! Action execution against the platform layer.
//!
//! Translates [`Action`] values from the policy engine into concrete
//! platform calls (disable, enable, kill), supporting dry-run mode.

use macwarden_core::Action;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::platform::Platform;

/// The outcome of executing a single action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The service label the action targeted.
    pub label: String,
    /// Human-readable description of the action (e.g. "disable", "kill").
    pub action: String,
    /// Whether the action completed successfully.
    pub success: bool,
    /// Error message if the action failed.
    pub error: Option<String>,
}

/// Executes a list of enforcement actions against the platform.
///
/// When `dry_run` is `true`, actions are logged but not performed, and all
/// results are returned as successful.
///
/// The `domain` parameter specifies the launchd domain target (e.g.
/// `"system"`, `"gui/501"`).
pub fn execute_actions(
    platform: &dyn Platform,
    actions: &[Action],
    domain: &str,
    dry_run: bool,
) -> Vec<ActionResult> {
    let mut results = Vec::with_capacity(actions.len());

    for action in actions {
        let result = if dry_run {
            info!(action = %action, "dry-run: would execute");
            ActionResult {
                label: action.label().to_owned(),
                action: action.to_string(),
                success: true,
                error: None,
            }
        } else {
            execute_single(platform, action, domain)
        };
        results.push(result);
    }

    results
}

/// Executes a single action and captures the result.
fn execute_single(platform: &dyn Platform, action: &Action, domain: &str) -> ActionResult {
    let label = action.label().to_owned();
    let action_desc = action.to_string();

    let result = match action {
        Action::Disable { label } => platform.disable(domain, label),
        Action::Enable { label } => platform.enable(domain, label),
        Action::Kill { pid, .. } => platform.kill_process(*pid),
    };

    match result {
        Ok(()) => {
            info!(action = %action_desc, "executed");
            ActionResult {
                label,
                action: action_desc,
                success: true,
                error: None,
            }
        }
        Err(e) => ActionResult {
            label,
            action: action_desc,
            success: false,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
