//! Rule mutations (R7): the panel's block/unblock toggles.
//!
//! A `SetRule` (a) validates its inputs at the boundary (R9), (b) writes or
//! removes a rule using the exact same file convention as `net block`/`net
//! unblock` (or the in-memory session set for `Session`), and critically (c)
//! hot-reloads the daemon's live rule set via [`super::state::ServerState::reload`]
//! so the next `GetSnapshot` and the next ES decision see the change with a
//! bumped `generation`. This closes the real gap where `net block` writes a file
//! that nothing running reloads.
//!
//! The pure pieces — slug derivation, TOML generation, rule construction, and
//! target-verdict evaluation — are unit-tested without touching the filesystem
//! or a live server.

use std::path::PathBuf;

use ipc::protocol::{Response, RuleTarget, WireDuration, WireRuleChange, WireVerdict};
use ipc::validate::{
    rules_path_within, validate_code_id, validate_expiry, validate_hostname,
    validate_rule_batch_len,
};
use net::{
    AddressFamily, DestMatcher, Destination, HostPattern, NetworkAction, NetworkRule,
    ProcessIdentity, ProcessMatcher, RuleDuration, RuleId, RuleSet,
};

use super::error::{Result, ServerError};
use super::snapshot::verdict_of;
use super::state::{ServerState, now_ms};

/// Bounded horizon for an `Until` expiry: one year (R9).
const EXPIRY_HORIZON_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// Apply a `SetRule` mutation end to end and return the `RuleAck` (R7).
pub fn apply_set_rule(
    state: &ServerState,
    target: &RuleTarget,
    allow: bool,
    duration: WireDuration,
) -> Result<Response> {
    let applied = apply_one(state, target, allow, duration)?;
    let generation = state.reload()?;
    let (app, host) = target_parts(target);
    let ruleset = state.ruleset();
    let verdict = verdict_for_target(&ruleset, app, host);
    Ok(Response::RuleAck {
        applied,
        generation,
        verdict,
    })
}

/// Apply a **batch** of block/unblock changes as one reload and return the
/// `RulesAck` (R7). Every entry is validated and applied (no reload between
/// entries), then a single [`ServerState::reload`] hot-swaps the live rule set —
/// so a whole-group toggle is one mutation, not N. `applied` is `true` when at
/// least one change took effect.
pub fn apply_set_rules(state: &ServerState, rules: &[WireRuleChange]) -> Result<Response> {
    validate_rule_batch_len(rules.len())?;
    let mut applied = false;
    for change in rules {
        applied |= apply_one(state, &change.target, change.allow, change.duration)?;
    }
    let generation = state.reload()?;
    Ok(Response::RulesAck {
        applied,
        generation,
    })
}

/// Validate one change and add/remove its rule **without** reloading — the shared
/// core of [`apply_set_rule`] and [`apply_set_rules`]. Returns whether it took
/// effect. The caller reloads once (per single mutation, or once per batch).
fn apply_one(
    state: &ServerState,
    target: &RuleTarget,
    allow: bool,
    duration: WireDuration,
) -> Result<bool> {
    let (app, host) = target_parts(target);
    if let Some(app) = app {
        validate_code_id(app)?;
    }
    if let Some(host) = host {
        validate_hostname(host)?;
    }
    if let WireDuration::Until { expiry_ms } = duration {
        validate_expiry(expiry_ms, now_ms().max(0) as u64, EXPIRY_HORIZON_MS)?;
    }
    if allow {
        remove_rule(state, app, host, duration)
    } else {
        add_rule(state, app, host, duration)
    }
}

/// Decompose a [`RuleTarget`] into optional app code id + host.
fn target_parts(target: &RuleTarget) -> (Option<&str>, Option<&str>) {
    match target {
        RuleTarget::App { code_id } => (Some(code_id), None),
        RuleTarget::Domain { host } => (None, Some(host)),
        RuleTarget::AppDomain { code_id, host } => (Some(code_id), Some(host)),
    }
}

/// Add a deny rule (block). Returns whether it was applied.
fn add_rule(
    state: &ServerState,
    app: Option<&str>,
    host: Option<&str>,
    duration: WireDuration,
) -> Result<bool> {
    match duration {
        WireDuration::Session => {
            let rule = build_rule(app, host, RuleDuration::Session, state.next_rule_id())?;
            state.add_session_rule(rule);
            Ok(true)
        }
        WireDuration::Permanent => {
            write_rule_file(state, app, host)?;
            Ok(true)
        }
        WireDuration::Until { expiry_ms } => {
            let path = write_rule_file(state, app, host)?;
            state.track_expiring(path, expiry_ms);
            Ok(true)
        }
    }
}

/// Remove a deny rule (unblock). Returns whether anything was removed.
fn remove_rule(
    state: &ServerState,
    app: Option<&str>,
    host: Option<&str>,
    duration: WireDuration,
) -> Result<bool> {
    if matches!(duration, WireDuration::Session) {
        let name = rule_name(app, host);
        let removed = state.remove_session_rules(|r| r.name == name);
        return Ok(removed > 0);
    }
    let path = rule_file_path(state, app, host)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ServerError::RuleFileIo(e.to_string())),
    }
}

/// Write a `block-{slug}.toml` file matching the `net block` format (R7).
/// Returns the written path.
fn write_rule_file(state: &ServerState, app: Option<&str>, host: Option<&str>) -> Result<PathBuf> {
    let path = rule_file_path(state, app, host)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ServerError::RuleFileIo(e.to_string()))?;
        net::secure_dir(parent);
    }
    let content = generate_rule_toml(app, host);
    std::fs::write(&path, content).map_err(|e| ServerError::RuleFileIo(e.to_string()))?;
    net::secure_file(&path);
    Ok(path)
}

/// The validated rule-file path for a target, guarded against escaping the
/// rules directory (R9).
fn rule_file_path(state: &ServerState, app: Option<&str>, host: Option<&str>) -> Result<PathBuf> {
    let file_name = format!("block-{}.toml", make_slug(app, host));
    let path = rules_path_within(state.rules_dir(), &file_name)?;
    Ok(path)
}

/// Derive the filesystem slug for a target, matching `net block`'s `make_slug`.
#[must_use]
pub fn make_slug(app: Option<&str>, host: Option<&str>) -> String {
    let raw = match (app, host) {
        (Some(a), Some(h)) => format!("{a}-{h}"),
        (Some(a), None) => a.to_owned(),
        (None, Some(h)) => h.to_owned(),
        (None, None) => "unknown".to_owned(),
    };
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// The human-readable rule name for a target (matches `net block`).
fn rule_name(app: Option<&str>, host: Option<&str>) -> String {
    match (app, host) {
        (Some(a), Some(h)) => format!("Block {a} -> {h}"),
        (Some(a), None) => format!("Block {a} (all traffic)"),
        (None, Some(h)) => format!("Block {h} (all apps)"),
        (None, None) => "Block rule".to_owned(),
    }
}

/// Generate the deny-rule TOML with the exact key spacing `net unblock`'s
/// content-scan fallback matches on (`process = "..."`, `dest = "..."`,
/// `action = "deny"`).
#[must_use]
pub fn generate_rule_toml(app: Option<&str>, host: Option<&str>) -> String {
    let name = rule_name(app, host);
    let process = app.unwrap_or("*");
    let dest = host.unwrap_or("*");
    format!(
        "# Auto-generated by macwarden panel\n\
         name = \"{name}\"\n\
         process = \"{process}\"\n\
         dest = \"{dest}\"\n\
         action = \"deny\"\n\
         enabled = true\n"
    )
}

/// Build an in-memory deny [`NetworkRule`] for a target (Session/Until).
fn build_rule(
    app: Option<&str>,
    host: Option<&str>,
    duration: RuleDuration,
    id: u64,
) -> Result<NetworkRule> {
    let process = match app {
        Some(a) => ProcessMatcher::code_id(a).map_err(|e| ServerError::Reload(e.to_string()))?,
        None => ProcessMatcher::Any,
    };
    let destination = match host {
        Some(h) => DestMatcher {
            host: Some(HostPattern::new(h).map_err(|e| ServerError::Reload(e.to_string()))?),
            ..Default::default()
        },
        None => DestMatcher::default(),
    };
    Ok(NetworkRule {
        id: RuleId(id),
        name: rule_name(app, host),
        process,
        destination,
        action: NetworkAction::Deny,
        duration,
        enabled: true,
        note: None,
    })
}

/// Evaluate the resulting verdict for a target against the live rule set (R7).
#[must_use]
pub fn verdict_for_target(ruleset: &RuleSet, app: Option<&str>, host: Option<&str>) -> WireVerdict {
    use std::net::{IpAddr, Ipv4Addr};
    let process = ProcessIdentity {
        pid: 0,
        uid: 0,
        path: PathBuf::from(app.unwrap_or("/")),
        code_id: app.map(ToOwned::to_owned),
        team_id: None,
        is_valid_signature: None,
        is_apple_signed: None,
    };
    let destination = Destination {
        host: host.map(ToOwned::to_owned),
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    let decision = ruleset.decide_for(&process, &destination);
    verdict_of(&decision).0
}

#[cfg(test)]
#[path = "mutation_test.rs"]
mod mutation_test;
