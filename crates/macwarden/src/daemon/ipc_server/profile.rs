//! Policy profile read + mutations (R7): the panel's mode / flags / groups /
//! allow-list controls.
//!
//! Each mutation (a) validates its inputs at the boundary (R9) reusing the
//! `ipc` validators plus a CIDR parse and an all-`None`-entry rejection,
//! (b) loads the persisted [`net::PolicyConfig`] from
//! `~/.macwarden/net-profile.toml`, applies the change, writes it back
//! **atomically** (temp file + rename, in [`net::PolicyConfig::save`]), and
//! critically (c) hot-reloads the daemon's live rule set via
//! [`ServerState::reload`], bumping `generation` — the same machinery
//! [`super::mutation::apply_set_rule`] uses. The echoed [`WireProfile`] lets the
//! panel re-render from truth.
//!
//! The pure pieces — wire<->config conversion, group-state derivation, entry
//! normalization — are unit-tested without touching the filesystem.

use std::path::PathBuf;

use ipc::protocol::{Response, WireAllowEntry, WireGroupState, WireMode, WireProfile};
use ipc::validate::{ValidationError, validate_app, validate_hostname, validate_team_id};
use net::{
    AllowListEntry, GroupSettings, NetworkGroup, NetworkGroups, PolicyConfig, PolicyMode,
    parse_ip_or_cidr,
};

use super::error::{Result, ServerError};
use super::state::ServerState;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// R7: answer [`ipc::protocol::Request::GetProfile`].
pub fn get_profile(state: &ServerState) -> Result<Response> {
    let config = load_config(state)?;
    Ok(Response::Profile {
        profile: wire_profile(&config)?,
    })
}

/// R7: set the global mode.
pub fn set_mode(state: &ServerState, mode: WireMode) -> Result<Response> {
    let mut config = load_config(state)?;
    config.mode = from_wire_mode(mode);
    finish(state, &config)
}

/// R7: toggle "Allow Apple programs".
pub fn set_apple_allow(state: &ServerState, allow: bool) -> Result<Response> {
    let mut config = load_config(state)?;
    config.allow_apple_programs = allow;
    finish(state, &config)
}

/// R7: toggle "Allow DNS traffic".
pub fn set_dns_allow(state: &ServerState, allow: bool) -> Result<Response> {
    let mut config = load_config(state)?;
    config.allow_dns_traffic = allow;
    finish(state, &config)
}

/// R7: enable/disable a built-in group durably.
pub fn set_group_enabled(state: &ServerState, group: &str, enabled: bool) -> Result<Response> {
    let groups = builtin_groups()?;
    if groups.get(group).is_none() {
        return Err(ServerError::Validation(ValidationError::UnknownGroup));
    }
    let mut config = load_config(state)?;
    crate::commands::net::set_group_override(&mut config.groups, group, enabled);
    finish(state, &config)
}

/// R7: add an allow-list exception.
pub fn add_allow_entry(state: &ServerState, entry: &WireAllowEntry) -> Result<Response> {
    let parsed = entry_from_wire(entry)?;
    let mut config = load_config(state)?;
    let key = normalized_key(&parsed);
    if !config.allowlist.iter().any(|e| normalized_key(e) == key) {
        config.allowlist.push(parsed);
    }
    finish(state, &config)
}

/// R7: remove an allow-list exception, matched by normalized value.
pub fn remove_allow_entry(state: &ServerState, entry: &WireAllowEntry) -> Result<Response> {
    let parsed = entry_from_wire(entry)?;
    let key = normalized_key(&parsed);
    let mut config = load_config(state)?;
    config.allowlist.retain(|e| normalized_key(e) != key);
    finish(state, &config)
}

// ---------------------------------------------------------------------------
// I/O edge
// ---------------------------------------------------------------------------

/// The persisted policy config path, shared with the ruleset builder so a
/// mutation writes exactly the file the next reload reads.
fn config_path() -> Result<PathBuf> {
    crate::commands::net::policy_config_path().map_err(|e| ServerError::RuleFileIo(e.to_string()))
}

/// Load the persisted config (fail-open default on a missing/malformed file).
fn load_config(_state: &ServerState) -> Result<PolicyConfig> {
    Ok(PolicyConfig::load(&config_path()?))
}

/// Persist the mutated config atomically, hot-reload the live rule set, and
/// return the `ProfileAck` echoing the new state.
fn finish(state: &ServerState, config: &PolicyConfig) -> Result<Response> {
    let path = config_path()?;
    config
        .save(&path)
        .map_err(|e| ServerError::RuleFileIo(e.to_string()))?;
    let generation = state.reload()?;
    Ok(Response::ProfileAck {
        generation,
        profile: wire_profile(config)?,
    })
}

/// Load the built-in group set for names + domain counts.
fn builtin_groups() -> Result<NetworkGroups> {
    NetworkGroups::load_builtin().map_err(|e| ServerError::Reload(e.to_string()))
}

// ---------------------------------------------------------------------------
// Pure conversions
// ---------------------------------------------------------------------------

/// Build the wire profile from a config (pure over the built-in group set).
pub fn wire_profile(config: &PolicyConfig) -> Result<WireProfile> {
    let groups = builtin_groups()?;
    let group_states = groups
        .all()
        .iter()
        .map(|g| WireGroupState {
            name: g.name.clone(),
            description: g.description.clone(),
            enabled: group_enabled(g, &config.groups),
            default_enabled: g.default_enabled,
            domain_count: domain_count(g),
        })
        .collect();
    Ok(WireProfile {
        mode: to_wire_mode(config.mode),
        allow_apple_programs: config.allow_apple_programs,
        allow_dns_traffic: config.allow_dns_traffic,
        groups: group_states,
        allowlist: config.allowlist.iter().map(entry_to_wire).collect(),
    })
}

/// Whether a group is currently enabled given the config overrides. Mirrors
/// `net::group`'s internal resolution: explicit disable wins, then explicit
/// enable, then the group's default.
#[must_use]
pub fn group_enabled(group: &NetworkGroup, settings: &GroupSettings) -> bool {
    if settings.disable.iter().any(|n| n == &group.name) {
        return false;
    }
    if settings.enable.iter().any(|n| n == &group.name) {
        return true;
    }
    group.default_enabled
}

/// Total domain patterns in a group.
fn domain_count(group: &NetworkGroup) -> usize {
    group.rules.iter().map(|r| r.dest_hosts.len()).sum()
}

/// Convert a policy mode to the wire mode.
#[must_use]
pub fn to_wire_mode(mode: PolicyMode) -> WireMode {
    match mode {
        PolicyMode::AllowAll => WireMode::AllowAll,
        PolicyMode::BlockAll => WireMode::BlockAll,
    }
}

/// Convert a wire mode to the policy mode.
#[must_use]
pub fn from_wire_mode(mode: WireMode) -> PolicyMode {
    match mode {
        WireMode::AllowAll => PolicyMode::AllowAll,
        WireMode::BlockAll => PolicyMode::BlockAll,
    }
}

/// Convert a typed allow-list entry to the wire form.
pub fn entry_to_wire(entry: &AllowListEntry) -> WireAllowEntry {
    WireAllowEntry {
        app: entry.app.clone(),
        team_id: entry.team_id.clone(),
        host: entry.host.clone(),
        ip: entry.ip.map(|n| n.to_string()),
        note: entry.note.clone(),
    }
}

/// Validate and convert a wire allow entry to the typed form (R9 boundary).
///
/// # Errors
///
/// Returns a [`ServerError::Validation`] for an all-`None` entry, an
/// `app`+`team_id` conflict, or an invalid app/team/host/ip field.
pub fn entry_from_wire(entry: &WireAllowEntry) -> Result<AllowListEntry> {
    if entry.app.is_none() && entry.team_id.is_none() && entry.host.is_none() && entry.ip.is_none()
    {
        return Err(ServerError::Validation(ValidationError::AllowEntryEmpty));
    }
    if entry.app.is_some() && entry.team_id.is_some() {
        return Err(ServerError::Validation(ValidationError::AllowEntryConflict));
    }
    if let Some(app) = &entry.app {
        validate_app(app)?;
    }
    if let Some(team) = &entry.team_id {
        validate_team_id(team)?;
    }
    if let Some(host) = &entry.host {
        validate_hostname(host)?;
    }
    let ip = match &entry.ip {
        Some(s) => Some(parse_ip_or_cidr(s).map_err(|_| ValidationError::InvalidIp)?),
        None => None,
    };
    Ok(AllowListEntry {
        app: entry.app.clone(),
        team_id: entry.team_id.clone(),
        host: entry.host.clone(),
        ip,
        note: entry.note.clone(),
    })
}

/// A stable key for allow-list dedup / removal, ignoring the free-form note.
#[must_use]
pub fn normalized_key(entry: &AllowListEntry) -> String {
    format!(
        "app={}|team={}|host={}|ip={}",
        entry.app.as_deref().unwrap_or(""),
        entry.team_id.as_deref().unwrap_or(""),
        entry.host.as_deref().unwrap_or(""),
        entry.ip.map(|n| n.to_string()).unwrap_or_default(),
    )
}

#[cfg(test)]
#[path = "profile_test.rs"]
mod profile_test;
