//! Request handlers: pure functions over the injected [`ServerState`].
//!
//! [`handle_request`] maps a data/mutation [`Request`] to its [`Response`]
//! without touching the socket — so snapshot fusion (R4), history (R5), detail
//! (R6), and mutation (R7) are all unit-testable against a hand-built state with
//! a stub scanner, no root and no `lsof`. The connection layer ([`super::conn`])
//! owns the handshake, version gate, and subscription frames; everything else
//! routes here.

use ipc::protocol::{Capability, ErrorKind, Request, Response};

use super::error::ServerError;
use super::state::ServerState;
use super::{detail, history, mutation, profile, snapshot};

/// Sample age past which `GetSnapshot` warns the live view is stale. The sampler
/// self-paces near the 500 ms sample floor, so several seconds without a fresh
/// sample means it is genuinely wedged, not merely between scans.
const WARN_STALE_MS: u64 = 10_000;

/// Handle a data or mutation request, producing its response (R4–R7).
///
/// Handshake and subscribe frames are intercepted by the connection layer and
/// never reach here; if one does, it is a protocol error.
#[must_use]
pub fn handle_request(state: &ServerState, request: &Request) -> Response {
    match request {
        Request::GetSnapshot => handle_snapshot(state),
        Request::GetHistory { scope, app_id } => handle_history(state, *scope, app_id.as_deref()),
        Request::GetAppDetail { id } => handle_detail(detail::app_detail(state, id)),
        Request::GetProcDetail { id } => handle_detail(detail::proc_detail(state, id)),
        Request::GetDomainDetail { host } => handle_detail(detail::domain_detail(state, host)),
        Request::SetRule {
            target,
            allow,
            duration,
        } => handle_set_rule(state, target, *allow, *duration),
        Request::SetRules { rules } => handle_set_rules(state, rules),
        Request::SetExecPolicy { .. } => unsupported("exec policy is not active on this daemon"),
        Request::GetProfile => handle_policy(state, profile::get_profile(state)),
        Request::SetMode { mode } => handle_policy_mut(state, |s| profile::set_mode(s, *mode)),
        Request::SetAppleAllow { allow } => {
            handle_policy_mut(state, |s| profile::set_apple_allow(s, *allow))
        }
        Request::SetDnsAllow { allow } => {
            handle_policy_mut(state, |s| profile::set_dns_allow(s, *allow))
        }
        Request::SetGroupEnabled { group, enabled } => {
            handle_policy_mut(state, |s| profile::set_group_enabled(s, group, *enabled))
        }
        Request::AddAllowListEntry { entry } => {
            handle_policy_mut(state, |s| profile::add_allow_entry(s, entry))
        }
        Request::RemoveAllowListEntry { entry } => {
            handle_policy_mut(state, |s| profile::remove_allow_entry(s, entry))
        }
        // Server-push (R10) is deferred: no live event source exists yet, so
        // `PushEvents` is not advertised and subscriptions are refused.
        Request::Subscribe { .. } | Request::Unsubscribe => {
            unsupported("server-push events are not supported")
        }
        // Packet trace (R8/R9): a live trace runs in the connection layer's
        // trace mode ([`super::conn::serve_trace`]), which owns the per-connection
        // [`super::trace_session::TraceSession`] and its server-push writer.
        // `StartTrace` is intercepted there and never reaches here; a
        // `StopTrace`/`GetPacketBytes` that reaches this pre-trace path has no
        // active session, so it is answered gracefully rather than as an error.
        Request::StartTrace { .. } => {
            refused("internal: StartTrace must be handled by the connection layer")
        }
        Request::StopTrace => Response::TraceStarted {
            session_ok: false,
            source: ipc::protocol::WireTraceSource::Unknown,
        },
        Request::GetPacketBytes { seq } => {
            Response::PacketBytes(super::trace_map::unavailable_bytes(*seq))
        }
        Request::GetBans => handle_get_bans(state),
        Request::SetBan {
            ip,
            ban,
            ban_secs,
            detector,
        } => handle_set_ban(state, ip, *ban, *ban_secs, detector.as_deref()),
        // The handshake is owned by the connection layer; a `Hello` never
        // reaches here.
        Request::Hello { .. } => Response::Error {
            kind: ErrorKind::BadRequest,
            message: "unexpected handshake frame".to_owned(),
        },
    }
}

/// R4: fuse a live snapshot with per-destination verdicts.
///
/// Reads the latest connection sample cached by the background sampler — never
/// scans inline — and fuses it against the *current* ruleset, so the answer is
/// milliseconds-fast yet reflects verdict changes from a just-applied mutation.
/// Before the first sample lands the cache is empty, so this returns an empty
/// (correctly-shaped) snapshot; the panel fills in on a later poll.
///
/// The generation is read **before** the ruleset (matching [`mutation`]'s
/// write order: swap ruleset, then bump generation). Reading generation first
/// guarantees the stamped value is `<=` the generation of the ruleset actually
/// fused here — a reload landing mid-build can only make the ruleset newer than
/// the stamp, never the reverse. The opposite order could stamp `N+1` onto an
/// `N` ruleset, advertising a mutation the snapshot does not yet reflect.
///
/// The sample age from [`ServerState::sample_age_ms`] is stamped into the
/// `Snapshot` (and logged past [`WARN_STALE_MS`]) so a wedged sampler — socket
/// alive but the scan loop frozen — is observable to the panel rather than
/// rendered as fresh.
fn handle_snapshot(state: &ServerState) -> Response {
    let generation = state.generation();
    let sample_age_ms = state.sample_age_ms();
    // A large/growing sample age means the background sampler is wedged and the
    // live view is stale; surface it in the daemon log too. `WARN_STALE_MS`
    // keeps steady-state noise out of the log.
    if let Some(age) = sample_age_ms
        && age > WARN_STALE_MS
    {
        tracing::warn!(
            sample_age_ms = age,
            "connection sample is stale (sampler wedged?)"
        );
    }
    let conns = state.latest_conns();
    let ruleset = state.ruleset();
    let apple_allow = crate::commands::net::policy_apple_allow();
    let data = snapshot::build_snapshot(&conns, &ruleset, apple_allow);
    Response::Snapshot {
        apps: data.apps,
        net_rows: data.net_rows,
        procs: data.procs,
        proc_groups: data.proc_groups,
        totals: data.totals,
        generation,
        sample_age_ms,
    }
}

/// R5: answer history from the metrics store, gated on the capability.
fn handle_history(
    state: &ServerState,
    scope: ipc::protocol::HistoryScope,
    app_id: Option<&str>,
) -> Response {
    if !has(state, Capability::History) {
        return unsupported("history is not available on this daemon");
    }
    let Some(store) = state.metrics() else {
        return unsupported("history is not available on this daemon");
    };
    let Ok(guard) = store.lock() else {
        return refused("metrics store unavailable");
    };
    match history::build_history(&guard, scope, app_id, state.session_start_ms) {
        Ok(buckets) => Response::History { buckets },
        Err(e) => error_response(&e),
    }
}

/// R6: return a detail, or `None` for an unknown target. The detail path reads
/// the cached sample and cannot fail, so this is infallible.
fn handle_detail(detail: Option<ipc::protocol::WireDetail>) -> Response {
    Response::Detail { detail }
}

/// R7: apply a mutation, gated on the capability.
fn handle_set_rule(
    state: &ServerState,
    target: &ipc::protocol::RuleTarget,
    allow: bool,
    duration: ipc::protocol::WireDuration,
) -> Response {
    if !has(state, Capability::Mutations) {
        return unsupported("mutations are not available on this daemon");
    }
    match mutation::apply_set_rule(state, target, allow, duration) {
        Ok(response) => response,
        Err(e) => error_response(&e),
    }
}

/// R7: apply a **batch** of mutations as one reload, gated on the capability.
fn handle_set_rules(state: &ServerState, rules: &[ipc::protocol::WireRuleChange]) -> Response {
    if !has(state, Capability::Mutations) {
        return unsupported("mutations are not available on this daemon");
    }
    match mutation::apply_set_rules(state, rules) {
        Ok(response) => response,
        Err(e) => error_response(&e),
    }
}

/// R7: answer a policy **read**, gated on [`Capability::Policy`].
fn handle_policy(state: &ServerState, result: super::error::Result<Response>) -> Response {
    if !has(state, Capability::Policy) {
        return unsupported("policy is not available on this daemon");
    }
    result.unwrap_or_else(|e| error_response(&e))
}

/// R7: apply a policy **mutation**, gated on [`Capability::Policy`]. The
/// mutation loads the profile, applies the change, saves atomically, and
/// hot-reloads the live rule set.
fn handle_policy_mut(
    state: &ServerState,
    apply: impl FnOnce(&ServerState) -> super::error::Result<Response>,
) -> Response {
    if !has(state, Capability::Policy) {
        return unsupported("policy is not available on this daemon");
    }
    apply(state).unwrap_or_else(|e| error_response(&e))
}

/// Spec 010 R8: list the active banwatch bans, gated on [`Capability::BanWatch`].
///
/// The listed bans are those created by manual operator action ([`handle_set_ban`])
/// and not yet expired by the sweeper. Automatic detection is not wired in this
/// build (see [`super::banwatch_svc`]), so this reflects manual bans + sweeper
/// state only.
fn handle_get_bans(state: &ServerState) -> Response {
    if !has(state, Capability::BanWatch) {
        return unsupported("banwatch is not available on this daemon");
    }
    let Some(service) = state.banwatch() else {
        return unsupported("banwatch is not available on this daemon");
    };
    Response::Bans {
        bans: service.list_bans(),
    }
}

/// Spec 010 R8: manually ban/unban an IP, then hot-reload the live rule set so
/// the change enforces (and the sysext's `RuleWatcher` reloads on the file
/// change). Gated on [`Capability::BanWatch`].
fn handle_set_ban(
    state: &ServerState,
    ip: &str,
    ban: bool,
    ban_secs: Option<u64>,
    detector: Option<&str>,
) -> Response {
    if !has(state, Capability::BanWatch) {
        return unsupported("banwatch is not available on this daemon");
    }
    let Some(service) = state.banwatch() else {
        return unsupported("banwatch is not available on this daemon");
    };
    let secs = ban_secs.map(|s| s.min(i64::MAX as u64) as i64);
    match service.set_ban(ip, ban, secs, detector) {
        Ok(applied) => match state.reload() {
            Ok(generation) => Response::BanAck {
                applied,
                generation,
            },
            Err(e) => error_response(&e),
        },
        Err(e) => error_response(&e),
    }
}

/// Whether the daemon advertises `capability`.
fn has(state: &ServerState, capability: Capability) -> bool {
    state.capabilities.contains(&capability)
}

/// Map a server error to a typed error response.
fn error_response(err: &ServerError) -> Response {
    let kind = match err {
        ServerError::Validation(_) => ErrorKind::BadRequest,
        _ => ErrorKind::Refused,
    };
    Response::Error {
        kind,
        message: err.to_string(),
    }
}

/// An `Unsupported` error response.
fn unsupported(message: &str) -> Response {
    Response::Error {
        kind: ErrorKind::Unsupported,
        message: message.to_owned(),
    }
}

/// A `Refused` error response.
fn refused(message: &str) -> Response {
    Response::Error {
        kind: ErrorKind::Refused,
        message: message.to_owned(),
    }
}

#[cfg(test)]
#[path = "handlers_test.rs"]
mod handlers_test;
