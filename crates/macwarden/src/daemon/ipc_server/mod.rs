//! Daemon-side IPC server (Phase 10, R4–R11).
//!
//! Serves the frozen `ipc` wire protocol to the GPUI panel over a Unix socket:
//! live snapshots with real per-destination verdicts (R4), history from the
//! metrics store (R5), inspector detail with openbinary passthrough (R6), and
//! rule mutations that hot-reload the live [`net::RuleSet`] (R7). It owns the
//! `Arc`-swappable rule set, runs alongside the enforcement monitor, and is
//! started foreground by `macwarden serve`.
//!
//! # Design
//!
//! - The request handlers ([`handlers::handle_request`]) are **pure functions**
//!   over an injected [`state::ServerState`] — a stub [`snapshot::ConnectionScanner`],
//!   a real [`metrics::MetricsStore`], and an [`inventory::InventoryStore`] — so
//!   R4–R7 unit-test without a socket or root.
//! - The transport ([`accept`], [`conn`]) is a thin, synchronous shell around
//!   those handlers, matching the monitor's no-async design.
//! - Peer auth uses the `ipc` [`ipc::server::UidVerifier`] (R2 Layer 1); the
//!   macOS code-signature check (Layer 2) grafts into the same `PeerVerifier`
//!   trait when `ipc` exposes it — see the TODO below.

mod accept;
mod banwatch_svc;
mod bundle;
mod conn;
mod detail;
mod error;
mod handlers;
mod history;
mod mutation;
mod packet_source;
mod policy_shim;
mod proc_owner;
mod proc_sample;
mod profile;
mod push;
mod rate;
mod rdns_cache;
mod ruleset;
mod scan;
mod snapshot;
mod state;
mod trace_map;
mod trace_session;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use inventory::InventoryStore;
use ipc::protocol::Capability;
use ipc::server::UidVerifier;
use metrics::MetricsStore;
use tracing::{error, info, warn};

/// Where the server binds and which sources it wires in (R1/R11).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Unix socket path to bind.
    pub socket_path: PathBuf,
    /// Directory holding `Permanent`/`Until` rule files.
    pub rules_dir: PathBuf,
    /// Metrics DB path; `None` disables history.
    pub metrics_db: Option<PathBuf>,
    /// The served user's uid (R2 Layer 1).
    pub served_uid: u32,
}

impl ServerConfig {
    /// The default user-agent configuration under `~/.macwarden/` (R1).
    ///
    /// TODO(root-daemon): the root LaunchDaemon variant uses
    /// `/var/run/macwarden/macwarden.sock` and resolves the served console
    /// user's uid via `SCDynamicStoreCopyConsoleUser` (R2). We serve as the user
    /// for now, so the socket path and served uid are the daemon's own.
    pub fn user_agent() -> anyhow::Result<Self> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        let base = PathBuf::from(home).join(".macwarden");
        Ok(Self {
            socket_path: base.join("macwarden.sock"),
            rules_dir: base.join("net-rules"),
            metrics_db: Some(base.join("metrics.db")),
            served_uid: accept::current_euid(),
        })
    }
}

/// Build the shared server state from a config, wiring the real backends (R11).
///
/// The scanner is *not* run here: the background sampler ([`run_sampler`],
/// started by [`serve`]) owns all scanning and keeps the state's cached sample
/// fresh, so request handlers never scan inline.
fn build_state(config: &ServerConfig) -> anyhow::Result<Arc<state::ServerState>> {
    let scanner: Arc<dyn snapshot::ConnectionScanner> = Arc::new(scan::NettopScanner::new());

    let metrics = config
        .metrics_db
        .as_ref()
        .and_then(|path| match MetricsStore::open(path) {
            Ok(store) => Some(Arc::new(Mutex::new(store))),
            Err(e) => {
                warn!(error = %e, "metrics store unavailable; history disabled");
                None
            }
        });

    let inventory = match InventoryStore::open() {
        Ok(store) => Some(Arc::new(store)),
        Err(e) => {
            warn!(error = %e, "inventory store unavailable; openbinary passthrough disabled");
            None
        }
    };

    let enforcing = super::enforcement::network_enforcement_active();

    // Open the banwatch engine over the same `~/.macwarden/` base dir the loader
    // reads (the rules-dir parent), sharing the metrics store. A failure or a
    // config-disabled engine yields `None`, so the `BanWatch` capability is
    // withheld rather than advertised for an engine that is not running.
    let base_dir = banwatch_svc::base_dir_of(&config.rules_dir);
    let banwatch = match banwatch_svc::BanwatchService::open(&base_dir, metrics.clone()) {
        Ok(service) => service.map(Arc::new),
        Err(e) => {
            warn!(error = %e, "banwatch unavailable; scanner protection disabled");
            None
        }
    };

    let capabilities = capabilities(
        metrics.is_some(),
        inventory.is_some(),
        enforcing,
        banwatch.is_some(),
    );
    let state = Arc::new(
        state::ServerState::new(
            env!("CARGO_PKG_VERSION").to_owned(),
            capabilities,
            config.rules_dir.clone(),
            scanner,
            metrics,
            inventory,
        )
        .context("failed to build IPC server state")?
        .with_banwatch(banwatch),
    );
    // `ServerState::new` builds the initial rule set before the banwatch engine
    // is attached, so it carries no bans. Reload once now — before the accept
    // loop starts serving — to fold in any persisted bans from the engine's
    // in-memory set, so a daemon restart enforces existing bans immediately
    // (and still without ever reopening the etch store on the read path).
    if state.banwatch().is_some()
        && let Err(e) = state.reload()
    {
        warn!(error = %e, "initial ban-aware ruleset reload failed; starting with no bans");
    }
    Ok(state)
}

/// Minimum spacing between samples. The loop is self-paced — the next scan
/// starts as soon as the previous finishes — but never busier than this floor,
/// so a fast scan on an idle machine doesn't spin the CPU.
const SAMPLE_FLOOR: Duration = Duration::from_millis(500);

/// The background sampling loop: scan continuously and publish each sample into
/// [`state::ServerState`] so request handlers read a cached sample instead of
/// scanning inline (R4/R6). Self-paced (next scan starts when the previous
/// finishes) with a [`SAMPLE_FLOOR`], and stops when `shutdown` is set.
///
/// A scan panic is caught at this thread boundary (project rule) and logged, so
/// a transient failure in the impure scanner never tears down the daemon; the
/// loop simply tries again on the next iteration.
fn run_sampler(state: &state::ServerState, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        let started = Instant::now();
        match catch_unwind(AssertUnwindSafe(|| state.scanner().scan())) {
            Ok(Ok(conns)) => state.store_conns(conns),
            Ok(Err(e)) => warn!(error = %e, "background sample failed; keeping last sample"),
            Err(_) => error!("background sampler panicked; keeping last sample"),
        }
        // Self-pace: only sleep the remainder of the floor if the scan was fast.
        if let Some(rest) = SAMPLE_FLOOR.checked_sub(started.elapsed())
            && !shutdown.load(Ordering::Relaxed)
        {
            std::thread::sleep(rest);
        }
    }
}

/// Advertised capabilities (R3). `ExecPolicy` is omitted (the ES exec tier is
/// inactive), so the panel keeps its "Prevent launch" control disabled.
///
/// `Trace` is advertised unconditionally: the trace backend always has a working
/// packet source — the synthetic
/// [`DemoSource`](packet_source::DemoSource) when no live BPF capture is
/// available — so the panel can always enable the Trace action, and the real
/// [`capture::CaptureSession`] slots in transparently under root when built with
/// the `capture-live` feature (R9/R12).
///
/// `NetworkEnforcement` (spec 009 R3) is the exception to unconditional
/// advertisement: it is added only when the fail-safe
/// [`enforcement::network_enforcement_active`] probe confirms the NE content
/// filter is genuinely activated and enabled, so the panel never drops its
/// "preview only" hint unless enforcement is real.
///
/// `BanWatch` (spec 010 R8) is advertised only when the banwatch engine opened
/// and is enabled in config — never for a disabled or failed engine, so the
/// panel's bans surface is shown only when it is real. The advertised surface is
/// **manual bans + the expiry/decay sweeper**; automatic detection feeds are
/// implemented but not wired in this build (see [`banwatch_svc`]).
#[allow(clippy::fn_params_excessive_bools)] // one independent gate per capability
fn capabilities(
    history: bool,
    openbinary: bool,
    enforcing: bool,
    banwatch: bool,
) -> Vec<Capability> {
    // `Policy` is always on for a daemon built with the rules/policy system —
    // it can always read and mutate `net-profile.toml` and hot-reload.
    let mut caps = vec![Capability::Mutations, Capability::Policy, Capability::Trace];
    if history {
        caps.push(Capability::History);
    }
    if openbinary {
        caps.push(Capability::Openbinary);
    }
    if enforcing {
        caps.push(Capability::NetworkEnforcement);
    }
    if banwatch {
        caps.push(Capability::BanWatch);
    }
    caps
}

/// Run the IPC server in the foreground until `shutdown` is set (R11).
///
/// Bind failures return an error so `macwarden serve` reports them; the
/// alongside-monitor spawn ([`spawn`]) logs and continues instead.
pub fn serve(config: &ServerConfig, shutdown: &AtomicBool) -> anyhow::Result<()> {
    let listener = match accept::bind_socket(&config.socket_path) {
        Ok(listener) => listener,
        // A live daemon already owns the socket: this is the expected singleton
        // outcome, not an error. Exit cleanly so the panel uses the existing one.
        Err(error::ServerError::AlreadyRunning(path)) => {
            info!(path = %path, "daemon already running; this instance is exiting");
            eprintln!("macwarden: daemon already running on {path}; leaving it in place");
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to bind {}", config.socket_path.display()));
        }
    };
    let state = build_state(config)?;
    // TODO(codesign-swap): replace `UidVerifier` with the `ipc` `CodesignVerifier`
    // (R2 Layer 2) once that type lands in `crates/ipc`; the accept loop is
    // generic over `PeerVerifier`, so this is a one-line change.
    let verifier = UidVerifier::new(config.served_uid);
    // Run the background sampler alongside the accept loop in a scope, so the
    // sampler borrows `state`/`shutdown` without `'static` plumbing and is joined
    // when the accept loop exits on shutdown (it stops within one sample).
    let result = std::thread::scope(|scope| {
        scope.spawn(|| run_sampler(&state, shutdown));
        scope.spawn(|| run_ban_sweeper(&state, shutdown));
        accept::run_accept_loop(&listener, &verifier, &state, shutdown)
    });
    let _ = std::fs::remove_file(&config.socket_path);
    result.map_err(anyhow::Error::new)
}

/// Interval between banwatch expiry/decay sweeps.
const BAN_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Periodically sweep the banwatch engine so expired bans are unbanned and stale
/// escalation counts decay. When a sweep lifts one or more bans, the live rule
/// set is reloaded so the freed IPs stop being denied (and the sysext's
/// `RuleWatcher` reloads on the file change). Inert when banwatch is disabled.
///
/// Runs on its own thread in the serve scope; a sweep panic is caught at this
/// boundary and logged so a transient failure never tears down the daemon.
fn run_ban_sweeper(state: &state::ServerState, shutdown: &AtomicBool) {
    if state.banwatch().is_none() {
        return;
    }
    while !shutdown.load(Ordering::Relaxed) {
        let unbanned = catch_unwind(AssertUnwindSafe(|| sweep_once(state))).unwrap_or_else(|_| {
            error!("banwatch sweeper panicked; continuing");
            0
        });
        if unbanned > 0
            && let Err(e) = state.reload()
        {
            warn!(error = %e, "ruleset reload after ban sweep failed");
        }
        sleep_until_deadline(BAN_SWEEP_INTERVAL, shutdown);
    }
}

/// Run one sweep, returning the number of bans lifted.
fn sweep_once(state: &state::ServerState) -> usize {
    state.banwatch().map_or(0, |bw| bw.sweep().len())
}

/// Sleep in short slices up to `interval`, waking early when `shutdown` is set.
fn sleep_until_deadline(interval: Duration, shutdown: &AtomicBool) {
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline && !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200).min(deadline - Instant::now()));
    }
}

/// Spawn the IPC server on a background thread alongside the monitor (R11).
///
/// Best-effort: a bind failure is logged, not fatal to the enforcement loop.
/// Returns the join handle so the caller can keep it alive for the loop's
/// lifetime.
#[must_use]
pub fn spawn(shutdown: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let config = match ServerConfig::user_agent() {
            Ok(config) => config,
            Err(e) => {
                warn!(error = %e, "IPC server not started");
                return;
            }
        };
        if let Err(e) = serve(&config, &shutdown) {
            warn!(error = %e, "IPC server exited with error");
        } else {
            info!("IPC server stopped");
        }
    })
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod mod_test;

#[cfg(all(test, unix))]
#[path = "integration_test.rs"]
mod integration_test;
