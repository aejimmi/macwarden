//! `DaemonSource` — a [`PanelSource`] backed by the `ipc` daemon client (R8).
//!
//! # Threading model
//!
//! A single background worker thread owns the [`UnixStream`] (the protocol is
//! strictly request→response with positional correlation, so all traffic must be
//! serialized on one connection). Mirroring `LiveSource`'s sampler, the worker
//! drives `GetSnapshot` at ~1 Hz and publishes the mapped rows into a shared
//! `Arc<Mutex<Arc<Cached>>>` slot the panel reads without blocking. Detail
//! queries and rule mutations are sent to the worker over a command channel and
//! answered on a per-request reply channel, so they too serialize on the one
//! connection. The panel's `tick()` is a no-op — the worker publishes
//! asynchronously.
//!
//! # Disconnect handling (R8)
//!
//! On any I/O/codec error the worker drops the connection, keeps serving the
//! last cached snapshot, and marks itself [`RuntimeStatus::Stale`]. It retries
//! with bounded exponential backoff, re-running the handshake through the
//! injected `reconnect` closure. If reconnection does not succeed within
//! [`GRACE_WINDOW`] it degrades to [`RuntimeStatus::Fallback`] (the panel reads
//! the status and can re-pick the `nettop` `LiveSource`). The worker exits when
//! the owning `DaemonSource` drops the command sender.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ipc::client::ClientHandle;
use ipc::codec::{CodecError, read_message, write_message};
use ipc::protocol::{
    Capability, Request, Response, RuleTarget, WireAllowEntry, WireDuration, WireMode, WireProfile,
    WireRuleChange,
};

use super::map;
use super::model::{AppRow, Detail, NetRow, ProcGroup, ProcRow, Totals};
use super::source::{DetailBackend, PanelSource, PolicyBackend, TraceBackend};
use super::trace::{DaemonTraceBackend, TraceConnector};
use crate::state::Route;

/// How often the worker requests a fresh snapshot.
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
/// Per-read socket timeout, so a wedged daemon cannot pin the worker forever and
/// so worker shutdown is bounded. Sized to tolerate a cold daemon's first
/// snapshot (scanner warm-up) without churn-reconnecting; with the daemon's
/// "respond fast while warming" behavior snapshots are prompt anyway, so this is
/// a safety ceiling, not the common-case latency.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the source serves stale data while reconnecting before degrading to
/// [`RuntimeStatus::Fallback`].
const GRACE_WINDOW: Duration = Duration::from_secs(10);
/// Initial reconnect backoff.
const INIT_BACKOFF: Duration = Duration::from_millis(500);
/// Maximum reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// How long a detail/mutation query waits for the worker before giving up.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

const STATUS_LIVE: u8 = 0;
const STATUS_STALE: u8 = 1;
const STATUS_FALLBACK: u8 = 2;

/// A daemon sample older than this means the background sampler is wedged (socket
/// alive but the scan loop frozen), so the live view is no longer current even
/// though the connection is healthy. Kept in step with the daemon's own
/// stale-sample warning threshold.
const STALE_SAMPLE_MS: u64 = 10_000;

/// Whether a daemon-reported sample age marks the live view as stale. `None` (a
/// daemon too old to report the age) is treated as fresh — the panel simply
/// forgoes this signal rather than falsely degrading.
#[must_use]
fn sample_is_stale(sample_age_ms: Option<u64>) -> bool {
    sample_age_ms.is_some_and(|age| age > STALE_SAMPLE_MS)
}

/// The live-connection health of a [`DaemonSource`] (R8). Surfaced so the panel
/// can show a "reconnecting" or "degraded" affordance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStatus {
    /// Connected; the last snapshot is fresh.
    Live,
    /// Disconnected within the grace window; serving the last cached snapshot
    /// while reconnecting.
    Stale,
    /// Reconnection failed past the grace window; the panel should re-pick the
    /// fallback source.
    Fallback,
}

/// The mapped, panel-ready payload of one snapshot exchange.
#[derive(Default, Clone, PartialEq)]
struct Cached {
    apps: Vec<AppRow>,
    net_rows: Vec<NetRow>,
    procs: Vec<ProcRow>,
    groups: Vec<ProcGroup>,
    totals: Totals,
    generation: u64,
    /// Age of the daemon's underlying sample when this snapshot was produced, or
    /// `None` from a daemon too old to report it. Drives [`sample_is_stale`].
    sample_age_ms: Option<u64>,
}

/// A request the panel asks the worker to run on the shared connection.
enum Cmd {
    /// A detail query (`GetAppDetail`/`GetProcDetail`/`GetDomainDetail`).
    Detail {
        request: Request,
        reply: Sender<Option<Detail>>,
    },
    /// A `SetRule` mutation.
    SetRule {
        target: RuleTarget,
        allow: bool,
        reply: Sender<bool>,
    },
    /// A batched `SetRules` mutation (e.g. a whole-group block/allow).
    SetRules {
        changes: Vec<WireRuleChange>,
        reply: Sender<bool>,
    },
    /// A profile read (`GetProfile`) or mutation (`SetMode`, `SetGroupEnabled`,
    /// allow-list edits, …). The reply carries the echoed [`WireProfile`] from
    /// the daemon's `Profile`/`ProfileAck`, or `None` on error/rejection.
    Policy {
        request: Request,
        reply: Sender<Option<WireProfile>>,
    },
}

/// The connection pair: a write half and a buffered read half over the same
/// socket, with the read timeout applied.
struct Conn {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Conn {
    fn new(stream: UnixStream) -> std::io::Result<Self> {
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self {
            writer: stream,
            reader,
        })
    }

    /// Send one request and read its single correlated response.
    fn request(&mut self, request: &Request) -> Result<Response, CodecError> {
        write_message(&mut self.writer, request)?;
        read_message(&mut self.reader)
    }
}

/// The background worker. Owns the connection and the reconnect closure.
struct Worker {
    conn: Option<Conn>,
    reconnect: Box<dyn FnMut() -> Option<UnixStream> + Send>,
    mutations: bool,
    latest: Arc<Mutex<Arc<Cached>>>,
    /// Bumps only when a freshly-mapped snapshot differs from the published one,
    /// so the panel can skip re-rendering an unchanged view (see
    /// [`DaemonSource::content_version`]).
    content: Arc<AtomicU64>,
    status: Arc<AtomicU8>,
    cmd_rx: Receiver<Cmd>,
    stale_since: Option<Instant>,
    next_reconnect_at: Instant,
    backoff: Duration,
}

impl Worker {
    fn run(mut self) {
        loop {
            self.maybe_reconnect();
            self.update_status();
            // Prefer user-initiated queries (detail / policy) over the periodic
            // snapshot: drain any that queued while we were busy so a click is
            // answered before the next snapshot request occupies the connection.
            self.drain_commands();
            self.snapshot_tick();
            match self.cmd_rx.recv_timeout(SNAPSHOT_INTERVAL) {
                Ok(cmd) => self.handle_cmd(cmd),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Handle every command already queued, without blocking. Keeps user queries
    /// ahead of the next snapshot when several land between ticks.
    fn drain_commands(&mut self) {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            self.handle_cmd(cmd);
        }
    }

    /// Request a snapshot and publish the mapped rows; a failure disconnects.
    fn snapshot_tick(&mut self) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        match conn.request(&Request::GetSnapshot) {
            Ok(Response::Snapshot {
                apps,
                net_rows,
                procs,
                proc_groups,
                totals,
                generation,
                sample_age_ms,
            }) => {
                let cached = Cached {
                    apps: apps.into_iter().map(map::app_row).collect(),
                    net_rows: net_rows.into_iter().map(map::net_row).collect(),
                    procs: procs.into_iter().map(map::proc_row).collect(),
                    groups: proc_groups.into_iter().map(map::proc_group).collect(),
                    totals: map::totals(totals),
                    generation,
                    sample_age_ms,
                };
                // Republish (and bump the content version) only when the mapped
                // snapshot actually differs from what the panel already shows.
                // On an idle machine consecutive snapshots are identical, so the
                // panel skips a full window layout+paint for that tick.
                if let Ok(mut slot) = self.latest.lock()
                    && **slot != cached
                {
                    *slot = Arc::new(cached);
                    self.content.fetch_add(1, Ordering::Relaxed);
                }
                self.mark_live();
            }
            Ok(_) => {}
            Err(_) => self.mark_disconnected(),
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Detail { request, reply } => {
                let detail = self.query_detail(&request);
                let _ = reply.send(detail);
            }
            Cmd::SetRule {
                target,
                allow,
                reply,
            } => {
                let applied = self.apply_rule(target, allow);
                let _ = reply.send(applied);
            }
            Cmd::SetRules { changes, reply } => {
                let applied = self.apply_rules(changes);
                let _ = reply.send(applied);
            }
            Cmd::Policy { request, reply } => {
                let profile = self.query_policy(&request);
                let _ = reply.send(profile);
            }
        }
    }

    /// Run a profile read/mutation and extract the echoed [`WireProfile`] from a
    /// `Profile` or `ProfileAck` response. Any other response (an `Error`, e.g.
    /// a rejected allow-list entry) yields `None`; an I/O error disconnects.
    fn query_policy(&mut self, request: &Request) -> Option<WireProfile> {
        let conn = self.conn.as_mut()?;
        match conn.request(request) {
            Ok(Response::Profile { profile } | Response::ProfileAck { profile, .. }) => {
                Some(profile)
            }
            Ok(_) => None,
            Err(_) => {
                self.mark_disconnected();
                None
            }
        }
    }

    fn query_detail(&mut self, request: &Request) -> Option<Detail> {
        let conn = self.conn.as_mut()?;
        match conn.request(request) {
            Ok(Response::Detail { detail }) => detail.map(map::detail),
            Ok(_) => None,
            Err(_) => {
                self.mark_disconnected();
                None
            }
        }
    }

    fn apply_rule(&mut self, target: RuleTarget, allow: bool) -> bool {
        if !self.mutations {
            return false;
        }
        let request = Request::SetRule {
            target,
            allow,
            duration: WireDuration::Session,
        };
        let Some(conn) = self.conn.as_mut() else {
            return false;
        };
        match conn.request(&request) {
            Ok(Response::RuleAck { applied, .. }) => applied,
            Ok(_) => false,
            Err(_) => {
                self.mark_disconnected();
                false
            }
        }
    }

    /// Send a batched `SetRules` and report whether the daemon applied it.
    fn apply_rules(&mut self, changes: Vec<WireRuleChange>) -> bool {
        if !self.mutations || changes.is_empty() {
            return false;
        }
        let Some(conn) = self.conn.as_mut() else {
            return false;
        };
        match conn.request(&Request::SetRules { rules: changes }) {
            Ok(Response::RulesAck { applied, .. }) => applied,
            Ok(_) => false,
            Err(_) => {
                self.mark_disconnected();
                false
            }
        }
    }

    fn maybe_reconnect(&mut self) {
        if self.conn.is_some() || Instant::now() < self.next_reconnect_at {
            return;
        }
        match (self.reconnect)().map(Conn::new) {
            Some(Ok(conn)) => {
                self.conn = Some(conn);
                self.stale_since = None;
                self.backoff = INIT_BACKOFF;
                self.mark_live();
            }
            _ => self.schedule_backoff(),
        }
    }

    fn schedule_backoff(&mut self) {
        self.next_reconnect_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    fn mark_live(&mut self) {
        self.stale_since = None;
        self.status.store(STATUS_LIVE, Ordering::Relaxed);
    }

    fn mark_disconnected(&mut self) {
        self.conn = None;
        if self.stale_since.is_none() {
            self.stale_since = Some(Instant::now());
            self.backoff = INIT_BACKOFF;
            self.next_reconnect_at = Instant::now() + self.backoff;
        }
        self.update_status();
    }

    fn update_status(&self) {
        let status = if self.conn.is_some() {
            STATUS_LIVE
        } else if self.stale_since.is_some_and(|t| t.elapsed() > GRACE_WINDOW) {
            STATUS_FALLBACK
        } else {
            STATUS_STALE
        };
        self.status.store(status, Ordering::Relaxed);
    }
}

/// A cloneable, `Send + Sync` handle onto the worker's command channel.
///
/// The panel moves this onto its background executor to resolve inspector
/// details and apply rule mutations without pinning the render thread: each
/// call posts a [`Cmd`] to the worker and blocks (bounded by [`QUERY_TIMEOUT`])
/// on a per-request reply channel. Cloning is cheap — an `mpsc::Sender` clone —
/// and every clone keeps the worker alive until all are dropped.
#[derive(Clone)]
struct DaemonBackend {
    cmd_tx: Sender<Cmd>,
    mutations: bool,
    policy: bool,
}

impl DaemonBackend {
    /// Post a detail query to the worker and block on its reply.
    fn query_detail(&self, request: Request) -> Option<Detail> {
        let (reply, rx) = channel();
        self.cmd_tx.send(Cmd::Detail { request, reply }).ok()?;
        rx.recv_timeout(QUERY_TIMEOUT).ok().flatten()
    }

    /// Post a profile read/mutation to the worker and block on its reply. Gated
    /// on the `Policy` capability so a daemon that never advertised it is never
    /// sent an unsupported request.
    fn query_policy(&self, request: Request) -> Option<WireProfile> {
        if !self.policy {
            return None;
        }
        let (reply, rx) = channel();
        self.cmd_tx.send(Cmd::Policy { request, reply }).ok()?;
        rx.recv_timeout(QUERY_TIMEOUT).ok().flatten()
    }
}

impl PolicyBackend for DaemonBackend {
    fn get_profile(&self) -> Option<WireProfile> {
        self.query_policy(Request::GetProfile)
    }

    fn set_mode(&self, mode: WireMode) -> Option<WireProfile> {
        self.query_policy(Request::SetMode { mode })
    }

    fn set_apple_allow(&self, allow: bool) -> Option<WireProfile> {
        self.query_policy(Request::SetAppleAllow { allow })
    }

    fn set_dns_allow(&self, allow: bool) -> Option<WireProfile> {
        self.query_policy(Request::SetDnsAllow { allow })
    }

    fn set_group_enabled(&self, group: String, enabled: bool) -> Option<WireProfile> {
        self.query_policy(Request::SetGroupEnabled { group, enabled })
    }

    fn add_allow_entry(&self, entry: WireAllowEntry) -> Option<WireProfile> {
        self.query_policy(Request::AddAllowListEntry { entry })
    }

    fn remove_allow_entry(&self, entry: WireAllowEntry) -> Option<WireProfile> {
        self.query_policy(Request::RemoveAllowListEntry { entry })
    }
}

impl DetailBackend for DaemonBackend {
    fn detail(&self, route: &Route) -> Option<Detail> {
        let request = match route {
            Route::App(id) => Request::GetAppDetail { id: id.clone() },
            Route::Proc(id) => Request::GetProcDetail { id: id.clone() },
            Route::Domain(host) => Request::GetDomainDetail { host: host.clone() },
            // Settings and Trace are UI-only views — they never resolve a detail.
            Route::Settings | Route::Trace(_) => return None,
        };
        self.query_detail(request)
    }

    fn set_rule(&self, target: &RuleTarget, allow: bool) -> bool {
        if !self.mutations {
            return false;
        }
        let (reply, rx) = channel();
        if self
            .cmd_tx
            .send(Cmd::SetRule {
                target: target.clone(),
                allow,
                reply,
            })
            .is_err()
        {
            return false;
        }
        rx.recv_timeout(QUERY_TIMEOUT).unwrap_or(false)
    }

    fn set_rules(&self, changes: &[(RuleTarget, bool)]) -> bool {
        if !self.mutations || changes.is_empty() {
            return false;
        }
        let rules = to_rule_changes(changes);
        let (reply, rx) = channel();
        if self
            .cmd_tx
            .send(Cmd::SetRules {
                changes: rules,
                reply,
            })
            .is_err()
        {
            return false;
        }
        rx.recv_timeout(QUERY_TIMEOUT).unwrap_or(false)
    }
}

/// Map `(target, allow)` pairs into `SetRules` wire changes, all at `Session`
/// duration — matching the single-app toggle so an aggregate group action and the
/// members' own toggles use the same rule kind. Pure, so it is unit-tested.
#[must_use]
fn to_rule_changes(changes: &[(RuleTarget, bool)]) -> Vec<WireRuleChange> {
    changes
        .iter()
        .map(|(target, allow)| WireRuleChange {
            target: target.clone(),
            allow: *allow,
            duration: WireDuration::Session,
        })
        .collect()
}

/// A [`PanelSource`] served by the macwarden daemon over `ipc` (R8).
pub struct DaemonSource {
    latest: Arc<Mutex<Arc<Cached>>>,
    /// Snapshot content version, shared with the worker. Bumps only when the
    /// published snapshot changes, letting the panel skip unchanged renders.
    content: Arc<AtomicU64>,
    status: Arc<AtomicU8>,
    backend: DaemonBackend,
    capabilities: Vec<Capability>,
    daemon_version: String,
    /// Opens fresh dedicated connections for per-app traces (R11). Only exposed
    /// through [`PanelSource::trace_backend`] when the daemon advertises
    /// [`Capability::Trace`].
    trace_connector: Arc<TraceConnector>,
    _worker: JoinHandle<()>,
}

impl DaemonSource {
    /// Build a source from a handshake-completed `ipc` [`ClientHandle`] and a
    /// `reconnect` closure that re-runs connect+handshake and yields a fresh
    /// post-handshake stream (or `None` when the daemon is unreachable).
    pub fn from_handle(
        handle: ClientHandle<UnixStream>,
        reconnect: Box<dyn FnMut() -> Option<UnixStream> + Send>,
        trace_connect: Box<dyn FnMut() -> Option<UnixStream> + Send>,
    ) -> std::io::Result<Self> {
        let capabilities = handle.capabilities().to_vec();
        let daemon_version = handle.daemon_version().to_string();
        let stream = handle.into_connection();
        Self::from_parts(
            stream,
            capabilities,
            daemon_version,
            reconnect,
            trace_connect,
        )
    }

    /// Build a source from an already handshake-completed `stream` plus the
    /// daemon's advertised `capabilities` and `daemon_version`. This is the core
    /// constructor (no handshake is performed on `stream` — the caller already
    /// did it and verified the socket owner).
    pub fn from_parts(
        stream: UnixStream,
        capabilities: Vec<Capability>,
        daemon_version: String,
        reconnect: Box<dyn FnMut() -> Option<UnixStream> + Send>,
        trace_connect: Box<dyn FnMut() -> Option<UnixStream> + Send>,
    ) -> std::io::Result<Self> {
        let conn = Conn::new(stream)?;
        let latest = Arc::new(Mutex::new(Arc::new(Cached::default())));
        let content = Arc::new(AtomicU64::new(0));
        let status = Arc::new(AtomicU8::new(STATUS_LIVE));
        let (cmd_tx, cmd_rx) = channel();
        let mutations = capabilities.contains(&Capability::Mutations);
        let policy = capabilities.contains(&Capability::Policy);
        let backend = DaemonBackend {
            cmd_tx,
            mutations,
            policy,
        };
        let worker = Worker {
            conn: Some(conn),
            reconnect,
            mutations,
            latest: Arc::clone(&latest),
            content: Arc::clone(&content),
            status: Arc::clone(&status),
            cmd_rx,
            stale_since: None,
            next_reconnect_at: Instant::now(),
            backoff: INIT_BACKOFF,
        };
        let worker_handle = thread::Builder::new()
            .name("daemon-source".into())
            .spawn(move || worker.run())?;
        Ok(Self {
            latest,
            content,
            status,
            backend,
            capabilities,
            daemon_version,
            trace_connector: Arc::new(TraceConnector::new(trace_connect)),
            _worker: worker_handle,
        })
    }

    /// The daemon's advertised build version.
    #[must_use]
    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    /// Whether the daemon advertised a capability.
    #[must_use]
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// The current live-connection health (R8).
    #[must_use]
    pub fn runtime_status(&self) -> RuntimeStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_LIVE => RuntimeStatus::Live,
            STATUS_FALLBACK => RuntimeStatus::Fallback,
            _ => RuntimeStatus::Stale,
        }
    }

    /// The generation of the currently cached snapshot (bumps on each mutation).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.cached().generation
    }

    fn cached(&self) -> Arc<Cached> {
        self.latest
            .lock()
            .map(|slot| Arc::clone(&slot))
            .unwrap_or_default()
    }
}

impl PanelSource for DaemonSource {
    fn name(&self) -> &'static str {
        "daemon"
    }

    fn is_live(&self) -> bool {
        // Honest degradation (R8): a daemon whose worker has lost the connection
        // (Stale) or given up past the grace window (Fallback) is no longer live.
        // The panel must stop claiming live and show a reconnecting affordance
        // rather than rendering the last cached snapshot as current. A wedged
        // sampler (socket alive, scan frozen) also makes the *view* stale even
        // though the connection is healthy, so the sample age gates liveness too.
        // Note enforcement_active() deliberately does NOT read the sample age: a
        // frozen sampler stalls the view, it does not stop the filter enforcing.
        self.runtime_status() == RuntimeStatus::Live
            && !sample_is_stale(self.cached().sample_age_ms)
    }

    fn enforcement_active(&self) -> bool {
        // Enforcement is real only when a live daemon advertises the
        // NetworkEnforcement capability. A dead/stale daemon's *last* capabilities
        // must never keep the UI in an "enforcing" state — gate on liveness too so
        // the block/allow controls and verdict dots degrade to preview honestly.
        self.runtime_status() == RuntimeStatus::Live
            && self.has_capability(Capability::NetworkEnforcement)
    }

    fn tick(&mut self) {
        // The worker publishes snapshots asynchronously; nothing to do per tick.
    }

    fn content_version(&self) -> Option<u64> {
        Some(self.content.load(Ordering::Relaxed))
    }

    fn apps(&self) -> Vec<AppRow> {
        self.cached().apps.clone()
    }

    fn app_count(&self) -> usize {
        self.cached().apps.len()
    }

    fn net_rows(&self) -> Vec<NetRow> {
        self.cached().net_rows.clone()
    }

    fn procs(&self) -> Vec<ProcRow> {
        self.cached().procs.clone()
    }

    fn proc_groups(&self) -> Vec<ProcGroup> {
        self.cached().groups.clone()
    }

    fn proc_group_count(&self) -> usize {
        self.cached().groups.len()
    }

    fn totals(&self) -> Totals {
        self.cached().totals
    }

    fn app_detail(&self, id: &str) -> Option<Detail> {
        self.backend
            .query_detail(Request::GetAppDetail { id: id.to_string() })
    }

    fn proc_detail(&self, id: &str) -> Option<Detail> {
        self.backend
            .query_detail(Request::GetProcDetail { id: id.to_string() })
    }

    fn domain_detail(&self, host: &str) -> Option<Detail> {
        self.backend.query_detail(Request::GetDomainDetail {
            host: host.to_string(),
        })
    }

    fn set_rule(&self, target: &RuleTarget, allow: bool) -> bool {
        self.backend.set_rule(target, allow)
    }

    fn detail_backend(&self) -> Option<Arc<dyn DetailBackend>> {
        Some(Arc::new(self.backend.clone()))
    }

    fn policy_backend(&self) -> Option<Arc<dyn PolicyBackend>> {
        self.has_capability(Capability::Policy)
            .then(|| Arc::new(self.backend.clone()) as Arc<dyn PolicyBackend>)
    }

    fn trace_backend(&self) -> Option<Arc<dyn TraceBackend>> {
        self.has_capability(Capability::Trace).then(|| {
            Arc::new(DaemonTraceBackend::new(Arc::clone(&self.trace_connector)))
                as Arc<dyn TraceBackend>
        })
    }
}

#[cfg(test)]
#[path = "daemon_test.rs"]
mod daemon_test;
