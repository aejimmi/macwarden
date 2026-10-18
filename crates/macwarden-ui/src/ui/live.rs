//! `LiveSource` — the real machine, and the default panel source.
//!
//! Three streams are fused each tick: `sysinfo` for CPU/memory/exe-paths,
//! `procmon` for code-signing and responsible-owner resolution, and `nettop`
//! for per-process and per-connection byte counters. `nettop` is sampled every
//! 2s on a background thread so the render loop never blocks on a subprocess;
//! rates are deltas between samples.
//!
//! Persistent accumulators (`app_totals`, `dest_totals`, `pid_net_totals`) fold
//! each sample's byte delta into per-app / per-destination running totals keyed
//! by rollup identity, so a destination seen once keeps its Session-scope row —
//! at rate 0 — for the panel's lifetime even after its sockets close.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use super::live_build::{
    AppAgg, BuildCtx, ProcMeta, app_identity, build_aggregates, build_net_rows, to_app_row,
    to_detail,
};
use super::rollup::{build_meta, build_procs, group_procs, resolve_owners, signature_of};
use crate::data::model::{AppRow, Detail, NetRow, ProcGroup, ProcRow, Signature, Totals};
use crate::data::nettop::{self, ProcNet};
use crate::data::source::PanelSource;

/// Interval between background nettop samples.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

/// A parsed nettop sample with the instant it was taken (for rate deltas).
struct Snapshot {
    at: Instant,
    procs: Vec<ProcNet>,
}

/// Background nettop sampler. Publishes the latest snapshot into a shared slot.
struct Sampler {
    latest: Arc<Mutex<Arc<Snapshot>>>,
    stop: Arc<AtomicBool>,
}

impl Sampler {
    fn spawn(initial: Arc<Snapshot>) -> Self {
        let latest = Arc::new(Mutex::new(initial));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_latest = Arc::clone(&latest);
        let thread_stop = Arc::clone(&stop);
        let spawned = thread::Builder::new()
            .name("nettop-sampler".into())
            .spawn(move || sample_loop(&thread_latest, &thread_stop));
        if let Err(e) = spawned {
            tracing::warn!(%e, "nettop sampler thread failed to start");
        }
        Self { latest, stop }
    }

    fn latest(&self) -> Option<Arc<Snapshot>> {
        self.latest.lock().ok().map(|g| Arc::clone(&g))
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn sample_loop(latest: &Arc<Mutex<Arc<Snapshot>>>, stop: &Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        thread::sleep(SAMPLE_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if let Some(procs) = run_nettop() {
            let snap = Arc::new(Snapshot {
                at: Instant::now(),
                procs,
            });
            if let Ok(mut slot) = latest.lock() {
                *slot = snap;
            }
        }
    }
}

fn run_nettop() -> Option<Vec<ProcNet>> {
    let output = Command::new("/usr/bin/nettop")
        .args(["-x", "-J", "bytes_in,bytes_out", "-l", "1"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(nettop::parse(&text))
}

/// Session-persistent byte accumulators keyed by rollup identity.
#[derive(Default)]
struct Accum {
    /// app id → accumulated (down, up).
    app_totals: HashMap<String, (u64, u64)>,
    /// (app id, "ip:port") → accumulated (down, up).
    dest_totals: HashMap<(String, String), (u64, u64)>,
    /// pid → accumulated net bytes (down + up), for the Processes tab.
    pid_net_totals: HashMap<u32, u64>,
    /// app id → (name, icon) so persisted-but-idle apps still render.
    app_meta: HashMap<String, (String, Option<PathBuf>)>,
}

/// The default live system source.
pub struct LiveSource {
    system: System,
    sampler: Sampler,
    cur: Arc<Snapshot>,
    meta: HashMap<u32, ProcMeta>,
    owner: HashMap<u32, u32>,
    resp_cache: HashMap<u32, u32>,
    proc_rates: HashMap<u32, (u64, u64)>,
    remote_rates: HashMap<(u32, String), (u64, u64)>,
    accum: Accum,
    aggs: Vec<AppAgg>,
    apps_cache: Vec<AppRow>,
    net_cache: Vec<NetRow>,
    procs_cache: Vec<ProcRow>,
    groups_cache: Vec<ProcGroup>,
    totals_cache: Totals,
}

impl Default for LiveSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveSource {
    /// Build the source, take a first nettop sample, and start the sampler.
    #[must_use]
    pub fn new() -> Self {
        let mut system = System::new_all();
        // sysinfo derives per-process CPU from the delta between two refreshes
        // taken at least MINIMUM_CPU_UPDATE_INTERVAL apart. `new_all` is the
        // first sample; prime a second one after that minimum wait so CPU reads
        // non-zero from the first paint instead of after the first tick.
        thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        let procs = run_nettop().unwrap_or_default();
        let cur = Arc::new(Snapshot {
            at: Instant::now(),
            procs,
        });
        let sampler = Sampler::spawn(Arc::clone(&cur));
        let mut src = Self {
            system,
            sampler,
            cur,
            meta: HashMap::new(),
            owner: HashMap::new(),
            resp_cache: HashMap::new(),
            proc_rates: HashMap::new(),
            remote_rates: HashMap::new(),
            accum: Accum::default(),
            aggs: Vec::new(),
            apps_cache: Vec::new(),
            net_cache: Vec::new(),
            procs_cache: Vec::new(),
            groups_cache: Vec::new(),
            totals_cache: Totals::default(),
        };
        src.refresh_identity();
        src.maybe_seed_session();
        src.rebuild();
        src
    }

    /// Debug hook (`MACWARDEN_UI_SEED_SESSION`): prime the session accumulators
    /// from the first snapshot's cumulative counters so a populated Session /
    /// totals view can be captured at first paint. No effect unless set.
    fn maybe_seed_session(&mut self) {
        if std::env::var_os("MACWARDEN_UI_SEED_SESSION").is_none() {
            return;
        }
        let cur = Arc::clone(&self.cur);
        for proc in &cur.procs {
            self.accumulate_app(proc, proc.bytes_in, proc.bytes_out);
            for conn in &proc.conns {
                let ep = format!("{}:{}", conn.remote_ip, conn.remote_port);
                let id = app_identity(proc, &self.meta, &self.owner).0;
                let dest = self.accum.dest_totals.entry((id, ep)).or_default();
                dest.0 = dest.0.saturating_add(conn.bytes_in);
                dest.1 = dest.1.saturating_add(conn.bytes_out);
            }
        }
    }

    /// Rebuild the pid → metadata and pid → owner maps from the current sysinfo
    /// snapshot. Owner lookups are memoised across ticks.
    fn refresh_identity(&mut self) {
        self.meta = build_meta(&self.system);
        let pids: Vec<u32> = self.system.processes().keys().map(|p| p.as_u32()).collect();
        self.owner = resolve_owners(pids.into_iter(), &mut self.resp_cache);
    }

    /// Fold a freshly published sample into rates and session accumulators.
    fn consume(&mut self, latest: Arc<Snapshot>) {
        let dt = latest
            .at
            .saturating_duration_since(self.cur.at)
            .as_secs_f64()
            .max(0.001);
        self.recompute_proc_rates(&latest, dt);
        self.recompute_remote_rates(&latest, dt);
        self.cur = latest;
    }

    /// Per-process deltas → live rate, and accumulate per-app / per-pid totals.
    fn recompute_proc_rates(&mut self, latest: &Snapshot, dt: f64) {
        let deltas: Vec<(u32, u64, u64)> = {
            let prev = index_procs(&self.cur);
            latest
                .procs
                .iter()
                .map(|proc| {
                    let (pin, pout) = prev
                        .get(&proc.pid)
                        .map_or((proc.bytes_in, proc.bytes_out), |p| {
                            (p.bytes_in, p.bytes_out)
                        });
                    (
                        proc.pid,
                        proc.bytes_in.saturating_sub(pin),
                        proc.bytes_out.saturating_sub(pout),
                    )
                })
                .collect()
        };
        self.proc_rates.clear();
        for (proc, &(_, din, dout)) in latest.procs.iter().zip(deltas.iter()) {
            self.proc_rates
                .insert(proc.pid, (per_sec(din, dt), per_sec(dout, dt)));
            self.accumulate_app(proc, din, dout);
        }
    }

    fn accumulate_app(&mut self, proc: &ProcNet, din: u64, dout: u64) {
        let (id, name, icon) = app_identity(proc, &self.meta, &self.owner);
        let app = self.accum.app_totals.entry(id.clone()).or_default();
        app.0 = app.0.saturating_add(din);
        app.1 = app.1.saturating_add(dout);
        self.accum.app_meta.entry(id).or_insert((name, icon));
        let net = self.accum.pid_net_totals.entry(proc.pid).or_default();
        *net = net.saturating_add(din).saturating_add(dout);
    }

    /// Per-(pid, endpoint) deltas → live rate, and accumulate per-destination
    /// totals keyed by the app's rollup identity.
    fn recompute_remote_rates(&mut self, latest: &Snapshot, dt: f64) {
        let prev = agg_remote_bytes(&self.cur);
        let cur = agg_remote_bytes(latest);
        self.remote_rates.clear();
        let app_of: HashMap<u32, String> = latest
            .procs
            .iter()
            .map(|p| (p.pid, app_identity(p, &self.meta, &self.owner).0))
            .collect();
        for (key, &(cin, cout)) in &cur {
            let (pin, pout) = prev.get(key).copied().unwrap_or((cin, cout));
            let din = cin.saturating_sub(pin);
            let dout = cout.saturating_sub(pout);
            self.remote_rates
                .insert(key.clone(), (per_sec(din, dt), per_sec(dout, dt)));
            if let Some(app_id) = app_of.get(&key.0) {
                let dest = self
                    .accum
                    .dest_totals
                    .entry((app_id.clone(), key.1.clone()))
                    .or_default();
                dest.0 = dest.0.saturating_add(din);
                dest.1 = dest.1.saturating_add(dout);
            }
        }
    }

    fn rebuild(&mut self) {
        let aggs = {
            let ctx = BuildCtx {
                meta: &self.meta,
                owner: &self.owner,
                proc_rates: &self.proc_rates,
                remote_rates: &self.remote_rates,
                app_totals: &self.accum.app_totals,
                dest_totals: &self.accum.dest_totals,
                app_meta: &self.accum.app_meta,
            };
            build_aggregates(&self.cur.procs, &ctx)
        };
        self.apps_cache = aggs.iter().map(to_app_row).collect();
        self.net_cache = build_net_rows(&aggs);
        self.procs_cache = build_procs(&self.system, &self.proc_rates, &self.accum.pid_net_totals);
        self.groups_cache = group_procs(self.procs_cache.clone(), &self.owner, &self.meta);
        self.totals_cache = self.compute_totals();
        self.aggs = aggs;
    }

    fn compute_totals(&self) -> Totals {
        let (down_bps, up_bps) = sum_pairs(self.proc_rates.values());
        let (down_bytes, up_bytes) = sum_pairs(self.accum.app_totals.values());
        let connections = self.cur.procs.iter().map(|p| p.conns.len() as u64).sum();
        Totals {
            down_bytes,
            up_bytes,
            trackers_blocked: 0,
            connections,
            down_bps,
            up_bps,
        }
    }

    fn agg_by_id(&self, id: &str) -> Option<&AppAgg> {
        self.aggs.iter().find(|a| a.id == id)
    }

    fn proc_row_detail(&self, pid: u32) -> Option<Detail> {
        let proc = self.system.process(sysinfo::Pid::from_u32(pid))?;
        let path = proc.exe().map(std::path::Path::to_path_buf);
        let signature = path
            .as_deref()
            .map_or(Signature::Unsigned, |p| signature_of(pid, p));
        let net = self.accum.pid_net_totals.get(&pid).copied().unwrap_or(0);
        let hosts: Vec<String> = self
            .cur
            .procs
            .iter()
            .filter(|p| p.pid == pid)
            .flat_map(|p| {
                p.conns
                    .iter()
                    .map(|c| format!("{}:{}", c.remote_ip, c.remote_port))
            })
            .collect();
        Some(Detail {
            name: proc.name().to_string_lossy().into_owned(),
            bundle_id: format!("pid {pid}"),
            bundle_path: path.clone(),
            in_bytes: net,
            out_bytes: 0,
            path: path.map_or_else(|| "—".into(), |p| p.display().to_string()),
            user: "—".into(),
            signature,
            openbinary: "not yet analyzed".into(),
            hostnames: hosts.clone(),
            ips: hosts,
            ports: Vec::new(),
            allowed_count: 0,
            denied_count: 0,
            allowed: true,
        })
    }
}

fn index_procs(snap: &Snapshot) -> HashMap<u32, &ProcNet> {
    snap.procs.iter().map(|p| (p.pid, p)).collect()
}

/// Cumulative bytes per (pid, "ip:port") endpoint across a snapshot's sockets.
fn agg_remote_bytes(snap: &Snapshot) -> HashMap<(u32, String), (u64, u64)> {
    let mut map: HashMap<(u32, String), (u64, u64)> = HashMap::new();
    for proc in &snap.procs {
        for conn in &proc.conns {
            let ep = format!("{}:{}", conn.remote_ip, conn.remote_port);
            let entry = map.entry((proc.pid, ep)).or_default();
            entry.0 = entry.0.saturating_add(conn.bytes_in);
            entry.1 = entry.1.saturating_add(conn.bytes_out);
        }
    }
    map
}

fn per_sec(delta: u64, dt: f64) -> u64 {
    (delta as f64 / dt) as u64
}

fn sum_pairs<'a>(pairs: impl Iterator<Item = &'a (u64, u64)>) -> (u64, u64) {
    pairs.fold((0u64, 0u64), |(a, b), &(x, y)| {
        (a.saturating_add(x), b.saturating_add(y))
    })
}

impl PanelSource for LiveSource {
    fn name(&self) -> &'static str {
        "live"
    }

    fn is_live(&self) -> bool {
        true
    }

    fn tick(&mut self) {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        self.refresh_identity();
        if let Some(latest) = self.sampler.latest()
            && !Arc::ptr_eq(&latest, &self.cur)
        {
            self.consume(latest);
        }
        self.rebuild();
    }

    fn apps(&self) -> Vec<AppRow> {
        self.apps_cache.clone()
    }

    fn net_rows(&self) -> Vec<NetRow> {
        self.net_cache.clone()
    }

    fn procs(&self) -> Vec<ProcRow> {
        self.procs_cache.clone()
    }

    fn proc_groups(&self) -> Vec<ProcGroup> {
        self.groups_cache.clone()
    }

    fn totals(&self) -> Totals {
        self.totals_cache
    }

    fn app_detail(&self, id: &str) -> Option<Detail> {
        let agg = self.agg_by_id(id)?;
        let pid = agg.pids.first().copied();
        let path = agg
            .icon_path
            .as_ref()
            .map_or_else(|| "—".into(), |p| p.display().to_string());
        let signature = match (pid, agg.icon_path.as_deref()) {
            (Some(pid), Some(p)) => signature_of(pid, p),
            _ => Signature::Unsigned,
        };
        Some(to_detail(agg, signature, path))
    }

    fn proc_detail(&self, id: &str) -> Option<Detail> {
        let pid: u32 = id.parse().ok()?;
        self.proc_row_detail(pid)
    }

    fn binary_paths(&self) -> Vec<PathBuf> {
        let mut seen = std::collections::HashSet::new();
        self.system
            .processes()
            .values()
            .filter_map(|p| p.exe().map(std::path::Path::to_path_buf))
            .filter(|p| seen.insert(p.clone()))
            .collect()
    }

    fn domain_detail(&self, host: &str) -> Option<Detail> {
        let users: Vec<&AppAgg> = self
            .aggs
            .iter()
            .filter(|a| a.remotes.iter().any(|r| r.endpoint() == host))
            .collect();
        if users.is_empty() {
            return None;
        }
        Some(Detail {
            name: host.to_string(),
            bundle_id: format!("{} app(s)", users.len()),
            bundle_path: None,
            in_bytes: 0,
            out_bytes: 0,
            path: users
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            user: "—".into(),
            signature: Signature::Unsigned,
            openbinary: "reachable".into(),
            hostnames: vec![host.to_string()],
            ips: vec![host.to_string()],
            ports: Vec::new(),
            allowed_count: 1,
            denied_count: 0,
            allowed: true,
        })
    }
}
