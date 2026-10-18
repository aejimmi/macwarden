//! Aggregation helpers that fold the raw nettop sample and sysinfo metadata
//! into the panel's snapshot types. Kept pure (no GPUI, no syscalls) so the
//! per-tick shaping logic stays small and reviewable.
//!
//! Two axes are folded here:
//! - **App rollup** — helper processes are remapped to their responsible app
//!   (via the `owner` map) and to the enclosing `.app` bundle, so Chrome Helper
//!   and `com.apple.WebKit.Networking` collapse into Chrome / Safari.
//! - **Endpoint aggregation** — a process's several sockets to one remote
//!   endpoint collapse into a single row carrying a socket count.
//!
//! Live rates come from the current sample; accumulated totals come from the
//! caller's session accumulators, so idle-but-seen apps and destinations persist
//! as rate-0 rows under a totals scope.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::data::model::{AppRow, Detail, DomainRow, Flow, NetRow, Signature, Verdict};
use crate::data::nettop::ProcNet;

/// Per-process metadata sourced from sysinfo, joined against nettop by pid.
pub struct ProcMeta {
    /// Full process name.
    pub name: String,
    /// Executable path, if resolvable.
    pub exe: Option<PathBuf>,
}

/// One remote endpoint, aggregated across a process's connections.
pub struct RemoteAgg {
    /// Remote IP address.
    pub ip: String,
    /// Representative remote port.
    pub port: u16,
    /// Current throughput in bytes per second.
    pub rate_bps: u64,
    /// Accumulated bytes to this endpoint since the panel launched.
    pub total_bytes: u64,
    /// Number of active sockets collapsed into this endpoint.
    pub sockets: u32,
}

impl RemoteAgg {
    /// `ip:port` display key.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

/// An application aggregated from one or more processes sharing a bundle.
pub struct AppAgg {
    /// Stable key — bundle path or executable path.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Icon source path (bundle or executable).
    pub icon_path: Option<PathBuf>,
    /// Contributing process ids (first is the representative for signatures).
    pub pids: Vec<u32>,
    /// Combined download rate in bytes per second.
    pub down_bps: u64,
    /// Combined upload rate in bytes per second.
    pub up_bps: u64,
    /// Bytes downloaded since the panel launched (persistent accumulator).
    pub total_down: u64,
    /// Bytes uploaded since the panel launched (persistent accumulator).
    pub total_up: u64,
    /// Remote endpoints, most active first.
    pub remotes: Vec<RemoteAgg>,
}

impl AppAgg {
    /// Combined live rate.
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.down_bps + self.up_bps
    }

    /// Combined accumulated total.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total_down + self.total_up
    }
}

/// Inputs shared by every process during aggregation.
pub struct BuildCtx<'a> {
    /// pid → sysinfo metadata.
    pub meta: &'a HashMap<u32, ProcMeta>,
    /// pid → responsible/owning pid (self when not a helper).
    pub owner: &'a HashMap<u32, u32>,
    /// pid → (down_bps, up_bps).
    pub proc_rates: &'a HashMap<u32, (u64, u64)>,
    /// (pid, "ip:port") → (down_bps, up_bps).
    pub remote_rates: &'a HashMap<(u32, String), (u64, u64)>,
    /// app id → accumulated (down, up) bytes since launch.
    pub app_totals: &'a HashMap<String, (u64, u64)>,
    /// (app id, "ip:port") → accumulated (down, up) bytes since launch.
    pub dest_totals: &'a HashMap<(String, String), (u64, u64)>,
    /// app id → (display name, icon path) — remembered so persisted-but-idle
    /// apps still render a name and icon when no live process backs them.
    pub app_meta: &'a HashMap<String, (String, Option<PathBuf>)>,
}

/// Mutable per-app accumulator used only while folding; converted to [`AppAgg`].
struct AggBuild {
    id: String,
    name: String,
    icon_path: Option<PathBuf>,
    pids: Vec<u32>,
    down_bps: u64,
    up_bps: u64,
    total_down: u64,
    total_up: u64,
    remotes: HashMap<String, RemoteAgg>,
}

/// The `.app` bundle directory enclosing `path`, if any.
#[must_use]
pub fn bundle_of(path: &Path) -> Option<PathBuf> {
    let mut acc = PathBuf::new();
    for comp in path.components() {
        acc.push(comp);
        if acc
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(".app"))
        {
            return Some(acc);
        }
    }
    None
}

/// Resolve `(id, display_name, icon_path)` for a process.
#[must_use]
pub fn identity(exe: Option<&Path>, fallback: &str) -> (String, String, Option<PathBuf>) {
    let Some(exe) = exe else {
        return (fallback.to_string(), fallback.to_string(), None);
    };
    if let Some(bundle) = bundle_of(exe) {
        let name = bundle.file_stem().map_or_else(
            || fallback.to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        return (bundle.to_string_lossy().into_owned(), name, Some(bundle));
    }
    let name = exe.file_name().map_or_else(
        || fallback.to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    (
        exe.to_string_lossy().into_owned(),
        name,
        Some(exe.to_path_buf()),
    )
}

/// Resolve the rollup identity for a nettop process, following its responsible
/// owner to the owning app when one exists.
#[must_use]
pub fn app_identity(
    proc: &ProcNet,
    meta: &HashMap<u32, ProcMeta>,
    owner: &HashMap<u32, u32>,
) -> (String, String, Option<PathBuf>) {
    let owner_pid = owner.get(&proc.pid).copied().unwrap_or(proc.pid);
    let ometa = meta.get(&owner_pid).or_else(|| meta.get(&proc.pid));
    let exe = ometa.and_then(|m| m.exe.as_deref());
    let fallback = ometa.map_or(proc.name.as_str(), |m| m.name.as_str());
    identity(exe, fallback)
}

/// Fold the nettop sample plus persistent accumulators into per-app aggregates,
/// sorted by live rate then accumulated volume.
#[must_use]
pub fn build_aggregates(sample: &[ProcNet], ctx: &BuildCtx) -> Vec<AppAgg> {
    let mut apps: HashMap<String, AggBuild> = HashMap::new();
    for proc in sample {
        let (id, name, icon_path) = app_identity(proc, ctx.meta, ctx.owner);
        let entry = apps
            .entry(id.clone())
            .or_insert_with(|| new_build(id, name, icon_path));
        fold_proc(entry, proc, ctx);
    }
    overlay_persistent(&mut apps, ctx);
    finish(apps)
}

fn new_build(id: String, name: String, icon_path: Option<PathBuf>) -> AggBuild {
    AggBuild {
        id,
        name,
        icon_path,
        pids: Vec::new(),
        down_bps: 0,
        up_bps: 0,
        total_down: 0,
        total_up: 0,
        remotes: HashMap::new(),
    }
}

fn fold_proc(entry: &mut AggBuild, proc: &ProcNet, ctx: &BuildCtx) {
    entry.pids.push(proc.pid);
    if let Some((d, u)) = ctx.proc_rates.get(&proc.pid) {
        entry.down_bps += d;
        entry.up_bps += u;
    }
    fold_remotes(entry, proc, ctx);
}

/// Collapse a process's sockets by endpoint, counting sockets and summing the
/// per-endpoint rate across the app's processes.
fn fold_remotes(entry: &mut AggBuild, proc: &ProcNet, ctx: &BuildCtx) {
    let mut per_ep: HashMap<String, (String, u16, u32)> = HashMap::new();
    for conn in &proc.conns {
        let ep = format!("{}:{}", conn.remote_ip, conn.remote_port);
        let slot = per_ep
            .entry(ep)
            .or_insert((conn.remote_ip.clone(), conn.remote_port, 0));
        slot.2 += 1;
    }
    for (ep, (ip, port, sockets)) in per_ep {
        let rate = ctx
            .remote_rates
            .get(&(proc.pid, ep.clone()))
            .map_or(0, |(d, u)| d + u);
        let slot = entry.remotes.entry(ep).or_insert_with(|| RemoteAgg {
            ip,
            port,
            rate_bps: 0,
            total_bytes: 0,
            sockets: 0,
        });
        slot.rate_bps = slot.rate_bps.saturating_add(rate);
        slot.sockets = slot.sockets.saturating_add(sockets);
    }
}

/// Attach accumulated totals and surface persisted-but-idle apps / endpoints so
/// a totals scope shows the full session, not just the live moment.
fn overlay_persistent(apps: &mut HashMap<String, AggBuild>, ctx: &BuildCtx) {
    for (id, &(td, tu)) in ctx.app_totals {
        let entry = apps.entry(id.clone()).or_insert_with(|| {
            let (name, icon) = ctx
                .app_meta
                .get(id)
                .cloned()
                .unwrap_or_else(|| (short_name(id), None));
            new_build(id.clone(), name, icon)
        });
        entry.total_down = td;
        entry.total_up = tu;
    }
    for ((app_id, ep), &(td, tu)) in ctx.dest_totals {
        let Some(entry) = apps.get_mut(app_id) else {
            continue;
        };
        let (ip, port) = split_endpoint(ep);
        let slot = entry
            .remotes
            .entry(ep.clone())
            .or_insert_with(|| RemoteAgg {
                ip,
                port,
                rate_bps: 0,
                total_bytes: 0,
                sockets: 0,
            });
        slot.total_bytes = td + tu;
    }
}

/// Last path component of an id, as a display fallback.
fn short_name(id: &str) -> String {
    Path::new(id)
        .file_name()
        .map_or_else(|| id.to_string(), |s| s.to_string_lossy().into_owned())
}

/// Split an `ip:port` endpoint back into its parts (IPv6-safe via `rsplit`).
fn split_endpoint(ep: &str) -> (String, u16) {
    match ep.rsplit_once(':') {
        Some((ip, port)) => (ip.to_string(), port.parse().unwrap_or(0)),
        None => (ep.to_string(), 0),
    }
}

fn finish(apps: HashMap<String, AggBuild>) -> Vec<AppAgg> {
    let mut list: Vec<AppAgg> = apps
        .into_values()
        .filter(|b| !b.remotes.is_empty() || b.total_down + b.total_up > 0)
        .map(seal)
        .collect();
    list.sort_by(|a, b| b.rate().cmp(&a.rate()).then(b.total().cmp(&a.total())));
    list.truncate(40);
    list
}

fn seal(b: AggBuild) -> AppAgg {
    let mut remotes: Vec<RemoteAgg> = b.remotes.into_values().collect();
    remotes.sort_by(|a, b| {
        b.rate_bps
            .cmp(&a.rate_bps)
            .then(b.total_bytes.cmp(&a.total_bytes))
    });
    remotes.truncate(12);
    AppAgg {
        id: b.id,
        name: b.name,
        icon_path: b.icon_path,
        pids: b.pids,
        down_bps: b.down_bps,
        up_bps: b.up_bps,
        total_down: b.total_down,
        total_up: b.total_up,
        remotes,
    }
}

fn domain_of(r: &RemoteAgg) -> DomainRow {
    DomainRow {
        host: r.endpoint(),
        country: None,
        verdict: Verdict::Allow,
        rate_bps: r.rate_bps,
        total_bytes: r.total_bytes,
        sockets: r.sockets,
        allowed: true,
    }
}

/// Project an aggregate into an Apps-tab row (carries both live rate and
/// accumulated totals; the tab decides which to show per the active scope).
#[must_use]
pub fn to_app_row(app: &AppAgg) -> AppRow {
    let rate = app.rate();
    let domains = app.remotes.iter().map(domain_of).collect();
    AppRow {
        id: app.id.clone(),
        name: app.name.clone(),
        bundle_path: app.icon_path.clone(),
        allowed: true,
        known_bad: false,
        is_system: false,
        down_bytes: app.total_down,
        up_bytes: app.total_up,
        flow: if rate > 0 {
            Flow::Active(rate)
        } else {
            Flow::Idle
        },
        domains,
    }
}

/// Flatten apps into a flat destination list for the Network tab. Ordering and
/// scope filtering are left to the tab, which knows the active scope.
#[must_use]
pub fn build_net_rows(apps: &[AppAgg]) -> Vec<NetRow> {
    apps.iter()
        .flat_map(|a| {
            a.remotes.iter().map(move |r| NetRow {
                app_name: a.name.clone(),
                app_path: a.icon_path.clone(),
                domain: domain_of(r),
            })
        })
        .collect()
}

/// Build the inspector detail for an aggregate. `signature`/`path` come from the
/// representative process (resolved by the caller, which owns procmon access).
#[must_use]
pub fn to_detail(app: &AppAgg, signature: Signature, path: String) -> Detail {
    let ips: Vec<String> = app.remotes.iter().map(|r| r.ip.clone()).collect();
    let mut ports: Vec<String> = app
        .remotes
        .iter()
        .map(|r| format!("{}/tcp", r.port))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    Detail {
        name: app.name.clone(),
        bundle_id: app.id.clone(),
        bundle_path: app.icon_path.clone(),
        in_bytes: app.total_down,
        out_bytes: app.total_up,
        path,
        user: "—".into(),
        signature,
        openbinary: "not yet analyzed".into(),
        hostnames: ips.clone(),
        ips,
        ports,
        allowed_count: app.remotes.len() as u32,
        denied_count: 0,
        allowed: true,
    }
}

#[cfg(test)]
#[path = "live_build_test.rs"]
mod live_build_test;
