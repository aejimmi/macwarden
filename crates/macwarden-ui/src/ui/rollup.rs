//! sysinfo-backed helpers: process metadata, code-signing lookup, responsible
//! owner resolution, and the Processes-tab rollup that groups helper processes
//! under their responsible app.
//!
//! The pure shaping (`group_procs`) is separated from the macOS FFI (`build_meta`,
//! `resolve_owners`, `signature_of`) so the grouping logic stays testable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sysinfo::System;

use super::live_build::{ProcMeta, identity};
use crate::data::model::{ProcGroup, ProcRow, Signature};

/// Cap on cached responsible lookups before a wholesale reset — keeps the map
/// from growing unbounded across a long-lived panel as pids churn.
const RESP_CACHE_CAP: usize = 4096;

/// Snapshot sysinfo into a pid → metadata map for aggregation joins.
#[must_use]
pub fn build_meta(system: &System) -> HashMap<u32, ProcMeta> {
    system
        .processes()
        .values()
        .map(|p| {
            (
                p.pid().as_u32(),
                ProcMeta {
                    name: p.name().to_string_lossy().into_owned(),
                    exe: p.exe().map(Path::to_path_buf),
                },
            )
        })
        .collect()
}

/// Resolve each pid to its responsible owner pid, memoising results. A pid that
/// is its own responsible process (or fails lookup) maps to itself.
#[must_use]
pub fn resolve_owners(
    pids: impl Iterator<Item = u32>,
    cache: &mut HashMap<u32, u32>,
) -> HashMap<u32, u32> {
    if cache.len() > RESP_CACHE_CAP {
        cache.clear();
    }
    let mut out = HashMap::new();
    for pid in pids {
        let owner = *cache.entry(pid).or_insert_with(|| owner_of(pid));
        out.insert(pid, owner);
    }
    out
}

#[cfg(target_os = "macos")]
fn owner_of(pid: u32) -> u32 {
    match procmon::responsible::get_responsible_pid(pid) {
        Ok(Some(owner)) => owner,
        _ => pid,
    }
}

#[cfg(not(target_os = "macos"))]
fn owner_of(pid: u32) -> u32 {
    pid
}

/// Summarise a process's code-signing identity for the inspector.
#[must_use]
pub fn signature_of(pid: u32, path: &Path) -> Signature {
    #[cfg(target_os = "macos")]
    {
        match procmon::code_signing::get_code_signing_info(pid, path) {
            Ok(info) if info.is_apple_signed => Signature::Apple,
            Ok(info) => match info.team_id {
                Some(team) if info.is_valid => Signature::DevId(team),
                _ => Signature::Unsigned,
            },
            Err(_) => Signature::Unsigned,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, path);
        Signature::Unsigned
    }
}

/// Build the flat per-process rows (all processes, for counts and detail).
#[must_use]
pub fn build_procs(
    system: &System,
    proc_rates: &HashMap<u32, (u64, u64)>,
    net_totals: &HashMap<u32, u64>,
) -> Vec<ProcRow> {
    system
        .processes()
        .values()
        .map(|proc| proc_row(proc, proc_rates, net_totals))
        .collect()
}

fn proc_row(
    proc: &sysinfo::Process,
    proc_rates: &HashMap<u32, (u64, u64)>,
    net_totals: &HashMap<u32, u64>,
) -> ProcRow {
    let pid = proc.pid().as_u32();
    let net = proc_rates.get(&pid).map_or(0, |(d, u)| d + u);
    let mem_bytes = proc.memory();
    // The panel's own sampler is also unprivileged, so a zero memory means the
    // process's task info was unreadable — mark it unknown, not a fabricated 0.
    let stats_known = mem_bytes > 0;
    ProcRow {
        id: pid.to_string(),
        name: proc.name().to_string_lossy().into_owned(),
        bundle_path: proc.exe().map(PathBuf::from),
        cpu: proc.cpu_usage(),
        mem_bytes,
        net_bps: net,
        net_bytes: net_totals.get(&pid).copied().unwrap_or(0),
        stats_known,
    }
}

/// Group per-process rows under their responsible app. `owner` maps pid → owner
/// pid; `meta` supplies owner exe paths for the group's identity.
#[must_use]
pub fn group_procs(
    procs: Vec<ProcRow>,
    owner: &HashMap<u32, u32>,
    meta: &HashMap<u32, ProcMeta>,
) -> Vec<ProcGroup> {
    let mut groups: HashMap<String, ProcGroup> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for proc in procs {
        let (id, name, icon) = group_identity(&proc, owner, meta);
        let group = groups.entry(id.clone()).or_insert_with(|| {
            order.push(id.clone());
            ProcGroup {
                id,
                name,
                bundle_path: icon,
                cpu: 0.0,
                mem_bytes: 0,
                net_bps: 0,
                net_bytes: 0,
                stats_known: false,
                procs: Vec::new(),
            }
        });
        group.cpu += proc.cpu;
        group.mem_bytes = group.mem_bytes.saturating_add(proc.mem_bytes);
        group.net_bps = group.net_bps.saturating_add(proc.net_bps);
        group.net_bytes = group.net_bytes.saturating_add(proc.net_bytes);
        group.stats_known |= proc.stats_known;
        group.procs.push(proc);
    }
    finish_groups(groups, order)
}

fn group_identity(
    proc: &ProcRow,
    owner: &HashMap<u32, u32>,
    meta: &HashMap<u32, ProcMeta>,
) -> (String, String, Option<PathBuf>) {
    let pid: u32 = proc.id.parse().unwrap_or(0);
    let owner_pid = owner.get(&pid).copied().unwrap_or(pid);
    let ometa = meta.get(&owner_pid).or_else(|| meta.get(&pid));
    let exe = ometa
        .and_then(|m| m.exe.as_deref())
        .or(proc.bundle_path.as_deref());
    identity(exe, &proc.name)
}

fn finish_groups(mut groups: HashMap<String, ProcGroup>, order: Vec<String>) -> Vec<ProcGroup> {
    let mut out: Vec<ProcGroup> = order
        .into_iter()
        .filter_map(|id| groups.remove(&id))
        .map(|mut g| {
            g.procs.sort_by(|a, b| b.mem_bytes.cmp(&a.mem_bytes));
            g
        })
        .collect();
    out.sort_by(|a, b| b.mem_bytes.cmp(&a.mem_bytes));
    out.truncate(80);
    out
}

#[cfg(test)]
#[path = "rollup_test.rs"]
mod rollup_test;
