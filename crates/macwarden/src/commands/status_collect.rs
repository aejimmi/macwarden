//! Data collectors for `macwarden status` — gathers state from each dimension.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;

use catalog::{load_builtin_artifacts, load_builtin_groups};
use launchd::Platform;
use policy::group::Safety;
use policy::score::{DeviceState, NetworkState, ServiceState, TraceState};
use policy::{ArtifactAction, ServiceInfo, resolve_group_services};

use crate::cli;
use crate::commands::scrub_fs;

// ---------------------------------------------------------------------------
// Display types
// ---------------------------------------------------------------------------

/// Per-group info for the services section.
pub struct GroupInfo {
    pub name: String,
    pub safety: Safety,
    pub running_count: usize,
    pub total_count: usize,
}

/// Per-domain info for the footprint section.
pub struct DomainInfo {
    pub name: String,
    pub size_bytes: u64,
}

/// Extra network display data (not part of scoring).
pub struct NetworkDisplay {
    pub listening_ports: u32,
    pub outbound_conns: u32,
}

// ---------------------------------------------------------------------------
// Service collector
// ---------------------------------------------------------------------------

/// Collect service state by safety tier.
pub fn collect_services() -> Option<ServiceState> {
    collect_services_inner().ok()
}

/// Inner collector that can fail.
fn collect_services_inner() -> Result<ServiceState> {
    let groups = load_builtin_groups();
    let all_services: Vec<ServiceInfo> = crate::commands::scan::discover_services()?;

    let mut rec_total: u32 = 0;
    let mut rec_stopped: u32 = 0;
    let mut opt_total: u32 = 0;
    let mut opt_stopped: u32 = 0;

    for group in &groups {
        let matched = resolve_group_services(group, &all_services);
        let any_running = matched
            .iter()
            .any(|s| s.state == policy::ServiceState::Running);

        match group.safety {
            Safety::Recommended => {
                rec_total += 1;
                if !any_running {
                    rec_stopped += 1;
                }
            }
            Safety::Optional => {
                opt_total += 1;
                if !any_running {
                    opt_stopped += 1;
                }
            }
            Safety::Keep => {}
        }
    }

    Ok(ServiceState {
        recommended_total: rec_total,
        recommended_stopped: rec_stopped,
        optional_total: opt_total,
        optional_stopped: opt_stopped,
    })
}

// ---------------------------------------------------------------------------
// Trace collector
// ---------------------------------------------------------------------------

/// Collect trace state and per-domain details.
pub fn collect_traces() -> (Option<TraceState>, Vec<DomainInfo>) {
    let (state, infos) = collect_traces_inner();
    (Some(state), infos)
}

/// Inner trace collector (infallible).
fn collect_traces_inner() -> (TraceState, Vec<DomainInfo>) {
    let domains = load_builtin_artifacts();
    let mut total_bytes: u64 = 0;
    let mut domains_total: u32 = 0;
    let mut domains_clean: u32 = 0;
    let mut domain_infos = Vec::new();

    for domain in &domains {
        let mut domain_size: u64 = 0;
        domains_total += 1;

        for artifact in &domain.artifacts {
            if let ArtifactAction::Path(ref raw_path) = artifact.action {
                let expanded =
                    cli::expand_home(raw_path).unwrap_or_else(|_| PathBuf::from(raw_path));
                domain_size += scrub_fs::compute_size(&expanded);
            }
        }

        if domain_size == 0 {
            domains_clean += 1;
        }

        total_bytes += domain_size;

        if domain_size > 0 {
            domain_infos.push(DomainInfo {
                name: domain.name.clone(),
                size_bytes: domain_size,
            });
        }
    }

    domain_infos.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    (
        TraceState {
            total_bytes,
            domains_total,
            domains_clean,
        },
        domain_infos,
    )
}

// ---------------------------------------------------------------------------
// Device collector
// ---------------------------------------------------------------------------

/// Collect device access state from TCC.
pub fn collect_devices() -> Option<DeviceState> {
    collect_devices_inner().ok()
}

/// Inner device collector.
fn collect_devices_inner() -> Result<DeviceState> {
    let user_db =
        super::devices::expand_tcc_path("~/Library/Application Support/com.apple.TCC/TCC.db")?;

    let entries = super::devices::read_tcc_db(&user_db)?;

    let camera_grants = entries
        .iter()
        .filter(|e| {
            e.service == super::devices::TCC_CAMERA && e.auth_value == super::devices::AUTH_ALLOWED
        })
        .count() as u32;

    let mic_grants = entries
        .iter()
        .filter(|e| {
            e.service == super::devices::TCC_MICROPHONE
                && e.auth_value == super::devices::AUTH_ALLOWED
        })
        .count() as u32;

    let camera_running = u32::from(sensors::camera::is_active().unwrap_or(false));
    let mic_running = u32::from(sensors::microphone::is_active().unwrap_or(false));

    Ok(DeviceState {
        camera_grants,
        mic_grants,
        camera_running,
        mic_running,
    })
}

// ---------------------------------------------------------------------------
// Network collector
// ---------------------------------------------------------------------------

/// Collect network shield state and active tracker connection count.
pub fn collect_network() -> NetworkState {
    let shield = super::net::net_shield::load_shield_config();
    let entries = collect_raw_connections();
    let tracker_connections = entries.iter().filter(|e| e.tracker.is_some()).count() as u32;

    // Count internet (non-local) connections using the canonical check.
    let internet_connections = entries
        .iter()
        .filter(|e| {
            e.remote_ip
                .as_deref()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| !net::is_local_network(&ip))
        })
        .count() as u32;

    NetworkState {
        shield_enabled: shield.enabled,
        tracker_connections,
        internet_connections,
    }
}

/// Collect listening ports and outbound connections.
pub fn collect_network_display() -> NetworkDisplay {
    let entries = collect_raw_connections();
    let listening = entries.iter().filter(|e| e.conn_type == "LISTEN").count() as u32;
    let outbound = entries
        .iter()
        .filter(|e| e.conn_type == "ESTABLISHED")
        .count() as u32;
    NetworkDisplay {
        listening_ports: listening,
        outbound_conns: outbound,
    }
}

/// Shared: collect and enrich network connections.
fn collect_raw_connections() -> Vec<super::network::NetEntry> {
    let groups = load_builtin_groups();
    let platform = launchd::MacOsPlatform::new();
    let pid_to_label: HashMap<u32, String> = platform
        .enumerate()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| e.pid.map(|p| (p, e.label)))
        .collect();

    let mut entries = super::network::collect_network_connections_pub(&pid_to_label, &groups);
    super::network_enrich::enrich_entries(&mut entries);
    entries
}

// ---------------------------------------------------------------------------
// Group info collector
// ---------------------------------------------------------------------------

/// Collect per-group service info — ALL groups, not just active.
pub fn collect_group_infos() -> Vec<GroupInfo> {
    let groups = load_builtin_groups();
    let all_services = crate::commands::scan::discover_services().unwrap_or_default();

    let mut infos: Vec<GroupInfo> = groups
        .iter()
        .filter_map(|group| {
            if group.safety == Safety::Keep {
                return None;
            }
            let matched = resolve_group_services(group, &all_services);
            let total = matched.len();
            let running = matched
                .iter()
                .filter(|s| s.state == policy::ServiceState::Running)
                .count();
            Some(GroupInfo {
                name: group.name.clone(),
                safety: group.safety,
                running_count: running,
                total_count: total,
            })
        })
        .collect();

    // Sort: active recommended first, then active optional, then disabled.
    infos.sort_by(|a, b| {
        let a_active = a.running_count > 0;
        let b_active = b.running_count > 0;
        b_active
            .cmp(&a_active)
            .then_with(|| a.safety.cmp(&b.safety))
            .then_with(|| b.running_count.cmp(&a.running_count))
    });

    infos
}
