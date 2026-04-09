//! Privacy score computation — a 0-100 score based on four privacy dimensions.
//!
//! Pure logic, no platform dependencies. The scoring engine takes pre-collected
//! state from the caller and produces a breakdown with per-dimension results
//! and actionable recommendations.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// State of launchd services grouped by safety tier.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceState {
    /// Total recommended-to-disable groups.
    pub recommended_total: u32,
    /// Recommended groups that are fully stopped.
    pub recommended_stopped: u32,
    /// Total optional groups.
    pub optional_total: u32,
    /// Optional groups that are fully stopped.
    pub optional_stopped: u32,
}

/// State of forensic traces on disk.
#[derive(Debug, Clone, Serialize)]
pub struct TraceState {
    /// Total bytes of artifacts found on disk.
    pub total_bytes: u64,
    /// Number of artifact domains checked.
    pub domains_total: u32,
    /// Number of domains with zero bytes on disk.
    pub domains_clean: u32,
}

/// State of camera and microphone access grants.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceState {
    /// Number of apps authorized for camera access.
    pub camera_grants: u32,
    /// Number of apps authorized for microphone access.
    pub mic_grants: u32,
    /// Number of camera-authorized apps currently running.
    pub camera_running: u32,
    /// Number of mic-authorized apps currently running.
    pub mic_running: u32,
}

/// State of network shield and tracker connections.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkState {
    /// Whether the tracker shield is enabled.
    pub shield_enabled: bool,
    /// Number of active tracker connections detected.
    pub tracker_connections: u32,
    /// Total outbound internet connections (excludes local/private network).
    pub internet_connections: u32,
}

/// Aggregated input for scoring — each dimension is optional.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreInput {
    /// Service enforcement state.
    pub services: Option<ServiceState>,
    /// Forensic trace state.
    pub traces: Option<TraceState>,
    /// Device access state.
    pub devices: Option<DeviceState>,
    /// Network shield state.
    pub network: Option<NetworkState>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Result for a single scoring dimension.
#[derive(Debug, Clone, Serialize)]
pub struct DimensionResult {
    /// Points earned in this dimension.
    pub earned: u32,
    /// Maximum possible points (after weight redistribution).
    pub max: u32,
    /// Human-readable summary (e.g. "34 of 48 groups active").
    pub label: String,
}

/// A recommended action to improve the privacy score.
#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    /// The macwarden command to run.
    pub command: String,
    /// Estimated score improvement in points.
    pub points: u32,
    /// What the command does.
    pub description: String,
}

/// Full scoring breakdown with per-dimension results.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreBreakdown {
    /// Overall 0-100 privacy score.
    pub total: u32,
    /// Service dimension result.
    pub services: Option<DimensionResult>,
    /// Trace dimension result.
    pub traces: Option<DimensionResult>,
    /// Device dimension result.
    pub devices: Option<DimensionResult>,
    /// Network dimension result.
    pub network: Option<DimensionResult>,
    /// Total trace bytes for recommendation descriptions.
    #[serde(skip)]
    trace_bytes: u64,
}

// ---------------------------------------------------------------------------
// Base weights
// ---------------------------------------------------------------------------

/// Base weight for each dimension (summing to 100).
const W_SERVICES: f64 = 40.0;
/// Base weight for the traces dimension.
const W_TRACES: f64 = 25.0;
/// Base weight for the devices dimension.
const W_DEVICES: f64 = 15.0;
/// Base weight for the network dimension.
const W_NETWORK: f64 = 20.0;

/// Byte threshold constants for trace tiers.
const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

/// Compute the privacy score from collected dimension state.
///
/// When a dimension is `None`, its weight is redistributed proportionally
/// to the available dimensions. If all dimensions are `None`, returns 100.
#[must_use]
pub fn compute_score(input: &ScoreInput) -> ScoreBreakdown {
    let available_weight = available_sum(input);

    // All dimensions unavailable => perfect score.
    if available_weight == 0.0 {
        return ScoreBreakdown {
            total: 100,
            services: None,
            traces: None,
            devices: None,
            network: None,
            trace_bytes: 0,
        };
    }

    let scale = 100.0 / available_weight;

    let services = input.services.as_ref().map(|s| {
        let w = W_SERVICES * scale;
        let earned = compute_services(s, w);
        DimensionResult {
            earned,
            max: w.round() as u32,
            label: format_services_label(s),
        }
    });

    let traces = input.traces.as_ref().map(|t| {
        let w = W_TRACES * scale;
        let earned = compute_traces(t, w);
        DimensionResult {
            earned,
            max: w.round() as u32,
            label: format_traces_label(t),
        }
    });

    let devices = input.devices.as_ref().map(|d| {
        let w = W_DEVICES * scale;
        let earned = compute_devices(d, w);
        DimensionResult {
            earned,
            max: w.round() as u32,
            label: format_devices_label(d),
        }
    });

    let network = input.network.as_ref().map(|n| {
        let w = W_NETWORK * scale;
        let earned = compute_network(n, w);
        DimensionResult {
            earned,
            max: w.round() as u32,
            label: format_network_label(n),
        }
    });

    let total_earned: u32 = [&services, &traces, &devices, &network]
        .iter()
        .filter_map(|d| d.as_ref())
        .map(|d| d.earned)
        .sum();

    let total = total_earned.min(100);
    let trace_bytes = input.traces.as_ref().map_or(0, |t| t.total_bytes);

    ScoreBreakdown {
        total,
        services,
        traces,
        devices,
        network,
        trace_bytes,
    }
}

// ---------------------------------------------------------------------------
// Per-dimension scoring
// ---------------------------------------------------------------------------

/// Services: `weight * (stopped_rec + 0.5 * stopped_opt) / (total_rec + 0.5 * total_opt)`.
fn compute_services(s: &ServiceState, weight: f64) -> u32 {
    let denom = f64::from(s.recommended_total) + 0.5 * f64::from(s.optional_total);
    if denom == 0.0 {
        return weight.round() as u32;
    }
    let numer = f64::from(s.recommended_stopped) + 0.5 * f64::from(s.optional_stopped);
    let raw = weight * (numer / denom);
    (raw.round() as u32).min(weight.round() as u32)
}

/// Traces: tiered thresholds on total_bytes.
fn compute_traces(t: &TraceState, weight: f64) -> u32 {
    let pct = if t.total_bytes == 0 {
        1.0
    } else if t.total_bytes < MB {
        0.8
    } else if t.total_bytes < 10 * MB {
        0.6
    } else if t.total_bytes < 100 * MB {
        0.4
    } else if t.total_bytes < GB {
        0.2
    } else {
        0.0
    };
    let raw = weight * pct;
    (raw.round() as u32).min(weight.round() as u32)
}

/// Devices: `weight - min(weight, 2*total_grants + running_count)`.
fn compute_devices(d: &DeviceState, weight: f64) -> u32 {
    let total_grants = f64::from(d.camera_grants + d.mic_grants);
    let running = f64::from(d.camera_running + d.mic_running);
    let penalty = (2.0 * total_grants + running).min(weight);
    let raw = weight - penalty;
    (raw.round().max(0.0) as u32).min(weight.round() as u32)
}

/// Network: half for shield on, half for zero tracker connections.
fn compute_network(n: &NetworkState, weight: f64) -> u32 {
    let half = weight / 2.0;
    let shield_pts = if n.shield_enabled { half } else { 0.0 };
    let conn_pts = if n.tracker_connections == 0 {
        half
    } else {
        (half - f64::from(n.tracker_connections)).max(0.0)
    };
    let raw = shield_pts + conn_pts;
    (raw.round() as u32).min(weight.round() as u32)
}

// ---------------------------------------------------------------------------
// Weight redistribution helper
// ---------------------------------------------------------------------------

/// Sum the base weights of all available (Some) dimensions.
fn available_sum(input: &ScoreInput) -> f64 {
    let mut total = 0.0;
    if input.services.is_some() {
        total += W_SERVICES;
    }
    if input.traces.is_some() {
        total += W_TRACES;
    }
    if input.devices.is_some() {
        total += W_DEVICES;
    }
    if input.network.is_some() {
        total += W_NETWORK;
    }
    total
}

// ---------------------------------------------------------------------------
// Label formatting
// ---------------------------------------------------------------------------

/// Human label for services dimension.
fn format_services_label(s: &ServiceState) -> String {
    let running_rec = s.recommended_total.saturating_sub(s.recommended_stopped);
    let running_opt = s.optional_total.saturating_sub(s.optional_stopped);
    let running = running_rec + running_opt;
    let total = s.recommended_total + s.optional_total;
    format!("{running} of {total} privacy-relevant groups active")
}

/// Human label for traces dimension.
fn format_traces_label(t: &TraceState) -> String {
    format!("{} on disk", format_bytes(t.total_bytes))
}

/// Human label for devices dimension.
fn format_devices_label(d: &DeviceState) -> String {
    let total = d.camera_grants + d.mic_grants;
    let running = d.camera_running + d.mic_running;
    format!("{total} grants, {running} active")
}

/// Human label for network dimension.
fn format_network_label(n: &NetworkState) -> String {
    let shield = if n.shield_enabled { "on" } else { "off" };
    if n.internet_connections > 0 {
        format!(
            "shield {shield}, {} internet connections, {} trackers",
            n.internet_connections, n.tracker_connections
        )
    } else {
        format!(
            "shield {shield}, {} tracker connections",
            n.tracker_connections
        )
    }
}

/// Format bytes as human-readable (1024-based).
fn format_bytes(bytes: u64) -> String {
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

impl ScoreBreakdown {
    /// Produce up to 3 actionable recommendations, sorted by points descending.
    #[must_use]
    pub fn recommendations(&self) -> Vec<Recommendation> {
        let mut recs = Vec::with_capacity(3);

        if let Some(ref svc) = self.services {
            let gap = svc.max.saturating_sub(svc.earned);
            if gap > 0 {
                recs.push(Recommendation {
                    command: "macwarden use privacy".to_owned(),
                    points: gap,
                    description: "apply privacy profile (disables telemetry, Siri, AirPlay, more)"
                        .to_owned(),
                });
            }
        }

        if let Some(ref tr) = self.traces {
            let gap = tr.max.saturating_sub(tr.earned);
            if gap > 0 {
                let size = format_bytes(self.trace_bytes);
                recs.push(Recommendation {
                    command: "macwarden scrub all".to_owned(),
                    points: gap,
                    description: format!("remove {size} of forensic traces"),
                });
            }
        }

        if let Some(ref net) = self.network {
            let gap = net.max.saturating_sub(net.earned);
            if gap > 0 {
                recs.push(Recommendation {
                    command: "macwarden net shield on".to_owned(),
                    points: gap,
                    description: "block 624 known tracker domains".to_owned(),
                });
            }
        }

        recs.sort_by(|a, b| b.points.cmp(&a.points));
        recs.truncate(3);
        recs
    }
}

#[cfg(test)]
#[path = "score_test.rs"]
mod score_test;
