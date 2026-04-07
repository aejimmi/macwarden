//! `macwarden status` — privacy posture dashboard with 0-100 score.
//!
//! Display-only module. Data collection lives in `status_collect`.

use anyhow::{Context, Result};

use policy::score::{
    self, DeviceState, NetworkState, ScoreBreakdown, ScoreInput, ServiceState, TraceState,
};

use crate::cli::OutputFormat;
use crate::commands::scrub_fs;
use crate::commands::status_collect::{self, DomainInfo, GroupInfo};

// ---------------------------------------------------------------------------
// Serialisable JSON envelope
// ---------------------------------------------------------------------------

/// Full status output for JSON serialization.
#[derive(Debug, serde::Serialize)]
struct StatusJson {
    score: ScoreBreakdown,
    recommendations: Vec<score::Recommendation>,
    raw: RawData,
}

/// Raw collector data for JSON output.
#[derive(Debug, serde::Serialize)]
struct RawData {
    services: Option<ServiceState>,
    traces: Option<TraceState>,
    devices: Option<DeviceState>,
    network: Option<NetworkState>,
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

/// Run the `status` command.
pub fn run(format: OutputFormat) -> Result<()> {
    let services = status_collect::collect_services();
    let (traces, domain_infos) = status_collect::collect_traces();
    let devices = status_collect::collect_devices();
    let network = Some(status_collect::collect_network());
    let group_infos = status_collect::collect_group_infos();

    let input = ScoreInput {
        services: services.clone(),
        traces: traces.clone(),
        devices: devices.clone(),
        network: network.clone(),
    };

    let breakdown = score::compute_score(&input);

    match format {
        OutputFormat::Table => {
            print_dashboard(
                &breakdown,
                &group_infos,
                &domain_infos,
                devices.as_ref(),
                network.as_ref(),
            );
        }
        OutputFormat::Json => {
            print_json(&breakdown, &input)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ANSI colors (matching macdecompile DNA style)
// ---------------------------------------------------------------------------

/// Bold white — section headers.
const BOLD: &str = "\x1b[1;37m";
/// Normal white — bar labels, normal items.
const N: &str = "\x1b[37m";
/// Red — concerning items (high running count, large traces).
const RED: &str = "\x1b[31m";
/// Dim gray — metadata, empty bars, secondary info.
const DIM: &str = "\x1b[90m";
/// Green — good state indicators.
const GRN: &str = "\x1b[32m";
/// Reset all formatting.
const RST: &str = "\x1b[0m";
/// Bar width in characters (matches macdecompile).
const BAR_W: u32 = 24;
/// Label width for bar alignment — fits "apple-intelligence" (19) + padding.
const LABEL_W: usize = 20;

/// Groups that are genuinely privacy-invasive (shown in red when active).
const INVASIVE_GROUPS: &[&str] = &[
    "telemetry",
    "profiling",
    "siri",
    "apple-intelligence",
    "media-analysis",
    "location",
    "screentime",
];

// ---------------------------------------------------------------------------
// Table display
// ---------------------------------------------------------------------------

/// Print the privacy dashboard to stdout.
fn print_dashboard(
    breakdown: &ScoreBreakdown,
    groups: &[GroupInfo],
    domains: &[DomainInfo],
    devices: Option<&DeviceState>,
    network: Option<&NetworkState>,
) {
    println!();
    print_score_header(breakdown);
    print_services_section(breakdown, groups);
    print_traces_section(breakdown, domains);
    print_devices_section(breakdown, devices);
    print_network_section(breakdown, network);
    print_recommendations(breakdown);
}

/// Print a bar with filled/empty blocks.
fn print_bar(label: &str, value: u32, max: u32, color: &str) {
    let filled = if max > 0 {
        (u64::from(value) * u64::from(BAR_W) / u64::from(max)).min(u64::from(BAR_W)) as u32
    } else {
        0
    };
    let empty = BAR_W - filled;
    let bar_f: String = "\u{2588}".repeat(filled as usize);
    let bar_e: String = "\u{2591}".repeat(empty as usize);
    println!("  {color}{label:<LABEL_W$}{bar_f}{DIM}{bar_e}{RST} {value:>4}");
}

/// Print the score bar aligned with other sections.
fn print_score_header(breakdown: &ScoreBreakdown) {
    let total = breakdown.total;
    let color = if total >= 70 {
        GRN
    } else if total >= 40 {
        N
    } else {
        RED
    };
    println!("  {DIM}privacy score based on services, traces, device access, and network{RST}");
    println!();
    println!("  {BOLD}SCORE{RST}");
    print_bar("privacy", total, 100, color);
    println!();
}

/// Print the services section — ALL groups with active/disabled status.
fn print_services_section(breakdown: &ScoreBreakdown, groups: &[GroupInfo]) {
    println!("  {BOLD}SERVICES{RST}  {DIM}red = tracks your activity{RST}");
    match &breakdown.services {
        Some(dim) => {
            for g in groups {
                let active = g.running_count > 0;
                let is_invasive = INVASIVE_GROUPS.iter().any(|&r| r == g.name);
                let (color, status) = if !active {
                    (GRN, "disabled".to_owned())
                } else if is_invasive {
                    (RED, "active".to_owned())
                } else {
                    (N, "active".to_owned())
                };
                let filled = if g.total_count > 0 {
                    (u64::from(g.running_count as u32) * u64::from(BAR_W)
                        / u64::from(g.total_count as u32))
                    .min(u64::from(BAR_W)) as u32
                } else {
                    0
                };
                let empty = BAR_W - filled;
                let bar_f: String = "\u{2588}".repeat(filled as usize);
                let bar_e: String = "\u{2591}".repeat(empty as usize);
                println!(
                    "  {color}{:<LABEL_W$}{bar_f}{DIM}{bar_e}{RST} {color}{status}{RST}",
                    g.name
                );
            }
            println!("  {DIM}{}{RST}", dim.label);
        }
        None => {
            println!("  {DIM}unavailable{RST}");
        }
    }
    println!();
}

/// Print the privacy footprint section with bar charts.
fn print_traces_section(breakdown: &ScoreBreakdown, domains: &[DomainInfo]) {
    println!("  {BOLD}PRIVACY FOOTPRINT{RST}  {DIM}files that reveal your activity{RST}");
    match &breakdown.traces {
        Some(dim) => {
            let max_size = domains.first().map_or(1, |d| d.size_bytes.max(1));
            for d in domains {
                let size_str = scrub_fs::format_size(d.size_bytes);
                let ratio = if max_size > 0 {
                    (d.size_bytes as f64 / max_size as f64 * f64::from(BAR_W)) as u32
                } else {
                    0
                };
                let filled = ratio.min(BAR_W);
                let empty = BAR_W - filled;
                let bar_f: String = "\u{2588}".repeat(filled as usize);
                let bar_e: String = "\u{2591}".repeat(empty as usize);
                println!(
                    "  {N}{:<LABEL_W$}{bar_f}{DIM}{bar_e}{RST} {size_str:>10}",
                    d.name
                );
            }
            println!("  {DIM}{}{RST}", dim.label);
        }
        None => {
            println!("  {DIM}unavailable{RST}");
        }
    }
    println!();
}

/// Print the devices section.
fn print_devices_section(breakdown: &ScoreBreakdown, devices: Option<&DeviceState>) {
    println!("  {BOLD}DEVICE ACCESS{RST}");
    match (&breakdown.devices, devices) {
        (Some(_), Some(d)) => {
            let cam_color = if d.camera_running > 0 { RED } else { N };
            let mic_color = if d.mic_running > 0 { RED } else { N };
            print_bar("camera", d.camera_grants, 10, cam_color);
            print_bar("microphone", d.mic_grants, 10, mic_color);
            let running = d.camera_running + d.mic_running;
            if running > 0 {
                println!("  {RED}{running} devices actively in use{RST}");
            }
        }
        _ => {
            println!("  {DIM}unavailable (requires Full Disk Access){RST}");
        }
    }
    println!();
}

/// Print the network section.
fn print_network_section(breakdown: &ScoreBreakdown, network: Option<&NetworkState>) {
    println!("  {BOLD}NETWORK{RST}");
    match (&breakdown.network, network) {
        (Some(_), Some(n)) => {
            let shield_color = if n.shield_enabled { GRN } else { RED };
            let shield_label = if n.shield_enabled {
                "enabled"
            } else {
                "disabled"
            };
            println!(
                "  {N}{:<LABEL_W$}{shield_color}{shield_label}{RST}",
                "tracker shield"
            );
            let conn_color = if n.tracker_connections == 0 { GRN } else { RED };
            println!(
                "  {N}{:<LABEL_W$}{conn_color}{}{RST}",
                "tracker conns", n.tracker_connections
            );
            let net_display = status_collect::collect_network_display();
            if net_display.listening_ports > 0 {
                println!(
                    "  {N}{:<LABEL_W$}{N}{}{RST}",
                    "listening ports", net_display.listening_ports
                );
            }
            if net_display.outbound_conns > 0 {
                println!(
                    "  {N}{:<LABEL_W$}{N}{}{RST}",
                    "outbound conns", net_display.outbound_conns
                );
            }
        }
        _ => {
            println!("  {DIM}unavailable{RST}");
        }
    }
    println!();
}

/// Print recommendations with honest descriptions.
fn print_recommendations(breakdown: &ScoreBreakdown) {
    let recs = breakdown.recommendations();
    if recs.is_empty() {
        return;
    }
    println!("  {BOLD}RECOMMENDATIONS{RST}  {DIM}(review before running){RST}");
    for rec in &recs {
        println!(
            "  {N}{:<28}{RST} {GRN}+{:<2}{RST} pts   {DIM}{}{RST}",
            rec.command, rec.points, rec.description,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

/// Print the status as JSON.
fn print_json(breakdown: &ScoreBreakdown, input: &ScoreInput) -> Result<()> {
    let recs = breakdown.recommendations();
    let output = StatusJson {
        score: breakdown.clone(),
        recommendations: recs,
        raw: RawData {
            services: input.services.clone(),
            traces: input.traces.clone(),
            devices: input.devices.clone(),
            network: input.network.clone(),
        },
    };
    let json = serde_json::to_string_pretty(&output).context("failed to serialize status")?;
    println!("{json}");
    Ok(())
}
