//! `macwarden monitor` — continuous enforcement with drift detection.
//!
//! Watches plist directories via FSEvents and runs a periodic reconciliation
//! sweep. When drift is detected (a denied service respawned or a new plist
//! appeared), re-enforces the active profile.
//!
//! Monitors camera and microphone hardware via the `sensors` crate. When a
//! hardware activation is detected, an immediate enforcement sweep runs —
//! catching denied services that access the mic/camera within milliseconds
//! instead of waiting for the 60-second sweep.
//!
//! Synchronous design: `notify` crate delivers FSEvents on a background thread
//! into a `std::sync::mpsc` channel. The main thread does `recv_timeout(60s)`,
//! which doubles as the periodic sweep timer. `signal-hook` handles SIGTERM
//! and SIGINT for clean shutdown.
//!
//! Profile hot-reload: when `~/.macwarden/active-profile` changes
//! (e.g. another terminal runs `macwarden apply developer`), the monitor
//! reloads the new profile and re-sweeps.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use catalog::load_builtin_profiles;
use launchd::{MacOsPlatform, Platform};
use policy::{Action, Profile, ServiceInfo, diff, is_critical, resolve_extends, validate_profile};

use super::enforce;
use crate::cli;
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reconciliation sweep interval (also the recv_timeout for the event channel).
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Debounce window — suppress repeated messages for the same service.
const DEBOUNCE_WINDOW: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Monitor message types
// ---------------------------------------------------------------------------

/// Messages flowing through the main monitor channel.
///
/// Replaces the previous approach of multiplexing FSEvents, profile reloads,
/// and sensor events through a single `Vec<String>` with sentinel values.
enum MonitorMessage {
    /// FSEvents fired for one or more plist files.
    FsEvent(Vec<String>),
    /// The active-profile config file changed.
    ProfileReload,
    /// A hardware sensor event (camera/mic activated/deactivated/connected).
    Sensor(sensors::SensorEvent),
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `monitor` command.
///
/// Loads the active profile (or the given override), performs an initial
/// enforcement sweep, then enters the watch loop. Exits cleanly on
/// SIGTERM or SIGINT.
pub fn run(profile_override: Option<&str>) -> Result<()> {
    let builtins = load_builtin_profiles();
    let allow_reload = profile_override.is_none();

    let profile_name = resolve_profile_name(profile_override)?;
    let mut resolved = resolve_profile(&profile_name, &builtins)?;
    let mut current_profile_name = profile_name;

    let platform = MacOsPlatform::new();

    // Register signal handler for clean shutdown.
    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&shutdown))
            .context("failed to register signal handler")?;
    }

    // Initial enforcement sweep.
    println!("macwarden monitor — profile: {current_profile_name}");
    println!("Running initial enforcement sweep...\n");

    let mut stats = MonitorStats::default();
    let initial = enforce_sweep(&resolved, &platform, &mut stats)?;
    if initial == 0 {
        println!("System is in compliance.\n");
    } else {
        println!("\nInitial sweep: {initial} service(s) re-enforced.\n");
    }

    // Start FSEvents watcher.
    let (tx, rx) = mpsc::channel();
    let _watcher = start_watcher(tx.clone(), allow_reload)?;

    // Start hardware sensor monitoring.
    let _sensor_guards = start_sensors(tx.clone());

    println!("Watching for drift (Ctrl+C to stop)...\n");

    let mut debounce: HashMap<String, Instant> = HashMap::new();

    // Main loop: recv_timeout doubles as the sweep timer.
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match rx.recv_timeout(SWEEP_INTERVAL) {
            Ok(msg) => {
                handle_message(
                    msg,
                    &mut resolved,
                    &mut current_profile_name,
                    &builtins,
                    &platform,
                    &mut stats,
                    &mut debounce,
                )?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodic reconciliation sweep.
                let count = enforce_sweep(&resolved, &platform, &mut stats)?;
                stats.sweeps += 1;
                if count > 0 {
                    stats.sweep_enforcements += count;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!("watcher channel disconnected — exiting");
                break;
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }

    println!("\nShutting down.");
    println!(
        "  Sweeps: {}, drift corrections: {} (sweep: {}, event: {}, sensor: {}), \
         profile reloads: {}",
        stats.sweeps,
        stats.sweep_enforcements + stats.event_enforcements + stats.sensor_enforcements,
        stats.sweep_enforcements,
        stats.event_enforcements,
        stats.sensor_enforcements,
        stats.profile_reloads,
    );

    Ok(())
}

/// Dispatch a single monitor message.
fn handle_message(
    msg: MonitorMessage,
    resolved: &mut Profile,
    current_name: &mut String,
    builtins: &[Profile],
    platform: &dyn Platform,
    stats: &mut MonitorStats,
    debounce: &mut HashMap<String, Instant>,
) -> Result<()> {
    match msg {
        MonitorMessage::ProfileReload => {
            handle_profile_reload(resolved, current_name, builtins, platform, stats, debounce)?;
        }
        MonitorMessage::Sensor(event) => {
            handle_sensor_event(&event, resolved, platform, stats)?;
        }
        MonitorMessage::FsEvent(labels) => {
            handle_fs_event(labels, resolved, platform, stats, debounce)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

/// Handle a profile reload signal.
fn handle_profile_reload(
    resolved: &mut Profile,
    current_name: &mut String,
    builtins: &[Profile],
    platform: &dyn Platform,
    stats: &mut MonitorStats,
    debounce: &mut HashMap<String, Instant>,
) -> Result<()> {
    if let Some(new_profile) = try_reload_profile(current_name, builtins)? {
        *current_name = new_profile.0;
        *resolved = new_profile.1;
        debounce.clear();
        stats.profile_reloads += 1;

        let count = enforce_sweep(resolved, platform, stats)?;
        if count > 0 {
            stats.event_enforcements += count;
        }
    }
    Ok(())
}

/// Handle a hardware sensor event.
fn handle_sensor_event(
    event: &sensors::SensorEvent,
    profile: &Profile,
    platform: &dyn Platform,
    stats: &mut MonitorStats,
) -> Result<()> {
    let device = event.device();
    match event {
        sensors::SensorEvent::DeviceActivated(_) => {
            // Screen capture is informational — no enforcement sweep.
            if device.kind == sensors::MediaDeviceKind::Screen {
                println!(
                    "  [{kind}] {name} — screen recording detected",
                    kind = device.kind,
                    name = device.name,
                );
            } else {
                println!(
                    "  [{kind}] {name} activated — running enforcement sweep",
                    kind = device.kind,
                    name = device.name,
                );
                let count = enforce_sweep(profile, platform, stats)?;
                if count > 0 {
                    stats.sensor_enforcements += count;
                } else {
                    println!(
                        "  [{kind}] all running services are allowed by profile",
                        kind = device.kind,
                    );
                }
            }
        }
        sensors::SensorEvent::DeviceDeactivated(_) => {
            println!(
                "  [{kind}] {name} deactivated",
                kind = device.kind,
                name = device.name,
            );
        }
        sensors::SensorEvent::DeviceConnected(_) => {
            println!(
                "  [{kind}] {name} connected",
                kind = device.kind,
                name = device.name,
            );
        }
        sensors::SensorEvent::DeviceDisconnected(_) => {
            println!(
                "  [{kind}] {name} disconnected",
                kind = device.kind,
                name = device.name,
            );
        }
    }
    Ok(())
}

/// Handle FSEvents for plist file changes.
fn handle_fs_event(
    labels: Vec<String>,
    profile: &Profile,
    platform: &dyn Platform,
    stats: &mut MonitorStats,
    debounce: &mut HashMap<String, Instant>,
) -> Result<()> {
    let now = Instant::now();
    let fresh: Vec<String> = labels
        .into_iter()
        .filter(|l| {
            debounce
                .get(l)
                .is_none_or(|last| now.duration_since(*last) > DEBOUNCE_WINDOW)
        })
        .collect();

    if !fresh.is_empty() {
        let count = enforce_sweep(profile, platform, stats)?;
        let now = Instant::now();
        for label in &fresh {
            debounce.insert(label.clone(), now);
        }
        if count > 0 {
            stats.event_enforcements += count;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

/// Determine the profile name to use.
fn resolve_profile_name(profile_override: Option<&str>) -> Result<String> {
    if let Some(name) = profile_override {
        return Ok(name.to_owned());
    }
    let name = cli::read_active_profile()?;
    if name == "base" && !cli::active_profile_path()?.exists() {
        anyhow::bail!(
            "no active profile set. Run `macwarden apply <profile>` first, \
             or use `macwarden monitor --profile <name>`."
        );
    }
    Ok(name)
}

/// Load, validate, and resolve a profile by name.
fn resolve_profile(name: &str, builtins: &[Profile]) -> Result<Profile> {
    let profile = builtins
        .iter()
        .find(|p| p.profile.name == name)
        .context(format!("profile '{name}' not found"))?;

    validate_profile(profile).context("profile validation failed")?;

    resolve_extends(profile, builtins).context(format!("failed to resolve profile '{name}'"))
}

/// Try to reload the profile if the active-profile file changed.
///
/// Returns `Some((new_name, resolved_profile))` if the profile changed,
/// `None` if it's the same profile (or couldn't be loaded).
fn try_reload_profile(
    current_name: &str,
    builtins: &[Profile],
) -> Result<Option<(String, Profile)>> {
    let new_name = cli::read_active_profile()?;
    if new_name == current_name {
        return Ok(None);
    }

    match resolve_profile(&new_name, builtins) {
        Ok(resolved) => {
            println!("\n  [reload] profile changed: {current_name} → {new_name}. Re-sweeping...\n");
            Ok(Some((new_name, resolved)))
        }
        Err(e) => {
            tracing::warn!(
                profile = %new_name,
                error = %e,
                "failed to reload profile — keeping current"
            );
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Enforcement sweep
// ---------------------------------------------------------------------------

/// Discover services, diff against profile, enforce denials. Returns the
/// number of services re-enforced.
///
/// On first drift detection in a session, writes a snapshot for rollback.
fn enforce_sweep(
    profile: &Profile,
    platform: &dyn Platform,
    stats: &mut MonitorStats,
) -> Result<usize> {
    let services = discover_services()?;
    let actions = diff(&services, profile);

    if actions.is_empty() {
        return Ok(0);
    }

    // Deduplicate — engine emits Disable AND Kill for running services,
    // but enforce_disable handles kill internally.
    let mut seen = HashSet::new();
    let to_disable: Vec<&ServiceInfo> = actions
        .iter()
        .filter(|(_, a)| matches!(a, Action::Disable { .. }))
        .filter(|(svc, _)| seen.insert(svc.label.clone()))
        .map(|(svc, _)| svc)
        .collect();

    if to_disable.is_empty() {
        return Ok(0);
    }

    // Write a snapshot on first drift correction so rollback is possible.
    if !stats.snapshot_written {
        if let Err(e) = enforce::write_snapshot("monitor", &to_disable) {
            tracing::warn!(error = %e, "failed to write monitor snapshot");
        }
        stats.snapshot_written = true;
    }

    let count = to_disable.len();
    for svc in &to_disable {
        if is_critical(&svc.label) {
            continue;
        }
        println!(
            "  [drift] re-disabled {} (category: {}, safety: {})",
            svc.label, svc.category, svc.safety,
        );
        enforce::enforce_disable(svc, platform, false, true);
        stats.total_enforcements += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Hardware sensor monitoring
// ---------------------------------------------------------------------------

/// Sensor monitor guards — kept alive for the duration of the watch session.
/// Dropped on shutdown, which cleanly removes the hardware listeners.
struct SensorGuards {
    _mic: Option<sensors::microphone::MicMonitor>,
    _cam: Option<sensors::camera::CameraMonitor>,
    _screen: Option<sensors::screen::ScreenMonitor>,
    _power: Option<sensors::power::PowerMonitor>,
}

/// Start camera, microphone, screen, and power monitoring.
///
/// Events are forwarded into the main channel as `MonitorMessage::Sensor`
/// variants via a bridge thread. Debouncing and sleep/wake suppression
/// are applied at the sensor layer.
fn start_sensors(tx: mpsc::Sender<MonitorMessage>) -> SensorGuards {
    let (sensor_tx, sensor_rx) = mpsc::channel();

    // Start power monitor (sleep/wake awareness).
    let (power, awake) = match sensors::power::PowerMonitor::start() {
        Ok((p, a)) => {
            println!("  Power monitoring: active (sleep/wake awareness)");
            (Some(p), Some(a))
        }
        Err(e) => {
            tracing::debug!(error = %e, "power monitoring unavailable");
            (None, None)
        }
    };

    // Wrap the sensor sender with debouncing.
    let debounced = std::sync::Arc::new(sensors::debounce::DebouncedSender::new(sensor_tx));

    // Bridge thread: forward sensor events into the main MonitorMessage channel.
    // Checks the awake flag to suppress events during sleep/wake transitions.
    let main_tx = tx;
    let awake_flag = awake.clone();
    std::thread::Builder::new()
        .name("sensor-fwd".into())
        .spawn(move || {
            for event in sensor_rx {
                // Suppress sensor events while system is asleep/waking.
                if let Some(ref flag) = awake_flag
                    && !flag.load(std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::debug!("suppressing sensor event during sleep/wake");
                    continue;
                }
                if main_tx.send(MonitorMessage::Sensor(event)).is_err() {
                    break;
                }
            }
        })
        .ok();

    // Start microphone monitor (CoreAudio — multi-device listeners).
    let mic = match sensors::microphone::MicMonitor::start(debounced.inner()) {
        Ok(m) => {
            println!("  Microphone monitoring: active (CoreAudio, multi-device)");
            Some(m)
        }
        Err(e) => {
            tracing::debug!(error = %e, "microphone monitoring unavailable");
            None
        }
    };

    // Start camera monitor (IOKit notifications with polling fallback).
    let cam = match sensors::camera::CameraMonitor::start(debounced.inner().clone()) {
        Ok(c) => {
            println!("  Camera monitoring: active (IOKit)");
            Some(c)
        }
        Err(e) => {
            tracing::debug!(error = %e, "camera monitoring unavailable");
            None
        }
    };

    // Start screen capture monitor (polling).
    let screen = match sensors::screen::ScreenMonitor::start(debounced.inner().clone()) {
        Ok(s) => {
            println!("  Screen capture monitoring: active (polling)");
            Some(s)
        }
        Err(e) => {
            tracing::debug!(error = %e, "screen capture monitoring unavailable");
            None
        }
    };

    SensorGuards {
        _mic: mic,
        _cam: cam,
        _screen: screen,
        _power: power,
    }
}

// ---------------------------------------------------------------------------
// FSEvents watcher
// ---------------------------------------------------------------------------

/// Start an FSEvents watcher on the canonical plist directories.
///
/// Returns the watcher (must be kept alive) and sends `MonitorMessage`
/// variants through the channel when files change.
///
/// When `watch_profile` is true, also watches the active-profile config file
/// and sends a `ProfileReload` message when it changes.
fn start_watcher(
    tx: mpsc::Sender<MonitorMessage>,
    watch_profile: bool,
) -> Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(event) = res else { return };

        // Only react to file creation, modification, and removal.
        let dominated = matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        );
        if !dominated {
            return;
        }

        // Check if the active-profile file changed.
        let is_profile_change = event
            .paths
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("active-profile"));

        if is_profile_change {
            let _ = tx.send(MonitorMessage::ProfileReload);
            return;
        }

        // Extract labels from affected plist paths.
        let labels: Vec<String> = event
            .paths
            .iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("plist"))
            .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(String::from))
            .collect();

        if !labels.is_empty() {
            let _ = tx.send(MonitorMessage::FsEvent(labels));
        }
    })?;

    // Watch plist directories.
    let dirs = cli::plist_dirs().context("failed to expand plist directories")?;
    for dir in &dirs {
        if dir.is_dir() {
            watcher.watch(dir, RecursiveMode::NonRecursive)?;
            tracing::info!(path = %dir.display(), "watching plist directory");
        }
    }

    // Watch the config directory for active-profile changes.
    if watch_profile
        && let Ok(profile_path) = cli::active_profile_path()
        && let Some(config_dir) = profile_path.parent()
        && config_dir.is_dir()
    {
        watcher.watch(config_dir, RecursiveMode::NonRecursive)?;
        tracing::info!(path = %config_dir.display(), "watching config directory");
    }

    Ok(watcher)
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Counters for the monitor session summary.
#[derive(Debug, Default)]
struct MonitorStats {
    /// Number of periodic sweeps completed.
    sweeps: usize,
    /// Total individual enforcement actions taken.
    total_enforcements: usize,
    /// Enforcements triggered by periodic sweep.
    sweep_enforcements: usize,
    /// Enforcements triggered by FSEvents.
    event_enforcements: usize,
    /// Enforcements triggered by hardware sensor events.
    sensor_enforcements: usize,
    /// Number of profile reloads.
    profile_reloads: usize,
    /// Whether a snapshot has been written this session.
    snapshot_written: bool,
}
