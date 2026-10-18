//! Daemon-side banwatch integration (spec 010, stages C–F).
//!
//! [`BanwatchService`] owns the pure [`banwatch::Engine`] behind a single
//! `Mutex` (the concurrency shape CLAUDE.md prescribes). The daemon's
//! enforcement read path — [`BanwatchService::active_ban_ips`] — takes this lock
//! only to **snapshot** the active-ban IP set out of the engine's in-memory
//! store into a `Vec`, then releases it before the caller composes the rule set.
//! Sourcing bans from that authoritative in-memory set (rather than reopening
//! the etch store on the read path) is what keeps a daemon reload from tearing
//! against an in-flight etch WAL compaction. The lock otherwise only serializes
//! the infrequent signal/sweep/mutation writes. It is the seam between the
//! platform feeds that live in the daemon and the pure engine:
//!
//! - [`BanwatchService::on_verdict`] — the daemon's own connection verdict stream
//!   into the `repeat-blocked` detector (the no-privilege default).
//! - [`BanwatchService::on_auth_line`] — a unified-log line into the
//!   `auth-failure` detector, self-disabling on `<private>` redaction.
//! - [`BanwatchService::observe_packet`] — a BPF `(ip, port, syn)` event into the
//!   `port-scan` detector.
//!
//! A ban/unban is persisted by the engine, recorded to metrics here, and returned
//! to the caller, which reloads the daemon's live `RuleSet` (so the sysext's
//! `RuleWatcher` reloads) and pushes the wire event. Every method is total —
//! a poisoned lock or a disabled engine yields "no event", never a panic.
//!
//! # What `Capability::BanWatch` actually promises today
//!
//! **Manual bans and the periodic sweeper only.** [`BanwatchService::set_ban`]
//! (operator ban/unban over IPC) and [`BanwatchService::sweep`] (expiry + decay)
//! are live and enforced. The three auto-detection feeds below —
//! [`BanwatchService::on_verdict`], [`BanwatchService::on_auth_line`], and
//! [`BanwatchService::observe_packet`] — are implemented and unit-tested but have
//! **no live producer wired in this build** (they are `#[allow(dead_code)]`).
//! Automatic banning is therefore **not active**; the capability advertises the
//! surface that genuinely works (manual bans + sweeper), and wiring the feeds is
//! deliberately out of scope here (it depends on the spec-009 inbound NE verdict
//! stream, not activated on this host).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use banwatch::detect::{self, PortScanDetector};
use banwatch::record::{BanRecord, BanSource};
use banwatch::{BanEvent, Engine, now_secs};
use ipc::protocol::WireBan;
use metrics::{MetricEvent, MetricsStore};
use tracing::{info, warn};

use super::error::{Result, ServerError};

/// The daemon's banwatch integration: the engine plus platform-feed adapters.
pub struct BanwatchService {
    engine: Mutex<Engine>,
    port_scan: Mutex<PortScanDetector>,
    metrics: Option<Arc<Mutex<MetricsStore>>>,
    /// Latched once the auth-failure feed observes a `<private>` redaction, so
    /// the one-time warning fires once and the detector then stays inert.
    auth_redaction_warned: AtomicBool,
}

impl BanwatchService {
    /// Open the service for a `~/.macwarden/` base directory, or `None` when
    /// banwatch is disabled in config (so the daemon withholds the capability).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Banwatch`] only if the etch ban store cannot be
    /// opened; config loading itself fails open to defaults.
    pub fn open(
        base_dir: &Path,
        metrics: Option<Arc<Mutex<MetricsStore>>>,
    ) -> Result<Option<Self>> {
        let engine = Engine::open(base_dir).map_err(|e| ServerError::Banwatch(e.to_string()))?;
        if !engine.config().enabled {
            info!("banwatch disabled in config; capability withheld");
            return Ok(None);
        }
        let cfg = engine.config();
        let port_scan = PortScanDetector::new(
            cfg.port_scan.enabled,
            cfg.port_scan.distinct_ports,
            cfg.port_scan.syn_rate,
            cfg.port_scan.find_time,
        );
        Ok(Some(Self {
            engine: Mutex::new(engine),
            port_scan: Mutex::new(port_scan),
            metrics,
            auth_redaction_warned: AtomicBool::new(false),
        }))
    }

    /// Snapshot the active-ban IP set from the engine's **in-memory** store
    /// (deduplicated, sorted). This is the authoritative source the daemon's
    /// ruleset composition reads — never the on-disk etch store — so a reload
    /// can never tear against an in-flight WAL compaction (the torn-read bug).
    ///
    /// The engine lock is held only for the snapshot into a `Vec`, then released
    /// before the caller composes the rule set, so it never nests under the
    /// ruleset lock. A poisoned lock yields an empty set (fail-open to "no bans",
    /// never a panic).
    #[must_use]
    pub fn active_ban_ips(&self) -> Vec<IpAddr> {
        let now = now_secs();
        let mut ips: Vec<IpAddr> = self
            .with_engine(|e| Some(e.active_bans(now)))
            .unwrap_or_default()
            .into_iter()
            .map(|rec| rec.ip)
            .collect();
        ips.sort_unstable();
        ips.dedup();
        ips
    }

    /// List the active bans as wire DTOs, newest ban first.
    #[must_use]
    pub fn list_bans(&self) -> Vec<WireBan> {
        let now = now_secs();
        let mut records = self
            .engine
            .lock()
            .map(|e| e.active_bans(now))
            .unwrap_or_default();
        records.sort_by(|a, b| b.banned_at.cmp(&a.banned_at));
        records.iter().map(wire_ban).collect()
    }

    /// Apply a manual ban or unban and record metrics for each resulting event.
    /// Returns whether the mutation took effect. The caller reloads the live
    /// rule set so the change enforces.
    pub fn set_ban(
        &self,
        ip_str: &str,
        ban: bool,
        ban_secs: Option<i64>,
        _detector: Option<&str>,
    ) -> Result<bool> {
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| ServerError::Banwatch(format!("invalid IP `{ip_str}`")))?;
        let now = now_secs();
        let events: Vec<BanEvent> = self
            .with_engine(|e| {
                Some(if ban {
                    e.manual_ban(ip, ban_secs, now).into_iter().collect()
                } else {
                    e.manual_unban(ip, now)
                })
            })
            .unwrap_or_default();
        for event in &events {
            self.record_metric(event);
        }
        Ok(!events.is_empty())
    }

    /// Run the periodic sweep (expiry + decay), recording each unban to metrics.
    #[must_use]
    pub fn sweep(&self) -> Vec<BanEvent> {
        let events = self
            .with_engine(|e| Some(e.sweep(now_secs())))
            .unwrap_or_default();
        for event in &events {
            self.record_metric(event);
        }
        events
    }

    // -- internals ----------------------------------------------------------

    /// Run `f` under the engine lock, yielding `None` on a poisoned lock.
    fn with_engine<R>(&self, f: impl FnOnce(&mut Engine) -> Option<R>) -> Option<R> {
        self.engine.lock().ok().and_then(|mut e| f(&mut e))
    }

    /// Write the metric row for a ban/unban lifecycle event (best-effort).
    fn record_metric(&self, event: &BanEvent) {
        let Some(store) = &self.metrics else {
            return;
        };
        let Ok(guard) = store.lock() else {
            return;
        };
        if let Err(e) = guard.record(&metric_event(event)) {
            warn!(error = %e, "banwatch metric record failed");
        }
    }
}

/// Live platform-feed adapters (spec 010 stages C/E/F).
///
/// These turn the daemon's platform inputs — its own connection **verdict**
/// stream (`repeat-blocked`), the `log stream` subprocess (`auth-failure`), and
/// the BPF capture feed (`port-scan`) — into engine signals. They are the seam
/// wired when the inbound NE verdict stream is live: a `repeat-blocked` ban keyed
/// on a flow's *remote* endpoint only makes sense for **inbound** flows to a
/// listening service (feeding the *outbound* connection stream would ban a
/// destination for every app), so the live source is the spec-009 inbound NE
/// verdict path, not yet activated on this host. Implemented to that boundary and
/// exercised directly by the unit tests (same pattern as spec 009). Marked
/// `dead_code` only because no live feed calls them in this build.
#[allow(dead_code)]
impl BanwatchService {
    /// Whether the `auth-failure` detector is enabled (opt-in) in config — the
    /// gate the daemon checks before spawning the `log stream` subprocess.
    #[must_use]
    pub fn auth_failure_enabled(&self) -> bool {
        self.engine
            .lock()
            .map(|e| e.config().auth_failure.enabled)
            .unwrap_or(false)
    }

    /// Feed one connection verdict into the `repeat-blocked` detector. Returns a
    /// ban event when the flow's remote IP trips the threshold.
    #[must_use]
    pub fn on_verdict(&self, remote_ip: IpAddr, allowed: bool) -> Option<BanEvent> {
        let signal = detect::on_verdict(remote_ip, allowed)?;
        let event = self.with_engine(|e| e.record(&signal, now_secs()))?;
        self.record_metric(&event);
        Some(event)
    }

    /// Feed one unified-log line into the `auth-failure` detector. Returns a ban
    /// event when the peer trips the threshold. On the first `<private>`
    /// redaction, logs a one-time warning; the detector then stays inert (it can
    /// never see a real peer), matching the spec's opt-in caveat.
    #[must_use]
    pub fn on_auth_line(&self, line: &str) -> Option<BanEvent> {
        if let detect::AuthLine::Redacted = detect::parse_auth_failure(line) {
            if !self.auth_redaction_warned.swap(true, Ordering::Relaxed) {
                warn!(
                    "auth-failure detector saw a <private> peer: the unified log \
                     redacts SSH/Screen-Sharing peer IPs on this host; the detector \
                     stays inert. Enable private-data logging (a signed profile) to use it."
                );
            }
            return None;
        }
        let signal = detect::authlog::signal_from_line(line)?;
        let event = self.with_engine(|e| e.record(&signal, now_secs()))?;
        self.record_metric(&event);
        Some(event)
    }

    /// Feed one BPF packet event into the `port-scan` detector. Returns a ban
    /// event when the source crosses a scan threshold.
    #[must_use]
    pub fn observe_packet(&self, ip: IpAddr, port: u16, is_syn: bool) -> Option<BanEvent> {
        let now = now_secs();
        let signal = self
            .port_scan
            .lock()
            .ok()
            .and_then(|mut d| d.observe(ip, port, is_syn, now))?;
        let event = self.with_engine(|e| e.record(&signal, now))?;
        self.record_metric(&event);
        Some(event)
    }

    /// Register the host's own interface addresses for the `ignore_self` guard.
    pub fn set_self_addrs(&self, addrs: Vec<IpAddr>) {
        if let Ok(mut e) = self.engine.lock() {
            e.set_self_addrs(addrs);
        }
    }
}

/// Convert a [`BanRecord`] into its wire DTO.
fn wire_ban(rec: &BanRecord) -> WireBan {
    WireBan {
        ip: rec.ip.to_string(),
        detector: rec.detector.clone(),
        banned_at_ms: to_ms(rec.banned_at),
        expires_at_ms: rec.expires_at.map(to_ms),
        escalation_count: rec.escalation_count,
        source: source_str(rec.source).to_owned(),
    }
}

/// Convert a [`BanEvent`] into its metric event.
fn metric_event(event: &BanEvent) -> MetricEvent {
    match event {
        BanEvent::Banned(rec) => MetricEvent::IpBanned {
            ip: rec.ip.to_string(),
            detector: rec.detector.clone(),
            ban_secs: rec
                .expires_at
                .map(|exp| (exp - rec.banned_at).max(0) as u64),
            escalation_count: rec.escalation_count,
            source: source_str(rec.source).to_owned(),
        },
        BanEvent::Unbanned { ip, detector } => MetricEvent::IpUnbanned {
            ip: ip.to_string(),
            detector: detector.clone(),
        },
    }
}

/// The wire/metrics string for a ban source (a detector id, or `manual`).
fn source_str(source: BanSource) -> &'static str {
    source.detector()
}

/// Convert unix seconds to unix milliseconds, clamping negatives to zero.
fn to_ms(secs: i64) -> u64 {
    (secs.max(0) as u64).saturating_mul(1_000)
}

/// The base directory (`~/.macwarden/`) for a rules directory.
#[must_use]
pub fn base_dir_of(rules_dir: &Path) -> PathBuf {
    rules_dir
        .parent()
        .map_or_else(|| rules_dir.to_path_buf(), Path::to_path_buf)
}

#[cfg(test)]
#[path = "banwatch_svc_test.rs"]
mod banwatch_svc_test;
