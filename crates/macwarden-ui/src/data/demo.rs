//! Deterministic demo data — the default source for `cargo run`.
//!
//! A tiny linear-congruential generator jitters throughput each tick so the
//! panel feels live without any real system access. Fully cross-platform, so
//! the numbers are identical on macOS and Linux CI.

use std::path::PathBuf;

use super::model::{
    AppRow, Detail, DomainRow, Flow, NetRow, ProcRow, Signature, Totals, Verdict, format_bytes,
};
use super::source::PanelSource;

/// A seeded, allocation-free PRNG for jittering rates deterministically.
struct Lcg(u64);

impl Lcg {
    fn next_u32(&mut self) -> u32 {
        // Numerical Recipes constants.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (self.0 >> 33) as u32
    }

    /// Uniform in `[lo, hi]`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + u64::from(self.next_u32()) % (hi - lo + 1)
    }
}

/// The default panel source: a curated set of apps with plausible traffic.
pub struct DemoSource {
    apps: Vec<AppRow>,
    rng: Lcg,
    totals: Totals,
    procs: Vec<ProcRow>,
    /// Canonical per-app flow; `Active(base)` holds the un-jittered baseline.
    flows: Vec<Flow>,
    /// Per-app, per-domain baseline rate so live jitter mean-reverts (never
    /// drifts off into implausible GB/s territory).
    domain_bases: Vec<Vec<u64>>,
}

impl Default for DemoSource {
    fn default() -> Self {
        Self::new()
    }
}

fn app_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/Applications/{name}.app"))
}

fn dom(host: &str, country: &str, verdict: Verdict, rate: u64) -> DomainRow {
    DomainRow {
        host: host.to_string(),
        country: Some(country.to_string()),
        verdict,
        rate_bps: rate,
        total_bytes: rate.saturating_mul(60),
        sockets: 1,
        allowed: !matches!(verdict, Verdict::Blocked),
    }
}

impl DemoSource {
    /// Build the demo dataset.
    #[must_use]
    pub fn new() -> Self {
        let apps = vec![
            AppRow {
                id: "com.google.Chrome".into(),
                name: "Google Chrome".into(),
                bundle_path: Some(app_path("Google Chrome")),
                allowed: true,
                known_bad: false,
                is_system: false,
                down_bytes: 214_000_000,
                up_bytes: 8_400_000,
                flow: Flow::Active(2_000_000),
                domains: vec![
                    dom("googlevideo.com", "US", Verdict::Allow, 1_800_000),
                    dom("clients4.google.com", "US", Verdict::Allow, 42_000),
                    dom("doubleclick.net", "US", Verdict::Tracker, 3_100),
                    dom("google-analytics.com", "US", Verdict::Tracker, 900),
                ],
            },
            AppRow {
                id: "com.apple.Safari".into(),
                name: "Safari".into(),
                bundle_path: Some(PathBuf::from("/Applications/Safari.app")),
                allowed: true,
                known_bad: false,
                is_system: false,
                down_bytes: 41_000_000,
                up_bytes: 2_100_000,
                flow: Flow::Active(300_000),
                domains: vec![
                    dom("apple.com", "US", Verdict::Allow, 120_000),
                    dom("icloud.com", "US", Verdict::Allow, 34_000),
                    dom("cdn-apple.com", "US", Verdict::Allow, 12_000),
                ],
            },
            AppRow {
                id: "com.tinyspeck.slackmacgap".into(),
                name: "Slack".into(),
                bundle_path: Some(app_path("Slack")),
                allowed: true,
                known_bad: false,
                is_system: false,
                down_bytes: 14_000_000,
                up_bytes: 1_900_000,
                flow: Flow::Active(50_000),
                domains: vec![
                    dom("slack.com", "US", Verdict::Allow, 88_000),
                    dom("slack-edge.com", "US", Verdict::Allow, 22_000),
                    dom("segment.io", "US", Verdict::Tracker, 1_400),
                ],
            },
            AppRow {
                id: "us.zoom.xos".into(),
                name: "zoom.us".into(),
                bundle_path: Some(app_path("zoom.us")),
                allowed: true,
                known_bad: false,
                is_system: false,
                down_bytes: 96_000_000,
                up_bytes: 900_000,
                flow: Flow::Session(4_200_000),
                domains: vec![
                    dom("zoom.us", "US", Verdict::Allow, 2_400_000),
                    dom("zoomgov.com", "US", Verdict::Allow, 140_000),
                ],
            },
            AppRow {
                id: "com.spotify.client".into(),
                name: "Spotify".into(),
                bundle_path: Some(app_path("Spotify")),
                allowed: true,
                known_bad: false,
                is_system: false,
                down_bytes: 22_000_000,
                up_bytes: 400_000,
                flow: Flow::Idle,
                domains: vec![
                    dom("spotifycdn.com", "SE", Verdict::Allow, 320_000),
                    dom("scdn.co", "SE", Verdict::Allow, 96_000),
                    dom("crashlytics.com", "US", Verdict::Tracker, 700),
                ],
            },
            AppRow {
                id: "com.adobe.Photoshop".into(),
                name: "Photoshop".into(),
                bundle_path: Some(PathBuf::from(
                    "/Applications/Adobe Photoshop 2024/Adobe Photoshop 2024.app",
                )),
                allowed: false,
                known_bad: false,
                is_system: false,
                down_bytes: 6_000_000,
                up_bytes: 600_000,
                flow: Flow::Idle,
                domains: vec![
                    dom("adobe.io", "US", Verdict::Blocked, 0),
                    dom("adobestats.io", "US", Verdict::Tracker, 0),
                ],
            },
            AppRow {
                id: "internal.telemetryd".into(),
                name: "telemetryd".into(),
                bundle_path: None,
                allowed: false,
                known_bad: true,
                is_system: false,
                down_bytes: 500_000,
                up_bytes: 500_000,
                flow: Flow::Zero,
                domains: vec![
                    dom("metrics.example.net", "US", Verdict::Blocked, 0),
                    dom("t.appsflyer.com", "US", Verdict::Tracker, 0),
                ],
            },
            AppRow {
                id: "com.apple.apsd".into(),
                name: "apsd".into(),
                bundle_path: None,
                allowed: true,
                known_bad: false,
                is_system: true,
                down_bytes: 3_200_000,
                up_bytes: 210_000,
                flow: Flow::Active(9_000),
                domains: vec![
                    dom("push.apple.com", "US", Verdict::Allow, 6_000),
                    dom("courier.push.apple.com", "US", Verdict::Allow, 2_000),
                ],
            },
            AppRow {
                id: "com.apple.trustd".into(),
                name: "trustd".into(),
                bundle_path: None,
                allowed: true,
                known_bad: false,
                is_system: true,
                down_bytes: 640_000,
                up_bytes: 88_000,
                flow: Flow::Idle,
                domains: vec![
                    dom("ocsp.apple.com", "US", Verdict::Allow, 0),
                    dom("valid.apple.com", "US", Verdict::Allow, 0),
                ],
            },
        ];

        let procs = derive_procs(&apps);
        let flows = apps.iter().map(|a| a.flow).collect();
        let domain_bases = apps
            .iter()
            .map(|a| a.domains.iter().map(|d| d.rate_bps).collect())
            .collect();
        let totals = totals_from_apps(&apps, 1_284, 3_612);
        Self {
            apps,
            rng: Lcg(0x5eed_1234_dead_beef),
            totals,
            procs,
            flows,
            domain_bases,
        }
    }

    fn app_by_id(&self, id: &str) -> Option<&AppRow> {
        self.apps.iter().find(|a| a.id == id)
    }
}

/// Footer totals are the sum of the per-app Today totals, so the bar always
/// agrees with the Apps tab under the Today scope (never a runaway counter).
fn totals_from_apps(apps: &[AppRow], trackers_blocked: u64, connections: u64) -> Totals {
    Totals {
        down_bytes: apps.iter().map(|a| a.down_bytes).sum(),
        up_bytes: apps.iter().map(|a| a.up_bytes).sum(),
        trackers_blocked,
        connections,
        down_bps: 0,
        up_bps: 0,
    }
}

fn derive_procs(apps: &[AppRow]) -> Vec<ProcRow> {
    let mut procs: Vec<ProcRow> = apps
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let net_bps: u64 = a.domains.iter().map(|d| d.rate_bps).sum();
            ProcRow {
                id: a.id.clone(),
                name: a.name.clone(),
                bundle_path: a.bundle_path.clone(),
                cpu: 2.0 + (i as f32) * 3.5,
                mem_bytes: 180_000_000 + (i as u64) * 240_000_000,
                net_bps,
                net_bytes: a.down_bytes + a.up_bytes,
                stats_known: true,
            }
        })
        .collect();
    procs.push(ProcRow {
        id: "kernel_task".into(),
        name: "kernel_task".into(),
        bundle_path: None,
        cpu: 6.4,
        mem_bytes: 1_400_000_000,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
    });
    procs.push(ProcRow {
        id: "WindowServer".into(),
        name: "WindowServer".into(),
        bundle_path: None,
        cpu: 9.1,
        mem_bytes: 720_000_000,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
    });
    procs
}

/// Advance one app: jitter live domain rates (only while streaming), refresh
/// the real-time flow around its baseline, and drift the Today totals by a few KB.
fn tick_app(app: &mut AppRow, base_flow: Flow, bases: &[u64], rng: &mut Lcg) {
    let streaming = matches!(base_flow, Flow::Active(_));
    let allowed = app.allowed;
    for (d, &base) in app.domains.iter_mut().zip(bases.iter()) {
        if !streaming || !allowed || d.verdict == Verdict::Blocked {
            d.rate_bps = 0;
            continue;
        }
        let base = base.max(1_000);
        d.rate_bps = rng.range(base / 2, base + base / 2);
    }
    app.flow = match base_flow {
        Flow::Active(base) => Flow::Active(rng.range(base * 3 / 4, base * 5 / 4)),
        other => other,
    };
    app.down_bytes = app.down_bytes.saturating_add(rng.range(200, 3_000));
    app.up_bytes = app.up_bytes.saturating_add(rng.range(50, 400));
}

/// Gently random-walk CPU for active processes so the Processes tab feels live.
fn jitter_cpu(procs: &mut [ProcRow], rng: &mut Lcg) {
    for p in procs {
        if p.bundle_path.is_some() || p.net_bps > 0 {
            p.cpu = (p.cpu + rng.range(0, 40) as f32 / 10.0 - 2.0).clamp(0.1, 95.0);
        }
    }
}

fn detail_from_app(app: &AppRow) -> Detail {
    let hostnames: Vec<String> = app.domains.iter().map(|d| d.host.clone()).collect();
    let denied = app
        .domains
        .iter()
        .filter(|d| matches!(d.verdict, Verdict::Blocked | Verdict::Tracker))
        .count() as u32;
    let allowed = app.domains.len() as u32 - denied;
    Detail {
        name: app.name.clone(),
        bundle_id: app.id.clone(),
        bundle_path: app.bundle_path.clone(),
        in_bytes: app.down_bytes,
        out_bytes: app.up_bytes,
        path: app.bundle_path.as_ref().map_or_else(
            || format!("/usr/libexec/{}", app.name),
            |p| p.display().to_string(),
        ),
        user: "kingkong".into(),
        signature: signature_for(&app.id),
        openbinary: openbinary_for(&app.id),
        hostnames,
        ips: vec!["142.250.72.14".into(), "17.253.144.10".into()],
        ports: vec!["443/tcp".into(), "443/udp (QUIC)".into()],
        allowed_count: allowed,
        denied_count: denied,
        allowed: app.allowed,
    }
}

fn signature_for(id: &str) -> Signature {
    if id.starts_with("com.apple.") {
        Signature::Apple
    } else if id == "internal.telemetryd" {
        Signature::Unsigned
    } else {
        Signature::DevId(team_for(id).to_string())
    }
}

fn team_for(id: &str) -> &'static str {
    match id {
        "com.google.Chrome" => "EQHXZ8M8AV",
        "com.spotify.client" => "2FNC3A47ZF",
        "us.zoom.xos" => "BJ4HAAB9B3",
        _ => "9BNSXJN65R",
    }
}

fn openbinary_for(id: &str) -> String {
    match id {
        "com.google.Chrome" => "known good · Chrome 126".into(),
        "com.apple.Safari" => "known good · Safari 17.5".into(),
        "internal.telemetryd" => "known bad · unsigned telemetry".into(),
        _ => "not yet analyzed".into(),
    }
}

impl PanelSource for DemoSource {
    fn name(&self) -> &'static str {
        "demo"
    }

    fn tick(&mut self) {
        {
            let Self {
                apps,
                rng,
                flows,
                domain_bases,
                ..
            } = &mut *self;
            for ((app, &base_flow), bases) in
                apps.iter_mut().zip(flows.iter()).zip(domain_bases.iter())
            {
                tick_app(app, base_flow, bases, rng);
            }
        }
        self.procs = derive_procs(&self.apps);
        jitter_cpu(&mut self.procs, &mut self.rng);
        self.totals.down_bytes = self.apps.iter().map(|a| a.down_bytes).sum();
        self.totals.up_bytes = self.apps.iter().map(|a| a.up_bytes).sum();
        self.totals.trackers_blocked = self
            .totals
            .trackers_blocked
            .saturating_add(self.rng.range(0, 2));
        self.totals.connections = self.totals.connections.saturating_add(self.rng.range(0, 3));
    }

    fn apps(&self) -> Vec<AppRow> {
        self.apps.clone()
    }

    fn net_rows(&self) -> Vec<NetRow> {
        let mut rows: Vec<NetRow> = self
            .apps
            .iter()
            .flat_map(|a| {
                a.domains.iter().map(move |d| NetRow {
                    app_name: a.name.clone(),
                    app_path: a.bundle_path.clone(),
                    domain: d.clone(),
                })
            })
            .collect();
        rows.sort_by(|a, b| b.domain.rate_bps.cmp(&a.domain.rate_bps));
        rows
    }

    fn procs(&self) -> Vec<ProcRow> {
        self.procs.clone()
    }

    fn totals(&self) -> Totals {
        self.totals
    }

    fn app_detail(&self, id: &str) -> Option<Detail> {
        self.app_by_id(id).map(detail_from_app)
    }

    fn proc_detail(&self, id: &str) -> Option<Detail> {
        if let Some(app) = self.app_by_id(id) {
            return Some(detail_from_app(app));
        }
        let p = self.procs.iter().find(|p| p.id == id)?;
        Some(Detail {
            name: p.name.clone(),
            bundle_id: p.id.clone(),
            bundle_path: p.bundle_path.clone(),
            in_bytes: 0,
            out_bytes: 0,
            path: format!("/usr/libexec/{}", p.name),
            user: "root".into(),
            signature: Signature::Apple,
            openbinary: "known good · system".into(),
            hostnames: vec![],
            ips: vec![],
            ports: vec![],
            allowed_count: 0,
            denied_count: 0,
            allowed: true,
        })
    }

    fn domain_detail(&self, host: &str) -> Option<Detail> {
        let using: Vec<&AppRow> = self
            .apps
            .iter()
            .filter(|a| a.domains.iter().any(|d| d.host == host))
            .collect();
        let first = using.first()?;
        let d = first.domains.iter().find(|d| d.host == host)?;
        Some(Detail {
            name: host.to_string(),
            bundle_id: d
                .country
                .clone()
                .map_or_else(|| "—".into(), |c| format!("{c} · AS15169")),
            bundle_path: None,
            in_bytes: d.rate_bps.saturating_mul(60),
            out_bytes: d.rate_bps.saturating_mul(5),
            path: format!(
                "{} apps · {}",
                using.len(),
                format_bytes(d.rate_bps.saturating_mul(60))
            ),
            user: using
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            signature: Signature::Apple,
            openbinary: match d.verdict {
                Verdict::Tracker => "known tracker".into(),
                Verdict::Blocked => "blocked destination".into(),
                Verdict::Allow => "reachable".into(),
            },
            hostnames: vec![host.to_string()],
            ips: vec!["142.250.72.14".into()],
            ports: vec!["443/tcp".into()],
            allowed_count: u32::from(d.verdict == Verdict::Allow),
            denied_count: u32::from(d.verdict != Verdict::Allow),
            allowed: d.allowed,
        })
    }

    /// The demo advertises a synthetic trace stream so the packet-trace view is
    /// fully exercisable from `--demo`, with no daemon and no root.
    #[cfg(unix)]
    fn trace_backend(&self) -> Option<std::sync::Arc<dyn super::source::TraceBackend>> {
        Some(std::sync::Arc::new(super::trace::DemoTraceBackend))
    }
}

#[cfg(test)]
#[path = "demo_test.rs"]
mod demo_test;
