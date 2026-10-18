#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::*;
use crate::data::nettop::{Conn, ProcNet};

#[test]
fn test_bundle_of_finds_app_directory() {
    let p = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    let bundle = bundle_of(p).expect("bundle found");
    assert_eq!(bundle, PathBuf::from("/Applications/Google Chrome.app"));
}

#[test]
fn test_bundle_of_none_for_plain_binary() {
    assert!(bundle_of(Path::new("/usr/bin/curl")).is_none());
}

#[test]
fn test_identity_bundle_uses_app_name() {
    let (id, name, icon) = identity(
        Some(Path::new(
            "/Applications/Ghostty.app/Contents/MacOS/ghostty",
        )),
        "ghostty",
    );
    assert_eq!(id, "/Applications/Ghostty.app");
    assert_eq!(name, "Ghostty");
    assert_eq!(icon, Some(PathBuf::from("/Applications/Ghostty.app")));
}

#[test]
fn test_identity_standalone_binary() {
    let (id, name, icon) = identity(Some(Path::new("/usr/bin/curl")), "curl");
    assert_eq!(id, "/usr/bin/curl");
    assert_eq!(name, "curl");
    assert_eq!(icon, Some(PathBuf::from("/usr/bin/curl")));
}

#[test]
fn test_identity_no_exe_falls_back() {
    let (id, name, icon) = identity(None, "kernel_task");
    assert_eq!(id, "kernel_task");
    assert_eq!(name, "kernel_task");
    assert_eq!(icon, None);
}

const GHOSTTY_ID: &str = "/Applications/Ghostty.app";

struct Fixtures {
    meta: HashMap<u32, ProcMeta>,
    owner: HashMap<u32, u32>,
    proc_rates: HashMap<u32, (u64, u64)>,
    remote_rates: HashMap<(u32, String), (u64, u64)>,
    app_totals: HashMap<String, (u64, u64)>,
    dest_totals: HashMap<(String, String), (u64, u64)>,
    app_meta: HashMap<String, (String, Option<PathBuf>)>,
}

impl Fixtures {
    fn ctx(&self) -> BuildCtx<'_> {
        BuildCtx {
            meta: &self.meta,
            owner: &self.owner,
            proc_rates: &self.proc_rates,
            remote_rates: &self.remote_rates,
            app_totals: &self.app_totals,
            dest_totals: &self.dest_totals,
            app_meta: &self.app_meta,
        }
    }
}

fn ghostty_fixtures() -> Fixtures {
    let mut meta = HashMap::new();
    meta.insert(
        42,
        ProcMeta {
            name: "ghostty".into(),
            exe: Some(PathBuf::from(
                "/Applications/Ghostty.app/Contents/MacOS/ghostty",
            )),
        },
    );
    let mut proc_rates = HashMap::new();
    proc_rates.insert(42, (1000u64, 200u64));
    let mut remote_rates = HashMap::new();
    remote_rates.insert((42u32, "1.2.3.4:443".to_string()), (900u64, 100u64));
    let mut app_totals = HashMap::new();
    app_totals.insert(GHOSTTY_ID.to_string(), (5000u64, 800u64));
    let mut dest_totals = HashMap::new();
    dest_totals.insert(
        (GHOSTTY_ID.to_string(), "1.2.3.4:443".to_string()),
        (4000u64, 500u64),
    );
    Fixtures {
        meta,
        owner: HashMap::new(),
        proc_rates,
        remote_rates,
        app_totals,
        dest_totals,
        app_meta: HashMap::new(),
    }
}

fn ghostty_sample() -> Vec<ProcNet> {
    vec![ProcNet {
        pid: 42,
        name: "ghostty".into(),
        bytes_in: 5000,
        bytes_out: 800,
        conns: vec![Conn {
            proto: "tcp4".into(),
            remote_ip: "1.2.3.4".into(),
            remote_port: 443,
            bytes_in: 5000,
            bytes_out: 800,
        }],
    }]
}

#[test]
fn test_build_aggregates_rolls_up_by_bundle() {
    let f = ghostty_fixtures();
    let aggs = build_aggregates(&ghostty_sample(), &f.ctx());
    assert_eq!(aggs.len(), 1);
    let app = &aggs[0];
    assert_eq!(app.name, "Ghostty");
    assert_eq!(app.down_bps, 1000);
    assert_eq!(app.up_bps, 200);
    assert_eq!(app.total_down, 5000);
    assert_eq!(app.total_up, 800);
    assert_eq!(app.remotes.len(), 1);
    assert_eq!(app.remotes[0].rate_bps, 1000);
    assert_eq!(app.remotes[0].total_bytes, 4500);
    assert_eq!(app.remotes[0].sockets, 1);
}

#[test]
fn test_to_app_row_active_flow_and_host() {
    let f = ghostty_fixtures();
    let aggs = build_aggregates(&ghostty_sample(), &f.ctx());
    let row = to_app_row(&aggs[0]);
    assert!(matches!(row.flow, crate::data::model::Flow::Active(1200)));
    assert_eq!(row.domains[0].host, "1.2.3.4:443");
    assert_eq!(row.domains[0].sockets, 1);
}

#[test]
fn test_endpoint_aggregation_counts_sockets() {
    let f = ghostty_fixtures();
    // Five sockets to the same remote endpoint collapse into one row.
    let conn = |port: u16| Conn {
        proto: "tcp4".into(),
        remote_ip: "1.2.3.4".into(),
        remote_port: port,
        bytes_in: 10,
        bytes_out: 10,
    };
    let sample = vec![ProcNet {
        pid: 42,
        name: "ghostty".into(),
        bytes_in: 5000,
        bytes_out: 800,
        conns: vec![conn(443), conn(443), conn(443), conn(443), conn(443)],
    }];
    let aggs = build_aggregates(&sample, &f.ctx());
    assert_eq!(aggs[0].remotes.len(), 1);
    assert_eq!(aggs[0].remotes[0].sockets, 5);
}

#[test]
fn test_responsible_owner_rolls_helper_into_app() {
    let mut f = ghostty_fixtures();
    // A helper pid 99 whose responsible owner is the ghostty pid 42.
    f.owner.insert(99, 42);
    let sample = vec![ProcNet {
        pid: 99,
        name: "ghostty-helper".into(),
        bytes_in: 1,
        bytes_out: 1,
        conns: vec![Conn {
            proto: "tcp4".into(),
            remote_ip: "5.6.7.8".into(),
            remote_port: 443,
            bytes_in: 1,
            bytes_out: 1,
        }],
    }];
    let aggs = build_aggregates(&sample, &f.ctx());
    assert_eq!(aggs.len(), 1);
    assert_eq!(aggs[0].id, GHOSTTY_ID);
    assert_eq!(aggs[0].name, "Ghostty");
}

#[test]
fn test_persisted_app_survives_without_live_process() {
    let mut f = ghostty_fixtures();
    // A destination and app seen earlier but with no live process this tick.
    f.app_meta.insert(
        "com.seen.App".into(),
        ("Seen".into(), Some(PathBuf::from("/Applications/Seen.app"))),
    );
    f.app_totals.insert("com.seen.App".into(), (9000, 100));
    f.dest_totals
        .insert(("com.seen.App".into(), "9.9.9.9:443".into()), (8000, 90));
    // Empty sample — nothing is live.
    let aggs = build_aggregates(&[], &f.ctx());
    let seen = aggs.iter().find(|a| a.id == "com.seen.App").expect("seen");
    assert_eq!(seen.name, "Seen");
    assert_eq!(seen.total_down, 9000);
    assert_eq!(seen.rate(), 0);
    assert_eq!(seen.remotes.len(), 1);
    assert_eq!(seen.remotes[0].total_bytes, 8090);
    assert_eq!(seen.remotes[0].rate_bps, 0);
}

#[test]
fn test_build_aggregates_drops_silent_processes() {
    let mut meta = HashMap::new();
    meta.insert(
        9,
        ProcMeta {
            name: "idle".into(),
            exe: None,
        },
    );
    let f = Fixtures {
        meta,
        owner: HashMap::new(),
        proc_rates: HashMap::new(),
        remote_rates: HashMap::new(),
        app_totals: HashMap::new(),
        dest_totals: HashMap::new(),
        app_meta: HashMap::new(),
    };
    let sample = vec![ProcNet {
        pid: 9,
        name: "idle".into(),
        bytes_in: 0,
        bytes_out: 0,
        conns: Vec::new(),
    }];
    assert!(build_aggregates(&sample, &f.ctx()).is_empty());
}
