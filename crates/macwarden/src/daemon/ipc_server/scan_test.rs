//! Tests for the pure nettop → [`LiveConn`] mapping.
#![allow(clippy::indexing_slicing, clippy::float_cmp)]

use std::collections::HashMap;

use netsample::{Conn, ProcNet};

use super::super::proc_sample::ProcStat;
use super::*;

fn conn(proto: &str, ip: &str, port: u16) -> Conn {
    Conn {
        proto: proto.to_owned(),
        remote_ip: ip.to_owned(),
        remote_port: port,
        bytes_in: 0,
        bytes_out: 0,
    }
}

fn proc_with(name: &str, pid: u32, conns: Vec<Conn>) -> ProcNet {
    ProcNet {
        pid,
        name: name.to_owned(),
        bytes_in: 4096,
        bytes_out: 1024,
        conns,
    }
}

#[test]
fn test_map_proc_stamps_identity_and_process_bytes_on_each_conn() {
    let proc = proc_with(
        "Chrome",
        900,
        vec![conn("tcp4", "1.2.3.4", 443), conn("tcp6", "2606::1", 443)],
    );
    let out = map_proc(
        &proc,
        Some("com.google.Chrome"),
        Some("/Applications/Chrome.app"),
        None,
        None,
        &RdnsResolver::new(),
    );
    assert_eq!(out.len(), 2);
    for live in &out {
        assert_eq!(live.pid, 900);
        assert_eq!(live.process, "Chrome");
        assert_eq!(live.code_id.as_deref(), Some("com.google.Chrome"));
        assert_eq!(live.path.as_deref(), Some("/Applications/Chrome.app"));
        // Process-level counters stamped on every conn of the pid.
        assert_eq!(live.bytes_in, 4096);
        assert_eq!(live.bytes_out, 1024);
        assert!(live.host.is_none());
    }
    assert_eq!(
        out[0].ip.map(|ip| ip.to_string()).as_deref(),
        Some("1.2.3.4")
    );
    assert_eq!(out[0].port, 443);
}

#[test]
fn test_map_proc_maps_protocol_token_to_wire_protocol() {
    let proc = proc_with(
        "resolver",
        11,
        vec![conn("udp4", "8.8.8.8", 53), conn("tcp4", "8.8.8.8", 443)],
    );
    let out = map_proc(&proc, None, None, None, None, &RdnsResolver::new());
    assert_eq!(out[0].protocol, "UDP");
    assert_eq!(out[1].protocol, "TCP");
}

#[test]
fn test_map_proc_drops_local_noise() {
    let proc = proc_with(
        "noisy",
        22,
        vec![
            conn("udp4", "127.0.0.1", 5353),
            conn("tcp6", "fe80::1", 1024),
            conn("tcp4", "9.9.9.9", 443),
        ],
    );
    let out = map_proc(&proc, None, None, None, None, &RdnsResolver::new());
    assert_eq!(out.len(), 1, "loopback and link-local must be filtered");
    assert_eq!(
        out[0].ip.map(|ip| ip.to_string()).as_deref(),
        Some("9.9.9.9")
    );
}

#[test]
fn test_map_proc_app_id_falls_back_to_process_without_code_id() {
    let proc = proc_with("mystery", 33, vec![conn("tcp4", "5.5.5.5", 80)]);
    let out = map_proc(&proc, None, None, None, None, &RdnsResolver::new());
    assert_eq!(out[0].app_id(), "mystery");
}

fn live(app: &str, host: &str, port: u16) -> LiveConn {
    LiveConn {
        code_id: Some(app.to_owned()),
        process: app.to_owned(),
        pid: 1,
        path: None,
        host: Some(host.to_owned()),
        ip: None,
        port,
        protocol: "TCP".to_owned(),
        bytes_in: 0,
        bytes_out: 0,
        is_apple_signed: None,
        cpu: 0.0,
        mem_bytes: 0,
        ..LiveConn::default()
    }
}

/// An empty per-pid stat map: `accumulate` re-stamps to zero.
fn no_stats() -> HashMap<u32, ProcStat> {
    HashMap::new()
}

#[test]
fn test_accumulate_retains_union_across_samples() {
    let mut session = Session::default();
    let first = accumulate(&mut session, vec![live("a", "a.com", 443)], &no_stats());
    assert_eq!(first.len(), 1);
    // A later sample with a different app must not drop the first.
    let second = accumulate(&mut session, vec![live("b", "b.com", 443)], &no_stats());
    assert_eq!(second.len(), 2, "prior app must persist as an idle row");
    // An empty sample (quiet instant) still returns the full retained union.
    let third = accumulate(&mut session, vec![], &no_stats());
    assert_eq!(third.len(), 2);
}

#[test]
fn test_accumulate_refreshes_same_key_without_duplicating() {
    let mut session = Session::default();
    accumulate(&mut session, vec![live("a", "a.com", 443)], &no_stats());
    let mut updated = live("a", "a.com", 443);
    updated.bytes_in = 9999;
    let out = accumulate(&mut session, vec![updated], &no_stats());
    assert_eq!(out.len(), 1, "same destination must dedup, not duplicate");
    assert_eq!(out[0].bytes_in, 9999, "latest counters win");
}

#[test]
fn test_accumulate_caps_new_admissions_at_max_retained() {
    let mut session = Session::default();
    let flood: Vec<LiveConn> = (0..MAX_RETAINED + 50)
        .map(|i| live(&format!("app{i}"), &format!("h{i}.com"), 443))
        .collect();
    let out = accumulate(&mut session, flood, &no_stats());
    assert_eq!(out.len(), MAX_RETAINED, "growth is bounded");
}

#[test]
fn test_accumulate_stamps_cpu_mem_from_stats_by_pid() {
    let mut session = Session::default();
    let mut c = live("a", "a.com", 443);
    c.pid = 77;
    let mut stats = HashMap::new();
    stats.insert(
        77,
        ProcStat {
            cpu: 42.5,
            mem_bytes: 8_000_000,
            stats_known: true,
            user: Some("tester".to_owned()),
        },
    );
    let out = accumulate(&mut session, vec![c], &stats);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].cpu, 42.5, "cpu is stamped from the per-pid stats");
    assert_eq!(out[0].mem_bytes, 8_000_000, "mem is stamped from the stats");
}

#[test]
fn test_accumulate_zeroes_cpu_mem_for_departed_pid() {
    let mut session = Session::default();
    let mut c = live("a", "a.com", 443);
    c.pid = 5;
    c.cpu = 99.0;
    c.mem_bytes = 123;
    // Stats for pid 5 are absent (process gone) → re-stamp falls back to zero.
    let out = accumulate(&mut session, vec![c], &no_stats());
    assert_eq!(out[0].cpu, 0.0, "a departed pid must not show stale cpu");
    assert_eq!(
        out[0].mem_bytes, 0,
        "a departed pid must not show stale mem"
    );
}
