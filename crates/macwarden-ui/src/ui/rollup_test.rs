#![allow(clippy::indexing_slicing, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;

use super::*;
use crate::data::model::ProcRow;

fn row(id: &str, name: &str, exe: Option<&str>, mem: u64, net_bps: u64, net_bytes: u64) -> ProcRow {
    ProcRow {
        id: id.into(),
        name: name.into(),
        bundle_path: exe.map(PathBuf::from),
        cpu: 1.0,
        mem_bytes: mem,
        net_bps,
        net_bytes,
        stats_known: true,
    }
}

fn meta(pid: u32, name: &str, exe: &str) -> (u32, ProcMeta) {
    (
        pid,
        ProcMeta {
            name: name.into(),
            exe: Some(PathBuf::from(exe)),
        },
    )
}

#[test]
fn test_group_procs_rolls_helper_under_owner() {
    let procs = vec![
        row(
            "10",
            "Safari",
            Some("/Applications/Safari.app/Contents/MacOS/Safari"),
            200,
            10,
            100,
        ),
        row(
            "11",
            "com.apple.WebKit.Networking",
            Some(
                "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
            ),
            80,
            5,
            50,
        ),
    ];
    let owner: HashMap<u32, u32> = [(10, 10), (11, 10)].into_iter().collect();
    let m: HashMap<u32, ProcMeta> = [
        meta(10, "Safari", "/Applications/Safari.app/Contents/MacOS/Safari"),
        meta(
            11,
            "com.apple.WebKit.Networking",
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
        ),
    ]
    .into_iter()
    .collect();

    let groups = group_procs(procs, &owner, &m);
    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.name, "Safari");
    assert_eq!(g.procs.len(), 2);
    assert!(g.is_group());
    assert_eq!(g.mem_bytes, 280);
    assert_eq!(g.net_bps, 15);
    assert_eq!(g.net_bytes, 150);
    // Heaviest member first.
    assert_eq!(g.procs[0].name, "Safari");
}

#[test]
fn test_group_procs_standalone_daemon_stays_singleton() {
    let procs = vec![row("42", "trustd", Some("/usr/libexec/trustd"), 30, 0, 0)];
    let owner: HashMap<u32, u32> = [(42, 42)].into_iter().collect();
    let m: HashMap<u32, ProcMeta> = [meta(42, "trustd", "/usr/libexec/trustd")]
        .into_iter()
        .collect();

    let groups = group_procs(procs, &owner, &m);
    assert_eq!(groups.len(), 1);
    assert!(!groups[0].is_group());
    assert_eq!(groups[0].name, "trustd");
}

#[test]
fn test_resolve_owners_uses_cache() {
    // On non-macOS the FFI shim maps every pid to itself; either way a cached
    // entry is returned verbatim without re-querying.
    let mut cache: HashMap<u32, u32> = [(7, 3)].into_iter().collect();
    let out = resolve_owners([7u32].into_iter(), &mut cache);
    assert_eq!(out.get(&7), Some(&3));
}
