#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr};

use tempfile::TempDir;

use crate::record::BanSource;

fn ip(d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, d))
}

fn rec(d: u8, expires: Option<i64>) -> BanRecord {
    BanRecord {
        ip: ip(d),
        detector: "repeat-blocked".to_owned(),
        banned_at: 100,
        expires_at: expires,
        escalation_count: 0,
        source: BanSource::RepeatBlocked,
    }
}

fn put(store: &BanStore, r: BanRecord) {
    store
        .write(|tx| {
            tx.bans.put((r.ip, r.detector.clone()), r);
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_open_stamps_schema_and_roundtrips() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    {
        let store = open_store(&store_dir(base)).unwrap();
        put(&store, rec(1, Some(10_000_000_000)));
    }
    // Reopen: the ban survives (simulated restart).
    let store = open_store(&store_dir(base)).unwrap();
    assert_eq!(store.read().bans.len(), 1);
    assert_eq!(
        store.read().meta.get(SCHEMA_VERSION_KEY).copied(),
        Some(SCHEMA_VERSION)
    );
}

#[test]
fn test_active_ban_ips_filters_expired() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let store = open_store(&store_dir(base)).unwrap();
    let now = crate::now_secs();
    put(&store, rec(1, Some(now + 10_000))); // active
    put(&store, rec(2, Some(now - 10))); // expired
    put(&store, rec(3, None)); // permanent
    drop(store);

    let ips = active_ban_ips(base);
    assert!(ips.contains(&ip(1)));
    assert!(ips.contains(&ip(3)));
    assert!(!ips.contains(&ip(2)), "expired excluded");
}

#[test]
fn test_active_ban_ips_missing_store_is_empty() {
    let dir = TempDir::new().unwrap();
    // No store dir created at all.
    assert!(active_ban_ips(dir.path()).is_empty());
}

#[test]
fn test_active_ban_ips_corrupt_store_is_empty_not_panic() {
    let dir = TempDir::new().unwrap();
    let sd = store_dir(dir.path());
    std::fs::create_dir_all(&sd).unwrap();
    // Write garbage into where a WAL would live — a hostile/truncated store.
    std::fs::write(sd.join("wal.log"), b"\x00\x01garbage-not-a-wal").unwrap();
    std::fs::write(sd.join("wal.bin"), b"\x00\x01garbage-not-a-wal").unwrap();
    std::fs::write(sd.join("snapshot.postcard"), b"\xffnot-a-snapshot").unwrap();
    // Must not panic, and — as the test name promises — must yield no bans, so a
    // hostile store fails open to "no bans" rather than composing a garbage IP.
    assert!(
        active_ban_ips(dir.path()).is_empty(),
        "a corrupt store must yield zero bans"
    );
}

#[test]
fn test_active_ban_records_sorted() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let store = open_store(&store_dir(base)).unwrap();
    let now = crate::now_secs();
    put(&store, rec(5, Some(now + 1_000)));
    put(&store, rec(2, Some(now + 1_000)));
    drop(store);
    let records = active_ban_records(base);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].ip, ip(2));
    assert_eq!(records[1].ip, ip(5));
}
