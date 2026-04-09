use super::persist;
use crate::cache::DnsCache;
use persist::DnsCacheStore;
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn test_save_and_load_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dns-cache.json");

    let cache = DnsCache::new(100);
    cache.insert(
        "1.1.1.1".parse::<IpAddr>().unwrap(),
        "one.one.one.one".to_owned(),
        Duration::from_secs(3600),
    );
    cache.insert(
        "8.8.8.8".parse::<IpAddr>().unwrap(),
        "dns.google".to_owned(),
        Duration::from_secs(300),
    );

    let saved = persist::save(&cache, &path).expect("save");
    assert_eq!(saved, 2);

    let cache2 = DnsCache::new(100);
    let loaded = persist::load(&cache2, &path).expect("load");
    assert_eq!(loaded, 2);

    assert_eq!(
        cache2.lookup(&"1.1.1.1".parse().unwrap()),
        Some("one.one.one.one".to_owned())
    );
    assert_eq!(
        cache2.lookup(&"8.8.8.8".parse().unwrap()),
        Some("dns.google".to_owned())
    );
}

#[test]
fn test_load_missing_file_returns_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nonexistent.json");

    let cache = DnsCache::new(100);
    let loaded = persist::load(&cache, &path).expect("load");
    assert_eq!(loaded, 0);
    assert!(cache.is_empty());
}

#[test]
fn test_expired_entries_not_loaded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dns-cache.json");

    // Write a cache file with an entry that has 0 remaining seconds.
    let content = r#"{
        "version": 1,
        "saved_at": 0,
        "entries": [
            { "ip": "1.1.1.1", "hostname": "expired.example", "ttl_secs": 10, "remaining_secs": 5 }
        ]
    }"#;
    std::fs::write(&path, content).expect("write");

    let cache = DnsCache::new(100);
    // saved_at=0 means the file is from epoch. All remaining_secs have elapsed.
    let loaded = persist::load(&cache, &path).expect("load");
    assert_eq!(loaded, 0);
    assert!(cache.is_empty());
}

#[test]
fn test_empty_cache_saves_empty_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dns-cache.json");

    let cache = DnsCache::new(100);
    let saved = persist::save(&cache, &path).expect("save");
    assert_eq!(saved, 0);

    let cache2 = DnsCache::new(100);
    let loaded = persist::load(&cache2, &path).expect("load");
    assert_eq!(loaded, 0);
}

#[test]
fn test_unsupported_version_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dns-cache.json");

    let content = r#"{ "version": 99, "saved_at": 0, "entries": [] }"#;
    std::fs::write(&path, content).expect("write");

    let cache = DnsCache::new(100);
    let result = persist::load(&cache, &path);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("version 99"),
        "should mention bad version"
    );
}

#[test]
fn test_ipv6_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dns-cache.json");

    let cache = DnsCache::new(100);
    cache.insert(
        "2001:db8::1".parse::<IpAddr>().unwrap(),
        "ipv6.example.com".to_owned(),
        Duration::from_secs(600),
    );

    persist::save(&cache, &path).expect("save");

    let cache2 = DnsCache::new(100);
    let loaded = persist::load(&cache2, &path).expect("load");
    assert_eq!(loaded, 1);
    assert_eq!(
        cache2.lookup(&"2001:db8::1".parse().unwrap()),
        Some("ipv6.example.com".to_owned())
    );
}

// ---------------------------------------------------------------------------
// Etchdb-backed DnsCacheStore
// ---------------------------------------------------------------------------

#[test]
fn test_etchdb_store_open_and_flush() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("dns-store");

    let cache = DnsCache::new(100);
    cache.insert(
        "1.1.1.1".parse::<IpAddr>().unwrap(),
        "one.one.one.one".to_owned(),
        Duration::from_secs(3600),
    );
    cache.insert(
        "8.8.8.8".parse::<IpAddr>().unwrap(),
        "dns.google".to_owned(),
        Duration::from_secs(300),
    );

    let store = DnsCacheStore::open(store_dir.clone(), cache).expect("open");
    let flushed = store.flush().expect("flush");
    assert_eq!(flushed, 2);
    drop(store);

    // Reopen and verify entries were persisted.
    let cache2 = DnsCache::new(100);
    let store2 = DnsCacheStore::open(store_dir, cache2).expect("reopen");
    assert_eq!(
        store2.cache().lookup(&"1.1.1.1".parse().unwrap()),
        Some("one.one.one.one".to_owned())
    );
    assert_eq!(
        store2.cache().lookup(&"8.8.8.8".parse().unwrap()),
        Some("dns.google".to_owned())
    );
}

#[test]
fn test_etchdb_store_empty_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("dns-store-empty");

    let cache = DnsCache::new(100);
    let store = DnsCacheStore::open(store_dir, cache).expect("open");
    let flushed = store.flush().expect("flush");
    assert_eq!(flushed, 0);
    assert!(store.cache().is_empty());
}

#[test]
fn test_etchdb_store_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("dns-store-reopen");

    // First session: insert and flush.
    {
        let cache = DnsCache::new(100);
        cache.insert(
            "142.250.80.46".parse::<IpAddr>().unwrap(),
            "www.google.com".to_owned(),
            Duration::from_secs(7200),
        );
        let store = DnsCacheStore::open(store_dir.clone(), cache).expect("open");
        store.flush().expect("flush");
        // Drop triggers another flush + stop.
    }

    // Second session: entries should be loaded.
    {
        let cache = DnsCache::new(100);
        let store = DnsCacheStore::open(store_dir, cache).expect("reopen");
        assert_eq!(
            store.cache().lookup(&"142.250.80.46".parse().unwrap()),
            Some("www.google.com".to_owned())
        );
    }
}
