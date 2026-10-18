//! Tests for the pure cache/queue decision logic (no DNS, no network).
use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IP")
}

#[test]
fn test_probe_miss_marks_pending_and_requests_enqueue() {
    let inner = Inner::default();
    assert_eq!(inner.probe(ip("1.2.3.4")), Probe::Enqueue);
    // Same IP, still in flight → do not re-enqueue.
    assert_eq!(inner.probe(ip("1.2.3.4")), Probe::Skip);
}

#[test]
fn test_store_positive_then_probe_hits() {
    let inner = Inner::default();
    assert_eq!(inner.probe(ip("1.1.1.1")), Probe::Enqueue);
    inner.store(ip("1.1.1.1"), Some("one.one.one.one".to_owned()));
    assert_eq!(
        inner.probe(ip("1.1.1.1")),
        Probe::Hit(Some("one.one.one.one".to_owned()))
    );
}

#[test]
fn test_store_negative_is_cached_and_not_re_enqueued() {
    let inner = Inner::default();
    assert_eq!(inner.probe(ip("9.9.9.9")), Probe::Enqueue);
    // Garbage/absent PTR → cached negative.
    inner.store(ip("9.9.9.9"), None);
    assert_eq!(inner.probe(ip("9.9.9.9")), Probe::Hit(None));
}

#[test]
fn test_store_clears_pending_so_a_later_miss_can_re_enqueue_after_eviction() {
    let inner = Inner::default();
    inner.probe(ip("8.8.8.8"));
    inner.store(ip("8.8.8.8"), Some("dns.google".to_owned()));
    // Cached now, so a repeat probe hits rather than re-enqueues.
    assert!(matches!(inner.probe(ip("8.8.8.8")), Probe::Hit(_)));
}

#[test]
fn test_probe_skips_when_cache_full() {
    let inner = Inner::default();
    // Fill the cache to the ceiling with resolved entries.
    {
        let mut cache = lock(&inner.cache);
        for i in 0..MAX_ENTRIES {
            let addr = IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            cache.insert(addr, Some(format!("h{i}")));
        }
    }
    // A brand-new miss must not be admitted (neither enqueued nor cached).
    assert_eq!(inner.probe(ip("203.0.113.7")), Probe::Skip);
}

#[test]
fn test_store_does_not_grow_past_max() {
    let inner = Inner::default();
    {
        let mut cache = lock(&inner.cache);
        for i in 0..MAX_ENTRIES {
            let addr = IpAddr::from([11, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            cache.insert(addr, None);
        }
    }
    inner.store(ip("203.0.113.9"), Some("overflow.example".to_owned()));
    assert_eq!(lock(&inner.cache).len(), MAX_ENTRIES, "growth is bounded");
}

#[test]
fn test_resolver_resolve_is_nonblocking_miss_returns_none() {
    let resolver = RdnsResolver::new();
    // First call on an unknown IP never blocks and yields None.
    assert!(resolver.resolve(ip("192.0.2.123")).is_none());
}
