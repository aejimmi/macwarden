use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;

use cache::DnsCache;

#[test]
fn test_insert_and_lookup_returns_hostname() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    cache.insert(ip, "example.com".to_owned(), Duration::from_secs(300));

    assert_eq!(cache.lookup(&ip), Some("example.com".to_owned()));
}

#[test]
fn test_lookup_miss_returns_none() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(cache.lookup(&ip), None);
}

#[test]
fn test_ttl_expiration_returns_none() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Insert with a very short TTL.
    cache.insert(ip, "expired.local".to_owned(), Duration::from_millis(1));

    // Wait for TTL to elapse.
    thread::sleep(Duration::from_millis(10));

    assert_eq!(cache.lookup(&ip), None);
}

#[test]
fn test_expired_entry_removed_on_lookup() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    cache.insert(ip, "gone.local".to_owned(), Duration::from_millis(1));
    assert_eq!(cache.len(), 1);

    thread::sleep(Duration::from_millis(10));

    // Lookup triggers lazy removal.
    let _ = cache.lookup(&ip);
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_overwrite_entry_second_wins() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    cache.insert(ip, "first.example.com".to_owned(), Duration::from_secs(60));
    cache.insert(ip, "second.example.com".to_owned(), Duration::from_secs(60));

    assert_eq!(cache.lookup(&ip), Some("second.example.com".to_owned()));
    // Overwrite should not increase len.
    assert_eq!(cache.len(), 1);
}

#[test]
fn test_capacity_eviction_oldest_removed() {
    let cache = DnsCache::new(3);

    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 3));
    let ip4 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 4));

    cache.insert(ip1, "one.local".to_owned(), Duration::from_secs(300));
    cache.insert(ip2, "two.local".to_owned(), Duration::from_secs(300));
    cache.insert(ip3, "three.local".to_owned(), Duration::from_secs(300));

    // At capacity (3). Inserting a 4th should evict ip1 (LRU).
    cache.insert(ip4, "four.local".to_owned(), Duration::from_secs(300));

    assert_eq!(cache.len(), 3);
    assert_eq!(cache.lookup(&ip1), None); // evicted
    assert_eq!(cache.lookup(&ip2), Some("two.local".to_owned()));
    assert_eq!(cache.lookup(&ip4), Some("four.local".to_owned()));
}

#[test]
fn test_lru_ordering_promoted_on_lookup() {
    let cache = DnsCache::new(3);

    let ip1 = IpAddr::V4(Ipv4Addr::new(2, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(2, 0, 0, 3));
    let ip4 = IpAddr::V4(Ipv4Addr::new(2, 0, 0, 4));

    cache.insert(ip1, "one.local".to_owned(), Duration::from_secs(300));
    cache.insert(ip2, "two.local".to_owned(), Duration::from_secs(300));
    cache.insert(ip3, "three.local".to_owned(), Duration::from_secs(300));

    // Access ip1 -- promotes it to most-recently-used.
    let _ = cache.lookup(&ip1);

    // Insert ip4 -- should evict ip2 (now the LRU), not ip1.
    cache.insert(ip4, "four.local".to_owned(), Duration::from_secs(300));

    assert_eq!(cache.lookup(&ip1), Some("one.local".to_owned())); // promoted, kept
    assert_eq!(cache.lookup(&ip2), None); // evicted
    assert_eq!(cache.lookup(&ip3), Some("three.local".to_owned()));
    assert_eq!(cache.lookup(&ip4), Some("four.local".to_owned()));
}

#[test]
fn test_clear_empties_cache() {
    let cache = DnsCache::new(100);

    cache.insert(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        "one.one.one.one".to_owned(),
        Duration::from_secs(60),
    );
    cache.insert(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        "dns.google".to_owned(),
        Duration::from_secs(60),
    );

    assert_eq!(cache.len(), 2);
    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_zero_capacity_upgraded_to_one() {
    let cache = DnsCache::new(0);
    assert_eq!(cache.capacity(), 1);

    let ip = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));
    cache.insert(ip, "five.local".to_owned(), Duration::from_secs(60));
    assert_eq!(cache.lookup(&ip), Some("five.local".to_owned()));
}

#[test]
fn test_concurrent_reads_no_panic() {
    let cache = DnsCache::new(1000);

    // Pre-populate.
    for i in 0..100u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        cache.insert(ip, format!("host-{i}.local"), Duration::from_secs(300));
    }

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let c = cache.clone();
            thread::spawn(move || {
                for i in 0..100u8 {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
                    let _ = c.lookup(&ip);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("reader thread panicked");
    }
}

#[test]
fn test_concurrent_insert_and_lookup_consistent() {
    let cache = DnsCache::new(500);

    let writer = {
        let c = cache.clone();
        thread::spawn(move || {
            for i in 0..200u16 {
                let ip = IpAddr::V4(Ipv4Addr::new(172, 16, (i >> 8) as u8, (i & 0xFF) as u8));
                c.insert(ip, format!("w-{i}.local"), Duration::from_secs(300));
            }
        })
    };

    let reader = {
        let c = cache.clone();
        thread::spawn(move || {
            for i in 0..200u16 {
                let ip = IpAddr::V4(Ipv4Addr::new(172, 16, (i >> 8) as u8, (i & 0xFF) as u8));
                // Either None (not yet written) or the correct hostname.
                if let Some(h) = c.lookup(&ip) {
                    assert_eq!(h, format!("w-{i}.local"));
                }
            }
        })
    };

    writer.join().expect("writer thread panicked");
    reader.join().expect("reader thread panicked");
}

#[test]
fn test_ipv6_addresses_work() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x6812));
    cache.insert(ip, "cloudflare.com".to_owned(), Duration::from_secs(60));
    assert_eq!(cache.lookup(&ip), Some("cloudflare.com".to_owned()));
}
