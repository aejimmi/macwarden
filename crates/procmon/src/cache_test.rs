use super::*;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn make_info(code_id: &str) -> CodeSigningInfo {
    CodeSigningInfo {
        code_id: Some(code_id.to_string()),
        team_id: None,
        is_apple_signed: false,
        is_valid: true,
    }
}

#[test]
fn test_insert_and_get() {
    let mut cache = CodeSigningCache::new(10, Duration::from_secs(60));
    let path = PathBuf::from("/usr/bin/curl");
    let info = make_info("com.apple.curl");

    cache.insert(42, path.clone(), info);

    let result = cache.get(42, &path);
    assert!(result.is_some());
    assert_eq!(
        result.and_then(|i| i.code_id.as_deref()),
        Some("com.apple.curl")
    );
}

#[test]
fn test_get_missing() {
    let cache = CodeSigningCache::new(10, Duration::from_secs(60));
    let result = cache.get(42, Path::new("/usr/bin/curl"));
    assert!(result.is_none());
}

#[test]
fn test_get_expired() {
    let mut cache = CodeSigningCache::new(10, Duration::from_millis(50));
    let path = PathBuf::from("/usr/bin/curl");
    cache.insert(42, path.clone(), make_info("com.apple.curl"));

    // Wait for expiry
    thread::sleep(Duration::from_millis(80));

    let result = cache.get(42, &path);
    assert!(result.is_none(), "expired entry should not be returned");
}

#[test]
fn test_evict_expired() {
    let mut cache = CodeSigningCache::new(10, Duration::from_millis(50));
    cache.insert(1, PathBuf::from("/a"), make_info("a"));
    cache.insert(2, PathBuf::from("/b"), make_info("b"));

    thread::sleep(Duration::from_millis(80));

    // Insert a fresh one
    cache.insert(3, PathBuf::from("/c"), make_info("c"));

    cache.evict_expired();

    assert_eq!(cache.len(), 1, "only the fresh entry should remain");
    assert!(cache.get(3, Path::new("/c")).is_some());
}

#[test]
fn test_max_entries_eviction() {
    let mut cache = CodeSigningCache::new(3, Duration::from_secs(60));

    cache.insert(1, PathBuf::from("/a"), make_info("a"));
    cache.insert(2, PathBuf::from("/b"), make_info("b"));
    cache.insert(3, PathBuf::from("/c"), make_info("c"));

    assert_eq!(cache.len(), 3);

    // Inserting a 4th should evict the oldest
    cache.insert(4, PathBuf::from("/d"), make_info("d"));

    assert_eq!(cache.len(), 3);
    assert!(cache.get(4, Path::new("/d")).is_some());
}

#[test]
fn test_pid_path_keying() {
    let mut cache = CodeSigningCache::new(10, Duration::from_secs(60));
    let path = PathBuf::from("/usr/bin/curl");

    // Same path, different PIDs
    cache.insert(1, path.clone(), make_info("first"));
    cache.insert(2, path.clone(), make_info("second"));

    assert_eq!(
        cache.get(1, &path).and_then(|i| i.code_id.as_deref()),
        Some("first")
    );
    assert_eq!(
        cache.get(2, &path).and_then(|i| i.code_id.as_deref()),
        Some("second")
    );
}

#[test]
fn test_same_pid_different_path() {
    let mut cache = CodeSigningCache::new(10, Duration::from_secs(60));

    // Same PID, different paths (PID reuse scenario)
    cache.insert(42, PathBuf::from("/old/binary"), make_info("old"));
    cache.insert(42, PathBuf::from("/new/binary"), make_info("new"));

    assert_eq!(
        cache
            .get(42, Path::new("/old/binary"))
            .and_then(|i| i.code_id.as_deref()),
        Some("old")
    );
    assert_eq!(
        cache
            .get(42, Path::new("/new/binary"))
            .and_then(|i| i.code_id.as_deref()),
        Some("new")
    );
}

#[test]
fn test_is_empty() {
    let cache = CodeSigningCache::new(10, Duration::from_secs(60));
    assert!(cache.is_empty());
}

#[test]
fn test_len() {
    let mut cache = CodeSigningCache::new(10, Duration::from_secs(60));
    assert_eq!(cache.len(), 0);

    cache.insert(1, PathBuf::from("/a"), make_info("a"));
    assert_eq!(cache.len(), 1);

    cache.insert(2, PathBuf::from("/b"), make_info("b"));
    assert_eq!(cache.len(), 2);
}
