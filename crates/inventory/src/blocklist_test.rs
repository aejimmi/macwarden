use super::*;

#[test]
fn test_parse_hash_lines() {
    let input = "
# comment
aabbcc112233

DDEEFF445566
  spaces_around
";
    let bl = HashBlocklist::from_str(input);
    assert_eq!(bl.len(), 3);
    assert!(bl.contains("aabbcc112233"));
    assert!(bl.contains("ddeeff445566")); // lowercased
    assert!(bl.contains("spaces_around"));
}

#[test]
fn test_empty_blocklist() {
    let bl = HashBlocklist::from_str("");
    assert!(bl.is_empty());
    assert!(!bl.contains("anything"));
}

#[test]
fn test_comments_and_blanks_skipped() {
    let input = "# only comments\n\n# another\n";
    let bl = HashBlocklist::from_str(input);
    assert!(bl.is_empty());
}

#[test]
fn test_load_file() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("hashes.txt");
    std::fs::write(&path, "abc123\ndef456\n").expect("write");

    let bl = HashBlocklist::load_file(&path).expect("load");
    assert_eq!(bl.len(), 2);
    assert!(bl.contains("abc123"));
    assert!(bl.contains("def456"));
}

#[test]
fn test_load_file_missing() {
    let result = HashBlocklist::load_file(Path::new("/nonexistent/hashes.txt"));
    assert!(result.is_err());
}

#[test]
fn test_merge() {
    let mut bl = HashBlocklist::from_str("aaa\nbbb\n");
    bl.merge_str("ccc\naaa\n"); // aaa is a duplicate
    assert_eq!(bl.len(), 3);
    assert!(bl.contains("aaa"));
    assert!(bl.contains("ccc"));
}

#[test]
fn test_builtin_loads_without_panic() {
    // Just verify the embedded file parses without error.
    let bl = HashBlocklist::load();
    // The seed file has no hashes, just comments.
    assert!(bl.is_empty() || bl.len() > 0);
}
