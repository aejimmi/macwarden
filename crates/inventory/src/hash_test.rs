use super::*;

#[test]
fn test_hash_file_matches_known() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("test.bin");
    std::fs::write(&path, b"hello world").expect("write");

    let hash = hash_file(&path).expect("hash");
    // SHA-256 of "hello world"
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_hash_file_empty() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("empty");
    std::fs::write(&path, b"").expect("write");

    let hash = hash_file(&path).expect("hash");
    // SHA-256 of empty string
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_hash_file_not_found() {
    let result = hash_file(Path::new("/nonexistent/file"));
    assert!(result.is_err());
}
