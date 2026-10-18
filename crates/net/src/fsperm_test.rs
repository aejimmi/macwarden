use super::*;

use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn test_secure_file_sets_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("secret.toml");
    std::fs::write(&path, b"x").expect("write");
    // Start world-readable, then harden.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    secure_file(&path);
    let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "file must be owner-only rw");
}

#[cfg(unix)]
#[test]
fn test_secure_dir_sets_0700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let sub = dir.path().join("state");
    std::fs::create_dir(&sub).expect("mkdir");
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    secure_dir(&sub);
    let mode = std::fs::metadata(&sub).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "dir must be owner-only access");
}

#[test]
fn test_secure_file_missing_path_is_not_fatal() {
    // A chmod on a nonexistent path is logged, never panics.
    let dir = TempDir::new().expect("tempdir");
    secure_file(&dir.path().join("does-not-exist"));
}
