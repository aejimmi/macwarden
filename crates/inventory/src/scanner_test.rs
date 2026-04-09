use super::*;
use std::os::unix::fs::PermissionsExt;

/// Create a fake `.app` bundle with an executable and `Info.plist`.
fn create_fake_bundle(dir: &Path, name: &str, exec_name: &str) {
    let bundle = dir.join(format!("{name}.app"));
    let macos = bundle.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).expect("create MacOS dir");

    let plist_dir = bundle.join("Contents");
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{exec_name}</string>
    <key>CFBundleIdentifier</key>
    <string>com.test.{name}</string>
    <key>CFBundleName</key>
    <string>{name}</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
</dict>
</plist>"#
    );
    std::fs::write(plist_dir.join("Info.plist"), plist_content).expect("write plist");

    let exec_path = macos.join(exec_name);
    std::fs::write(&exec_path, b"#!/bin/sh\necho hello").expect("write exec");
    std::fs::set_permissions(&exec_path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// Create a fake naked executable.
fn create_fake_binary(dir: &Path, name: &str) {
    let path = dir.join(name);
    std::fs::write(&path, b"\xfe\xed\xfa\xcfFAKE").expect("write binary");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

// ---------------------------------------------------------------------------
// Targeted scan tests
// ---------------------------------------------------------------------------

#[test]
fn test_scan_app_bundles() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    create_fake_bundle(tmp.path(), "TestApp", "TestApp");

    let results = scan_directories(&[tmp.path().to_path_buf()]).expect("scan");
    assert_eq!(results.len(), 1);
    assert!(results[0].executable.ends_with("Contents/MacOS/TestApp"));
    assert!(results[0].bundle_path.is_some());
}

#[test]
fn test_scan_naked_binaries() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    create_fake_binary(tmp.path(), "curl");
    create_fake_binary(tmp.path(), "git");

    let results = scan_directories(&[tmp.path().to_path_buf()]).expect("scan");
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.bundle_path.is_none()));
}

#[test]
fn test_scan_mixed_dir() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    create_fake_bundle(tmp.path(), "MyApp", "MyApp");
    create_fake_binary(tmp.path(), "helper");

    let results = scan_directories(&[tmp.path().to_path_buf()]).expect("scan");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_scan_skips_nonexistent_dir() {
    let results = scan_directories(&[PathBuf::from("/nonexistent/path/12345")]).expect("scan");
    assert!(results.is_empty());
}

#[test]
fn test_scan_multiple_dirs() {
    let tmp1 = tempfile::TempDir::new().expect("tempdir");
    let tmp2 = tempfile::TempDir::new().expect("tempdir");
    create_fake_bundle(tmp1.path(), "App1", "App1");
    create_fake_binary(tmp2.path(), "tool");

    let results =
        scan_directories(&[tmp1.path().to_path_buf(), tmp2.path().to_path_buf()]).expect("scan");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_scan_deduplicates() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    create_fake_binary(tmp.path(), "dup");

    let results =
        scan_directories(&[tmp.path().to_path_buf(), tmp.path().to_path_buf()]).expect("scan");
    assert_eq!(results.len(), 1);
}

// ---------------------------------------------------------------------------
// Mach-O detection tests
// ---------------------------------------------------------------------------

#[test]
fn test_is_macho_64() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("macho64");
    // MH_MAGIC_64 + padding
    std::fs::write(&path, b"\xfe\xed\xfa\xcfpadding").expect("write");
    assert!(is_macho(&path));
}

#[test]
fn test_is_macho_32() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("macho32");
    std::fs::write(&path, b"\xfe\xed\xfa\xcepadding").expect("write");
    assert!(is_macho(&path));
}

#[test]
fn test_is_macho_fat() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("fat");
    std::fs::write(&path, b"\xca\xfe\xba\xbepadding").expect("write");
    assert!(is_macho(&path));
}

#[test]
fn test_is_not_macho() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("text");
    std::fs::write(&path, b"#!/bin/sh\necho hello").expect("write");
    assert!(!is_macho(&path));
}

#[test]
fn test_is_macho_empty_file() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("empty");
    std::fs::write(&path, b"").expect("write");
    assert!(!is_macho(&path));
}

#[test]
fn test_is_macho_too_short() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("short");
    std::fs::write(&path, b"\xfe\xed").expect("write");
    assert!(!is_macho(&path));
}

// ---------------------------------------------------------------------------
// Full scan tests
// ---------------------------------------------------------------------------

/// Test that mdfind_executables returns paths (requires Spotlight on macOS).
#[test]
#[cfg(target_os = "macos")]
fn test_mdfind_returns_paths() {
    let paths = mdfind_executables();
    // Spotlight should find at least some executables on any macOS system.
    assert!(!paths.is_empty(), "mdfind should find executables");
}

/// Test that scan_full finds apps and system binaries.
#[test]
#[cfg(target_os = "macos")]
fn test_scan_full_finds_system_binaries() {
    let home = PathBuf::from(std::env::var("HOME").expect("HOME set"));
    let results = scan_full(&home);

    // Should find system binaries from /usr/bin, /usr/sbin, etc.
    assert!(
        results
            .iter()
            .any(|r| r.executable.starts_with("/usr/bin/")),
        "should find binaries in /usr/bin"
    );

    // Should find at least some .app bundles from /Applications.
    assert!(
        results.iter().any(|r| r.bundle_path.is_some()),
        "should find .app bundles"
    );
}
