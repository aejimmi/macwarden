use super::*;

fn create_bundle_with_plist(dir: &std::path::Path, plist_xml: &str) -> std::path::PathBuf {
    let bundle = dir.join("Test.app");
    let contents = bundle.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).expect("mkdir");
    std::fs::write(contents.join("Info.plist"), plist_xml).expect("write plist");
    bundle
}

#[test]
fn test_read_full_metadata() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleName</key>
    <string>TestApp</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.0</string>
</dict>
</plist>"#;

    let bundle = create_bundle_with_plist(tmp.path(), plist);
    let meta = read_bundle_metadata(&bundle).expect("parse");

    assert_eq!(meta.bundle_id.as_deref(), Some("com.test.app"));
    assert_eq!(meta.name.as_deref(), Some("TestApp"));
    assert_eq!(meta.version.as_deref(), Some("2.1.0"));
}

#[test]
fn test_display_name_preferred_over_bundle_name() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Pretty Name</string>
    <key>CFBundleName</key>
    <string>UglyName</string>
</dict>
</plist>"#;

    let bundle = create_bundle_with_plist(tmp.path(), plist);
    let meta = read_bundle_metadata(&bundle).expect("parse");

    assert_eq!(meta.name.as_deref(), Some("Pretty Name"));
}

#[test]
fn test_missing_plist_returns_error() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let bundle = tmp.path().join("NoInfo.app");
    std::fs::create_dir_all(bundle.join("Contents/MacOS")).expect("mkdir");

    let result = read_bundle_metadata(&bundle);
    assert!(result.is_err());
}

#[test]
fn test_partial_metadata() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.minimal.app</string>
</dict>
</plist>"#;

    let bundle = create_bundle_with_plist(tmp.path(), plist);
    let meta = read_bundle_metadata(&bundle).expect("parse");

    assert_eq!(meta.bundle_id.as_deref(), Some("com.minimal.app"));
    assert!(meta.name.is_none());
    assert!(meta.version.is_none());
}
