use super::*;

use std::io::Write;

/// Helper: write an XML plist string to a temp file and return its path.
fn write_temp_plist(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("test.plist");
    let mut file = std::fs::File::create(&path).expect("failed to create temp plist");
    file.write_all(content.as_bytes())
        .expect("failed to write temp plist");
    (dir, path)
}

const FULL_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.analyticsd</string>
    <key>Program</key>
    <string>/usr/libexec/analyticsd</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>Disabled</key>
    <false/>
</dict>
</plist>"#;

#[test]
fn test_parse_plist_full() {
    let (_dir, path) = write_temp_plist(FULL_PLIST);
    let info = parse_plist(&path).expect("failed to parse valid plist");

    assert_eq!(info.label, "com.apple.analyticsd");
    assert_eq!(info.program.as_deref(), Some("/usr/libexec/analyticsd"));
    assert!(info.run_at_load);
    assert!(info.keep_alive);
    assert!(!info.disabled);
    assert_eq!(info.path, path);
}

#[test]
fn test_parse_plist_program_arguments() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/test</string>
        <string>--flag</string>
    </array>
</dict>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let info = parse_plist(&path).expect("failed to parse plist with ProgramArguments");

    assert_eq!(info.label, "com.example.test");
    assert_eq!(info.program.as_deref(), Some("/usr/bin/test"));
    assert!(!info.run_at_load);
    assert!(!info.keep_alive);
    assert!(!info.disabled);
}

#[test]
fn test_parse_plist_keep_alive_dict() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.keepalive</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
</dict>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let info = parse_plist(&path).expect("failed to parse plist with KeepAlive dict");

    assert!(info.keep_alive, "KeepAlive dict should be treated as true");
}

#[test]
fn test_parse_plist_disabled() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.disabled</string>
    <key>Disabled</key>
    <true/>
</dict>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let info = parse_plist(&path).expect("failed to parse disabled plist");

    assert!(info.disabled);
}

#[test]
fn test_parse_plist_missing_label() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Program</key>
    <string>/usr/bin/test</string>
</dict>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let result = parse_plist(&path);
    assert!(result.is_err(), "missing Label should produce an error");
}

#[test]
fn test_parse_plist_not_a_dict() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <string>not a dict</string>
</array>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let result = parse_plist(&path);
    assert!(
        result.is_err(),
        "non-dict plist root should produce an error"
    );
}

#[test]
fn test_parse_plist_nonexistent_file() {
    let result = parse_plist(std::path::Path::new("/nonexistent/path/to/file.plist"));
    assert!(result.is_err(), "nonexistent file should produce an error");
}

#[test]
fn test_parse_plist_invalid_content() {
    let (_dir, path) = write_temp_plist("this is not a plist at all");
    let result = parse_plist(&path);
    assert!(
        result.is_err(),
        "invalid plist content should produce an error"
    );
}

#[test]
fn test_parse_plist_minimal() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.minimal</string>
</dict>
</plist>"#;

    let (_dir, path) = write_temp_plist(xml);
    let info = parse_plist(&path).expect("failed to parse minimal plist");

    assert_eq!(info.label, "com.example.minimal");
    assert!(info.program.is_none());
    assert!(!info.run_at_load);
    assert!(!info.keep_alive);
    assert!(!info.disabled);
}
