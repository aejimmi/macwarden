use super::*;

#[test]
fn test_display_name_prefers_bundle_name() {
    let rec = BinaryRecord {
        path: "/Applications/Slack.app/Contents/MacOS/Slack".into(),
        sha256: "abc123def456".into(),
        bundle_id: Some("com.tinyspeck.slackmacgap".into()),
        name: Some("Slack".into()),
        version: Some("4.36.0".into()),
        code_id: None,
        team_id: None,
        is_apple_signed: false,
        is_valid_sig: true,
        scanned_at: 1_700_000_000_000,
        is_blocklisted: false,
        openbinary: None,
        analyzed_at: None,
    };
    assert_eq!(rec.display_name(), "Slack");
}

#[test]
fn test_display_name_falls_back_to_filename() {
    let rec = BinaryRecord {
        path: "/usr/bin/curl".into(),
        sha256: "abc123def456".into(),
        bundle_id: None,
        name: None,
        version: None,
        code_id: None,
        team_id: None,
        is_apple_signed: true,
        is_valid_sig: true,
        scanned_at: 1_700_000_000_000,
        is_blocklisted: false,
        openbinary: None,
        analyzed_at: None,
    };
    assert_eq!(rec.display_name(), "curl");
}

#[test]
fn test_short_hash() {
    let rec = BinaryRecord {
        path: "/usr/bin/curl".into(),
        sha256: "abcdef1234567890abcdef1234567890".into(),
        bundle_id: None,
        name: None,
        version: None,
        code_id: None,
        team_id: None,
        is_apple_signed: false,
        is_valid_sig: false,
        scanned_at: 0,
        is_blocklisted: false,
        openbinary: None,
        analyzed_at: None,
    };
    assert_eq!(rec.short_hash(), "abcdef123456");
}
