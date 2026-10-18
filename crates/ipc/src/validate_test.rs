use std::path::Path;

use super::*;

#[test]
fn test_hostname_accepts_valid_names() {
    assert!(validate_hostname("googlevideo.com").is_ok());
    assert!(validate_hostname("a.b.c.example-1.com").is_ok());
    assert!(validate_hostname("localhost").is_ok());
    assert!(validate_hostname("xn--nxasmq6b.example").is_ok());
}

#[test]
fn test_hostname_rejects_path_traversal() {
    // `../etc` is rejected (its leading empty label trips the label check before
    // the char check); `a/b`'s slash trips the char check directly.
    assert!(validate_hostname("../etc").is_err());
    assert_eq!(validate_hostname("a/b"), Err(ValidationError::HostnameChar));
}

#[test]
fn test_hostname_rejects_space() {
    assert_eq!(validate_hostname("a b"), Err(ValidationError::HostnameChar));
}

#[test]
fn test_hostname_rejects_over_length() {
    let long = format!("{}.com", "a".repeat(300));
    assert_eq!(
        validate_hostname(&long),
        Err(ValidationError::HostnameTooLong)
    );
}

#[test]
fn test_hostname_rejects_leading_and_trailing_dash_label() {
    assert_eq!(
        validate_hostname("-lead.com"),
        Err(ValidationError::HostnameLabel)
    );
    assert_eq!(
        validate_hostname("trail-.com"),
        Err(ValidationError::HostnameLabel)
    );
}

#[test]
fn test_hostname_rejects_empty_and_empty_label() {
    assert_eq!(validate_hostname(""), Err(ValidationError::HostnameEmpty));
    assert_eq!(
        validate_hostname("a..b"),
        Err(ValidationError::HostnameLabel)
    );
}

#[test]
fn test_hostname_rejects_over_length_label() {
    let label = "a".repeat(64);
    assert_eq!(
        validate_hostname(&format!("{label}.com")),
        Err(ValidationError::HostnameLabel)
    );
}

#[test]
fn test_hostname_rejects_non_ascii() {
    assert_eq!(
        validate_hostname("exämple.com"),
        Err(ValidationError::HostnameChar)
    );
}

#[test]
fn test_code_id_accepts_reverse_dns_form() {
    assert!(validate_code_id("com.google.Chrome").is_ok());
    assert!(validate_code_id("ai.macwarden.panel").is_ok());
    assert!(validate_code_id("my-app_v2.tool").is_ok());
}

#[test]
fn test_code_id_rejects_shell_metacharacters() {
    for bad in ["com.a;rm -rf", "a|b", "a$(x)", "a`b`", "a/b", "a b"] {
        assert_eq!(
            validate_code_id(bad),
            Err(ValidationError::CodeIdChar),
            "should reject {bad}"
        );
    }
}

#[test]
fn test_code_id_rejects_empty_and_over_length() {
    assert_eq!(validate_code_id(""), Err(ValidationError::CodeIdLength));
    let long = "a".repeat(MAX_CODE_ID_LEN + 1);
    assert_eq!(validate_code_id(&long), Err(ValidationError::CodeIdLength));
}

#[test]
fn test_team_id_accepts_ten_upper_alnum() {
    assert!(validate_team_id("EQHXZ8M8AV").is_ok());
    assert!(validate_team_id("0123456789").is_ok());
}

#[test]
fn test_team_id_rejects_wrong_length_and_charset() {
    assert_eq!(validate_team_id("SHORT"), Err(ValidationError::TeamId));
    assert_eq!(
        validate_team_id("ELEVENCHARS0"),
        Err(ValidationError::TeamId)
    );
    assert_eq!(validate_team_id("lowercase1"), Err(ValidationError::TeamId)); // lowercase rejected
    assert_eq!(validate_team_id("ABC;123456"), Err(ValidationError::TeamId));
}

#[test]
fn test_expiry_bounds() {
    let now = 1_000_000;
    let horizon = 3_600_000; // 1 hour
    assert!(validate_expiry(now + 1000, now, horizon).is_ok());
    assert_eq!(
        validate_expiry(now, now, horizon),
        Err(ValidationError::ExpiryPast)
    );
    assert_eq!(
        validate_expiry(now - 1, now, horizon),
        Err(ValidationError::ExpiryPast)
    );
    assert_eq!(
        validate_expiry(now + horizon + 1, now, horizon),
        Err(ValidationError::ExpiryTooFar)
    );
}

#[test]
fn test_rule_slug_derives_from_validated_host() {
    assert_eq!(
        rule_slug("googlevideo.com").expect("slug"),
        "googlevideo.com"
    );
    assert!(rule_slug("../etc").is_err());
}

#[test]
fn test_rules_path_within_accepts_safe_slug() {
    let dir = Path::new("/home/u/.macwarden/net-rules");
    let path = rules_path_within(dir, "googlevideo.com").expect("within");
    assert_eq!(path, dir.join("googlevideo.com"));
    assert!(path.starts_with(dir));
}

#[test]
fn test_rules_path_within_rejects_escape() {
    let dir = Path::new("/home/u/.macwarden/net-rules");
    for bad in ["..", "../secret", "a/b", "..\\win", "sub/../..", ""] {
        assert_eq!(
            rules_path_within(dir, bad),
            Err(ValidationError::PathEscape),
            "should reject {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// R7 allow-list app selector
// ---------------------------------------------------------------------------

#[test]
fn test_validate_app_accepts_code_id_and_path() {
    assert!(validate_app("com.google.Chrome").is_ok());
    assert!(validate_app("/Applications/Chrome.app/Contents/MacOS/Chrome").is_ok());
}

#[test]
fn test_validate_app_rejects_bad_code_id() {
    assert_eq!(validate_app("bad id"), Err(ValidationError::CodeIdChar));
}

#[test]
fn test_validate_app_rejects_path_with_nul() {
    assert_eq!(validate_app("/bin/\nsh"), Err(ValidationError::CodeIdChar));
}

// ---------------------------------------------------------------------------
// R8 StartTrace app_id
// ---------------------------------------------------------------------------

#[test]
fn test_validate_app_id_accepts_code_id_and_path() {
    assert!(validate_app_id("com.google.Chrome").is_ok());
    assert!(validate_app_id("/Applications/Chrome.app/Contents/MacOS/Chrome").is_ok());
}

#[test]
fn test_validate_app_id_rejects_injection() {
    assert_eq!(
        validate_app_id("bad; rm -rf"),
        Err(ValidationError::CodeIdChar)
    );
    assert_eq!(validate_app_id(""), Err(ValidationError::CodeIdLength));
    assert_eq!(
        validate_app_id("/bin/\nsh"),
        Err(ValidationError::CodeIdChar)
    );
}

#[test]
fn test_validate_rule_batch_len_rejects_empty() {
    assert_eq!(
        validate_rule_batch_len(0),
        Err(ValidationError::RuleBatchEmpty)
    );
}

#[test]
fn test_validate_rule_batch_len_accepts_within_cap() {
    assert!(validate_rule_batch_len(1).is_ok());
    assert!(validate_rule_batch_len(MAX_RULE_BATCH).is_ok());
}

#[test]
fn test_validate_rule_batch_len_rejects_over_cap() {
    assert_eq!(
        validate_rule_batch_len(MAX_RULE_BATCH + 1),
        Err(ValidationError::RuleBatchTooLarge)
    );
}
