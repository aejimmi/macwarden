use super::*;
use crate::rule::NetworkAction;
use std::io::Write;

#[test]
fn test_parse_hosts_format() {
    let content = "\
0.0.0.0 ad.example.com
127.0.0.1 tracker.example.com
0.0.0.0 malware.example.com
";
    let bl = Blocklist::parse("test-hosts", content, BlocklistFormat::Hosts)
        .expect("should parse hosts format");
    assert_eq!(bl.len(), 3);
    assert!(bl.contains("ad.example.com"));
    assert!(bl.contains("tracker.example.com"));
    assert!(bl.contains("malware.example.com"));
}

#[test]
fn test_parse_domain_list_format() {
    let content = "\
ad.example.com
tracker.example.com
malware.example.com
";
    let bl = Blocklist::parse("test-domains", content, BlocklistFormat::DomainList)
        .expect("should parse domain list format");
    assert_eq!(bl.len(), 3);
    assert!(bl.contains("ad.example.com"));
    assert!(bl.contains("tracker.example.com"));
    assert!(bl.contains("malware.example.com"));
}

#[test]
fn test_hosts_skips_comments_and_blanks() {
    let content = "\
# This is a comment
0.0.0.0 ad.example.com

# Another comment

0.0.0.0 tracker.example.com
";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts).expect("should parse");
    assert_eq!(bl.len(), 2);
}

#[test]
fn test_hosts_skips_localhost() {
    let content = "\
127.0.0.1 localhost
127.0.0.1 local
127.0.0.1 broadcasthost
0.0.0.0 ad.example.com
";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts).expect("should parse");
    assert_eq!(bl.len(), 1);
    assert!(bl.contains("ad.example.com"));
    assert!(!bl.contains("localhost"));
}

#[test]
fn test_contains_exact() {
    let content = "tracker.example.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList).expect("should parse");
    assert!(bl.contains("tracker.example.com"));
}

#[test]
fn test_contains_subdomain_walking() {
    let content = "tracker.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList).expect("should parse");

    assert!(
        bl.contains("api.tracker.com"),
        "subdomain should match via domain walking"
    );
    assert!(
        bl.contains("deep.nested.tracker.com"),
        "deeply nested subdomain should match"
    );
}

#[test]
fn test_contains_no_partial_match() {
    let content = "apple.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList).expect("should parse");

    assert!(
        !bl.contains("evilapple.com"),
        "evilapple.com must NOT match apple.com"
    );
}

#[test]
fn test_case_insensitive() {
    let content = "google-analytics.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList).expect("should parse");

    assert!(
        bl.contains("Google-Analytics.COM"),
        "matching should be case insensitive"
    );
}

#[test]
fn test_inline_comments() {
    let content = "0.0.0.0 domain.com # this is a comment\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts).expect("should parse");
    assert_eq!(bl.len(), 1);
    assert!(bl.contains("domain.com"));
}

#[test]
fn test_empty_blocklist() {
    let bl = Blocklist::parse("empty", "", BlocklistFormat::DomainList)
        .expect("should parse empty content");
    assert!(bl.is_empty());
    assert_eq!(bl.len(), 0);
    assert_eq!(bl.name(), "empty");
}

// ---------------------------------------------------------------------------
// BlocklistConfig + load_from_file tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_file_hosts() {
    let dir = tempfile::tempdir().expect("should create temp dir");
    let file_path = dir.path().join("hosts.txt");
    let mut f = std::fs::File::create(&file_path).expect("should create file");
    writeln!(f, "0.0.0.0 ad.example.com").expect("write");
    writeln!(f, "0.0.0.0 tracker.example.com").expect("write");
    drop(f);

    let config = BlocklistConfig {
        name: "test-hosts".to_owned(),
        source: file_path.to_string_lossy().into_owned(),
        format: BlocklistFormat::Hosts,
        action: crate::rule::NetworkAction::Deny,
        update_interval: None,
        enabled: true,
    };

    let bl = load_from_file(&config).expect("should load from file");
    assert_eq!(bl.len(), 2);
    assert!(bl.contains("ad.example.com"));
    assert!(bl.contains("tracker.example.com"));
    assert_eq!(bl.name(), "test-hosts");
}

#[test]
fn test_load_from_file_missing() {
    let config = BlocklistConfig {
        name: "missing".to_owned(),
        source: "/nonexistent/path/hosts.txt".to_owned(),
        format: BlocklistFormat::Hosts,
        action: crate::rule::NetworkAction::Deny,
        update_interval: None,
        enabled: true,
    };

    let result = load_from_file(&config);
    assert!(result.is_err(), "missing file should return error");
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("blocklist load"),
        "error should mention blocklist load, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Windows line endings (\r\n)
// ---------------------------------------------------------------------------

#[test]
fn test_hosts_format_crlf_line_endings() {
    let content = "0.0.0.0 ad.example.com\r\n0.0.0.0 tracker.example.com\r\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts)
        .expect("should parse CRLF hosts file");
    assert_eq!(bl.len(), 2);
    assert!(bl.contains("ad.example.com"));
    assert!(bl.contains("tracker.example.com"));
}

#[test]
fn test_domain_list_format_crlf_line_endings() {
    let content = "ad.example.com\r\ntracker.example.com\r\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList)
        .expect("should parse CRLF domain list");
    // CRLF: the \r becomes part of the domain string unless stripped.
    // The parser uses `str::lines()` which handles \r\n correctly.
    assert_eq!(bl.len(), 2, "CRLF lines should parse cleanly");
    assert!(bl.contains("ad.example.com"));
    assert!(bl.contains("tracker.example.com"));
}

// ---------------------------------------------------------------------------
// Tabs vs spaces in hosts file
// ---------------------------------------------------------------------------

#[test]
fn test_hosts_format_tab_separator() {
    // Hosts files sometimes use a tab between address and domain.
    let content = "0.0.0.0\tad.example.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts)
        .expect("should parse tab-separated hosts file");
    assert_eq!(bl.len(), 1);
    assert!(bl.contains("ad.example.com"));
}

#[test]
fn test_hosts_format_multiple_spaces() {
    let content = "0.0.0.0  ad.example.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts)
        .expect("should parse multi-space hosts file");
    assert_eq!(bl.len(), 1);
    assert!(bl.contains("ad.example.com"));
}

// ---------------------------------------------------------------------------
// Error: redirect address with no domain
// ---------------------------------------------------------------------------

#[test]
fn test_hosts_redirect_addr_no_domain_returns_error() {
    // A line with only a redirect address and no domain is a parse error.
    let content = "0.0.0.0\n";
    let result = Blocklist::parse("test", content, BlocklistFormat::Hosts);
    assert!(
        result.is_err(),
        "redirect address with no domain should return error"
    );
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no domain"),
        "error should mention missing domain, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Whitespace-only lines
// ---------------------------------------------------------------------------

#[test]
fn test_domain_list_whitespace_only_lines_skipped() {
    let content = "ad.example.com\n   \n\t\ntracker.example.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::DomainList)
        .expect("should skip whitespace-only lines");
    assert_eq!(bl.len(), 2);
}

// ---------------------------------------------------------------------------
// Non-redirect addresses are skipped silently
// ---------------------------------------------------------------------------

#[test]
fn test_hosts_non_redirect_addr_skipped() {
    // Lines not starting with a recognized redirect address are skipped.
    let content = "192.168.1.1 router.local\n0.0.0.0 ad.example.com\n";
    let bl = Blocklist::parse("test", content, BlocklistFormat::Hosts).expect("should parse");
    assert_eq!(bl.len(), 1, "non-redirect address line should be skipped");
    assert!(bl.contains("ad.example.com"));
    assert!(!bl.contains("router.local"));
}

// ---------------------------------------------------------------------------
// to_blocklist_entries
// ---------------------------------------------------------------------------

#[test]
fn test_to_blocklist_entries_includes_all_domains() {
    let content = "ad.example.com\ntracker.example.com\n";
    let bl =
        Blocklist::parse("peter-lowe", content, BlocklistFormat::DomainList).expect("should parse");
    let entries = bl.to_blocklist_entries();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(entry.list_name, "peter-lowe");
        assert!(
            entry.domain == "ad.example.com" || entry.domain == "tracker.example.com",
            "unexpected domain: {}",
            entry.domain
        );
    }
}

// ---------------------------------------------------------------------------
// BlocklistConfig accessors
// ---------------------------------------------------------------------------

#[test]
fn test_blocklist_config_default_action_is_deny() {
    let toml_str = r#"
name = "test"
source = "/tmp/test.txt"
format = "domain-list"
"#;
    let config: BlocklistConfig = toml::from_str(toml_str).expect("should parse");
    assert_eq!(
        config.action,
        NetworkAction::Deny,
        "default action should be Deny"
    );
    assert!(config.enabled, "default enabled should be true");
}

#[test]
fn test_blocklist_name_and_format_accessors() {
    let content = "example.com\n";
    let bl =
        Blocklist::parse("my-list", content, BlocklistFormat::DomainList).expect("should parse");
    assert_eq!(bl.name(), "my-list");
    assert_eq!(bl.format(), BlocklistFormat::DomainList);
}
