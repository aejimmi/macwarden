#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// Empty and degenerate inputs
// ---------------------------------------------------------------------------

#[test]
fn test_empty_string_domain_walk_does_not_match_anything() {
    // An empty pattern creates a DomainWalk with domain="" and subdomain glob
    // "*.". It should only match "" exactly — not any real hostname.
    let pat = HostPattern::new("").expect("empty string is valid glob input");
    assert!(!pat.matches("com"), "empty pattern should not match 'com'");
    assert!(
        !pat.matches("example.com"),
        "empty pattern should not match 'example.com'"
    );
    // Exact match against the empty string itself.
    assert!(pat.matches(""), "empty pattern should match empty string");
}

#[test]
fn test_single_dot_pattern() {
    // "." is a plain domain — DomainWalk: matches "." and "*.".
    let pat = HostPattern::new(".").expect("dot is valid");
    // The exact domain "." should match.
    assert!(pat.matches("."), "dot should match dot");
    // "com." is technically a subdomain of "." but not a real hostname.
    // The glob "*.{.}" would be "*..". We don't assert the precise outcome —
    // we assert it doesn't panic.
    let _ = pat.matches("com");
    let _ = pat.matches("example.com");
}

#[test]
fn test_bare_tld_domain_walk() {
    // "com" as a plain domain: matches "com" and "*.com".
    let pat = HostPattern::new("com").expect("valid pattern");
    assert!(pat.matches("com"), "should match exact TLD");
    assert!(pat.matches("example.com"), "should match subdomain of TLD");
    assert!(
        !pat.matches("example.net"),
        "should not match different TLD"
    );
}

#[test]
fn test_trailing_dot_in_hostname_is_not_matched() {
    // "apple.com" pattern; "apple.com." (FQDN with trailing dot) must NOT
    // match via domain walk because "apple.com." != "apple.com" and
    // "apple.com." does not end with ".apple.com".
    let pat = HostPattern::new("apple.com").expect("valid pattern");
    assert!(
        !pat.matches("apple.com."),
        "trailing-dot FQDN must not match bare domain pattern"
    );
}

#[test]
fn test_exact_prefix_with_trailing_dot() {
    // Same check with exact-match prefix.
    let pat = HostPattern::new("=apple.com").expect("valid pattern");
    assert!(pat.matches("apple.com"), "exact match should work");
    assert!(
        !pat.matches("apple.com."),
        "exact match must not match trailing-dot FQDN"
    );
}

// ---------------------------------------------------------------------------
// Domain-boundary safety
// ---------------------------------------------------------------------------

#[test]
fn test_domain_walk_does_not_match_suffix_without_boundary() {
    // "tracker.com" must NOT match "eviltracker.com".
    let pat = HostPattern::new("tracker.com").expect("valid pattern");
    assert!(!pat.matches("eviltracker.com"));
    assert!(!pat.matches("nottracker.com"));
}

#[test]
fn test_domain_walk_matches_deep_subdomain() {
    let pat = HostPattern::new("example.com").expect("valid pattern");
    assert!(pat.matches("a.b.c.example.com"));
}

#[test]
fn test_exact_match_rejects_subdomains() {
    let pat = HostPattern::new("=example.com").expect("valid pattern");
    assert!(pat.matches("example.com"));
    assert!(!pat.matches("sub.example.com"));
    assert!(!pat.matches("a.b.example.com"));
}

// ---------------------------------------------------------------------------
// Unicode / non-ASCII hostnames
// ---------------------------------------------------------------------------

#[test]
fn test_unicode_hostname_does_not_panic() {
    // Internationalised domain name as input to matches().
    let pat = HostPattern::new("example.com").expect("valid pattern");
    // Should not panic, return false (unicode != ascii domain).
    let result = pat.matches("例え.com");
    let _ = result; // outcome is not the point, absence of panic is
}

#[test]
fn test_unicode_in_pattern_does_not_panic() {
    // Unicode directly in the pattern string.
    let result = HostPattern::new("例え.com");
    // Whether it succeeds or returns an error, it must not panic.
    let _ = result;
}

// ---------------------------------------------------------------------------
// Very long hostname
// ---------------------------------------------------------------------------

#[test]
fn test_very_long_hostname_does_not_panic() {
    let long = format!("{}.example.com", "a".repeat(300));
    let pat = HostPattern::new("example.com").expect("valid pattern");
    // Should return true (it's a valid subdomain) and not panic.
    assert!(
        pat.matches(&long),
        "very long subdomain should still match via domain walk"
    );
}

#[test]
fn test_very_long_pattern_does_not_panic() {
    let long = "a".repeat(300) + ".example.com";
    let result = HostPattern::new(&long);
    // Whether it succeeds or errors, must not panic.
    let _ = result;
}

// ---------------------------------------------------------------------------
// Exact-match with empty suffix (="")
// ---------------------------------------------------------------------------

#[test]
fn test_exact_empty_string_matches_only_empty() {
    let pat = HostPattern::new("=").expect("valid exact-empty pattern");
    assert!(pat.matches(""), "exact empty should match empty");
    assert!(!pat.matches("x"), "exact empty should not match 'x'");
}

// ---------------------------------------------------------------------------
// Accessors and trait impls
// ---------------------------------------------------------------------------

#[test]
fn test_as_str_returns_original_pattern() {
    let raw = "*.analytics.example.com";
    let pat = HostPattern::new(raw).expect("valid glob pattern");
    assert_eq!(pat.as_str(), raw);
}

#[test]
fn test_display_returns_original_pattern() {
    let raw = "apple.com";
    let pat = HostPattern::new(raw).expect("valid pattern");
    assert_eq!(pat.to_string(), raw);
}

#[test]
fn test_serde_round_trip() {
    // Use toml for serialization — serde_json is not a dep of this crate.
    let raw = "=apple.com";
    let pat = HostPattern::new(raw).expect("valid pattern");
    // Serialize via toml (requires a wrapper because toml needs a map at root).
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper {
        host: HostPattern,
    }
    let w = Wrapper { host: pat };
    let toml_str = toml::to_string(&w).expect("serialize");
    let back: Wrapper = toml::from_str(&toml_str).expect("deserialize");
    assert_eq!(back.host.as_str(), raw);
    assert!(back.host.matches("apple.com"));
    assert!(!back.host.matches("sub.apple.com"));
}

#[test]
fn test_serde_deserialize_invalid_pattern_returns_error() {
    // An unclosed bracket is not a valid glob and the HostPattern::new call
    // inside the Deserialize impl should return an error.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct Wrapper {
        host: HostPattern,
    }
    let bad_toml = r#"host = "[invalid""#;
    let result: std::result::Result<Wrapper, _> = toml::from_str(bad_toml);
    assert!(
        result.is_err(),
        "deserializing an invalid glob pattern should fail"
    );
}
