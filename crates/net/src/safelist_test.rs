use super::*;

#[test]
fn test_ocsp_is_essential() {
    assert!(
        is_essential_domain("ocsp.apple.com"),
        "ocsp.apple.com should be essential"
    );
}

#[test]
fn test_time_is_essential() {
    assert!(
        is_essential_domain("time.apple.com"),
        "time.apple.com should be essential"
    );
}

#[test]
fn test_gateway_is_essential() {
    assert!(
        is_essential_domain("gateway.icloud.com"),
        "gateway.icloud.com should be essential"
    );
}

#[test]
fn test_captive_is_essential() {
    assert!(
        is_essential_domain("captive.apple.com"),
        "captive.apple.com should be essential"
    );
}

#[test]
fn test_subdomain_of_essential_is_essential() {
    assert!(
        is_essential_domain("cdn.ocsp.apple.com"),
        "subdomain of essential domain should also be essential"
    );
    assert!(
        is_essential_domain("us-east.gateway.icloud.com"),
        "deeper subdomain of essential domain should also be essential"
    );
}

#[test]
fn test_random_apple_domain_not_essential() {
    assert!(
        !is_essential_domain("tracking.apple.com"),
        "tracking.apple.com is NOT in the safe-list"
    );
    assert!(
        !is_essential_domain("analytics.apple.com"),
        "analytics.apple.com is NOT in the safe-list"
    );
}

#[test]
fn test_non_apple_not_essential() {
    assert!(
        !is_essential_domain("google.com"),
        "google.com is not essential"
    );
    assert!(
        !is_essential_domain("example.com"),
        "example.com is not essential"
    );
}

#[test]
fn test_case_insensitive_matching() {
    assert!(
        is_essential_domain("OCSP.APPLE.COM"),
        "matching should be case-insensitive"
    );
    assert!(
        is_essential_domain("Time.Apple.Com"),
        "matching should be case-insensitive"
    );
}

#[test]
fn test_no_partial_domain_match() {
    assert!(
        !is_essential_domain("evil-ocsp.apple.com"),
        "evil-ocsp.apple.com must NOT match via partial overlap"
    );
}

#[test]
fn test_count_returns_expected() {
    assert_eq!(count(), 11, "essential domain list should have 11 entries");
}
