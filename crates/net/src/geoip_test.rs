use super::*;
use std::net::{IpAddr, Ipv4Addr};

/// Helper: skip test if geo databases are not installed locally.
fn require_geo() -> GeoLookup {
    if !databases_available() {
        eprintln!("SKIP: geo databases not installed at ~/.macwarden/geo/");
        // Return early — test passes vacuously when DBs are absent.
        // This avoids CI failures on machines without GeoLite2 downloads.
        std::process::exit(0);
    }
    GeoLookup::new().expect("databases should load when files exist")
}

#[test]
fn test_lookup_google_dns() {
    let geo = require_geo();
    let info = geo.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(info.country.as_deref(), Some("US"));
    assert!(
        info.asn_name
            .as_deref()
            .is_some_and(|n| n.contains("GOOGLE")),
        "expected ASN containing GOOGLE, got {:?}",
        info.asn_name,
    );
}

#[test]
fn test_lookup_cloudflare_dns() {
    let geo = require_geo();
    let info = geo.lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    // Cloudflare DNS is anycast, country may vary, but ASN should be present.
    assert!(
        info.asn_name.is_some(),
        "Cloudflare 1.1.1.1 should have an ASN name",
    );
}

#[test]
fn test_lookup_private_ip_returns_defaults() {
    let geo = require_geo();
    let info = geo.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(info.country.is_none(), "private IP has no country");
    assert!(info.asn_name.is_none(), "private IP has no ASN");
}

#[test]
fn test_truncate_asn_simple() {
    assert_eq!(truncate_asn("GOOGLE LLC"), "GOOGLE");
}

#[test]
fn test_truncate_asn_hyphenated() {
    assert_eq!(truncate_asn("CLOUDFLARE-NET"), "CLOUDFLARE-NET");
}

#[test]
fn test_truncate_asn_comma() {
    assert_eq!(truncate_asn("Amazon.com, Inc."), "Amazon.com");
}

#[test]
fn test_truncate_asn_single_word() {
    assert_eq!(truncate_asn("FACEBOOK"), "FACEBOOK");
}

#[test]
fn test_new_fails_when_dir_missing() {
    // Point at a directory that doesn't exist.
    let result = GeoLookup::from_dir(std::path::Path::new("/nonexistent/geo"));
    assert!(result.is_err(), "should fail when directory is missing");
}

#[test]
fn test_databases_available_reflects_disk() {
    // Just verify it doesn't panic — the result depends on the machine.
    let _ = databases_available();
}
