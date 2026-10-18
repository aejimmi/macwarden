use super::*;

#[test]
fn test_looks_like_ip_classifies_ipv4_and_cidr() {
    assert!(looks_like_ip("1.2.3.4"));
    assert!(looks_like_ip("140.82.112.0/20"));
    assert!(looks_like_ip("::1"));
    assert!(looks_like_ip("2606:4700::/32"));
}

#[test]
fn test_looks_like_ip_rejects_hostnames() {
    assert!(!looks_like_ip("example.com"));
    assert!(!looks_like_ip("*.googleapis.com"));
    assert!(!looks_like_ip("1.2.3")); // only three octets
    assert!(!looks_like_ip("a.b.c.d"));
}

#[test]
fn test_empty_entry_sets_exactly_one_field() {
    let host = empty_entry(EntryField::Host("*.example.com".to_string()));
    assert_eq!(host.host.as_deref(), Some("*.example.com"));
    assert!(host.ip.is_none());
    assert!(host.app.is_none());
    assert!(host.team_id.is_none());

    let ip = empty_entry(EntryField::Ip("10.0.0.0/8".to_string()));
    assert_eq!(ip.ip.as_deref(), Some("10.0.0.0/8"));
    assert!(ip.host.is_none());
}

#[test]
fn test_describe_entry_prefers_most_specific_field() {
    let app = WireAllowEntry {
        app: Some("com.google.Chrome".to_string()),
        team_id: None,
        host: Some("*.googleapis.com".to_string()),
        ip: None,
        note: None,
    };
    // App wins over host when both are present.
    assert_eq!(describe_entry(&app).1, "com.google.Chrome");

    let ip_only = empty_entry(EntryField::Ip("1.2.3.4".to_string()));
    assert_eq!(describe_entry(&ip_only).1, "1.2.3.4");
}
