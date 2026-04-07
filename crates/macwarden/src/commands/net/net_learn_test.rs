use super::*;

#[test]
fn test_parse_duration_seconds() {
    let d = parse_duration("30s").expect("should parse");
    assert_eq!(d, Duration::from_secs(30));
}

#[test]
fn test_parse_duration_minutes() {
    let d = parse_duration("5m").expect("should parse");
    assert_eq!(d, Duration::from_secs(300));
}

#[test]
fn test_parse_duration_hours() {
    let d = parse_duration("1h").expect("should parse");
    assert_eq!(d, Duration::from_secs(3600));
}

#[test]
fn test_parse_duration_bare_number() {
    let d = parse_duration("60").expect("should parse");
    assert_eq!(d, Duration::from_secs(60));
}

#[test]
fn test_parse_duration_invalid() {
    assert!(parse_duration("abc").is_err());
}

#[test]
fn test_parse_duration_empty() {
    assert!(parse_duration("").is_err());
}

#[test]
fn test_extract_base_domain_subdomain() {
    assert_eq!(extract_base_domain("mail.google.com"), "google.com");
}

#[test]
fn test_extract_base_domain_already_base() {
    assert_eq!(extract_base_domain("google.com"), "google.com");
}

#[test]
fn test_extract_base_domain_deep() {
    assert_eq!(extract_base_domain("a.b.c.example.com"), "example.com");
}

#[test]
fn test_extract_base_domain_single() {
    assert_eq!(extract_base_domain("localhost"), "localhost");
}

#[test]
fn test_update_profiles_basic() {
    let tracker_db = TrackerDatabase::load_builtin().expect("tracker db");
    let mut profiles = HashMap::new();

    let connections = vec![super::super::net_lsof::LsofConnection {
        process: "TestApp".to_owned(),
        pid: 123,
        remote_host: "example.com".to_owned(),
        remote_port: 443,
        protocol: "TCP".to_owned(),
    }];

    update_profiles(&mut profiles, &connections, &tracker_db);

    assert_eq!(profiles.len(), 1);
    let profile = profiles.get("TestApp").expect("should have TestApp");
    assert_eq!(profile.total_connections, 1);
    assert_eq!(profile.destinations.len(), 1);
    assert!(profile.destinations.contains_key("example.com"));
}

#[test]
fn test_update_profiles_tracker_detection() {
    let tracker_db = TrackerDatabase::load_builtin().expect("tracker db");
    let mut profiles = HashMap::new();

    let connections = vec![super::super::net_lsof::LsofConnection {
        process: "TestApp".to_owned(),
        pid: 123,
        remote_host: "google-analytics.com".to_owned(),
        remote_port: 443,
        protocol: "TCP".to_owned(),
    }];

    update_profiles(&mut profiles, &connections, &tracker_db);

    let profile = profiles.get("TestApp").expect("should have TestApp");
    assert_eq!(profile.tracker_connections, 1);
    let dest = profile
        .destinations
        .get("google-analytics.com")
        .expect("dest");
    assert!(dest.tracker_category.is_some());
}

#[test]
fn test_update_profiles_skips_noise() {
    let tracker_db = TrackerDatabase::load_builtin().expect("tracker db");
    let mut profiles = HashMap::new();

    let connections = vec![
        super::super::net_lsof::LsofConnection {
            process: "TestApp".to_owned(),
            pid: 123,
            remote_host: "127.0.0.1".to_owned(),
            remote_port: 80,
            protocol: "TCP".to_owned(),
        },
        super::super::net_lsof::LsofConnection {
            process: "TestApp".to_owned(),
            pid: 123,
            remote_host: "fe80::1".to_owned(),
            remote_port: 443,
            protocol: "TCP".to_owned(),
        },
    ];

    update_profiles(&mut profiles, &connections, &tracker_db);
    assert!(profiles.is_empty(), "noise should be filtered");
}

#[test]
fn test_update_profiles_multiple_apps() {
    let tracker_db = TrackerDatabase::load_builtin().expect("tracker db");
    let mut profiles = HashMap::new();

    let connections = vec![
        super::super::net_lsof::LsofConnection {
            process: "AppA".to_owned(),
            pid: 1,
            remote_host: "a.com".to_owned(),
            remote_port: 443,
            protocol: "TCP".to_owned(),
        },
        super::super::net_lsof::LsofConnection {
            process: "AppB".to_owned(),
            pid: 2,
            remote_host: "b.com".to_owned(),
            remote_port: 443,
            protocol: "TCP".to_owned(),
        },
    ];

    update_profiles(&mut profiles, &connections, &tracker_db);
    assert_eq!(profiles.len(), 2);
}
