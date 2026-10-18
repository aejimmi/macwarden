//! Tests for the pure policy-profile conversions and validation (R7/R9).

use super::*;
use ipc::validate::ValidationError;
use net::PolicyConfig;

fn wire(
    app: Option<&str>,
    team: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
) -> WireAllowEntry {
    WireAllowEntry {
        app: app.map(ToOwned::to_owned),
        team_id: team.map(ToOwned::to_owned),
        host: host.map(ToOwned::to_owned),
        ip: ip.map(ToOwned::to_owned),
        note: None,
    }
}

// ---------------------------------------------------------------------------
// Mode conversion
// ---------------------------------------------------------------------------

#[test]
fn test_mode_round_trips() {
    for mode in [WireMode::AllowAll, WireMode::BlockAll] {
        assert_eq!(to_wire_mode(from_wire_mode(mode)), mode);
    }
}

// ---------------------------------------------------------------------------
// wire_profile shape
// ---------------------------------------------------------------------------

#[test]
fn test_wire_profile_default_shape() {
    let profile = wire_profile(&PolicyConfig::default()).expect("wire profile");
    assert_eq!(profile.mode, WireMode::AllowAll);
    assert!(!profile.allow_apple_programs);
    assert!(profile.allow_dns_traffic);
    assert!(profile.allowlist.is_empty());
    assert!(!profile.groups.is_empty(), "built-in groups must be listed");
    // location-services is present (R6 include fix).
    assert!(profile.groups.iter().any(|g| g.name == "location-services"));
}

#[test]
fn test_wire_profile_populates_group_description_and_domain_count() {
    let profile = wire_profile(&PolicyConfig::default()).expect("wire profile");
    // Every built-in group carries a human description and a real domain count.
    for group in &profile.groups {
        assert!(
            !group.description.is_empty(),
            "group `{}` must carry a description for the Rules view",
            group.name
        );
        assert!(
            group.domain_count > 0,
            "group `{}` must count the domains it covers",
            group.name
        );
    }
    // Spot-check a known group's description matches the source of truth.
    let groups = builtin_groups().expect("built-in groups");
    let src = groups.get("location-services").expect("location group");
    let wired = profile
        .groups
        .iter()
        .find(|g| g.name == "location-services")
        .expect("location-services in profile");
    assert_eq!(wired.description, src.description);
    assert_eq!(wired.domain_count, domain_count(src));
}

#[test]
fn test_wire_profile_reflects_group_override() {
    let mut config = PolicyConfig::default();
    crate::commands::net::set_group_override(&mut config.groups, "development", true);
    let profile = wire_profile(&config).expect("wire profile");
    let dev = profile
        .groups
        .iter()
        .find(|g| g.name == "development")
        .expect("development group");
    assert!(dev.enabled, "explicitly enabled group shows enabled");
    assert!(!dev.default_enabled, "development is not default-enabled");
}

// ---------------------------------------------------------------------------
// entry_from_wire validation
// ---------------------------------------------------------------------------

#[test]
fn test_entry_all_none_rejected() {
    let err = entry_from_wire(&wire(None, None, None, None)).unwrap_err();
    assert!(matches!(
        err,
        ServerError::Validation(ValidationError::AllowEntryEmpty)
    ));
}

#[test]
fn test_entry_app_and_team_rejected() {
    let err = entry_from_wire(&wire(Some("com.a.b"), Some("EQHXZ8M8AV"), None, None)).unwrap_err();
    assert!(matches!(
        err,
        ServerError::Validation(ValidationError::AllowEntryConflict)
    ));
}

#[test]
fn test_entry_invalid_host_rejected() {
    let err = entry_from_wire(&wire(None, None, Some("bad host"), None)).unwrap_err();
    assert!(matches!(err, ServerError::Validation(_)));
}

#[test]
fn test_entry_invalid_ip_rejected() {
    let err = entry_from_wire(&wire(None, None, None, Some("not-an-ip"))).unwrap_err();
    assert!(matches!(
        err,
        ServerError::Validation(ValidationError::InvalidIp)
    ));
}

#[test]
fn test_entry_valid_cidr_parses() {
    let entry = entry_from_wire(&wire(
        Some("com.google.Chrome"),
        None,
        None,
        Some("10.0.0.0/8"),
    ))
    .expect("valid entry");
    assert!(entry.ip.is_some());
    assert_eq!(entry.app.as_deref(), Some("com.google.Chrome"));
}

// ---------------------------------------------------------------------------
// entry_to_wire / normalized_key round trip
// ---------------------------------------------------------------------------

#[test]
fn test_entry_wire_round_trip_key_stable() {
    let entry =
        entry_from_wire(&wire(None, Some("EQHXZ8M8AV"), Some("x.com"), None)).expect("valid entry");
    let back = entry_to_wire(&entry);
    let entry2 = entry_from_wire(&back).expect("valid entry");
    assert_eq!(normalized_key(&entry), normalized_key(&entry2));
}

#[test]
fn test_normalized_key_ignores_note() {
    let mut a = entry_from_wire(&wire(None, None, Some("x.com"), None)).expect("entry");
    let b = a.clone();
    a.note = Some("a note".to_owned());
    assert_eq!(normalized_key(&a), normalized_key(&b));
}
