#![allow(clippy::panic)]

use super::*;

#[test]
fn test_unknown_capability_string_deserializes_to_unknown() {
    let cap: Capability = serde_json::from_str("\"some_future_feature\"").expect("deserialize");
    assert_eq!(cap, Capability::Unknown);
}

#[test]
fn test_known_capability_strings_round_trip() {
    for cap in [
        Capability::History,
        Capability::PushEvents,
        Capability::Mutations,
        Capability::ExecPolicy,
        Capability::Openbinary,
        Capability::Policy,
        Capability::Trace,
        Capability::NetworkEnforcement,
    ] {
        let json = serde_json::to_string(&cap).expect("serialize");
        let back: Capability = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, cap);
    }
}

#[test]
fn test_network_enforcement_capability_wire_name() {
    // The additive spec-009 capability serializes to snake_case and an older
    // panel that predates it still round-trips it through Capability::Unknown.
    let json = serde_json::to_string(&Capability::NetworkEnforcement).expect("serialize");
    assert_eq!(json, "\"network_enforcement\"");
    let back: Capability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, Capability::NetworkEnforcement);
}

#[test]
fn test_welcome_with_unknown_capability_still_deserializes() {
    // A Welcome carrying an unrecognized capability deserializes without error;
    // the unknown capability maps to Capability::Unknown and is ignored (R3).
    let json = r#"{"welcome":{"protocol_version":1,"daemon_version":"9.9","capabilities":["history","teleport"]}}"#;
    let resp: Response = serde_json::from_str(json).expect("deserialize");
    match resp {
        Response::Welcome { capabilities, .. } => {
            assert!(capabilities.contains(&Capability::History));
            assert!(capabilities.contains(&Capability::Unknown));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }
}

#[test]
fn test_welcome_with_duplicate_network_enforcement_still_detected() {
    // A hostile or buggy daemon repeating a capability in the wire array is not
    // rejected -- `Vec<Capability>` tolerates duplicates and `.contains` still
    // finds it, so the panel's feature-detection is robust to a malformed list.
    let json = r#"{"welcome":{"protocol_version":1,"daemon_version":"1.0","capabilities":["network_enforcement","network_enforcement","mutations"]}}"#;
    let resp: Response = serde_json::from_str(json).expect("deserialize");
    match resp {
        Response::Welcome { capabilities, .. } => {
            assert_eq!(
                capabilities
                    .iter()
                    .filter(|c| **c == Capability::NetworkEnforcement)
                    .count(),
                2
            );
            assert!(capabilities.contains(&Capability::NetworkEnforcement));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }
}

#[test]
fn test_welcome_with_empty_capabilities_has_no_network_enforcement() {
    // The empty-array case (R3's "not enforcing" wire shape): no capability at
    // all, not even Unknown -- the panel must not spuriously detect enforcement.
    let json = r#"{"welcome":{"protocol_version":1,"daemon_version":"1.0","capabilities":[]}}"#;
    let resp: Response = serde_json::from_str(json).expect("deserialize");
    match resp {
        Response::Welcome { capabilities, .. } => {
            assert!(capabilities.is_empty());
            assert!(!capabilities.contains(&Capability::NetworkEnforcement));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }
}

#[test]
fn test_welcome_with_non_string_capability_element_fails_to_deserialize() {
    // A hostile wire sending numeric/null entries instead of capability strings
    // must not silently coerce to Unknown -- it should fail the whole message
    // rather than admit a type-confused capability list.
    let json = r#"{"welcome":{"protocol_version":1,"daemon_version":"1.0","capabilities":[1,2]}}"#;
    assert!(serde_json::from_str::<Response>(json).is_err());

    let json_null =
        r#"{"welcome":{"protocol_version":1,"daemon_version":"1.0","capabilities":[null]}}"#;
    assert!(serde_json::from_str::<Response>(json_null).is_err());
}

#[test]
fn test_welcome_missing_capabilities_field_fails_to_deserialize() {
    // `capabilities` carries no `#[serde(default)]` -- a Welcome with the field
    // omitted entirely (rather than an empty array) is rejected, not silently
    // treated as "no capabilities". Documents the field's current strictness so
    // a future relaxation is a deliberate, reviewed change.
    let json = r#"{"welcome":{"protocol_version":1,"daemon_version":"1.0"}}"#;
    assert!(serde_json::from_str::<Response>(json).is_err());
}

#[test]
fn test_welcome_with_large_hostile_capability_list_still_finds_known_capability() {
    // A daemon (or an attacker on the wire) sending a very long tail of garbage
    // capability strings must not prevent the panel from finding the one
    // capability it actually cares about, and must not panic on the volume.
    let mut caps: Vec<String> = (0..500).map(|i| format!("\"bogus_{i}\"")).collect();
    caps.push("\"network_enforcement\"".to_string());
    let json = format!(
        r#"{{"welcome":{{"protocol_version":1,"daemon_version":"1.0","capabilities":[{}]}}}}"#,
        caps.join(",")
    );
    let resp: Response = serde_json::from_str(&json).expect("deserialize");
    match resp {
        Response::Welcome { capabilities, .. } => {
            assert_eq!(capabilities.len(), 501);
            assert!(capabilities.contains(&Capability::NetworkEnforcement));
            assert!(
                capabilities
                    .iter()
                    .filter(|c| **c == Capability::Unknown)
                    .count()
                    >= 500
            );
        }
        other => panic!("expected Welcome, got {other:?}"),
    }
}

#[test]
fn test_unknown_error_kind_deserializes_to_unknown() {
    let kind: ErrorKind = serde_json::from_str("\"future_error\"").expect("deserialize");
    assert_eq!(kind, ErrorKind::Unknown);
}

#[test]
fn test_version_mismatch_handshake_shape() {
    // The daemon replies Welcome even on a version mismatch (so the panel learns
    // the daemon's version), then rejects subsequent requests with VersionMismatch.
    let welcome = Response::Welcome {
        protocol_version: PROTOCOL_VERSION + 1,
        daemon_version: "2.0.0".into(),
        capabilities: vec![],
    };
    let json = serde_json::to_string(&welcome).expect("serialize");
    let back: Response = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, welcome);

    let error = Response::Error {
        kind: ErrorKind::VersionMismatch,
        message: String::new(),
    };
    let err_json = serde_json::to_string(&error).expect("serialize");
    assert!(err_json.contains("version_mismatch"));
}

#[test]
fn test_protocol_version_is_stable_constant() {
    assert_eq!(PROTOCOL_VERSION, 1);
}
