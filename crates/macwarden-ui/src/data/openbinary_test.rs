#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;

use super::io::{PersistEntry, from_persist, secs_to_system_time};
use super::*;

/// A trimmed capture of a real `GET /binary/{sha}` response for `/bin/ls`: the
/// analysis is nested under `binary`, `title`/`summary` are null, and the name
/// must fall back to the code-signing identifier.
const LS_FIXTURE: &str = r#"{
  "binary": {
    "sha256": "a97c50d34f912a5ada66959c231897ec2144e3c9cb922cd8150e4f2b0c9470e7",
    "title": null,
    "summary": null,
    "verdict": { "label": "benign", "rationale": [], "version": "v4" },
    "fingerprint": { "name": "" },
    "code_signature": { "code_directory": { "identifier": "com.apple.ls" } }
  }
}"#;

#[test]
fn test_verdict_from_label_covers_known_labels() {
    assert_eq!(ObVerdict::from_label("benign"), ObVerdict::Benign);
    assert_eq!(ObVerdict::from_label("suspicious"), ObVerdict::Suspicious);
    assert_eq!(ObVerdict::from_label("malicious"), ObVerdict::Malicious);
    assert_eq!(
        ObVerdict::from_label("likely_malicious"),
        ObVerdict::LikelyMalicious
    );
    assert_eq!(
        ObVerdict::from_label("not_enough_evidence"),
        ObVerdict::NotEnoughEvidence
    );
    assert_eq!(
        ObVerdict::from_label("space_alien"),
        ObVerdict::Unrecognized
    );
}

#[test]
fn test_verdict_tone_mapping() {
    assert_eq!(ObVerdict::Benign.tone(), ObTone::Good);
    assert_eq!(ObVerdict::Suspicious.tone(), ObTone::Warn);
    assert_eq!(ObVerdict::Malicious.tone(), ObTone::Bad);
    assert_eq!(ObVerdict::LikelyMalicious.tone(), ObTone::Bad);
    assert_eq!(ObVerdict::NotEnoughEvidence.tone(), ObTone::Neutral);
    assert_eq!(ObVerdict::Unrecognized.tone(), ObTone::Neutral);
}

#[test]
fn test_parse_known_from_nested_fixture() {
    let doc: Value = serde_json::from_str(LS_FIXTURE).unwrap();
    let state = parse_known(&doc);
    match state {
        ObState::Known {
            verdict,
            title,
            summary,
        } => {
            assert_eq!(verdict, ObVerdict::Benign);
            // title/name null/empty → falls back to the signing identifier.
            assert_eq!(title.as_deref(), Some("com.apple.ls"));
            assert_eq!(summary, None);
        }
        other => panic!("expected Known, got {other:?}"),
    }
}

#[test]
fn test_parse_known_flat_shape_and_title_precedence() {
    let doc: Value = serde_json::json!({
        "title": "curl 8.7",
        "summary": "command-line HTTP client",
        "verdict": { "label": "suspicious" },
        "fingerprint": { "name": "curl" }
    });
    let state = parse_known(&doc);
    assert_eq!(
        state,
        ObState::Known {
            verdict: ObVerdict::Suspicious,
            title: Some("curl 8.7".to_owned()),
            summary: Some("command-line HTTP client".to_owned()),
        }
    );
}

#[test]
fn test_parse_known_missing_verdict_is_inconclusive() {
    let doc: Value = serde_json::json!({ "binary": { "fingerprint": { "name": "mystery" } } });
    assert_eq!(
        parse_known(&doc),
        ObState::Known {
            verdict: ObVerdict::NotEnoughEvidence,
            title: Some("mystery".to_owned()),
            summary: None,
        }
    );
}

#[test]
fn test_persist_round_trip_known_and_unknown() {
    let mut entries = HashMap::new();
    entries.insert(
        "/bin/ls".to_owned(),
        PersistEntry {
            sha256: "a97c50".to_owned(),
            mtime_secs: Some(1_783_096_786),
            verdict: Some(ObVerdict::Benign),
            title: Some("com.apple.ls".to_owned()),
            summary: None,
            too_large: false,
        },
    );
    entries.insert(
        "/opt/homebrew/bin/rg".to_owned(),
        PersistEntry {
            sha256: "2fb61b".to_owned(),
            mtime_secs: None,
            verdict: None,
            title: None,
            summary: None,
            too_large: false,
        },
    );
    let original = Persisted { entries };

    let json = serde_json::to_string(&original).unwrap();
    let back: Persisted = serde_json::from_str(&json).unwrap();

    let ls = back.entries.get("/bin/ls").unwrap();
    assert_eq!(ls.verdict, Some(ObVerdict::Benign));
    assert_eq!(ls.mtime_secs, Some(1_783_096_786));
    let rg = back.entries.get("/opt/homebrew/bin/rg").unwrap();
    assert_eq!(rg.verdict, None, "None verdict is a 404 marker");
}

#[test]
fn test_from_persist_maps_verdict_and_unknown() {
    let known = from_persist(PersistEntry {
        sha256: "deadbeef".to_owned(),
        mtime_secs: Some(1000),
        verdict: Some(ObVerdict::Malicious),
        title: Some("evil".to_owned()),
        summary: None,
        too_large: false,
    });
    assert_eq!(known.state.verdict(), Some(ObVerdict::Malicious));
    assert_eq!(known.mtime, Some(secs_to_system_time(1000)));

    let unknown = from_persist(PersistEntry {
        sha256: "cafe".to_owned(),
        mtime_secs: None,
        verdict: None,
        title: None,
        summary: None,
        too_large: false,
    });
    assert_eq!(unknown.state, ObState::Unknown);

    let too_large = from_persist(PersistEntry {
        sha256: "beef".to_owned(),
        mtime_secs: None,
        verdict: None,
        title: None,
        summary: None,
        too_large: true,
    });
    assert_eq!(too_large.state, ObState::TooLarge);
}

#[test]
fn test_cache_get_reads_stored_entry() {
    let mut entries = HashMap::new();
    let key = PathBuf::from("/bin/ls");
    entries.insert(
        key.clone(),
        Entry::terminal(
            ObState::Known {
                verdict: ObVerdict::Benign,
                title: Some("com.apple.ls".to_owned()),
                summary: None,
            },
            Some("a97c50".to_owned()),
            None,
        ),
    );
    let config = ObConfig {
        endpoint: "https://example/api".to_owned(),
        auto_upload: true,
    };
    let cache = ObCache::from_parts(config, PathBuf::new(), entries);

    assert_eq!(cache.endpoint(), "https://example/api");
    assert_eq!(
        cache.get(&key).and_then(|s| s.verdict()),
        Some(ObVerdict::Benign)
    );
    assert_eq!(cache.get(Path::new("/nope")), None);
}

#[test]
fn test_parse_config_absent_defaults_to_auto_upload() {
    let cfg = parse_config("");
    assert!(cfg.auto_upload, "absent auto_upload defaults to true");
    assert_eq!(cfg.endpoint, DEFAULT_ENDPOINT);

    // A config with only an endpoint still defaults auto_upload to true.
    let cfg = parse_config("[openbinary]\nendpoint = \"https://x/api/\"\n");
    assert!(cfg.auto_upload);
    assert_eq!(cfg.endpoint, "https://x/api", "trailing slash trimmed");
}

#[test]
fn test_parse_config_explicit_true_and_false() {
    let on = parse_config("[openbinary]\nauto_upload = true\n");
    assert!(on.auto_upload);

    let off = parse_config("[openbinary]\nauto_upload = false\n");
    assert!(!off.auto_upload, "explicit false honoured");

    // Malformed TOML falls back to defaults rather than panicking.
    let junk = parse_config("this is not = valid = toml [[[");
    assert!(junk.auto_upload);
    assert_eq!(junk.endpoint, DEFAULT_ENDPOINT);
}

#[test]
fn test_within_auto_cap_boundary() {
    assert!(within_auto_cap(0));
    assert!(within_auto_cap(MAX_AUTO_UPLOAD_BYTES));
    assert!(!within_auto_cap(MAX_AUTO_UPLOAD_BYTES + 1));
}

#[test]
fn test_too_large_round_trips_through_persist() {
    let e = Entry::terminal(ObState::TooLarge, Some("abc".to_owned()), None);
    let p = to_persist(&e).expect("TooLarge persists");
    assert!(p.too_large);
    assert_eq!(from_persist(p).state, ObState::TooLarge);

    // Transient states never persist.
    assert!(
        to_persist(&Entry::terminal(
            ObState::Analyzing,
            Some("x".to_owned()),
            None
        ))
        .is_none()
    );
}

#[test]
fn test_resolve_exe_plain_file_and_bundle() {
    let dir = tempfile::TempDir::new().unwrap();

    // Plain executable file resolves to itself.
    let file = dir.path().join("tool");
    std::fs::write(&file, b"\x7fELF").unwrap();
    assert_eq!(resolve_exe(&file), Some(file.clone()));

    // A `.app` bundle resolves to Contents/MacOS/<stem>.
    let app = dir.path().join("Widget.app");
    let macos = app.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let inner = macos.join("Widget");
    std::fs::write(&inner, b"\xcf\xfa\xed\xfe").unwrap();
    assert_eq!(resolve_exe(&app), Some(inner));

    // A missing path resolves to nothing.
    assert_eq!(resolve_exe(&dir.path().join("ghost")), None);
}
