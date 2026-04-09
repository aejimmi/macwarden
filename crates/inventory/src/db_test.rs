use super::*;
use crate::record::BinaryRecord;

fn make_record(path: &str, sha: &str) -> BinaryRecord {
    BinaryRecord {
        path: path.into(),
        sha256: sha.into(),
        bundle_id: None,
        name: None,
        version: None,
        code_id: None,
        team_id: None,
        is_apple_signed: false,
        is_valid_sig: false,
        scanned_at: 1_700_000_000_000,
        is_blocklisted: false,
        openbinary: None,
        analyzed_at: None,
    }
}

#[test]
fn test_roundtrip_upsert_and_read() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    let rec = make_record("/usr/bin/curl", "aabbcc");
    store.upsert(&rec).expect("upsert");

    let all = store.all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].path, "/usr/bin/curl");
    assert_eq!(all[0].sha256, "aabbcc");
}

#[test]
fn test_upsert_batch() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    let records = vec![
        make_record("/usr/bin/curl", "aaa"),
        make_record("/usr/bin/git", "bbb"),
        make_record("/usr/bin/ssh", "ccc"),
    ];
    store.upsert_batch(&records).expect("batch");

    assert_eq!(store.len(), 3);
}

#[test]
fn test_upsert_overwrites() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    let rec1 = make_record("/usr/bin/curl", "old_hash");
    store.upsert(&rec1).expect("first");

    let rec2 = make_record("/usr/bin/curl", "new_hash");
    store.upsert(&rec2).expect("second");

    let all = store.all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].sha256, "new_hash");
}

#[test]
fn test_unanalyzed_filter() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    let mut analyzed = make_record("/usr/bin/curl", "aaa");
    analyzed.analyzed_at = Some(1_700_000_000_000);
    analyzed.openbinary = Some(serde_json::json!({"status": "done"}));

    let pending = make_record("/usr/bin/git", "bbb");

    store.upsert_batch(&[analyzed, pending]).expect("batch");

    let unanalyzed = store.unanalyzed();
    assert_eq!(unanalyzed.len(), 1);
    assert_eq!(unanalyzed[0].path, "/usr/bin/git");
}

#[test]
fn test_save_analysis() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    let rec = make_record("/usr/bin/curl", "aaa");
    store.upsert(&rec).expect("insert");

    let analysis = serde_json::json!({"capabilities": ["network"]});
    store
        .save_analysis("/usr/bin/curl", analysis.clone(), 1_700_000_001_000)
        .expect("save");

    let all = store.all();
    assert_eq!(all[0].openbinary, Some(analysis));
    assert_eq!(all[0].analyzed_at, Some(1_700_000_001_000));
}

#[test]
fn test_reconcile_removes_stale_and_keeps_current() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = InventoryStore::open_at(tmp.path().to_path_buf()).expect("open");

    // Simulate a previous scan with 3 binaries.
    store
        .upsert_batch(&[
            make_record("/usr/bin/curl", "aaa"),
            make_record("/usr/bin/git", "bbb"),
            make_record("/usr/bin/old", "ccc"),
        ])
        .expect("initial");
    assert_eq!(store.len(), 3);

    // New scan only finds 2 — /usr/bin/old was uninstalled.
    let current = vec![
        make_record("/usr/bin/curl", "aaa"),
        make_record("/usr/bin/git", "bbb_new"),
    ];
    store.reconcile(&current).expect("reconcile");

    assert_eq!(store.len(), 2);
    let all = store.all();
    assert!(all.iter().any(|r| r.path == "/usr/bin/curl"));
    assert!(
        all.iter()
            .any(|r| r.path == "/usr/bin/git" && r.sha256 == "bbb_new")
    );
    assert!(!all.iter().any(|r| r.path == "/usr/bin/old"));
}
