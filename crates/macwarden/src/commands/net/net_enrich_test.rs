use super::*;

#[test]
fn test_status_does_not_panic() {
    // run_status reads from disk — just verify it doesn't crash.
    let result = run_status();
    assert!(result.is_ok(), "status should not fail: {result:?}");
}

#[test]
fn test_remove_when_nothing_installed() {
    let result = run_remove();
    assert!(result.is_ok(), "remove with no databases should succeed");
}

#[test]
fn test_download_requires_key() {
    let result = run_download(None);
    assert!(result.is_err(), "download without key should fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("license key"),
        "error should mention license key, got: {msg}",
    );
}

#[test]
fn test_db_age_days_missing_dir() {
    let age = db_age_days(std::path::Path::new("/nonexistent/geo"));
    assert!(age.is_none(), "missing dir should return None");
}
