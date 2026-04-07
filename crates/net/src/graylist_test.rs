use super::*;

#[test]
fn test_is_graylisted_curl() {
    assert!(is_graylisted("/usr/bin/curl"), "curl should be graylisted");
}

#[test]
fn test_is_graylisted_bash() {
    assert!(is_graylisted("/bin/bash"), "bash should be graylisted");
}

#[test]
fn test_is_graylisted_zsh() {
    assert!(is_graylisted("/bin/zsh"), "zsh should be graylisted");
}

#[test]
fn test_is_graylisted_python3() {
    assert!(
        is_graylisted("/usr/bin/python3"),
        "python3 should be graylisted"
    );
}

#[test]
fn test_is_graylisted_osascript() {
    assert!(
        is_graylisted("/usr/bin/osascript"),
        "osascript should be graylisted"
    );
}

#[test]
fn test_is_graylisted_mdnsresponder() {
    assert!(
        is_graylisted("/usr/sbin/mDNSResponder"),
        "mDNSResponder should be graylisted"
    );
}

#[test]
fn test_not_graylisted_safari() {
    assert!(
        !is_graylisted("/Applications/Safari.app/Contents/MacOS/Safari"),
        "Safari should NOT be graylisted"
    );
}

#[test]
fn test_not_graylisted_random_app() {
    assert!(
        !is_graylisted("/Applications/SomeApp.app/Contents/MacOS/SomeApp"),
        "random app should NOT be graylisted"
    );
}

#[test]
fn test_case_sensitive_matching() {
    assert!(
        !is_graylisted("/usr/bin/Curl"),
        "matching should be case-sensitive -- Curl != curl"
    );
    assert!(
        !is_graylisted("/BIN/BASH"),
        "matching should be case-sensitive -- /BIN/BASH != /bin/bash"
    );
}

#[test]
fn test_no_prefix_matching() {
    assert!(
        !is_graylisted("/usr/bin/curl-wrapper"),
        "should not match partial path"
    );
}

#[test]
fn test_count_returns_expected() {
    // 6 shells + 9 network tools + 3 scripting + 2 system = 20
    assert_eq!(count(), 20, "graylist should have 20 entries");
}
