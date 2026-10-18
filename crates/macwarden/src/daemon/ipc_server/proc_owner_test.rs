use super::owner_username;

#[test]
fn test_owner_username_resolves_self() {
    // The sysctl uid path plus its self-check must resolve our own process owner.
    let user = owner_username(std::process::id());
    assert!(user.is_some(), "our own process owner must resolve");
    if let Ok(env_user) = std::env::var("USER") {
        assert_eq!(
            user.as_deref(),
            Some(env_user.as_str()),
            "self owner should match $USER"
        );
    }
}

#[test]
fn test_owner_username_resolves_root_process() {
    // pid 1 (launchd) is root-owned; the sysctl path reads its uid unprivileged,
    // where sysinfo/proc_pidinfo would return nothing. This proves system daemons
    // resolve to a real user ("root"), not "—".
    assert_eq!(owner_username(1).as_deref(), Some("root"));
}
