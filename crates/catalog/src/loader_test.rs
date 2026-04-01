use super::*;

use policy::types::{Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};
use policy::{find_group, find_groups_for_service, resolve_group_services, validate_profile};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_service(label: &str) -> ServiceInfo {
    ServiceInfo {
        label: label.to_owned(),
        domain: Domain::User,
        plist_path: None,
        state: ServiceState::Running,
        category: ServiceCategory::Unknown,
        safety: SafetyLevel::Optional,
        description: None,
        pid: None,
    }
}

// ---------------------------------------------------------------------------
// Built-in groups: count and lookup
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_groups_count() {
    let groups = load_builtin_groups();
    assert_eq!(groups.len(), 34);
}

#[test]
fn test_find_group_by_name() {
    let groups = load_builtin_groups();
    assert!(find_group("spotlight", &groups).is_some());
    assert!(find_group("siri", &groups).is_some());
    assert!(find_group("telemetry", &groups).is_some());
    assert!(find_group("icloud-sync", &groups).is_some());
    assert!(find_group("cloudkit", &groups).is_some());
    assert!(find_group("keychain-sync", &groups).is_some());
    assert!(find_group("airdrop", &groups).is_some());
    assert!(find_group("gamekit", &groups).is_some());
    assert!(find_group("applemusic", &groups).is_some());
    assert!(find_group("mail", &groups).is_some());
    assert!(find_group("fmf", &groups).is_some());
    assert!(find_group("bluetooth", &groups).is_some());
    assert!(find_group("location", &groups).is_some());
    assert!(find_group("media-analysis", &groups).is_some());
    assert!(find_group("photos", &groups).is_some());
    assert!(find_group("notifications", &groups).is_some());
    assert!(find_group("safari", &groups).is_some());
    assert!(find_group("backup", &groups).is_some());
    assert!(find_group("updates", &groups).is_some());
    assert!(find_group("screentime", &groups).is_some());
    assert!(find_group("maps", &groups).is_some());
    assert!(find_group("apple-intelligence", &groups).is_some());
    assert!(find_group("remote-access", &groups).is_some());
    assert!(find_group("messages", &groups).is_some());
    assert!(find_group("wallet", &groups).is_some());
    assert!(find_group("crash-reports", &groups).is_some());
    assert!(find_group("hang-detection", &groups).is_some());
    assert!(find_group("network-quality", &groups).is_some());
    assert!(find_group("system-logging", &groups).is_some());
    assert!(find_group("nonexistent", &groups).is_none());
}

#[test]
fn test_find_group_case_insensitive() {
    let groups = load_builtin_groups();
    assert!(find_group("Spotlight", &groups).is_some());
    assert!(find_group("TELEMETRY", &groups).is_some());
}

// ---------------------------------------------------------------------------
// Built-in groups: pattern matching
// ---------------------------------------------------------------------------

#[test]
fn test_siri_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("siri", &groups).expect("siri group must exist");
    assert!(group.matches("com.apple.Siri.agent"));
    assert!(group.matches("com.apple.siriactionsd"));
    assert!(group.matches("com.apple.assistant_cdmd"));
    assert!(group.matches("com.apple.parsec-fbf"));
    assert!(group.matches("com.apple.DictationIM"));
}

#[test]
fn test_telemetry_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("telemetry", &groups).expect("telemetry group must exist");
    assert!(group.matches("com.apple.analyticsd"));
    assert!(group.matches("com.apple.SubmitDiagInfo"));
    assert!(group.matches("com.apple.inputanalyticsd"));
    assert!(group.matches("com.apple.triald"));
    // These moved to diagnostics group (dual-purpose):
    assert!(!group.matches("com.apple.CrashReporter.plist"));
    assert!(!group.matches("com.apple.ReportCrash"));
    assert!(!group.matches("com.apple.spindump"));
    assert!(!group.matches("com.apple.tailspind"));
}

#[test]
fn test_crash_reports_group() {
    let groups = load_builtin_groups();
    let group = find_group("crash-reports", &groups).expect("crash-reports group must exist");
    assert!(group.matches("com.apple.ReportCrash"));
    assert!(group.matches("com.apple.ReportCrash.Root"));
    assert!(group.matches("com.apple.CrashReporterSupportHelper"));
    assert!(!group.matches("com.apple.spindump"));
}

#[test]
fn test_hang_detection_group() {
    let groups = load_builtin_groups();
    let group = find_group("hang-detection", &groups).expect("hang-detection group must exist");
    assert!(group.matches("com.apple.spindump"));
    assert!(group.matches("com.apple.spindump_agent"));
    assert!(group.matches("com.apple.tailspind"));
    assert!(!group.matches("com.apple.diagnosticd"));
}

#[test]
fn test_system_logging_group() {
    let groups = load_builtin_groups();
    let group = find_group("system-logging", &groups).expect("system-logging group must exist");
    assert!(group.matches("com.apple.diagnosticd"));
    assert!(!group.matches("com.apple.analyticsd"));
}

#[test]
fn test_bluetooth_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("bluetooth", &groups).expect("bluetooth group must exist");
    assert!(group.matches("com.apple.bluetoothd"));
    assert!(group.matches("com.apple.bluetooth.something"));
    assert!(group.matches("com.apple.BTServer.agent"));
    assert!(group.matches("com.apple.BluetoothUIService"));
    assert!(!group.matches("com.apple.Siri.agent"));
}

#[test]
fn test_location_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("location", &groups).expect("location group must exist");
    assert!(group.matches("com.apple.locationd"));
    assert!(group.matches("com.apple.CoreLocationAgent"));
    assert!(group.matches("com.apple.geod"));
    assert!(group.matches("com.apple.routined"));
    assert!(!group.matches("com.apple.analyticsd"));
}

#[test]
fn test_photos_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("photos", &groups).expect("photos group must exist");
    assert!(group.matches("com.apple.photolibraryd"));
    assert!(group.matches("com.apple.cloudphotod"));
    assert!(group.matches("com.apple.CloudPhotosConfiguration"));
    // Analysis daemons moved to media-analysis group.
    assert!(!group.matches("com.apple.photoanalysisd"));
    assert!(!group.matches("com.apple.mediaanalysisd"));
    assert!(!group.matches("com.apple.analyticsd"));
}

#[test]
fn test_media_analysis_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("media-analysis", &groups).expect("media-analysis group must exist");
    assert!(group.matches("com.apple.photoanalysisd"));
    assert!(group.matches("com.apple.mediaanalysisd"));
    // Library and cloud daemons stay in photos group.
    assert!(!group.matches("com.apple.photolibraryd"));
    assert!(!group.matches("com.apple.cloudphotod"));
}

#[test]
fn test_profiling_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("profiling", &groups).expect("profiling group must exist");
    assert!(group.matches("com.apple.coreduetd"));
    assert!(group.matches("com.apple.duetexpertd"));
    assert!(group.matches("com.apple.suggestd"));
    assert!(group.matches("com.apple.biomesyncd"));
    assert!(!group.matches("com.apple.analyticsd"));
}

#[test]
fn test_backup_group_has_commands() {
    let groups = load_builtin_groups();
    let group = find_group("backup", &groups).expect("backup group must exist");
    assert_eq!(group.disable_commands.len(), 1);
    assert_eq!(group.disable_commands[0], "tmutil disable");
    assert_eq!(group.enable_commands.len(), 1);
    assert_eq!(group.enable_commands[0], "tmutil enable");
}

#[test]
fn test_apple_intelligence_group_patterns() {
    let groups = load_builtin_groups();
    let group =
        find_group("apple-intelligence", &groups).expect("apple-intelligence group must exist");
    assert!(group.matches("com.apple.generativeexperiencesd"));
    assert!(group.matches("com.apple.intelligenceflowd"));
    assert!(group.matches("com.apple.intelligencecontextd"));
    assert!(group.matches("com.apple.intelligenceplatformd"));
    assert!(group.matches("com.apple.knowledgeconstructiond"));
    assert!(group.matches("com.apple.knowledge-agent"));
    assert!(group.matches("com.apple.modelmanagerd"));
}

#[test]
fn test_messages_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("messages", &groups).expect("messages group must exist");
    assert!(group.matches("com.apple.imagent"));
    assert!(group.matches("com.apple.imtransferagent"));
    assert!(group.matches("com.apple.soagent"));
    assert!(group.matches("com.apple.identityservicesd"));
    assert!(group.matches("com.apple.CommCenter-osx"));
}

#[test]
fn test_wallet_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("wallet", &groups).expect("wallet group must exist");
    assert!(group.matches("com.apple.financed"));
    assert!(group.matches("com.apple.passd"));
    assert!(group.matches("com.apple.nfcd"));
    assert!(!group.matches("com.apple.Siri.agent"));
}

#[test]
fn test_remote_access_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("remote-access", &groups).expect("remote-access group must exist");
    assert!(group.matches("com.apple.screensharing"));
    assert!(group.matches("com.apple.screensharing.agent"));
    assert!(group.matches("com.apple.RemoteDesktop"));
    assert!(group.matches("com.apple.SSInvitationAgent"));
}

#[test]
fn test_safari_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("safari", &groups).expect("safari group must exist");
    assert!(group.matches("com.apple.Safari.agent"));
    assert!(group.matches("com.apple.SafariCloudHistoryPushAgent"));
    assert!(group.matches("com.apple.safaridavclient"));
    assert!(group.matches("com.apple.WebKit.WebContent"));
}

#[test]
fn test_screentime_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("screentime", &groups).expect("screentime group must exist");
    assert!(group.matches("com.apple.ScreenTimeAgent"));
    assert!(group.matches("com.apple.UsageTrackingAgent"));
    assert!(group.matches("com.apple.familycircled"));
    assert!(group.matches("com.apple.familynotificationd"));
    assert!(group.matches("com.apple.parentalcontrols.check"));
}

#[test]
fn test_maps_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("maps", &groups).expect("maps group must exist");
    assert!(group.matches("com.apple.Maps.pushdaemon"));
    assert!(group.matches("com.apple.maps.destinationd"));
    assert!(group.matches("com.apple.geod"));
    assert!(group.matches("com.apple.navd"));
}

#[test]
fn test_updates_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("updates", &groups).expect("updates group must exist");
    assert!(group.matches("com.apple.SoftwareUpdateAgent"));
    assert!(group.matches("com.apple.softwareupdated"));
    assert!(group.matches("com.apple.appstored"));
}

#[test]
fn test_notifications_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("notifications", &groups).expect("notifications group must exist");
    assert!(group.matches("com.apple.UserNotificationCenter"));
    assert!(group.matches("com.apple.usernoted"));
    assert!(group.matches("com.apple.apsd"));
    assert!(group.matches("com.apple.AOSPushRelay"));
}

// ---------------------------------------------------------------------------
// Built-in groups: reverse lookup
// ---------------------------------------------------------------------------

#[test]
fn test_find_groups_for_service_builtin() {
    let groups = load_builtin_groups();
    let matched = find_groups_for_service("com.apple.analyticsd", &groups);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].name, "telemetry");
}

#[test]
fn test_find_groups_for_service_no_match_builtin() {
    let groups = load_builtin_groups();
    let matched = find_groups_for_service("com.apple.WindowServer", &groups);
    assert!(matched.is_empty());
}

// ---------------------------------------------------------------------------
// Built-in groups: resolve against services
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_builtin_group_services() {
    let groups = load_builtin_groups();
    let services = vec![
        make_service("com.apple.metadata.mds"),
        make_service("com.apple.corespotlightd"),
        make_service("com.apple.Siri.agent"),
        make_service("com.apple.analyticsd"),
    ];

    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    let matched = resolve_group_services(group, &services);

    assert_eq!(matched.len(), 2);
    let labels: Vec<&str> = matched.iter().map(|s| s.label.as_str()).collect();
    assert!(labels.contains(&"com.apple.metadata.mds"));
    assert!(labels.contains(&"com.apple.corespotlightd"));
}

// ---------------------------------------------------------------------------
// Built-in profiles
// ---------------------------------------------------------------------------

#[test]
fn test_load_builtin_profiles_count() {
    let profiles = load_builtin_profiles();
    assert_eq!(profiles.len(), 1);
}

#[test]
fn test_builtin_profile_names() {
    let profiles = load_builtin_profiles();
    let names: Vec<&str> = profiles.iter().map(|p| p.profile.name.as_str()).collect();
    assert!(names.contains(&"privacy"));
}

#[test]
fn test_privacy_profile_denies_telemetry() {
    let builtins = load_builtin_profiles();
    let privacy = builtins
        .iter()
        .find(|p| p.profile.name == "privacy")
        .expect("privacy profile must exist");

    assert!(privacy.rules.deny.contains(&"com.apple.Siri*".to_owned()));
    assert!(
        privacy
            .rules
            .deny
            .contains(&"com.apple.tailspind".to_owned())
    );
    assert!(
        privacy
            .rules
            .deny
            .contains(&"com.apple.controlcenter".to_owned())
    );
}

#[test]
fn test_validate_all_builtins_pass() {
    for profile in load_builtin_profiles() {
        assert!(
            validate_profile(&profile).is_ok(),
            "builtin profile {} should pass validation",
            profile.profile.name
        );
    }
}
