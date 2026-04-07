#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

use policy::artifact::{ArtifactAction, find_artifact, find_artifact_domain};
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
    assert_eq!(groups.len(), 48);
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
    assert!(find_group("audit-logs", &groups).is_some());
    assert!(find_group("document-versions", &groups).is_some());
    assert!(find_group("fsevents", &groups).is_some());
    assert!(find_group("gatekeeper", &groups).is_some());
    assert!(find_group("install-history", &groups).is_some());
    assert!(find_group("network-usage", &groups).is_some());
    assert!(find_group("print-logs", &groups).is_some());
    assert!(find_group("quarantine", &groups).is_some());
    assert!(find_group("quicklook", &groups).is_some());
    assert!(find_group("recent-items", &groups).is_some());
    assert!(find_group("saved-state", &groups).is_some());
    assert!(find_group("shell-history", &groups).is_some());
    assert!(find_group("tcc", &groups).is_some());
    assert!(find_group("wifi", &groups).is_some());
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

// ---------------------------------------------------------------------------
// New scrub-focused groups
// ---------------------------------------------------------------------------

#[test]
fn test_wifi_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("wifi", &groups).expect("wifi group must exist");
    assert!(group.matches("com.apple.wifid"));
    assert!(group.matches("com.apple.wifi.WiFiAgent"));
    assert!(group.matches("com.apple.airportd"));
    assert!(!group.matches("com.apple.bluetoothd"));
}

#[test]
fn test_quicklook_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("quicklook", &groups).expect("quicklook group must exist");
    assert!(group.matches("com.apple.quicklook.ThumbnailsAgent"));
    assert!(!group.matches("com.apple.Spotlight"));
}

#[test]
fn test_quarantine_group_artifact_only() {
    let groups = load_builtin_groups();
    let group = find_group("quarantine", &groups).expect("quarantine group must exist");
    assert!(group.patterns.is_empty());
    assert!(
        group.cleanup_commands.is_empty(),
        "cleanup migrated to artifacts"
    );
}

#[test]
fn test_recent_items_group_artifact_only() {
    let groups = load_builtin_groups();
    let group = find_group("recent-items", &groups).expect("recent-items group must exist");
    assert!(group.patterns.is_empty());
    assert!(
        group.cleanup_commands.is_empty(),
        "cleanup migrated to artifacts"
    );
}

#[test]
fn test_bluetooth_group_has_cleanup() {
    let groups = load_builtin_groups();
    let group = find_group("bluetooth", &groups).expect("bluetooth group must exist");
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_location_group_has_cleanup() {
    let groups = load_builtin_groups();
    let group = find_group("location", &groups).expect("location group must exist");
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_safari_group_cleanup_migrated() {
    let groups = load_builtin_groups();
    let group = find_group("safari", &groups).expect("safari group must exist");
    assert!(
        group.cleanup_commands.is_empty(),
        "cleanup migrated to artifacts"
    );
}

#[test]
fn test_siri_group_has_cleanup() {
    let groups = load_builtin_groups();
    let group = find_group("siri", &groups).expect("siri group must exist");
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_shell_history_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("shell-history", &groups).expect("shell-history group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_saved_state_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("saved-state", &groups).expect("saved-state group must exist");
    assert!(group.patterns.is_empty());
    assert!(
        group.cleanup_commands.is_empty(),
        "cleanup migrated to artifacts"
    );
}

#[test]
fn test_install_history_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("install-history", &groups).expect("install-history group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_network_usage_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("network-usage", &groups).expect("network-usage group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_print_logs_group_patterns() {
    let groups = load_builtin_groups();
    let group = find_group("print-logs", &groups).expect("print-logs group must exist");
    assert!(group.matches("com.apple.cupsd"));
    assert!(group.matches("org.cups.cupsd"));
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_document_versions_group_scrub_only() {
    let groups = load_builtin_groups();
    let group =
        find_group("document-versions", &groups).expect("document-versions group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_tcc_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("tcc", &groups).expect("tcc group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_fsevents_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("fsevents", &groups).expect("fsevents group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_audit_logs_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("audit-logs", &groups).expect("audit-logs group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_gatekeeper_group_scrub_only() {
    let groups = load_builtin_groups();
    let group = find_group("gatekeeper", &groups).expect("gatekeeper group must exist");
    assert!(group.patterns.is_empty());
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_system_logging_group_has_cleanup() {
    let groups = load_builtin_groups();
    let group = find_group("system-logging", &groups).expect("system-logging group must exist");
    assert!(!group.cleanup_commands.is_empty());
}

#[test]
fn test_profiling_group_has_biome_cleanup() {
    let groups = load_builtin_groups();
    let group = find_group("profiling", &groups).expect("profiling group must exist");
    let has_biome = group.cleanup_commands.iter().any(|c| c.contains("biome"));
    assert!(has_biome, "profiling cleanup should include biome paths");
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

// ---------------------------------------------------------------------------
// Built-in artifact domains
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_artifacts_count() {
    let domains = load_builtin_artifacts();
    assert_eq!(domains.len(), 12);
}

#[test]
fn test_builtin_artifact_domain_names() {
    let domains = load_builtin_artifacts();
    let names: Vec<&str> = domains.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"saved-state"));
    assert!(names.contains(&"quarantine"));
    assert!(names.contains(&"recent-items"));
    assert!(names.contains(&"browser-traces"));
    assert!(names.contains(&"app-caches"));
    assert!(names.contains(&"mail"));
    assert!(names.contains(&"safari"));
    assert!(names.contains(&"system-logs"));
    assert!(names.contains(&"telemetry"));
    assert!(names.contains(&"spotlight"));
    assert!(names.contains(&"cloudkit-cache"));
    assert!(names.contains(&"quicklook"));
}

#[test]
fn test_builtin_artifacts_all_have_entries() {
    for domain in load_builtin_artifacts() {
        assert!(
            !domain.artifacts.is_empty(),
            "domain {} should have at least one artifact",
            domain.name
        );
    }
}

#[test]
fn test_find_artifact_domain_builtin() {
    let domains = load_builtin_artifacts();
    let found = find_artifact_domain("safari", &domains);
    assert!(found.is_some());
    assert_eq!(found.unwrap().artifacts.len(), 9);
}

#[test]
fn test_find_artifact_builtin() {
    let domains = load_builtin_artifacts();
    let result = find_artifact("quarantine-events-db", &domains);
    assert!(result.is_some());
    let (domain, artifact) = result.unwrap();
    assert_eq!(domain.name, "quarantine");
    assert!(
        matches!(&artifact.action, ArtifactAction::Path(p) if p.contains("QuarantineEventsV2"))
    );
}

#[test]
fn test_builtin_telemetry_has_command_artifact() {
    let domains = load_builtin_artifacts();
    let result = find_artifact("unified-log-erase", &domains);
    assert!(result.is_some());
    let (_, artifact) = result.unwrap();
    assert!(matches!(&artifact.action, ArtifactAction::Command(c) if c.contains("log erase")));
}
