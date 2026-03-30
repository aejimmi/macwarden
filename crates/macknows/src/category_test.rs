use super::*;

#[test]
fn test_categorize_apps_appusage() {
    assert_eq!(categorize("com.apple.osanalytics.appUsage"), Category::Apps,);
}

#[test]
fn test_categorize_apps_appkit() {
    assert_eq!(categorize("com.apple.appkit.app_config.v1"), Category::Apps,);
}

#[test]
fn test_categorize_location_locationd() {
    assert_eq!(categorize("com.apple.locationd.visits"), Category::Location,);
}

#[test]
fn test_categorize_location_coreroutine() {
    assert_eq!(
        categorize("com.apple.CoreRoutine.dailyRoutine"),
        Category::Location,
    );
}

#[test]
fn test_categorize_network_wifi() {
    assert_eq!(categorize("com.apple.wifi.scan-results"), Category::Network,);
}

#[test]
fn test_categorize_network_bluetooth() {
    assert_eq!(
        categorize("com.apple.Bluetooth.connection"),
        Category::Network,
    );
}

#[test]
fn test_categorize_ai_coreml() {
    assert_eq!(categorize("com.apple.CoreML.inference"), Category::Ai);
}

#[test]
fn test_categorize_ai_llm() {
    assert_eq!(categorize("com.apple.LLMInferenceEvent"), Category::Ai);
}

#[test]
fn test_categorize_ai_intelligence_platform() {
    assert_eq!(
        categorize("com.apple.intelligenceplatform.usage"),
        Category::Ai,
    );
}

#[test]
fn test_categorize_behavioral_personalization() {
    assert_eq!(
        categorize("com.apple.proactive.PersonalizationPortrait.entity"),
        Category::Behavioral,
    );
}

#[test]
fn test_categorize_behavioral_parsecd() {
    assert_eq!(
        categorize("com.apple.parsecd.interaction"),
        Category::Behavioral,
    );
}

#[test]
fn test_categorize_media_photos() {
    assert_eq!(categorize("com.apple.photos.analysis"), Category::Media);
}

#[test]
fn test_categorize_media_camera() {
    assert_eq!(categorize("com.apple.camera.session"), Category::Media);
}

#[test]
fn test_categorize_comms_messages() {
    assert_eq!(categorize("com.apple.Messages.sent"), Category::Comms);
}

#[test]
fn test_categorize_comms_siri() {
    assert_eq!(categorize("com.apple.Siri.request"), Category::Comms);
}

#[test]
fn test_categorize_security_syspolicy() {
    assert_eq!(categorize("com.apple.syspolicy.exec"), Category::Security,);
}

#[test]
fn test_categorize_safari() {
    assert_eq!(categorize("com.apple.Safari.browsing"), Category::Safari,);
}

#[test]
fn test_categorize_safari_shared() {
    assert_eq!(
        categorize("com.apple.SafariShared.autofill"),
        Category::Safari,
    );
}

#[test]
fn test_categorize_system_power() {
    assert_eq!(categorize("com.apple.power.battery"), Category::System);
}

#[test]
fn test_categorize_system_dasd() {
    assert_eq!(categorize("com.apple.dasd.schedule"), Category::System);
}

#[test]
fn test_categorize_other_unknown() {
    assert_eq!(categorize("com.apple.something.unknown"), Category::Other);
}

#[test]
fn test_categorize_other_no_apple_prefix() {
    assert_eq!(categorize("com.thirdparty.telemetry"), Category::Other);
}

#[test]
fn test_categorize_without_com_apple_prefix() {
    // Event names that lack com.apple. prefix should still match
    assert_eq!(categorize("CoreML.inference"), Category::Ai);
}

#[test]
fn test_category_display() {
    assert_eq!(Category::Apps.to_string(), "Apps");
    assert_eq!(Category::Ai.to_string(), "AI");
    assert_eq!(Category::Other.to_string(), "Other");
}

#[test]
fn test_category_from_str_case_insensitive() {
    assert_eq!("apps".parse::<Category>(), Ok(Category::Apps));
    assert_eq!("APPS".parse::<Category>(), Ok(Category::Apps));
    assert_eq!("Apps".parse::<Category>(), Ok(Category::Apps));
    assert_eq!("AI".parse::<Category>(), Ok(Category::Ai));
    assert_eq!("ai".parse::<Category>(), Ok(Category::Ai));
}

#[test]
fn test_category_from_str_invalid() {
    assert!("invalid".parse::<Category>().is_err());
}
