use super::demo_disclosure;
use ipc::protocol::WireTraceSource;

#[test]
fn test_live_source_has_no_demo_banner() {
    // Real capture is never labeled as demo.
    assert!(demo_disclosure(WireTraceSource::Live).is_none());
    assert!(WireTraceSource::Live.is_live());
}

#[test]
fn test_every_non_live_source_gets_a_demo_banner() {
    // Synthetic data must be unmistakably disclosed — every non-live source shows
    // a banner and is never treated as live.
    for source in [
        WireTraceSource::DemoNoAccess,
        WireTraceSource::DemoNoCapture,
        WireTraceSource::Unknown,
    ] {
        assert!(!source.is_live(), "{source:?} must not read as live");
        let banner = demo_disclosure(source).expect("non-live source must disclose");
        assert!(
            banner.contains("Demo stream"),
            "banner names the demo stream"
        );
    }
}

#[test]
fn test_no_access_banner_mentions_bpf() {
    // The "can capture but no access" case points the user at the fix.
    let banner = demo_disclosure(WireTraceSource::DemoNoAccess).unwrap();
    assert!(banner.contains("access_bpf") || banner.contains("root"));
}
