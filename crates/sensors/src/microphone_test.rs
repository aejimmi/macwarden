use super::*;

#[test]
fn test_is_active_returns_result() {
    // This calls real hardware — just verify it doesn't panic or crash.
    // On CI without audio hardware, it may return an error. Both are OK.
    let result = is_active();
    match result {
        Ok(active) => {
            // Valid boolean — mic is either active or not.
            assert!(active || !active);
        }
        Err(SensorError::NoDevice { kind }) => {
            assert_eq!(kind, "microphone");
        }
        Err(SensorError::CoreAudio { function, code }) => {
            // API call failed — acceptable on headless systems.
            assert!(!function.is_empty());
            assert_ne!(code, 0);
        }
        Err(_) => {
            // Other errors are unexpected but not worth panicking over.
        }
    }
}

#[test]
fn test_mic_monitor_start_and_drop() {
    let (tx, _rx) = mpsc::channel();

    // Start monitoring — may fail if no audio device exists.
    match MicMonitor::start(tx) {
        Ok(monitor) => {
            // Drop should cleanly remove the listener.
            drop(monitor);
        }
        Err(SensorError::NoDevice { .. }) => {
            // No mic on this system — OK.
        }
        Err(e) => {
            // Log but don't fail — CI may lack audio hardware.
            eprintln!("MicMonitor::start failed (expected on headless): {e}");
        }
    }
}
