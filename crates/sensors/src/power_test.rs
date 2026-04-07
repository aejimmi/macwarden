use super::*;

#[test]
fn test_power_monitor_start_and_drop() {
    match PowerMonitor::start() {
        Ok((monitor, awake)) => {
            // System should be awake right now.
            assert!(awake.load(Ordering::Relaxed));
            assert!(monitor.is_awake());
            // Drop should clean up without panic.
            drop(monitor);
        }
        Err(e) => {
            eprintln!("PowerMonitor::start failed (expected on CI): {e}");
        }
    }
}
