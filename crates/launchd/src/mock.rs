//! Mock platform for testing.
//!
//! Records all mutating calls (disable, enable, kill) so tests can assert
//! that the executor invoked the correct operations.

use std::sync::Mutex;

use crate::error::LaunchdError;
use crate::platform::{LaunchctlEntry, Platform, ProcessDetail, ServiceDetail, SipState};

/// A test double for the [`Platform`] trait.
///
/// Returns preconfigured data from `enumerate` and `sip_status`, and
/// records all `disable`, `enable`, and `kill_process` calls.
pub struct MockPlatform {
    /// Services returned by `enumerate`.
    services: Vec<LaunchctlEntry>,
    /// SIP state returned by `sip_status`.
    sip: SipState,
    /// Labels passed to `disable`, recorded as `"{domain}/{label}"`.
    disabled: Mutex<Vec<String>>,
    /// Labels passed to `enable`, recorded as `"{domain}/{label}"`.
    enabled: Mutex<Vec<String>>,
    /// PIDs passed to `kill_process`.
    killed: Mutex<Vec<u32>>,
    /// Targets passed to `bootout`, recorded as `"{domain}/{label}"`.
    booted_out: Mutex<Vec<String>>,
}

impl MockPlatform {
    /// Creates a new mock with the given services and SIP state.
    pub fn new(services: Vec<LaunchctlEntry>, sip: SipState) -> Self {
        Self {
            services,
            sip,
            disabled: Mutex::new(Vec::new()),
            enabled: Mutex::new(Vec::new()),
            killed: Mutex::new(Vec::new()),
            booted_out: Mutex::new(Vec::new()),
        }
    }

    /// Returns all labels that were disabled, in call order.
    pub fn disabled_labels(&self) -> Vec<String> {
        self.disabled
            .lock()
            .expect("disabled mutex poisoned")
            .clone()
    }

    /// Returns all labels that were enabled, in call order.
    pub fn enabled_labels(&self) -> Vec<String> {
        self.enabled.lock().expect("enabled mutex poisoned").clone()
    }

    /// Returns all PIDs that were killed, in call order.
    pub fn killed_pids(&self) -> Vec<u32> {
        self.killed.lock().expect("killed mutex poisoned").clone()
    }

    /// Returns all targets that were booted out, in call order.
    pub fn booted_out_targets(&self) -> Vec<String> {
        self.booted_out
            .lock()
            .expect("booted_out mutex poisoned")
            .clone()
    }
}

impl Platform for MockPlatform {
    fn enumerate(&self) -> Result<Vec<LaunchctlEntry>, LaunchdError> {
        Ok(self.services.clone())
    }

    fn disable(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        self.disabled
            .lock()
            .expect("disabled mutex poisoned")
            .push(format!("{domain}/{label}"));
        Ok(())
    }

    fn enable(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        self.enabled
            .lock()
            .expect("enabled mutex poisoned")
            .push(format!("{domain}/{label}"));
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<(), LaunchdError> {
        self.killed.lock().expect("killed mutex poisoned").push(pid);
        Ok(())
    }

    fn is_running(&self, label: &str) -> Result<bool, LaunchdError> {
        let running = self
            .services
            .iter()
            .any(|e| e.label == label && e.pid.is_some());
        Ok(running)
    }

    fn sip_status(&self) -> Result<SipState, LaunchdError> {
        Ok(self.sip.clone())
    }

    fn inspect(&self, domain: &str, label: &str) -> Result<ServiceDetail, LaunchdError> {
        let entry = self.services.iter().find(|e| e.label == label);
        Ok(ServiceDetail {
            label: label.to_owned(),
            domain: domain.to_owned(),
            state: if entry.and_then(|e| e.pid).is_some() {
                "running".to_owned()
            } else {
                "not running".to_owned()
            },
            pid: entry.and_then(|e| e.pid),
            ..ServiceDetail::default()
        })
    }

    fn process_detail(&self, pid: u32) -> Result<ProcessDetail, LaunchdError> {
        Ok(ProcessDetail {
            pid,
            ..ProcessDetail::default()
        })
    }

    fn bootout(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        self.booted_out
            .lock()
            .expect("booted_out mutex poisoned")
            .push(format!("{domain}/{label}"));
        Ok(())
    }
}

#[cfg(test)]
#[path = "mock_test.rs"]
mod mock_test;
