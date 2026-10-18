#![allow(clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use super::*;
use crate::data::openbinary::{ObState, ObVerdict};

fn task(path: &str) -> SweepTask {
    SweepTask::new(PathBuf::from(path), SweepAction::Fresh, true)
}

#[test]
fn test_should_sweep_maps_states_to_actions() {
    assert_eq!(should_sweep(None), Some(SweepAction::Fresh));
    assert_eq!(
        should_sweep(Some(&ObState::Analyzing)),
        Some(SweepAction::Recheck)
    );

    // Every settled or in-flight state is skipped.
    for state in [
        ObState::Pending,
        ObState::Uploading,
        ObState::Unknown,
        ObState::TooLarge,
        ObState::Error,
        ObState::Known {
            verdict: ObVerdict::Benign,
            title: None,
            summary: None,
        },
    ] {
        assert_eq!(should_sweep(Some(&state)), None, "{state:?} must skip");
    }
}

#[test]
fn test_task_new_encodes_action_and_auto_upload() {
    let fresh_on = SweepTask::new(PathBuf::from("/a"), SweepAction::Fresh, true);
    let fresh_off = SweepTask::new(PathBuf::from("/a"), SweepAction::Fresh, false);
    let recheck = SweepTask::new(PathBuf::from("/a"), SweepAction::Recheck, true);

    // A fresh candidate uploads only when auto_upload is on.
    assert_eq!(
        fresh_on,
        SweepTask {
            key: PathBuf::from("/a"),
            allow_upload: true,
            recheck: false,
        }
    );
    assert_eq!(
        fresh_off,
        SweepTask {
            key: PathBuf::from("/a"),
            allow_upload: false,
            recheck: false,
        }
    );
    // A re-check never uploads — it only re-GETs an Analyzing entry.
    assert_eq!(
        recheck,
        SweepTask {
            key: PathBuf::from("/a"),
            allow_upload: false,
            recheck: true,
        }
    );
}

#[test]
fn test_gap_after_upload_is_slower_than_lookup() {
    let lookup = gap_after(false);
    let upload = gap_after(true);
    assert!(lookup < upload, "lookups pace faster than uploads");
    assert_eq!(lookup, LOOKUP_GAP);
    assert_eq!(upload, UPLOAD_GAP);
}

#[test]
fn test_queue_fifo_order() {
    let mut q = SweepQueue::default();
    assert!(q.submit(task("/a")));
    assert!(q.submit(task("/b")));
    assert!(q.submit(task("/c")));

    assert_eq!(q.pop(), Some(task("/a")));
    assert_eq!(q.pop(), Some(task("/b")));
    assert_eq!(q.pop(), Some(task("/c")));
    assert_eq!(q.pop(), None);
}

#[test]
fn test_queue_dedups_in_flight_keys() {
    let mut q = SweepQueue::default();
    assert!(q.submit(task("/a")), "first submit accepted");
    assert!(!q.submit(task("/a")), "duplicate key rejected while queued");
    assert_eq!(
        q.progress(),
        Some((0, 1)),
        "denominator counts distinct keys"
    );

    // After settling, the key is eligible again.
    let _ = q.pop();
    q.settle(&PathBuf::from("/a"));
    assert!(q.submit(task("/a")), "re-submittable once settled");
}

#[test]
fn test_progress_climbs_one_per_settled_key() {
    let mut q = SweepQueue::default();
    assert_eq!(q.progress(), None, "empty queue is idle");
    q.submit(task("/a"));
    q.submit(task("/b"));
    assert_eq!(q.progress(), Some((0, 2)));

    let _ = q.pop();
    q.settle(&PathBuf::from("/a"));
    assert_eq!(q.progress(), Some((1, 2)), "one of two done");

    let _ = q.pop();
    q.settle(&PathBuf::from("/b"));
    assert_eq!(q.progress(), None, "idle once all settle");
}

#[test]
fn test_settle_unknown_key_is_noop() {
    let mut q = SweepQueue::default();
    q.settle(&PathBuf::from("/never-submitted"));
    assert_eq!(q.progress(), None, "settling an unknown key does nothing");
}
