//! Background binary sweep (cross-platform).
//!
//! On panel launch a single low-priority worker thread walks the currently
//! running binaries the panel knows about and, for each not already settled in
//! the [`ObCache`], hashes it and looks it up. A 404 with `auto_upload` enabled
//! uploads it. The worker is a deliberate good citizen on a first run of 500+
//! binaries:
//!
//! - lookups are paced at ~2/s; a miss that uploads waits a 2 s gap, so uploads
//!   run strictly sequentially (one queue, one worker);
//! - files over the auto-upload size cap cache as [`ObState::TooLarge`] instead
//!   of being pushed;
//! - jobs are polled lazily — an upload that returns pending settles as
//!   [`ObState::Analyzing`] and is re-checked with a plain `GET` on a later pass
//!   rather than holding a poll loop per upload;
//! - the persisted cache means settled states are skipped for free across
//!   restarts, and new processes are swept on a periodic re-pass.
//!
//! This module has zero platform or GPUI deps so it builds and unit-tests on
//! Linux CI; the running-binary list is supplied by the caller via [`Sweep::submit`].

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use openbinary_agent_core::{OpenBinaryClient, UploadResult, hash};

use super::openbinary::{ObCache, ObState, file_size, parse_known, resolve_exe, within_auto_cap};

/// Delay after a lookup that did not upload — ~2 lookups per second.
const LOOKUP_GAP: Duration = Duration::from_millis(500);

/// Delay after a lookup that uploaded — keeps uploads 2 s apart.
const UPLOAD_GAP: Duration = Duration::from_secs(2);

/// How long the worker naps when the queue is empty before re-draining.
const IDLE_NAP: Duration = Duration::from_secs(2);

/// The pacing gap to observe after a task, given whether it uploaded. A pure
/// helper so the pacing policy is unit-testable.
#[must_use]
pub fn gap_after(did_upload: bool) -> Duration {
    if did_upload { UPLOAD_GAP } else { LOOKUP_GAP }
}

/// What the sweep should do with a candidate given its cached state. A pure
/// decision so it can be exhaustively unit-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepAction {
    /// Never seen — look it up (and auto-upload on 404 if enabled).
    Fresh,
    /// Previously uploaded and awaiting analysis — re-check with a `GET` only.
    Recheck,
}

/// Decide whether (and how) to sweep a candidate given its cached state.
#[must_use]
pub fn should_sweep(state: Option<&ObState>) -> Option<SweepAction> {
    match state {
        None => Some(SweepAction::Fresh),
        Some(ObState::Analyzing) => Some(SweepAction::Recheck),
        Some(_) => None,
    }
}

/// A unit of sweep work, keyed by the resolved executable path. A miss that
/// needs an upload is handled inline (not re-queued) so the progress counter
/// climbs one-per-binary and uploads stay strictly sequential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepTask {
    key: PathBuf,
    /// Whether a 404 may trigger an auto-upload (fresh + `auto_upload` on).
    allow_upload: bool,
    /// Whether a 404 preserves an existing `Analyzing` state (a re-check).
    recheck: bool,
}

impl SweepTask {
    /// Build a task from a resolved key and the chosen action.
    #[must_use]
    pub fn new(key: PathBuf, action: SweepAction, auto_upload: bool) -> Self {
        Self {
            key,
            allow_upload: auto_upload && action == SweepAction::Fresh,
            recheck: action == SweepAction::Recheck,
        }
    }
}

/// A FIFO work queue with per-key de-duplication and cumulative progress
/// counters. Pure and lock-free — the caller wraps it in a `Mutex`.
#[derive(Default)]
pub struct SweepQueue {
    tasks: VecDeque<SweepTask>,
    /// Keys currently queued (submitted, not yet settled).
    in_flight: HashSet<PathBuf>,
    /// Cumulative distinct keys submitted (progress denominator).
    total: usize,
    /// Cumulative keys settled (progress numerator).
    done: usize,
}

impl SweepQueue {
    /// Submit a key. De-duplicated: a key already queued is ignored and returns
    /// `false`. Bumps the progress denominator on acceptance.
    pub fn submit(&mut self, task: SweepTask) -> bool {
        if !self.in_flight.insert(task.key.clone()) {
            return false;
        }
        self.total += 1;
        self.tasks.push_back(task);
        true
    }

    /// Pop the next task in FIFO order.
    pub fn pop(&mut self) -> Option<SweepTask> {
        self.tasks.pop_front()
    }

    /// Mark a key fully settled: clears its guard and advances the numerator.
    pub fn settle(&mut self, key: &Path) {
        if self.in_flight.remove(key) {
            self.done += 1;
        }
    }

    /// Current progress as `Some((done, total))` while work is outstanding, or
    /// `None` when idle (all submitted keys settled).
    #[must_use]
    pub fn progress(&self) -> Option<(usize, usize)> {
        (self.total > self.done).then_some((self.done, self.total))
    }
}

struct SweepShared {
    cache: ObCache,
    endpoint: String,
    auto_upload: bool,
    queue: Mutex<SweepQueue>,
    pending: Mutex<Vec<PathBuf>>,
    stop: AtomicBool,
}

/// Handle to the background sweep worker. Cheap to hold; dropping it signals the
/// worker to stop.
pub struct Sweep {
    shared: Arc<SweepShared>,
}

impl Sweep {
    /// Start the worker against a shared [`ObCache`], reading its endpoint and
    /// `auto_upload` setting.
    #[must_use]
    pub fn start(cache: ObCache) -> Self {
        let shared = Arc::new(SweepShared {
            endpoint: cache.endpoint().to_owned(),
            auto_upload: cache.auto_upload(),
            cache,
            queue: Mutex::new(SweepQueue::default()),
            pending: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
        });
        let worker = Arc::clone(&shared);
        if let Err(e) = thread::Builder::new()
            .name("ob-sweep".into())
            .spawn(move || run(&worker))
        {
            tracing::warn!(%e, "openbinary sweep thread failed to start");
        }
        Self { shared }
    }

    /// Hand the worker the current set of running binary paths. Cheap: the paths
    /// are stashed and de-duplicated against the cache on the worker thread.
    pub fn submit(&self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        if let Ok(mut pending) = self.shared.pending.lock() {
            pending.extend(paths);
        }
    }

    /// Sweep progress for the footer: `Some((done, total))` while active.
    #[must_use]
    pub fn progress(&self) -> Option<(usize, usize)> {
        self.shared.queue.lock().ok().and_then(|q| q.progress())
    }
}

impl Drop for Sweep {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

fn run(shared: &Arc<SweepShared>) {
    let client = OpenBinaryClient::new(shared.endpoint.clone());
    while !shared.stop.load(Ordering::Relaxed) {
        drain_submissions(shared);
        let Some(task) = pop_task(shared) else {
            nap(shared, IDLE_NAP);
            continue;
        };
        let did_upload = process(shared, &client, &task);
        nap(shared, gap_after(did_upload));
    }
}

/// Move stashed raw paths into the queue, resolving and de-duplicating them
/// against the cache. Runs on the worker so the render thread stays cheap.
fn drain_submissions(shared: &Arc<SweepShared>) {
    let paths = {
        let Ok(mut pending) = shared.pending.lock() else {
            return;
        };
        std::mem::take(&mut *pending)
    };
    for raw in paths {
        let Some(key) = resolve_exe(&raw) else {
            continue;
        };
        let Some(action) = should_sweep(shared.cache.get(&key).as_ref()) else {
            continue;
        };
        let task = SweepTask::new(key, action, shared.auto_upload);
        if let Ok(mut q) = shared.queue.lock() {
            q.submit(task);
        }
    }
}

fn pop_task(shared: &Arc<SweepShared>) -> Option<SweepTask> {
    shared.queue.lock().ok().and_then(|mut q| q.pop())
}

/// Run one task. Returns whether it performed an upload (for pacing).
fn process(shared: &Arc<SweepShared>, client: &OpenBinaryClient, task: &SweepTask) -> bool {
    let key = &task.key;
    let sha = match hash::hash_file(key) {
        Ok(sha) => sha,
        Err(e) => {
            tracing::debug!(%e, "sweep hash failed");
            settle(shared, key, ObState::Error, None);
            return false;
        }
    };
    match client.get_binary(&sha) {
        Ok(Some(doc)) => {
            settle(shared, key, parse_known(&doc), Some(sha));
            false
        }
        Ok(None) => on_miss(shared, client, key, &sha, task),
        Err(e) => {
            tracing::debug!(%e, "sweep lookup failed");
            settle(shared, key, ObState::Error, Some(sha));
            false
        }
    }
}

/// A 404 during a sweep lookup. Returns whether an upload was performed.
fn on_miss(
    shared: &Arc<SweepShared>,
    client: &OpenBinaryClient,
    key: &Path,
    sha: &str,
    task: &SweepTask,
) -> bool {
    if task.recheck {
        // Still analysing server-side; leave the existing state and settle.
        complete(shared, key);
        return false;
    }
    if !task.allow_upload {
        settle(shared, key, ObState::Unknown, Some(sha.to_owned()));
        return false;
    }
    if !file_size(key).is_none_or(within_auto_cap) {
        settle(shared, key, ObState::TooLarge, Some(sha.to_owned()));
        return false;
    }
    upload(shared, client, key, sha);
    true
}

/// Upload a within-cap miss. Lazy poll: a pending job settles as `Analyzing`
/// and is re-checked with a `GET` on a later pass.
fn upload(shared: &Arc<SweepShared>, client: &OpenBinaryClient, key: &Path, sha: &str) {
    match client.upload(key) {
        Ok(UploadResult::AlreadyDone { sha256, .. }) => {
            let state = match client.get_binary(&sha256) {
                Ok(Some(doc)) => parse_known(&doc),
                Ok(None) => ObState::Unknown,
                Err(_) => ObState::Error,
            };
            settle(shared, key, state, Some(sha256));
        }
        Ok(UploadResult::Pending { .. }) => {
            settle(shared, key, ObState::Analyzing, Some(sha.to_owned()));
        }
        Err(e) => {
            tracing::debug!(%e, "sweep upload failed");
            settle(shared, key, ObState::Error, Some(sha.to_owned()));
        }
    }
}

/// Record a settled state and advance the queue's progress for `key`.
fn settle(shared: &Arc<SweepShared>, key: &Path, state: ObState, sha: Option<String>) {
    shared.cache.record(key, state, sha, None);
    complete(shared, key);
}

fn complete(shared: &Arc<SweepShared>, key: &Path) {
    if let Ok(mut q) = shared.queue.lock() {
        q.settle(key);
    }
}

/// Sleep in short steps so a stop signal is observed promptly.
fn nap(shared: &Arc<SweepShared>, dur: Duration) {
    let step = Duration::from_millis(200);
    let mut left = dur;
    while left > Duration::ZERO && !shared.stop.load(Ordering::Relaxed) {
        let slice = left.min(step);
        thread::sleep(slice);
        left = left.saturating_sub(slice);
    }
}

#[cfg(test)]
#[path = "sweep_test.rs"]
mod sweep_test;
