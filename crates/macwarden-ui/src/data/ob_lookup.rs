//! The synchronous lookup / upload flows run on the cache's background worker
//! threads. Split out of `openbinary.rs` to keep it under the file-size limit;
//! as a descendant module it reaches the parent's private `Shared`/`Entry`/`store`.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use openbinary_agent_core::{JobStatus, OpenBinaryClient, UploadResult, hash};

use super::{
    Entry, MAX_MANUAL_UPLOAD_BYTES, ObState, Shared, file_size, parse_known, store, within_auto_cap,
};

/// Hash `exe`, look it up, and store the result. On a 404 with `auto_upload`
/// enabled the same thread continues into upload + poll so the inspector shows
/// `checking… → analyzing… → verdict` without user interaction.
pub(super) fn run_lookup(shared: &Arc<Shared>, key: &Path, exe: &Path, mtime: Option<SystemTime>) {
    let client = OpenBinaryClient::new(shared.endpoint.clone());
    let sha = match hash::hash_file(exe) {
        Ok(sha) => sha,
        Err(e) => {
            tracing::debug!(%e, "openbinary hash failed");
            store(shared, key, Entry::terminal(ObState::Error, None, mtime));
            return;
        }
    };
    match client.get_binary(&sha) {
        Ok(Some(doc)) => store(
            shared,
            key,
            Entry::terminal(parse_known(&doc), Some(sha), mtime),
        ),
        Ok(None) => on_lookup_miss(shared, key, exe, &sha, mtime, &client),
        Err(e) => {
            tracing::debug!(%e, "openbinary lookup failed");
            store(
                shared,
                key,
                Entry::terminal(ObState::Error, Some(sha), mtime),
            );
        }
    }
}

/// A 404 from the inspector lookup: auto-upload (respecting the size cap) when
/// enabled, otherwise settle as `Unknown`.
fn on_lookup_miss(
    shared: &Arc<Shared>,
    key: &Path,
    exe: &Path,
    sha: &str,
    mtime: Option<SystemTime>,
    client: &OpenBinaryClient,
) {
    if !shared.auto_upload {
        store(
            shared,
            key,
            Entry::terminal(ObState::Unknown, Some(sha.to_owned()), mtime),
        );
        return;
    }
    if !file_size(exe).is_none_or(within_auto_cap) {
        store(
            shared,
            key,
            Entry::terminal(ObState::TooLarge, Some(sha.to_owned()), mtime),
        );
        return;
    }
    store(
        shared,
        key,
        Entry::flight_with_sha(ObState::Uploading, sha.to_owned(), mtime),
    );
    let entry = match identify_flow(client, exe) {
        Ok((state, sha)) => Entry::terminal(state, sha, mtime),
        Err(e) => {
            tracing::debug!(%e, "openbinary auto-upload failed");
            Entry::terminal(ObState::Error, Some(sha.to_owned()), mtime)
        }
    };
    store(shared, key, entry);
}

/// Upload `exe` (manual path, up to the server cap), poll to completion, store.
pub(super) fn run_identify(
    shared: &Arc<Shared>,
    key: &Path,
    exe: &Path,
    mtime: Option<SystemTime>,
) {
    let client = OpenBinaryClient::new(shared.endpoint.clone())
        .with_max_upload_bytes(MAX_MANUAL_UPLOAD_BYTES);
    let entry = match identify_flow(&client, exe) {
        Ok((state, sha)) => Entry::terminal(state, sha, mtime),
        Err(e) => {
            tracing::debug!(%e, "openbinary identify failed");
            Entry::terminal(ObState::Error, None, mtime)
        }
    };
    store(shared, key, entry);
}

type FlowResult = Result<(ObState, Option<String>), openbinary_agent_core::AgentError>;

fn identify_flow(client: &OpenBinaryClient, exe: &Path) -> FlowResult {
    let sha = hash::hash_file(exe)?;
    let job_id = match client.upload(exe)? {
        UploadResult::AlreadyDone { sha256, .. } => {
            return Ok((fetch(client, &sha256), Some(sha256)));
        }
        UploadResult::Pending { job_id } => job_id,
    };
    let status = client.poll_job(&job_id, &mut |_| {})?;
    if let JobStatus::Failed(_) = status {
        return Ok((ObState::Error, Some(sha)));
    }
    Ok((fetch(client, &sha), Some(sha)))
}

fn fetch(client: &OpenBinaryClient, sha: &str) -> ObState {
    match client.get_binary(sha) {
        Ok(Some(doc)) => parse_known(&doc),
        Ok(None) => ObState::Unknown,
        Err(_) => ObState::Error,
    }
}
