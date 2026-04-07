//! macOS Endpoint Security event handler and worker dispatch.
//!
//! Contains the `extern "C"` block handler invoked by ES for each event,
//! the worker thread that processes events through the rule engine, and
//! the safety-net timer that auto-allows before the kernel deadline.
//!
//! # Architecture
//!
//! ```text
//! ES dispatch queue
//!   |
//!   +-- es_handler_invoke (extern "C" block)
//!         |
//!         +-- retain message, spawn worker thread
//!               |
//!               +-- process_event: evaluate rules, respond
//!               |
//!               +-- safety_net_timer: sleep(deadline - 2s), auto-allow
//! ```
//!
//! # Safety
//!
//! The handler function is `unsafe extern "C"` -- called by the ES
//! framework with valid pointers. All FFI calls inside use the
//! `SendClientPtr`/`SendMessagePtr` wrappers to satisfy `Send` bounds.

#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ffi;

use crate::client::{EsStats, HandlerContext};

// ---------------------------------------------------------------------------
// Global handler context
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// Global handler context for the ES block callback.
///
/// The ES block API requires a plain `extern "C"` function with no
/// captures. We store the handler context in a `OnceLock` that the
/// handler reads at invocation time.
pub(crate) static HANDLER_CONTEXT: OnceLock<Arc<HandlerContext>> = OnceLock::new();

/// Block descriptor for the global ES handler block.
pub(crate) static BLOCK_DESCRIPTOR: ffi::BlockDescriptor = ffi::BlockDescriptor {
    reserved: 0,
    size: std::mem::size_of::<ffi::BlockLiteral>() as u64,
};

// ---------------------------------------------------------------------------
// Handler (extern "C" block invoke function)
// ---------------------------------------------------------------------------

/// The `extern "C"` handler function invoked by the ES block.
///
/// # Safety
///
/// This function is called by the Endpoint Security framework on its
/// internal dispatch queue. The `client` and `message` pointers are
/// guaranteed valid by the framework for the duration of this call.
///
/// For AUTH events, we must respond before the message deadline.
/// We retain the message, spawn a worker thread, and set up a
/// safety-net timer.
#[allow(unsafe_code)]
pub(crate) unsafe extern "C" fn es_handler_invoke(
    _block: *const ffi::BlockLiteral,
    client: ffi::EsClientPtr,
    message: ffi::EsMessagePtr,
) {
    let Some(ctx) = HANDLER_CONTEXT.get() else {
        // Context not initialized -- auto-allow to avoid blocking.
        // SAFETY: client and message are valid (framework guarantee).
        unsafe {
            ffi::es_respond_auth_result(client, message, ffi::ES_AUTH_RESULT_ALLOW, false);
        }
        return;
    };

    // Increment received counter.
    if let Ok(mut stats) = ctx.stats.lock() {
        stats.events_received += 1;
    }

    // Retain the message so it survives past this callback.
    // SAFETY: message is a valid ES message pointer.
    unsafe { ffi::es_retain_message(message) };

    let ctx = Arc::clone(ctx);

    // Wrap raw pointers in Send-safe wrappers for the worker thread.
    let send_client = ffi::SendClientPtr::new(client);
    let send_message = ffi::SendMessagePtr::new(message);

    // Spawn a worker thread to process the event.
    // The worker will respond and release the message.
    std::thread::spawn(move || {
        process_event(&ctx, send_client, send_message);
    });
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Process a single ES event on a worker thread.
///
/// Evaluates rules and responds allow/deny. The safety-net timer runs
/// in a separate thread and auto-allows if this function takes too long.
#[allow(unsafe_code)]
fn process_event(
    ctx: &Arc<HandlerContext>,
    send_client: ffi::SendClientPtr,
    send_message: ffi::SendMessagePtr,
) {
    let responded = Arc::new(AtomicBool::new(false));

    // Default deadline for RESERVED_5 is ~15 seconds. We use a fixed
    // fallback since reading the actual deadline from the opaque message
    // requires additional FFI offset knowledge.
    let fallback_deadline = Duration::from_secs(15);
    let timer_deadline = fallback_deadline
        .checked_sub(ctx.safety_margin)
        .unwrap_or(Duration::from_secs(1));

    let responded_timer = Arc::clone(&responded);
    let stats_timer = Arc::clone(&ctx.stats);
    let timer_client = send_client;
    let timer_message = send_message;

    std::thread::spawn(move || {
        safety_net_timer(
            timer_deadline,
            &responded_timer,
            &stats_timer,
            timer_client,
            timer_message,
        );
    });

    // Evaluate the event through the rule engine.
    let action = evaluate_event(ctx);

    let es_result = match action {
        net::NetworkAction::Allow | net::NetworkAction::Log => ffi::ES_AUTH_RESULT_ALLOW,
        net::NetworkAction::Deny => ffi::ES_AUTH_RESULT_DENY,
    };

    if responded.swap(true, Ordering::AcqRel) {
        // Safety-net already responded -- don't double-respond.
        return;
    }

    // SAFETY: client and message are valid (retained). We checked
    // that we haven't already responded via the atomic flag.
    unsafe {
        ffi::es_respond_auth_result(
            send_client.as_ptr(),
            send_message.as_ptr(),
            es_result,
            false, // Don't cache -- rules may change
        );
    }
    // SAFETY: message was retained in the handler. Release it now.
    unsafe { ffi::es_release_message(send_message.as_ptr()) };

    if let Ok(mut stats) = ctx.stats.lock() {
        match action {
            net::NetworkAction::Allow => stats.events_allowed += 1,
            net::NetworkAction::Deny => stats.events_denied += 1,
            net::NetworkAction::Log => stats.events_logged += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Safety-net timer
// ---------------------------------------------------------------------------

/// Auto-allow if the worker hasn't responded before the deadline.
///
/// Sleeps until `deadline`, then checks the `responded` flag. If the
/// worker hasn't responded yet, sends `ES_AUTH_RESULT_ALLOW` and
/// releases the message.
#[allow(unsafe_code)]
fn safety_net_timer(
    deadline: Duration,
    responded: &AtomicBool,
    stats: &Mutex<EsStats>,
    client: ffi::SendClientPtr,
    message: ffi::SendMessagePtr,
) {
    std::thread::sleep(deadline);
    if responded.load(Ordering::Acquire) {
        return;
    }

    tracing::warn!(
        deadline_ms = deadline.as_millis() as u64,
        "safety-net timer fired, auto-allowing event"
    );

    // SAFETY: client and message are valid (retained earlier).
    unsafe {
        ffi::es_respond_auth_result(
            client.as_ptr(),
            message.as_ptr(),
            ffi::ES_AUTH_RESULT_ALLOW,
            false,
        );
    }
    // SAFETY: message was retained. Release it now.
    unsafe { ffi::es_release_message(message.as_ptr()) };

    if let Ok(mut s) = stats.lock() {
        s.events_auto_allowed += 1;
    }
}

// ---------------------------------------------------------------------------
// Event evaluation (placeholder)
// ---------------------------------------------------------------------------

/// Evaluate an event through the rule engine.
///
/// This is a placeholder that returns Allow -- the full implementation
/// requires reading process info from the ES message's audit token,
/// which needs additional FFI offset knowledge for the opaque
/// `es_message_t` struct.
///
/// The architecture is correct: parse event bytes, build
/// `ConnectionEvent`, call `rules.decide()`. The FFI offset details
/// for extracting the audit token and event data pointer from the
/// opaque message are deferred to when we have access to the ES
/// headers or can reverse-engineer the offsets.
fn evaluate_event(ctx: &HandlerContext) -> net::NetworkAction {
    // TODO: Extract audit_token from message -> pid, uid, path
    // TODO: Parse RESERVED_5 event bytes via net::parse_reserved5_event()
    // TODO: Look up code signing via procmon::code_signing
    // TODO: Look up responsible PID via procmon::responsible
    // TODO: Build ConnectionEvent and call ctx.rules.decide()

    let _ = ctx;
    net::NetworkAction::Allow
}

// ---------------------------------------------------------------------------
// Self-exemption
// ---------------------------------------------------------------------------

/// Mute the current process to avoid self-blocking.
#[allow(unsafe_code)]
pub(crate) fn mute_self(client: ffi::EsClientPtr) {
    let pid = std::process::id();
    tracing::debug!(pid, "self-exemption: would mute own process");

    // TODO: Implement proper audit token extraction via task_info.
    // mach_task_self() + task_info(TASK_AUDIT_TOKEN) -> audit_token
    // then es_mute_process(client, &token).
    let _ = client;
}
