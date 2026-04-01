//! CLI command implementations.
//!
//! Active commands (routed from cli.rs):
//!   scan, inspect (info), apply (use), disable (block), enable (allow),
//!   scrub, monitor (watch), daemon (watch --install), rollback (undo),
//!   groups (scan --groups), status (use with no arg), network, devices.
//!
//! Retained modules (not routed, kept for reuse):
//!   catalog, doctor, explain, profiles, ps.

// Active — routed from CLI.
pub mod apply;
pub mod daemon;
pub mod devices;
pub mod disable;
pub mod enable;
pub mod enforce;
pub mod groups;
pub mod inspect;
pub mod monitor;
pub mod network;
pub mod rollback;
pub mod scan;
pub mod scrub;
pub mod status;

// Retained — not routed from CLI but code preserved for future use.
#[allow(dead_code)]
pub mod catalog;
#[allow(dead_code)]
pub mod doctor;
#[allow(dead_code)]
pub mod explain;
#[allow(dead_code)]
pub mod profiles;
#[allow(dead_code)]
pub mod ps;
