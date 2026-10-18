//! Error types for the banwatch engine.

use thiserror::Error;

/// A banwatch failure. Persistence and config-parse errors are surfaced here;
/// the read paths that consume attacker-influenced data (log lines, packet
/// events, a corrupt store) never return an error — they degrade to "no ban"
/// or "no signal" per the spec's total-parsing contract.
#[derive(Debug, Error)]
pub enum BanwatchError {
    /// The active-ban / escalation-count store could not be opened or written.
    #[error("ban store error: {0}")]
    Store(String),

    /// The `~/.macwarden/` base directory could not be resolved (no `HOME`).
    #[error("cannot resolve base directory: {0}")]
    BaseDir(String),
}

/// Convenience result alias for banwatch operations.
pub type Result<T> = std::result::Result<T, BanwatchError>;
