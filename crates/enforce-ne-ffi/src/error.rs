//! Error type for the NetworkExtension decision core.

use thiserror::Error;

/// Failure loading or reloading the embedded [`net::RuleSet`].
#[derive(Debug, Error)]
pub enum NeError {
    /// The ruleset could not be composed from the `~/.macwarden/` files.
    #[error("failed to load ruleset: {0}")]
    Load(String),

    /// The base directory could not be resolved (e.g. `HOME` unset).
    #[error("could not resolve macwarden base directory")]
    NoBaseDir,
}
