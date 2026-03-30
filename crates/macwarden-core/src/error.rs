//! Error types for the macwarden-core crate.

use std::fmt;

/// All errors produced by the core crate.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Failed to parse a profile TOML file.
    #[error("failed to parse profile: {message}")]
    ProfileParse {
        /// Human-readable parse error detail.
        message: String,
    },

    /// Profile failed validation (e.g. deny list references critical services).
    #[error("profile validation failed: {message}")]
    ProfileValidation {
        /// Human-readable validation error detail.
        message: String,
    },

    /// One or more actions target critical services that cannot be disabled.
    #[error("safe-list violation: cannot act on critical services: {}", labels.join(", "))]
    SafelistViolation {
        /// The labels of the critical services that were targeted.
        labels: Vec<String>,
    },

    /// Profile extends chain contains a cycle.
    #[error("circular extends detected: {chain}")]
    CircularExtends {
        /// Human-readable representation of the cycle.
        chain: String,
    },

    /// A profile referenced in an extends chain was not found.
    #[error("profile not found: {name}")]
    ProfileNotFound {
        /// The missing profile name.
        name: String,
    },

    /// The extends chain exceeds the maximum allowed depth.
    #[error("extends chain exceeds maximum depth of {max_depth}")]
    MaxExtendsDepth {
        /// The maximum allowed depth.
        max_depth: usize,
    },
}

/// Convenience alias for results using [`CoreError`].
pub type Result<T> = std::result::Result<T, CoreError>;

/// Error returned when safe-list validation rejects actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafelistError {
    /// Labels that were rejected because they target critical services.
    pub rejected: Vec<String>,
}

impl fmt::Display for SafelistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot act on critical services: {}",
            self.rejected.join(", ")
        )
    }
}

impl std::error::Error for SafelistError {}

/// Error specific to profile validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    /// Human-readable validation error detail.
    pub message: String,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "profile validation error: {}", self.message)
    }
}

impl std::error::Error for ProfileError {}
