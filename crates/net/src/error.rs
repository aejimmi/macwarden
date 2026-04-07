//! Error types for the `net` crate.

/// All errors produced by the network firewall engine.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// A rule definition is invalid.
    #[error("invalid rule: {message}")]
    InvalidRule {
        /// Human-readable detail about what makes the rule invalid.
        message: String,
    },

    /// A host pattern could not be parsed.
    #[error("invalid host pattern `{pattern}`: {message}")]
    InvalidHostPattern {
        /// The pattern string that failed to parse.
        pattern: String,
        /// What went wrong.
        message: String,
    },

    /// A CIDR address or IP literal could not be parsed.
    #[error("invalid CIDR `{cidr}`: {message}")]
    InvalidCidr {
        /// The CIDR string that failed to parse.
        cidr: String,
        /// What went wrong.
        message: String,
    },

    /// A port or port range could not be parsed.
    #[error("invalid port `{port}`: {message}")]
    InvalidPort {
        /// The port string that failed to parse.
        port: String,
        /// What went wrong.
        message: String,
    },

    /// Two rules conflict (same process+dest, different actions).
    #[error("rule conflict between `{rule_a}` and `{rule_b}`")]
    RuleConflict {
        /// Name of the first conflicting rule.
        rule_a: String,
        /// Name of the second conflicting rule.
        rule_b: String,
    },

    /// A tracker database TOML file could not be parsed.
    #[error("tracker parse error in category `{category}`: {message}")]
    TrackerParse {
        /// Which tracker category failed.
        category: String,
        /// What went wrong.
        message: String,
    },

    /// A blocklist file could not be parsed.
    #[error("blocklist `{name}` parse error at line {line}: {message}")]
    BlocklistParse {
        /// Name of the blocklist.
        name: String,
        /// Line number (1-based) where the error occurred.
        line: usize,
        /// What went wrong.
        message: String,
    },

    /// A network group TOML file could not be parsed.
    #[error("group parse error in `{group}`: {message}")]
    GroupParse {
        /// Which group file failed.
        group: String,
        /// What went wrong.
        message: String,
    },

    /// The app category database could not be parsed.
    #[error("category parse error: {message}")]
    CategoryParse {
        /// What went wrong.
        message: String,
    },

    /// A network profile section could not be resolved.
    #[error("profile resolve error: {message}")]
    ProfileResolve {
        /// What went wrong.
        message: String,
    },

    /// A blocklist file could not be loaded from disk.
    #[error("blocklist load `{path}`: {message}")]
    BlocklistLoad {
        /// Filesystem path that failed.
        path: String,
        /// What went wrong.
        message: String,
    },

    /// A user rule TOML file could not be parsed.
    #[error("rule parse error in `{path}`: {message}")]
    RuleParse {
        /// Path or name of the rule source.
        path: String,
        /// What went wrong.
        message: String,
    },

    /// A GeoIP database could not be loaded or a lookup failed fatally.
    #[error("geoip error: {message}")]
    GeoIp {
        /// What went wrong.
        message: String,
    },
}

/// Convenience alias for results using [`NetError`].
pub type Result<T> = std::result::Result<T, NetError>;
