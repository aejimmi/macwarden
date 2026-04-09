//! `net` — network firewall rule engine for macwarden.
//!
//! Pure Rust, zero platform dependencies. Compiles and tests on any OS.
//!
//! # Modules
//!
//! - [`host`] — Domain pattern matching with boundary-aware semantics
//! - [`rule`] — Core types: `NetworkRule`, `ProcessMatcher`, `DestMatcher`
//! - [`connection`] — Connection event model and decision types
//! - [`matcher`] — Five-tier rule matching engine
//! - [`tracker`] — Curated tracker database (advertising, analytics, fingerprinting, social)
//! - [`blocklist`] — External blocklist parsing (hosts format, domain-list format)
//! - [`graylist`] — Abusable Apple-signed binaries (shells, curl, python, etc.)
//! - [`safelist`] — Essential domains that are never blocked (OCSP, NTP, etc.)
//! - [`group`] — Network rule groups (toggleable bundles of related rules)
//! - [`profile`] — Network profile section (parses and resolves `[network]` TOML)
//! - [`geoip`] — GeoIP lookups (country, ASN) via MaxMind databases on disk
//! - [`services`] — Well-known port to service name mapping
//! - [`es_event`] — Parser for ES `RESERVED_5` network AUTH event payloads
//! - [`error`] — Error types

pub mod blocklist;
pub mod connection;
pub mod domain_trie;
pub mod error;
pub mod es_event;
pub mod geoip;
pub mod graylist;
pub mod group;
pub mod host;
pub mod import;
pub mod matcher;
pub mod profile;
pub mod rule;
pub mod safelist;
pub mod services;
pub mod tracker;
pub mod user_rule;

// Re-export key types at crate root.
pub use appdb::{AppCategory, AppDb, AppProfile};
pub use blocklist::{Blocklist, BlocklistConfig, BlocklistFormat};
pub use connection::{
    AddressFamily, ConnectionEvent, Destination, MatchTier, MatchedRule, NetworkDecision,
    ProcessIdentity, is_local_network,
};
pub use domain_trie::DomainTrie;
pub use error::NetError;
pub use es_event::{ParsedNetworkEvent, parse_reserved5_event};
pub use geoip::{GeoInfo, GeoLookup, databases_available, geo_dir};
pub use group::{NetworkGroup, NetworkGroupRule, NetworkGroups};
pub use host::HostPattern;
pub use matcher::{BlocklistEntry, BreakageRisk, GroupedRule, RuleSet, TrackerRule};
pub use profile::{
    BlocklistSettings, GroupSettings, NetworkProfile, ProfileNetworkRule, ProfileProcess,
    TrackerSettings,
};
pub use rule::{
    DestMatcher, NetworkAction, NetworkRule, PortMatcher, ProcessMatcher, Protocol, RuleDuration,
    RuleId,
};
pub use tracker::{
    TrackerCategory, TrackerCategoryData, TrackerDatabase, TrackerDomain, TrackerMatch,
};
pub use user_rule::{UserRuleFile, load_user_rules};

/// Evaluate a connection event against a rule set.
///
/// Convenience wrapper around [`RuleSet::decide`].
pub fn decide(rules: &RuleSet, event: &ConnectionEvent) -> NetworkDecision {
    rules.decide(event)
}

/// Produce a human-readable explanation of the decision for a process + destination.
///
/// Convenience wrapper around [`RuleSet::explain`].
pub fn explain(rules: &RuleSet, process: &ProcessIdentity, dest: &Destination) -> String {
    rules.explain(process, dest)
}
