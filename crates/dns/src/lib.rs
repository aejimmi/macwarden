//! `dns` -- Passive DNS cache and wire parser for macwarden.
//!
//! Provides hostname enrichment for the network firewall by mapping
//! IP addresses to hostnames. Two data sources feed the cache:
//!
//! 1. ES RESERVED_5 events (which carry hostname + resolved_ip)
//! 2. BPF/pcap sniffer (future -- captures DNS responses on port 53)
//!
//! # Modules
//!
//! - [`cache`] -- Thread-safe LRU cache mapping IpAddr to hostname
//! - [`parser`] -- DNS wire format response parser (RFC 1035)

pub mod cache;
pub mod parser;
pub mod persist;

#[cfg(test)]
#[path = "cache_test.rs"]
mod cache_test;

#[cfg(test)]
#[path = "parser_test.rs"]
mod parser_test;

#[cfg(test)]
#[path = "persist_test.rs"]
mod persist_test;

pub use cache::{CacheSnapshot, DnsCache};
pub use parser::{DnsAnswer, DnsParseError, DnsResponse, parse_dns_response};
pub use persist::{DnsCacheStore, PersistError};
