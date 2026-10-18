use super::*;
use crate::data::model::{Flow, Verdict};

fn domain(host: &str) -> DomainRow {
    DomainRow {
        host: host.to_string(),
        country: None,
        verdict: Verdict::Allow,
        rate_bps: 0,
        total_bytes: 0,
        sockets: 1,
        allowed: true,
    }
}

fn app(name: &str, hosts: &[&str]) -> AppRow {
    AppRow {
        id: format!("id.{name}"),
        name: name.to_string(),
        bundle_path: None,
        allowed: true,
        known_bad: false,
        is_system: false,
        down_bytes: 0,
        up_bytes: 0,
        flow: Flow::Idle,
        domains: hosts.iter().map(|h| domain(h)).collect(),
    }
}

fn proc(id: &str, name: &str) -> ProcRow {
    ProcRow {
        id: id.to_string(),
        name: name.to_string(),
        bundle_path: None,
        cpu: 0.0,
        mem_bytes: 0,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
    }
}

fn group(id: &str, name: &str, procs: Vec<ProcRow>) -> ProcGroup {
    ProcGroup {
        id: id.to_string(),
        name: name.to_string(),
        bundle_path: None,
        cpu: 0.0,
        mem_bytes: 0,
        net_bps: 0,
        net_bytes: 0,
        stats_known: true,
        procs,
    }
}

#[test]
fn test_normalize_blank_is_none() {
    assert!(normalize("").is_none());
    assert!(normalize("   ").is_none());
}

#[test]
fn test_normalize_trims_and_lowercases() {
    assert_eq!(normalize("  Apple.COM ").as_deref(), Some("apple.com"));
}

#[test]
fn test_app_matches_by_name() {
    let a = app("Safari", &["apple.com"]);
    assert!(app_matches(&a, "safa"));
}

#[test]
fn test_app_matches_by_destination() {
    let a = app("Safari", &["init.push.apple.com", "gateway.icloud.com"]);
    assert!(app_matches(&a, "icloud.com"));
}

#[test]
fn test_app_matches_none() {
    let a = app("Safari", &["apple.com"]);
    assert!(!app_matches(&a, "google"));
}

#[test]
fn test_matched_domains_returns_only_hits() {
    let a = app("Safari", &["apple.com", "google.com", "push.apple.com"]);
    let candidates: Vec<&DomainRow> = a.domains.iter().collect();
    let hits = matched_domains(&candidates, "apple.com");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|d| d.host.contains("apple.com")));
}

#[test]
fn test_matched_domains_name_only_shows_all() {
    let a = app("Safari", &["apple.com", "google.com"]);
    let candidates: Vec<&DomainRow> = a.domains.iter().collect();
    // The needle matched the app name, not any host, so every destination shows.
    let hits = matched_domains(&candidates, "safari");
    assert_eq!(hits.len(), 2);
}

#[test]
fn test_group_matches_by_pid() {
    let g = group("pg", "Ghostty", vec![proc("4821", "ghostty-helper")]);
    assert!(group_matches(&g, "4821"));
    let first = g.procs.first().expect("group has a member process");
    assert!(proc_matches(first, "4821"));
}

#[test]
fn test_group_self_vs_member_match() {
    let g = group(
        "pg",
        "Ghostty",
        vec![proc("10", "login"), proc("11", "zsh")],
    );
    assert!(group_self_matches(&g, "ghost"));
    assert!(!group_self_matches(&g, "zsh"));
    assert!(group_matches(&g, "zsh"));
}

#[test]
fn test_group_matches_none() {
    let g = group("pg", "Ghostty", vec![proc("10", "zsh")]);
    assert!(!group_matches(&g, "firefox"));
}

#[test]
fn test_delete_last_word_single_word_clears() {
    assert_eq!(delete_last_word("firefox"), "");
}

#[test]
fn test_delete_last_word_drops_trailing_word_keeps_space() {
    assert_eq!(delete_last_word("one two three"), "one two ");
    assert_eq!(delete_last_word("apple.com google"), "apple.com ");
}

#[test]
fn test_delete_last_word_ignores_trailing_whitespace() {
    assert_eq!(delete_last_word("one two   "), "one ");
    assert_eq!(delete_last_word("solo   "), "");
}

#[test]
fn test_delete_last_word_empty_stays_empty() {
    assert_eq!(delete_last_word(""), "");
    assert_eq!(delete_last_word("   "), "");
}

#[test]
fn test_delete_last_word_unicode_safe() {
    // Multibyte content must not panic on the char-boundary slice.
    assert_eq!(delete_last_word("café über"), "café ");
    assert_eq!(delete_last_word("naïve"), "");
}
