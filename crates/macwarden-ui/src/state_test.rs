#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::data::model::{ProcGroup, ProcRow};

fn group(id: &str, cpu: f32, mem: u64, net: u64) -> ProcGroup {
    ProcGroup {
        id: id.into(),
        name: id.into(),
        bundle_path: None,
        cpu,
        mem_bytes: mem,
        net_bps: net,
        net_bytes: net,
        stats_known: true,
        procs: Vec::new(),
    }
}

fn proc(id: &str, cpu: f32, mem: u64, net: u64) -> ProcRow {
    ProcRow {
        id: id.into(),
        name: id.into(),
        bundle_path: None,
        cpu,
        mem_bytes: mem,
        net_bps: net,
        net_bytes: net.saturating_mul(60),
        stats_known: true,
    }
}

#[test]
fn test_default_state() {
    let s = PanelState::default();
    assert_eq!(s.tab(), Tab::Apps);
    assert_eq!(s.scope(), Scope::RealTime);
    assert_eq!(s.sort(), Sort::Net);
    assert!(!s.in_detail());
}

#[test]
fn test_tab_and_scope_and_sort_setters() {
    let mut s = PanelState::default();
    s.set_tab(Tab::Processes);
    s.set_scope(Scope::Today);
    s.set_sort(Sort::Cpu);
    assert_eq!(s.tab(), Tab::Processes);
    assert_eq!(s.scope(), Scope::Today);
    assert_eq!(s.sort(), Sort::Cpu);
}

#[test]
fn test_expansion_toggle_is_idempotent_pair() {
    let mut s = PanelState::default();
    assert!(!s.is_expanded("a"));
    s.toggle_expanded("a");
    assert!(s.is_expanded("a"));
    s.toggle_expanded("a");
    assert!(!s.is_expanded("a"));
}

#[test]
fn test_nav_push_pop() {
    let mut s = PanelState::default();
    s.push(Route::App("chrome".into()));
    assert!(s.in_detail());
    assert_eq!(s.current_route(), Some(&Route::App("chrome".into())));
    s.push(Route::Domain("googlevideo.com".into()));
    assert_eq!(
        s.current_route(),
        Some(&Route::Domain("googlevideo.com".into()))
    );
    s.pop();
    assert_eq!(s.current_route(), Some(&Route::App("chrome".into())));
    s.pop();
    assert!(!s.in_detail());
    s.pop(); // no panic at root
    assert!(!s.in_detail());
}

#[test]
fn test_app_allow_override_defaults_and_toggles() {
    let mut s = PanelState::default();
    // No override yet — follows the source default.
    assert!(s.app_allowed("x", true));
    assert!(!s.app_allowed("y", false));
    // Toggle relative to default.
    s.toggle_app_allow("x", true);
    assert!(!s.app_allowed("x", true));
    s.toggle_app_allow("x", true);
    assert!(s.app_allowed("x", true));
}

#[test]
fn test_set_app_allow_forces_state() {
    let mut s = PanelState::default();
    s.set_app_allow("x", false);
    assert!(!s.app_allowed("x", true));
    s.set_app_allow("x", true);
    assert!(s.app_allowed("x", false));
}

#[test]
fn test_domain_allow_override() {
    let mut s = PanelState::default();
    assert!(s.domain_allowed("host", true));
    s.toggle_domain_allow("host", true);
    assert!(!s.domain_allowed("host", true));
}

#[test]
fn test_scope_shows_totals_only_off_realtime() {
    assert!(!Scope::RealTime.shows_totals());
    assert!(Scope::Session.shows_totals());
    assert!(Scope::Hour.shows_totals());
    assert!(Scope::Today.shows_totals());
    assert_eq!(Scope::RealTime.live_label(), "Live");
    assert_eq!(Scope::Session.live_label(), "Session");
}

#[test]
fn test_expand_all_forces_every_disclosure_open() {
    let mut s = PanelState::default();
    assert!(!s.is_expanded("anything"));
    s.set_expand_all(true);
    assert!(s.is_expanded("anything"));
    assert!(s.is_expanded("other"));
    s.set_expand_all(false);
    assert!(!s.is_expanded("anything"));
}

#[test]
fn test_sort_groups_by_each_key() {
    let mut groups = vec![
        group("a", 1.0, 100, 5),
        group("b", 3.0, 300, 50),
        group("c", 2.0, 200, 20),
    ];
    let mut s = PanelState::default();
    s.set_sort(Sort::Net);
    s.sort_groups(&mut groups);
    assert_eq!(groups[0].id, "b");
    s.set_sort(Sort::Cpu);
    s.sort_groups(&mut groups);
    assert_eq!(groups[0].id, "b");
    assert_eq!(groups[2].id, "a");
    s.set_sort(Sort::Mem);
    s.sort_groups(&mut groups);
    assert_eq!(groups[0].id, "b");
    assert_eq!(groups[2].id, "a");
}

#[test]
fn test_sort_procs_by_each_key() {
    let s_net = {
        let mut s = PanelState::default();
        s.set_sort(Sort::Net);
        s
    };
    let mut rows = vec![
        proc("a", 1.0, 100, 5),
        proc("b", 3.0, 300, 50),
        proc("c", 2.0, 200, 20),
    ];
    s_net.sort_procs(&mut rows);
    assert_eq!(rows[0].id, "b");

    let mut s = PanelState::default();
    s.set_sort(Sort::Cpu);
    s.sort_procs(&mut rows);
    assert_eq!(rows[0].id, "b");
    assert_eq!(rows[2].id, "a");

    s.set_sort(Sort::Mem);
    s.sort_procs(&mut rows);
    assert_eq!(rows[0].id, "b");
    assert_eq!(rows[2].id, "a");
}

#[test]
fn test_toggle_popover_opens_and_closes() {
    let mut s = PanelState::default();
    assert_eq!(s.popover(), Popover::None);
    s.toggle_popover(Popover::Quick);
    assert_eq!(s.popover(), Popover::Quick);
    // Toggling the same popover closes it.
    s.toggle_popover(Popover::Quick);
    assert_eq!(s.popover(), Popover::None);
}

#[test]
fn test_toggle_popover_switches_between_kinds() {
    let mut s = PanelState::default();
    s.toggle_popover(Popover::Quick);
    // Opening a different popover replaces the open one (only one at a time).
    s.toggle_popover(Popover::Menu);
    assert_eq!(s.popover(), Popover::Menu);
    s.close_popover();
    assert_eq!(s.popover(), Popover::None);
}

#[test]
fn test_allow_draft_edit_and_clear() {
    let mut s = PanelState::default();
    assert_eq!(s.allow_draft(), "");
    s.push_allow_text("a");
    s.push_allow_text("p");
    s.push_allow_text("i");
    assert_eq!(s.allow_draft(), "api");
    s.pop_allow_char();
    assert_eq!(s.allow_draft(), "ap");
    s.clear_allow_draft();
    assert_eq!(s.allow_draft(), "");
}

#[test]
fn test_clear_local_allows_resets_overrides() {
    let mut s = PanelState::default();
    s.set_app_allow("com.example", false);
    s.toggle_domain_allow("evil.example", true);
    // A mode flip drops local overrides so daemon verdicts show through.
    s.clear_local_allows();
    // With no override, the source default is returned unchanged.
    assert!(s.app_allowed("com.example", true));
    assert!(!s.domain_allowed("evil.example", false));
}

#[test]
fn test_block_draft_edit_and_clear() {
    let mut s = PanelState::default();
    assert_eq!(s.block_draft(), "");
    s.push_block_text("a");
    s.push_block_text("d");
    s.push_block_text("s");
    assert_eq!(s.block_draft(), "ads");
    s.pop_block_char();
    assert_eq!(s.block_draft(), "ad");
    s.clear_block_draft();
    assert_eq!(s.block_draft(), "");
}

#[test]
fn test_settings_field_focus_defaults_to_none() {
    let mut s = PanelState::default();
    assert_eq!(s.settings_field(), SettingsField::None);
    s.set_settings_field(SettingsField::Block);
    assert_eq!(s.settings_field(), SettingsField::Block);
}

#[test]
fn test_group_expansion_toggles() {
    let mut s = PanelState::default();
    assert!(!s.is_group_expanded("privacy"));
    s.toggle_group_expanded("privacy");
    assert!(s.is_group_expanded("privacy"));
    s.toggle_group_expanded("privacy");
    assert!(!s.is_group_expanded("privacy"));
}

#[test]
fn test_blocked_domains_add_dedups_and_remove() {
    let mut s = PanelState::default();
    s.add_blocked_domain("ads.example.com".to_string());
    s.add_blocked_domain("ads.example.com".to_string()); // idempotent
    s.add_blocked_domain("track.example.net".to_string());
    assert_eq!(s.blocked_domains().len(), 2);
    s.remove_blocked_domain("ads.example.com");
    assert_eq!(s.blocked_domains(), &["track.example.net".to_string()]);
}

#[test]
fn test_block_error_set_and_clear() {
    let mut s = PanelState::default();
    assert_eq!(s.block_error(), None);
    s.set_block_error("couldn't add *.bad".to_string());
    assert_eq!(s.block_error(), Some("couldn't add *.bad"));
    s.clear_block_error();
    assert_eq!(s.block_error(), None);
}

#[test]
fn test_settings_route_pushes_and_pops() {
    let mut s = PanelState::default();
    assert!(!s.in_detail());
    s.push(Route::Settings);
    assert!(s.in_detail());
    assert_eq!(s.current_route(), Some(&Route::Settings));
    s.pop();
    assert!(!s.in_detail());
}
