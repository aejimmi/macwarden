//! Pure view-model state for the panel — no GPUI, fully unit-tested.
//!
//! The GPUI view owns a [`PanelState`] and a boxed source; every interaction
//! (tab switch, disclosure, navigation, switch toggle, sort) mutates this
//! struct so the logic can be exercised without rendering.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::data::model::{ProcGroup, ProcRow};

/// The two top-level tabs. Per-destination detail lives in the Apps tab's
/// row expansion (verdict dots, per-domain block/allow), so a separate flat
/// destination list would be redundant — hence just Apps and Processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    /// Apps and their destinations.
    #[default]
    Apps,
    /// Live process list.
    Processes,
}

impl Tab {
    /// Tab title.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Tab::Apps => "Apps",
            Tab::Processes => "Processes",
        }
    }

    /// All tabs in display order.
    #[must_use]
    pub fn all() -> [Tab; 2] {
        [Tab::Apps, Tab::Processes]
    }
}

/// The time scope selector on the secondary header line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Live, ~1 Hz.
    #[default]
    RealTime,
    /// Last hour (demo only — the live source has no history).
    Hour,
    /// Since midnight (demo only).
    Today,
    /// Everything accumulated since the panel launched (the live totals scope).
    Session,
}

impl Scope {
    /// Label for the small text button.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Scope::RealTime => "Real-time",
            Scope::Hour => "Hour",
            Scope::Today => "Today",
            Scope::Session => "Session",
        }
    }

    /// Label used in live mode, where Real-time reads simply as "Live".
    #[must_use]
    pub fn live_label(self) -> &'static str {
        match self {
            Scope::RealTime => "Live",
            other => other.label(),
        }
    }

    /// Whether this scope shows accumulated totals rather than live rates.
    #[must_use]
    pub fn shows_totals(self) -> bool {
        !matches!(self, Scope::RealTime)
    }

    /// Demo scopes, in display order.
    #[must_use]
    pub fn all() -> [Scope; 3] {
        [Scope::RealTime, Scope::Hour, Scope::Today]
    }

    /// Live-mode scopes: the panel cannot honestly split Hour from Today with no
    /// daemon history, so it collapses to a live rate view and a session total.
    #[must_use]
    pub fn live() -> [Scope; 2] {
        [Scope::RealTime, Scope::Session]
    }
}

/// Sort key for the Processes tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// By CPU descending.
    Cpu,
    /// By memory descending.
    Mem,
    /// By network rate descending.
    #[default]
    Net,
}

impl Sort {
    /// Label for the sort control.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Sort::Cpu => "CPU",
            Sort::Mem => "MEM",
            Sort::Net => "NET",
        }
    }

    /// All sort keys in display order.
    #[must_use]
    pub fn all() -> [Sort; 3] {
        [Sort::Cpu, Sort::Mem, Sort::Net]
    }
}

/// How often the panel refreshes live data — a user-facing performance/battery
/// trade-off. GPUI recomposites and re-presents the *whole* window on every
/// refreshed frame, so a longer interval linearly cuts the panel's steady-state
/// CPU at the cost of choppier live counters. Persisted across launches in
/// `~/.macwarden/ui-prefs.json` (see [`crate::data::prefs`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefreshRate {
    /// Refresh every second — the most responsive, highest CPU.
    Live,
    /// Refresh every two seconds — the balanced default.
    #[default]
    Balanced,
    /// Refresh every five seconds — the lightest on CPU and battery.
    Relaxed,
}

impl RefreshRate {
    /// The refresh period.
    #[must_use]
    pub fn interval(self) -> Duration {
        match self {
            RefreshRate::Live => Duration::from_secs(1),
            RefreshRate::Balanced => Duration::from_secs(2),
            RefreshRate::Relaxed => Duration::from_secs(5),
        }
    }

    /// Short control label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            RefreshRate::Live => "Live",
            RefreshRate::Balanced => "Balanced",
            RefreshRate::Relaxed => "Relaxed",
        }
    }

    /// A one-line explanation of the trade-off for the settings row.
    #[must_use]
    pub fn caption(self) -> &'static str {
        match self {
            RefreshRate::Live => "Updates every 1s — most responsive, highest CPU.",
            RefreshRate::Balanced => "Updates every 2s — recommended.",
            RefreshRate::Relaxed => "Updates every 5s — easiest on battery.",
        }
    }

    /// All rates in display order.
    #[must_use]
    pub fn all() -> [RefreshRate; 3] {
        [
            RefreshRate::Live,
            RefreshRate::Balanced,
            RefreshRate::Relaxed,
        ]
    }

    /// A stable string key for persistence — decoupled from the enum layout so
    /// the on-disk file survives reordering or additions.
    #[must_use]
    pub fn as_key(self) -> &'static str {
        match self {
            RefreshRate::Live => "live",
            RefreshRate::Balanced => "balanced",
            RefreshRate::Relaxed => "relaxed",
        }
    }

    /// Parse a persisted key; an unknown or absent key falls back to the default.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        match key {
            "live" => RefreshRate::Live,
            "relaxed" => RefreshRate::Relaxed,
            _ => RefreshRate::Balanced,
        }
    }
}

/// Which header popover is open, if any. Only one is open at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Popover {
    /// Nothing open.
    #[default]
    None,
    /// The quick-settings popover from the mode pill: Allow/Block radios, the
    /// coming-soon "Ask" row, the Apple/DNS toggles, and a "Rules & Settings…"
    /// footer link. Intentionally scroll-free — groups live in the Rules view.
    Quick,
    /// The `⋯` app menu: "Rules & Settings…" plus Quit.
    Menu,
}

/// A pushed full-panel route. `App`/`Domain`/`Proc` push the async inspector;
/// `Settings` pushes the full-panel Rules & Settings view (groups, allow list,
/// block list). Both reuse the same nav stack + back-chevron chrome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// App inspector keyed by app id.
    App(String),
    /// Domain inspector keyed by hostname.
    Domain(String),
    /// Process inspector keyed by process id.
    Proc(String),
    /// The full-panel Rules & Settings view.
    Settings,
    /// The full-panel per-app packet trace view, keyed by app id (R11).
    Trace(String),
}

/// Which text field in the Rules & Settings view currently receives typed keys.
/// The pushed view has no real `TextInput`; it captures key-downs and routes
/// them to whichever add-field the user last focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsField {
    /// No field focused — typed keys are ignored (only Esc backs out).
    #[default]
    None,
    /// The Allow List add-field.
    Allow,
    /// The Block List add-field.
    Block,
}

/// The full mutable state of the panel view.
#[derive(Debug, Default)]
pub struct PanelState {
    tab: Tab,
    scope: Scope,
    sort: Sort,
    nav: Vec<Route>,
    expanded: HashSet<String>,
    expand_all: bool,
    app_allow: HashMap<String, bool>,
    domain_allow: HashMap<String, bool>,
    popover: Popover,
    allow_draft: String,
    block_draft: String,
    settings_field: SettingsField,
    expanded_groups: HashSet<String>,
    blocked_domains: Vec<String>,
    block_error: Option<String>,
    filter: String,
    filter_active: bool,
    system_expanded: bool,
    refresh_rate: RefreshRate,
}

impl PanelState {
    /// Active tab.
    #[must_use]
    pub fn tab(&self) -> Tab {
        self.tab
    }

    /// Active scope.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Active sort key.
    #[must_use]
    pub fn sort(&self) -> Sort {
        self.sort
    }

    /// The live-data refresh cadence.
    #[must_use]
    pub fn refresh_rate(&self) -> RefreshRate {
        self.refresh_rate
    }

    /// Set the live-data refresh cadence.
    pub fn set_refresh_rate(&mut self, rate: RefreshRate) {
        self.refresh_rate = rate;
    }

    /// Switch tabs. Navigation stack is preserved so back returns to the tab.
    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
    }

    /// Set the time scope.
    pub fn set_scope(&mut self, scope: Scope) {
        self.scope = scope;
    }

    /// Set the process sort key.
    pub fn set_sort(&mut self, sort: Sort) {
        self.sort = sort;
    }

    /// Whether an app row is expanded to show its destinations. The
    /// `expand_all` override (a debug affordance for state screenshots) forces
    /// every disclosure open.
    #[must_use]
    pub fn is_expanded(&self, app_id: &str) -> bool {
        self.expand_all || self.expanded.contains(app_id)
    }

    /// Force every disclosure open regardless of individual toggles. Used only
    /// by the `MACWARDEN_UI_EXPAND_ALL` debug hook.
    pub fn set_expand_all(&mut self, on: bool) {
        self.expand_all = on;
    }

    /// Toggle a disclosure triangle.
    pub fn toggle_expanded(&mut self, app_id: &str) {
        if !self.expanded.remove(app_id) {
            self.expanded.insert(app_id.to_string());
        }
    }

    /// The current inspector route, if any is pushed.
    #[must_use]
    pub fn current_route(&self) -> Option<&Route> {
        self.nav.last()
    }

    /// Whether an inspector is showing.
    #[must_use]
    pub fn in_detail(&self) -> bool {
        !self.nav.is_empty()
    }

    /// Push an inspector route.
    pub fn push(&mut self, route: Route) {
        self.nav.push(route);
    }

    /// Pop one inspector level; no-op at the tab root.
    pub fn pop(&mut self) {
        self.nav.pop();
    }

    /// Resolve the effective allow state for an app, honouring user overrides.
    #[must_use]
    pub fn app_allowed(&self, id: &str, default: bool) -> bool {
        self.app_allow.get(id).copied().unwrap_or(default)
    }

    /// Flip an app's network-access override relative to the source default.
    pub fn toggle_app_allow(&mut self, id: &str, default: bool) {
        let next = !self.app_allowed(id, default);
        self.app_allow.insert(id.to_string(), next);
    }

    /// Force an app's allow state (used by the inspector Block action).
    pub fn set_app_allow(&mut self, id: &str, allowed: bool) {
        self.app_allow.insert(id.to_string(), allowed);
    }

    /// Resolve the effective allow state for a destination.
    #[must_use]
    pub fn domain_allowed(&self, host: &str, default: bool) -> bool {
        self.domain_allow.get(host).copied().unwrap_or(default)
    }

    /// Flip a destination's allow override.
    pub fn toggle_domain_allow(&mut self, host: &str, default: bool) {
        let next = !self.domain_allowed(host, default);
        self.domain_allow.insert(host.to_string(), next);
    }

    /// Force a destination's allow state (used by the child block action and its
    /// daemon-rejection revert).
    pub fn set_domain_allow(&mut self, host: &str, allowed: bool) {
        self.domain_allow.insert(host.to_string(), allowed);
    }

    /// The currently open header popover.
    #[must_use]
    pub fn popover(&self) -> Popover {
        self.popover
    }

    /// Toggle a header popover: open `kind` if a different (or no) popover is
    /// open, or close it if it is already the open one.
    pub fn toggle_popover(&mut self, kind: Popover) {
        self.popover = if self.popover == kind {
            Popover::None
        } else {
            kind
        };
    }

    /// Close any open header popover.
    pub fn close_popover(&mut self) {
        self.popover = Popover::None;
    }

    /// The current allow-list add-field draft text.
    #[must_use]
    pub fn allow_draft(&self) -> &str {
        &self.allow_draft
    }

    /// Append typed text to the allow-list draft (a single grapheme from a
    /// keystroke's `key_char`).
    pub fn push_allow_text(&mut self, text: &str) {
        self.allow_draft.push_str(text);
    }

    /// Remove the last character from the allow-list draft (backspace).
    pub fn pop_allow_char(&mut self) {
        self.allow_draft.pop();
    }

    /// Clear the allow-list draft (after a successful add, or on close).
    pub fn clear_allow_draft(&mut self) {
        self.allow_draft.clear();
    }

    /// The current block-list add-field draft text.
    #[must_use]
    pub fn block_draft(&self) -> &str {
        &self.block_draft
    }

    /// Append typed text to the block-list draft.
    pub fn push_block_text(&mut self, text: &str) {
        self.block_draft.push_str(text);
    }

    /// Remove the last character from the block-list draft (backspace).
    pub fn pop_block_char(&mut self) {
        self.block_draft.pop();
    }

    /// Clear the block-list draft (after a successful add).
    pub fn clear_block_draft(&mut self) {
        self.block_draft.clear();
    }

    /// Which Rules-view add-field currently receives typed keys.
    #[must_use]
    pub fn settings_field(&self) -> SettingsField {
        self.settings_field
    }

    /// Focus a Rules-view add-field (so typed keys route to it).
    pub fn set_settings_field(&mut self, field: SettingsField) {
        self.settings_field = field;
    }

    /// Whether a group row is expanded to show its description.
    #[must_use]
    pub fn is_group_expanded(&self, group: &str) -> bool {
        self.expanded_groups.contains(group)
    }

    /// Toggle a group row's description disclosure.
    pub fn toggle_group_expanded(&mut self, group: &str) {
        if !self.expanded_groups.remove(group) {
            self.expanded_groups.insert(group.to_string());
        }
    }

    /// The session's globally-blocked domains (client-side; the daemon has no
    /// profile field to echo these, so the panel tracks them locally).
    #[must_use]
    pub fn blocked_domains(&self) -> &[String] {
        &self.blocked_domains
    }

    /// Record a globally-blocked domain (idempotent — no duplicates).
    pub fn add_blocked_domain(&mut self, host: String) {
        if !self.blocked_domains.iter().any(|d| d == &host) {
            self.blocked_domains.push(host);
        }
    }

    /// Drop a globally-blocked domain from the local list.
    pub fn remove_blocked_domain(&mut self, host: &str) {
        self.blocked_domains.retain(|d| d != host);
    }

    /// The last block-list add error, if any (e.g. a domain the daemon rejected).
    #[must_use]
    pub fn block_error(&self) -> Option<&str> {
        self.block_error.as_deref()
    }

    /// Set an inline block-list add error.
    pub fn set_block_error(&mut self, message: String) {
        self.block_error = Some(message);
    }

    /// Clear the inline block-list add error.
    pub fn clear_block_error(&mut self) {
        self.block_error = None;
    }

    /// Drop every local block/unblock override so the daemon's fresh snapshot
    /// verdicts show through cleanly. Called on a global mode flip, where every
    /// row's verdict is recomputed daemon-side and a stale local override would
    /// otherwise mask it.
    pub fn clear_local_allows(&mut self) {
        self.app_allow.clear();
        self.domain_allow.clear();
    }

    /// The current search/filter query (the ⌘F field). Empty means no filter.
    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Whether the filter field is focused (caret shown, printable keys append).
    #[must_use]
    pub fn filter_active(&self) -> bool {
        self.filter_active
    }

    /// Focus or blur the filter field (blurring keeps the query, hides caret).
    pub fn set_filter_active(&mut self, active: bool) {
        self.filter_active = active;
    }

    /// Append typed text to the filter query (a single grapheme per keystroke).
    pub fn push_filter_text(&mut self, text: &str) {
        self.filter.push_str(text);
    }

    /// Remove the last character from the filter query (backspace).
    pub fn pop_filter_char(&mut self) {
        self.filter.pop();
    }

    /// Clear the filter query without changing focus.
    pub fn clear_filter(&mut self) {
        self.filter.clear();
    }

    /// Set the filter query outright (used by the debug env hook).
    pub fn set_filter(&mut self, query: String) {
        self.filter = query;
    }

    /// Whether the "macOS System" group at the top of the Apps list is expanded
    /// to reveal its member Apple daemons. Collapsed by default so the user sees
    /// their real apps first.
    #[must_use]
    pub fn system_expanded(&self) -> bool {
        self.system_expanded
    }

    /// Toggle the "macOS System" group disclosure.
    pub fn toggle_system_expanded(&mut self) {
        self.system_expanded = !self.system_expanded;
    }

    /// Sort process rows in place by the active key, descending.
    pub fn sort_procs(&self, procs: &mut [ProcRow]) {
        match self.sort {
            Sort::Cpu => procs.sort_by(|a, b| {
                b.cpu
                    .partial_cmp(&a.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Sort::Mem => procs.sort_by(|a, b| b.mem_bytes.cmp(&a.mem_bytes)),
            Sort::Net => procs.sort_by(|a, b| b.net_bps.cmp(&a.net_bps)),
        }
    }

    /// Sort process groups in place by the active key, descending. Under the
    /// Net key with no live traffic, ties break on accumulated bytes so the
    /// Session scope still ranks the heaviest talkers first.
    pub fn sort_groups(&self, groups: &mut [ProcGroup]) {
        match self.sort {
            Sort::Cpu => groups.sort_by(|a, b| {
                b.cpu
                    .partial_cmp(&a.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Sort::Mem => groups.sort_by(|a, b| b.mem_bytes.cmp(&a.mem_bytes)),
            Sort::Net => groups.sort_by(|a, b| {
                b.net_bps
                    .cmp(&a.net_bps)
                    .then(b.net_bytes.cmp(&a.net_bytes))
            }),
        }
    }
}

#[cfg(test)]
#[path = "state_test.rs"]
mod state_test;
