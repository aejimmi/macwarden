//! The root `Panel` entity: owns the view-model state, the active source, and
//! the ~1 Hz refresh tick. Renders the header/tab-body/footer chrome and
//! branches into the inspector when a route is pushed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{
    App, AppContext as _, Application, Bounds, Context, FocusHandle, FontWeight, IntoElement,
    KeyBinding, Menu, MenuItem, ParentElement as _, Render, RenderImage, Styled as _, Task,
    TitlebarOptions, Window, WindowBackgroundAppearance, WindowBounds, WindowOptions, div, point,
    px, size,
};
use ipc::protocol::WireProfile;

// The app-level Quit action, bound to ⌘Q and exposed in the macOS menu bar and
// the panel's `⋯` menu. Its handler calls [`gpui::App::quit`] so the process
// actually exits (the header ✕ only hides the window — a firewall keeps running).
gpui::actions!(macwarden, [Quit]);

use super::detail::back_chevron;
use super::icons::IconCache;
use super::theme::{
    self, FONT_BODY, Palette, WINDOW_HEIGHT, WINDOW_HEIGHT_SPLIT, WINDOW_WIDTH, WINDOW_WIDTH_SPLIT,
    palette,
};
use crate::data::demo::DemoSource;
use crate::data::model::Detail;
use crate::data::openbinary::ObCache;
use crate::data::source::{DaemonRetry, PanelSource};
use crate::data::sweep::Sweep;
use crate::state::{PanelState, Route};

/// How often the sweep re-scans for newly launched binaries.
const RESWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How often the panel retries the daemon while on the read-only fallback source
/// (see [`Panel::maybe_reconnect_daemon`]). Modest so the render thread's brief
/// connect attempt is negligible, quick enough that a daemon coming up after
/// launch is adopted within seconds.
const DAEMON_RETRY_INTERVAL: Duration = Duration::from_secs(8);

/// The single top-level view.
pub struct Panel {
    pub(super) state: PanelState,
    pub(super) source: Box<dyn PanelSource>,
    /// Factory that attempts a fresh daemon connection while the panel is on the
    /// read-only fallback source. `None` in demo mode / when there is nothing to
    /// upgrade to. Cleared once the daemon source is adopted (it self-heals).
    daemon_retry: Option<DaemonRetry>,
    /// When the last background daemon-reconnect attempt ran, throttling retries
    /// to [`DAEMON_RETRY_INTERVAL`].
    last_daemon_retry: Instant,
    pub(super) icons: IconCache,
    pub(super) ob: ObCache,
    pub(super) sweep: Sweep,
    /// The inspector detail for [`Self::detail_route`], resolved off the render
    /// thread. `None` while the first fetch for a route is still in flight.
    pub(super) detail: Option<Detail>,
    /// Which route [`Self::detail`] belongs to; guards stale fetch results and
    /// distinguishes a fresh open (show a placeholder) from a refresh tick
    /// (keep the current content).
    pub(super) detail_route: Option<Route>,
    /// Whether a fresh fetch is in flight with nothing cached yet to show.
    pub(super) detail_loading: bool,
    /// Set when the daemon's detail fetch failed/timed out but a row-derived seed
    /// is on screen, so the inspector can show a subtle "details unavailable" note
    /// instead of a blank enrichment.
    pub(super) detail_unavailable: bool,
    /// Whether the current [`Self::detail`] came from the daemon (a full detail)
    /// rather than a row-derived seed. Guards the "details unavailable" note from
    /// flipping on a transient refresh failure after a good detail landed.
    detail_from_daemon: bool,
    /// Whether a detail fetch is currently running. The refresh tick skips
    /// re-fetching while one is in flight, so it never cancels a slow query
    /// (the daemon round-trip can outlast the 1 s tick) mid-flight.
    detail_in_flight: bool,
    last_sweep: Instant,
    /// The daemon's current policy profile (R8), cached for the header controls.
    /// `None` until the first `GetProfile` lands (or when the source has no
    /// policy backend). Mutations apply optimistically here, then reconcile
    /// against the echoed `ProfileAck`.
    pub(super) profile: Option<WireProfile>,
    /// Whether the active source exposes a policy backend (daemon with the
    /// `Policy` capability). Gates the header mode / allow-list controls.
    pub(super) policy_available: bool,
    /// Whether a profile fetch is currently in flight, so the tick retry never
    /// cancels one mid-flight (see [`Self::maybe_load_profile`]).
    pub(super) profile_loading: bool,
    /// Focus target for the open popover overlay, so it can receive Esc.
    pub(super) policy_focus: FocusHandle,
    /// Focus target for the pushed Rules & Settings view, so it can receive Esc
    /// (back out) and typed characters for the allow-list / block-list fields.
    pub(super) rules_focus: FocusHandle,
    /// Focus target for the tab-view filter field (⌘F). Held by the tab-body
    /// container so ⌘F and typed characters reach [`Self::on_filter_key`] from
    /// anywhere in the list.
    pub(super) filter_focus: FocusHandle,
    /// The active packet-trace view (R11): the streaming session, its off-thread
    /// query handle, and the pure view-model. `Some` only while a
    /// [`Route::Trace`] is pushed; dropping it stops the capture session.
    pub(super) trace: Option<super::trace_view::TraceView>,
    /// Whether the window is currently grown to the wide trace-data canvas.
    /// Tracks the resize transition so [`Self::sync_window_size`] only resizes on
    /// enter/exit of the trace route, never fighting a manual drag-resize.
    trace_wide: bool,
    /// The last snapshot content version the panel rendered (R8 idle skip). The
    /// refresh tick compares [`crate::data::source::PanelSource::content_version`]
    /// against this and, at the tab root with no active sweep, skips `cx.notify()`
    /// when the snapshot is byte-for-byte unchanged — so a quiet firewall does no
    /// per-second window layout+paint. `None` until the first tick.
    last_content_version: Option<u64>,
    /// The source's `is_live()` at the last render (R8). The refresh tick forces
    /// a repaint when this flips so the header stops claiming live/enforcing the
    /// moment a daemon goes stale — a dead daemon publishes no new snapshot, so
    /// the content version alone would never trigger the degrade repaint. `None`
    /// until the first tick.
    last_live: Option<bool>,
    _tick: Task<()>,
    /// The current detail fetch. A fresh navigation replaces it — cancelling any
    /// stale fetch for the previous route — while refreshes wait for it to land.
    _detail_task: Task<()>,
    /// The current profile read/mutation task (R8). A newer policy action
    /// replaces it.
    pub(super) _policy_task: Task<()>,
}

impl Panel {
    /// Build the panel with the given source and start the refresh tick. The
    /// optional `daemon_retry` lets the panel upgrade off a read-only fallback to
    /// the daemon source once the daemon becomes reachable.
    pub fn new(
        cx: &mut Context<Self>,
        source: Box<dyn PanelSource>,
        daemon_retry: Option<DaemonRetry>,
    ) -> Self {
        // The user-configurable refresh cadence (persisted). The tick re-reads it
        // each cycle so a settings change applies within one interval.
        let refresh_rate = crate::data::prefs::load_refresh_rate();
        let tick = cx.spawn(async move |this, cx| {
            let mut interval = refresh_rate.interval();
            loop {
                cx.background_executor().timer(interval).await;
                let next = this.update(cx, |panel, cx| {
                    panel.source.tick();
                    panel.maybe_reconnect_daemon(cx);
                    panel.maybe_resweep();
                    panel.maybe_load_profile(cx);
                    panel.refresh_detail(cx);
                    panel.drain_trace(cx);
                    // Repaint only when the tick changed something visible.
                    // Async landings (detail/profile/trace/rule) self-notify,
                    // so the tick's own notify exists purely to advance live
                    // counters — skip it when the snapshot is unchanged.
                    if panel.tick_should_notify() {
                        cx.notify();
                    }
                    panel.state.refresh_rate().interval()
                });
                match next {
                    Ok(iv) => interval = iv,
                    Err(_) => break,
                }
            }
        });
        let mut state = PanelState::default();
        apply_debug_env(&mut state);
        state.set_refresh_rate(refresh_rate);
        let ob = ObCache::load();
        let sweep = Sweep::start(ob.clone());
        sweep.submit(source.binary_paths());
        let policy_available = source.policy_backend().is_some();
        let mut panel = Self {
            state,
            source,
            daemon_retry,
            last_daemon_retry: Instant::now(),
            icons: IconCache::new(),
            ob,
            sweep,
            detail: None,
            detail_route: None,
            detail_loading: false,
            detail_unavailable: false,
            detail_from_daemon: false,
            detail_in_flight: false,
            last_sweep: Instant::now(),
            profile: None,
            policy_available,
            profile_loading: false,
            policy_focus: cx.focus_handle(),
            rules_focus: cx.focus_handle(),
            filter_focus: cx.focus_handle(),
            trace: None,
            trace_wide: false,
            last_content_version: None,
            last_live: None,
            _tick: tick,
            _detail_task: Task::ready(()),
            _policy_task: Task::ready(()),
        };
        panel.load_profile(cx);
        panel.apply_trace_debug_env(cx);
        panel
    }

    /// Open a trace view directly from the environment, for deterministic
    /// screenshots without synthetic input: `MACWARDEN_UI_TRACE=<app_id>` enters
    /// the trace, and `MACWARDEN_UI_TRACE_SELECT` (any value) auto-selects the
    /// first streamed packet a few seconds in so the decode/hex pane populates.
    fn apply_trace_debug_env(&mut self, cx: &mut Context<Self>) {
        let Ok(app_id) = std::env::var("MACWARDEN_UI_TRACE") else {
            return;
        };
        if app_id.is_empty() {
            return;
        }
        // Open the app inspector first so the split's left pane is populated, and
        // resolve its detail synchronously here — the refresh tick may not pump
        // while the screen is locked during a screenshot capture.
        let app_route = Route::App(app_id.clone());
        self.state.push(app_route.clone());
        if let Some(detail) = self.resolve_detail(&app_route) {
            self.detail = Some(detail);
            self.detail_route = Some(app_route);
            self.detail_loading = false;
        }
        self.enter_trace(app_id, cx);
        if std::env::var_os("MACWARDEN_UI_TRACE_SELECT").is_none() {
            return;
        }
        // Debug hook: synchronously select the first primed packet and fetch its
        // bytes so the decode/hex detail pane is populated for a screenshot
        // without depending on the async fetch task. Only ever runs under the env
        // var, so it never blocks in normal operation.
        if let Some(tv) = self.trace.as_mut()
            && let Some(seq) = tv.model.first_seq()
        {
            tv.model.select(seq);
            if let Some(bytes) = tv.query.get_packet_bytes(seq) {
                tv.model.set_bytes(bytes);
            }
            cx.notify();
        }
    }

    /// Whether the refresh tick should repaint. Always repaints while a pushed
    /// view (inspector / trace / settings) or an active identification sweep is
    /// on screen — those have their own live streams. At the tab root it repaints
    /// only when the source reports a changed [`content_version`], so an idle
    /// panel does zero per-second layout+paint. Sources that can't report change
    /// (`content_version` is `None`, e.g. demo / `nettop` live) always repaint.
    ///
    /// [`content_version`]: crate::data::source::PanelSource::content_version
    fn tick_should_notify(&mut self) -> bool {
        let version = self.source.content_version();
        // A daemon going stale (or a recovered daemon coming back live) changes
        // no snapshot bytes, so force a repaint on the liveness transition — that
        // is what flips the header off "live/enforcing" and onto the stale
        // affordance (and back).
        let live = self.source.is_live();
        let live_changed = self.last_live != Some(live);
        let pinned = self.state.in_detail() || self.sweep.progress().is_some();
        let notify = should_notify(version, self.last_content_version, pinned || live_changed);
        self.last_content_version = version;
        self.last_live = Some(live);
        notify
    }

    /// Apply and persist a new refresh cadence from the settings control. The
    /// running tick picks it up on its next cycle (it re-reads the rate each
    /// iteration), so no task restart is needed.
    pub(super) fn set_refresh_rate(
        &mut self,
        rate: crate::state::RefreshRate,
        cx: &mut Context<Self>,
    ) {
        self.state.set_refresh_rate(rate);
        crate::data::prefs::save_refresh_rate(rate);
        cx.notify();
    }

    /// Push an inspector route and kick off its off-thread detail fetch. The
    /// single entry point for opening the inspector — every row-body click
    /// routes through here so the fetch never runs on the render thread.
    pub(super) fn navigate(&mut self, route: Route, cx: &mut Context<Self>) {
        self.state.push(route.clone());
        self.load_detail(route, cx);
        cx.notify();
    }

    /// Re-fetch the current route's detail on the refresh tick so live byte
    /// counters keep moving while the inspector is open. Skipped while a fetch is
    /// already in flight (so a slow query is never cancelled) and at the tab root.
    /// While a [`Route::Trace`] is open the inspector still shows on the left of
    /// the split, so the trace route is refreshed as its underlying app inspector
    /// to keep that pane live.
    fn refresh_detail(&mut self, cx: &mut Context<Self>) {
        if self.detail_in_flight {
            return;
        }
        if let Some(route) = self.state.current_route().cloned() {
            let route = match route {
                Route::Trace(id) => Route::App(id),
                other => other,
            };
            self.load_detail(route, cx);
        }
    }

    /// Resolve `route` to a [`Detail`] and cache it, off the render thread.
    ///
    /// A *fresh* open (the route differs from [`Self::detail_route`]) clears the
    /// stale content and flips `detail_loading` so the inspector shows a
    /// placeholder; a refresh for the same route keeps the current content until
    /// the new result lands. The blocking resolution runs on the background
    /// executor when the source exposes a [`crate::data::source::DetailBackend`]
    /// (the daemon), and inline on the fetch task otherwise (demo / `nettop`
    /// live, whose detail calls are cheap clones). The result is dropped if the
    /// user has since navigated away.
    fn load_detail(&mut self, route: Route, cx: &mut Context<Self>) {
        // Settings and Trace are UI-only views with no async detail to fetch.
        if matches!(route, Route::Settings | Route::Trace(_)) {
            return;
        }
        if self.detail_route.as_ref() != Some(&route) {
            // Seed instantly from the snapshot row the panel already has, so the
            // inspector renders name/icon/bytes/domains this frame instead of a
            // blank page; the daemon's fuller detail merges in when it lands.
            let seed = self.seed_detail(&route);
            self.detail_loading = seed.is_none();
            self.detail = seed;
            self.detail_unavailable = false;
            self.detail_from_daemon = false;
            self.detail_route = Some(route.clone());
        }
        self.detail_in_flight = true;
        let backend = self.source.detail_backend();
        self._detail_task = cx.spawn(async move |this, cx| {
            let resolved = match backend {
                Some(backend) => {
                    let route = route.clone();
                    cx.background_executor()
                        .spawn(async move { backend.detail(&route) })
                        .await
                }
                None => this
                    .update(cx, |panel, _| panel.resolve_detail(&route))
                    .ok()
                    .flatten(),
            };
            let _ = this.update(cx, |panel, cx| {
                // Ignore a result for a route the user has since navigated away
                // from: the newer fetch owns `detail_in_flight` and the cache.
                if panel.detail_route.as_ref() == Some(&route) {
                    panel.merge_detail(resolved);
                    panel.detail_in_flight = false;
                    cx.notify();
                }
            });
        });
    }

    /// Merge a daemon detail result into the inspector. `Some` replaces the
    /// row-derived seed with the full detail; `None` (fetch failed/timed out)
    /// keeps whatever seed is on screen and flags it so the view can show a
    /// subtle "details unavailable" note rather than blanking.
    fn merge_detail(&mut self, resolved: Option<Detail>) {
        self.detail_loading = false;
        if let Some(detail) = resolved {
            self.detail = Some(detail);
            self.detail_unavailable = false;
            self.detail_from_daemon = true;
        } else {
            // Keep the seed (if any). Only flag "unavailable" when we have a seed
            // on screen and never got a real daemon detail for this route, so a
            // transient refresh failure after a good detail does not falsely flip
            // the note.
            self.detail_unavailable = self.detail.is_some() && !self.detail_from_daemon;
        }
    }

    /// Build a partial [`Detail`] from the snapshot rows the panel already holds,
    /// so a freshly-opened inspector renders immediately (R6 responsiveness).
    fn seed_detail(&self, route: &Route) -> Option<Detail> {
        match route {
            Route::App(id) => self
                .source
                .apps()
                .iter()
                .find(|a| &a.id == id)
                .map(Detail::from_app_row),
            Route::Proc(id) => self
                .source
                .procs()
                .iter()
                .find(|p| &p.id == id)
                .map(Detail::from_proc_row),
            Route::Domain(host) => self
                .source
                .net_rows()
                .iter()
                .find(|r| &r.domain.host == host)
                .map(Detail::from_net_row),
            Route::Settings | Route::Trace(_) => None,
        }
    }

    /// Resolve a route to its [`Detail`] synchronously against the source. Used
    /// for the inline (cheap-source) path of [`Self::load_detail`].
    fn resolve_detail(&self, route: &Route) -> Option<Detail> {
        match route {
            Route::App(id) => self.source.app_detail(id),
            Route::Domain(host) => self.source.domain_detail(host),
            Route::Proc(id) => self.source.proc_detail(id),
            Route::Settings | Route::Trace(_) => None,
        }
    }

    /// Re-submit the current running binaries to the sweep once the re-pass
    /// interval has elapsed, so newly launched processes get swept too.
    fn maybe_resweep(&mut self) {
        if self.last_sweep.elapsed() < RESWEEP_INTERVAL {
            return;
        }
        self.last_sweep = Instant::now();
        self.sweep.submit(self.source.binary_paths());
    }

    /// Periodically retry the daemon and hot-swap to a fresh [`DaemonSource`]
    /// once one handshakes (so a daemon that comes up after launch — or comes
    /// *back* after dying mid-session — is adopted without a restart). A *live*
    /// daemon source self-heals via its own worker reconnect, so this stays out
    /// of the way then; but once that source has gone stale/fallback (R8:
    /// `is_live()` reads false) the panel re-arms and re-adopts, rather than
    /// serving a dead daemon's last snapshot forever. Throttled to
    /// [`DAEMON_RETRY_INTERVAL`]; the attempt itself is a fast connect that
    /// no-ops when the socket is absent.
    fn maybe_reconnect_daemon(&mut self, cx: &mut Context<Self>) {
        if !should_retry_daemon(
            self.daemon_retry.is_some(),
            self.source.name() == "daemon",
            self.source.is_live(),
        ) {
            return;
        }
        if self.last_daemon_retry.elapsed() < DAEMON_RETRY_INTERVAL {
            return;
        }
        self.last_daemon_retry = Instant::now();
        if let Some(retry) = self.daemon_retry.as_mut()
            && let Some(new_source) = retry()
        {
            self.adopt_source(new_source, cx);
        }
    }

    /// Replace the active source (e.g. fallback → daemon) and re-run the
    /// per-source setup: refresh the policy-backend gate, re-submit the sweep, and
    /// reload the profile so the header controls populate from the new source.
    fn adopt_source(&mut self, source: Box<dyn PanelSource>, cx: &mut Context<Self>) {
        self.source = source;
        self.policy_available = self.source.policy_backend().is_some();
        self.profile = None;
        self.profile_loading = false;
        self.last_content_version = None;
        self.last_live = None;
        self.sweep.submit(self.source.binary_paths());
        self.load_profile(cx);
        cx.notify();
    }

    /// Resolve the cached icon for an optional bundle/executable path.
    pub(super) fn icon_for(&self, path: Option<&std::path::Path>) -> Option<Arc<RenderImage>> {
        path.and_then(|p| self.icons.get(p))
    }

    fn chrome(p: Palette) -> gpui::Div {
        div()
            .size_full()
            .flex()
            .flex_col()
            // Solid opaque dark base (no vibrancy). Translucent material looked
            // washed-out over light wallpapers; a solid panel like FireWally reads
            // cleanly on any background and keeps the grayscale chrome / semantic
            // dots at full contrast.
            .bg(p.bg)
            .text_color(p.text)
            .font_family(".SystemUIFont")
            .text_size(FONT_BODY)
    }

    /// Custom drag-region title strip: our own close button top-left (the native
    /// traffic lights are moved off-screen in [`open`]), the centred wordmark, and
    /// the `⋯` app menu on the right edge. The close cluster and the menu cluster
    /// are equal fixed widths so the wordmark stays optically centred. The strip
    /// still drives the window drag.
    fn render_titlebar(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = palette(cx);
        // No ✕ in the strip: hiding the window ("Hide window") and quitting both
        // live in the ⋯ menu (a firewall keeps running, so close = hide). ⌘Q also
        // quits. The left cluster balances the right `⋯` cluster so the wordmark
        // stays optically centred; while an app/proc inspector is pushed it holds
        // the back chevron (left-aligned) so the detail header's icon can sit flush
        // left. The Settings view keeps its own inline back, so it is excluded.
        let show_back =
            self.state.in_detail() && !matches!(self.state.current_route(), Some(Route::Settings));
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(36.0))
            .px(px(8.0))
            // Transparent: the chrome's translucent base already fills behind the
            // strip, so the vibrancy blur reads at the top edge too. No second
            // opaque layer to darken it.
            .child(Self::render_titlebar_back(p, show_back, cx))
            .child(
                div().flex_1().flex().justify_center().items_center().child(
                    div()
                        .text_size(px(14.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(p.text)
                        .child("macwarden"),
                ),
            )
            // Right cluster: the `⋯` app menu, right-aligned in a box matching
            // the close-button cluster width so the wordmark stays optically
            // centred.
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_end()
                    .w(px(48.0))
                    .child(self.render_menu_glyph(p, cx)),
            )
    }

    /// The titlebar's fixed-width left cluster. Holds the back chevron
    /// (left-aligned) while an app/proc inspector is pushed, otherwise an empty
    /// spacer that balances the right `⋯` cluster so the wordmark stays
    /// optically centred.
    fn render_titlebar_back(p: Palette, show_back: bool, cx: &mut Context<Self>) -> gpui::Div {
        let mut cluster = div().flex().flex_row().items_center().w(px(48.0));
        if show_back {
            let on_back = cx.listener(|panel, _ev, _win, cx| {
                // Leaving a trace drops its session, which stops the capture.
                panel.trace = None;
                panel.state.pop();
                cx.notify();
            });
            cluster = cluster.child(back_chevron(p, on_back));
        }
        cluster
    }

    /// Grow the window to the master-detail split canvas while a packet trace is
    /// open and restore the compact panel size on close. Runs every render but
    /// only calls [`Window::resize`] on a transition, so it never fights a manual
    /// resize. `resize` sets the content size and anchors the window's existing
    /// corner, so the extra width appears to the right — the trace opens beside
    /// the inspector rather than replacing it.
    fn sync_window_size(&mut self, window: &mut Window) {
        let want_wide = matches!(self.state.current_route(), Some(Route::Trace(_)));
        if want_wide == self.trace_wide {
            return;
        }
        self.trace_wide = want_wide;
        let dims = if want_wide {
            size(WINDOW_WIDTH_SPLIT, WINDOW_HEIGHT_SPLIT)
        } else {
            size(WINDOW_WIDTH, WINDOW_HEIGHT)
        };
        window.resize(dims);
    }
}

/// Apply optional debug overrides from the environment so a specific panel
/// state can be captured without synthetic input. No-op unless the vars are set:
/// `MACWARDEN_UI_TAB` (apps|network|processes), `MACWARDEN_UI_SCOPE`
/// (live|session|realtime|hour|today), `MACWARDEN_UI_EXPAND_ALL` (any value),
/// `MACWARDEN_UI_INSPECT` (`proc:<pid>` or `app:<bundle-path>`) to open the
/// inspector directly, `MACWARDEN_UI_POPOVER` (`quick`|`menu`) to open a header
/// popover directly, `MACWARDEN_UI_SETTINGS` (any value) to push the Rules &
/// Settings view directly, `MACWARDEN_UI_FILTER` (any string) to preset the ⌘F
/// filter query so the filtered tree can be captured without synthetic keys,
/// `MACWARDEN_UI_SYSTEM_EXPAND` (any value) to open the "macOS System" group.
fn apply_debug_env(state: &mut PanelState) {
    if let Ok(popover) = std::env::var("MACWARDEN_UI_POPOVER") {
        match popover.to_ascii_lowercase().as_str() {
            "quick" | "mode" => state.toggle_popover(crate::state::Popover::Quick),
            "menu" => state.toggle_popover(crate::state::Popover::Menu),
            _ => {}
        }
    }
    if std::env::var_os("MACWARDEN_UI_SETTINGS").is_some() {
        state.push(crate::state::Route::Settings);
    }
    if let Ok(inspect) = std::env::var("MACWARDEN_UI_INSPECT") {
        if let Some(pid) = inspect.strip_prefix("proc:") {
            state.push(crate::state::Route::Proc(pid.to_string()));
        } else if let Some(path) = inspect.strip_prefix("app:") {
            state.push(crate::state::Route::App(path.to_string()));
        }
    }
    if let Ok(tab) = std::env::var("MACWARDEN_UI_TAB") {
        match tab.to_ascii_lowercase().as_str() {
            "processes" | "procs" => state.set_tab(crate::state::Tab::Processes),
            _ => state.set_tab(crate::state::Tab::Apps),
        }
    }
    if let Ok(scope) = std::env::var("MACWARDEN_UI_SCOPE") {
        match scope.to_ascii_lowercase().as_str() {
            "session" => state.set_scope(crate::state::Scope::Session),
            "hour" => state.set_scope(crate::state::Scope::Hour),
            "today" => state.set_scope(crate::state::Scope::Today),
            _ => state.set_scope(crate::state::Scope::RealTime),
        }
    }
    if std::env::var_os("MACWARDEN_UI_EXPAND_ALL").is_some() {
        state.set_expand_all(true);
    }
    if std::env::var_os("MACWARDEN_UI_SYSTEM_EXPAND").is_some() {
        state.toggle_system_expanded();
    }
    if let Ok(query) = std::env::var("MACWARDEN_UI_FILTER")
        && !query.is_empty()
    {
        state.set_filter(query);
        state.set_filter_active(true);
    }
}

/// Decide whether the refresh tick should repaint. Pure, so the idle-skip policy
/// is unit-testable. `pinned` forces a repaint (a live sub-view — inspector or
/// trace — or an active identification sweep is on screen). Otherwise a repaint
/// happens only when the snapshot `version` differs from `last`; a `None` version
/// (a source that cannot report change, e.g. demo / `nettop` live) always
/// repaints.
fn should_notify(version: Option<u64>, last: Option<u64>, pinned: bool) -> bool {
    pinned || version.is_none() || version != last
}

/// Whether the panel's periodic daemon retry should run this tick (R8). Pure, so
/// the re-arm policy is unit-tested rather than depending on a live socket.
///
/// - No retry factory (`has_retry` false, e.g. demo) → never.
/// - On a *live* daemon source → never: it self-heals via its own worker.
/// - On the fallback source, or on a daemon source that has gone stale/fallback
///   (`live` false) → retry, so a recovered daemon is re-adopted instead of the
///   panel serving a dead daemon's last snapshot indefinitely.
#[must_use]
fn should_retry_daemon(has_retry: bool, on_daemon: bool, live: bool) -> bool {
    has_retry && !(on_daemon && live)
}

#[cfg(test)]
#[path = "panel_test.rs"]
mod panel_test;

impl Render for Panel {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        self.sync_window_size(window);
        if matches!(self.state.current_route(), Some(Route::Trace(_))) {
            // The master-detail split canvas: the app inspector stays on the left
            // as context (its own back chevron exits to the list) and the trace
            // opens beside it on the right. No shared titlebar, tabs, scope, mode
            // pill, or search — each pane draws its own slim header.
            return Self::chrome(p).child(self.render_trace_split(cx));
        }
        if matches!(self.state.current_route(), Some(Route::Settings)) {
            let titlebar = self.render_titlebar(cx);
            return Self::chrome(p)
                .child(titlebar)
                .child(Self::render_rules_header(cx))
                .child(self.render_rules_body(cx))
                .child(self.render_footer(cx));
        }
        if self.state.in_detail() {
            let titlebar = self.render_titlebar(cx);
            return Self::chrome(p)
                .child(titlebar)
                .child(self.render_detail_header(cx))
                .child(self.render_detail_body(cx))
                .child(self.render_footer(cx));
        }
        let titlebar = self.render_titlebar(cx);
        Self::chrome(p)
            .child(titlebar)
            .child(self.render_header(cx))
            .child(self.render_tab_body(window, cx))
            .child(self.render_footer(cx))
            .children(self.render_policy_overlay(cx))
    }
}

/// Open the panel window with the given source. Called from [`super::launch`].
///
/// `daemon_retry` (when `Some`) lets the panel upgrade off a read-only fallback
/// to the daemon source once the daemon becomes reachable.
pub fn open(source: Box<dyn PanelSource>, daemon_retry: Option<DaemonRetry>) {
    let app = Application::new();
    app.run(move |cx: &mut App| {
        theme::init(cx);
        // Global Quit: ⌘Q and the macOS menu bar both exit the process. The panel
        // ⋯ menu drives the same [`Quit`] action.
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.set_menus(vec![Menu {
            name: "macwarden".into(),
            items: vec![MenuItem::action("Quit macwarden", Quit)],
        }]);
        let bounds = Bounds::centered(None, size(WINDOW_WIDTH, WINDOW_HEIGHT), cx);
        let opts = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: None,
                appears_transparent: true,
                // Hide the native traffic lights off-screen — the panel draws its
                // own close button top-left (see `render_titlebar`).
                traffic_light_position: Some(point(px(-120.0), px(-120.0))),
            }),
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_background: WindowBackgroundAppearance::Opaque,
            ..Default::default()
        };
        let mut src = Some(source);
        let mut retry = Some(daemon_retry);
        let window = cx.open_window(opts, |_window, cx| {
            let source = src.take().unwrap_or_else(|| Box::new(DemoSource::new()));
            let daemon_retry = retry.take().flatten();
            cx.new(|cx| Panel::new(cx, source, daemon_retry))
        });
        if let Ok(window) = window {
            cx.activate(true);
            let _ = window.update(cx, |_, window, _| window.activate_window());
        }
        // Add the menu-bar shield so the panel stays reachable after the ✕ hides
        // the window. Main-thread-only; best-effort — a missing marker or a
        // failed install just logs and leaves the panel running.
        if let Some(mtm) = objc2::MainThreadMarker::new() {
            super::statusbar::install(mtm);
        } else {
            tracing::warn!("launch not on main thread; skipping menu-bar status item");
        }
    });
}
