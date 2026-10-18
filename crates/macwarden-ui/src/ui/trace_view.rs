//! The per-app packet-trace view (R11) — a dedicated, Proxyman-style data view:
//! a wide columnar packet list ([`super::trace_list`]) over a side-by-side
//! decode-tree + hex detail pane ([`super::trace_detail`]), with protocol filter
//! tabs and a capture footer.
//!
//! The view is a pushed full-panel [`crate::state::Route::Trace`]. Unlike the
//! rest of the panel it drops the shared titlebar / tabs / scope / search chrome
//! entirely: its header is only the traced-app name, a live capture indicator,
//! and a close control. Entering it widens the window to the data canvas (see
//! [`super::panel::Panel::sync_window_size`]) and starts a dedicated streaming
//! [`TraceSession`] (see [`crate::data::trace`]); closing it (the ✕) drops the
//! session — which stops the capture — and restores the compact window.
//! Rendering only ever reads the pure [`TraceModel`]; the packet stream is
//! drained into it on the panel tick, and packet-byte fetches run off the render
//! thread — so a busy trace never blocks the UI.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    App, Context, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};

use ipc::protocol::WireTraceSource;

use super::detail::back_chevron;
use super::panel::Panel;
use super::theme::{
    FONT_CAPTION, FONT_MICRO, INSPECTOR_PANE_WIDTH, Palette, RADIUS, RADIUS_XS, SPACE_LG, SPACE_SM,
    palette,
};
use super::widgets::{Seg, footer_divider, segmented};
use crate::data::trace::{TraceQuery, TraceSession};
use crate::data::trace_model::{ProtoFilter, TraceModel};
use crate::state::Route;

/// The one-line disclosure banner for a non-live trace source, or `None` when the
/// source is real live capture. Pure, so the honesty mapping is unit-tested —
/// synthetic data must never read as real.
#[must_use]
pub(super) fn demo_disclosure(source: WireTraceSource) -> Option<&'static str> {
    match source {
        WireTraceSource::Live => None,
        WireTraceSource::DemoNoAccess => Some(
            "Demo stream — synthetic packets, not real traffic. The daemon can't open a capture \
             device; add your user to the access_bpf group (or run it as root) for live capture.",
        ),
        WireTraceSource::DemoNoCapture => Some(
            "Demo stream — synthetic packets, not real traffic. Live capture isn't built into \
             this daemon.",
        ),
        WireTraceSource::Unknown => {
            Some("Demo stream — synthetic packets, not real traffic (capture source unknown).")
        }
    }
}

/// How many packets to pull off the stream per drain (a full tick's worth).
const DRAIN_BUDGET: usize = 4096;

/// The active trace view aggregate held by the [`Panel`]: the streaming session
/// (`None` once stopped), a cloneable off-thread query handle, and the pure
/// view-model.
pub(crate) struct TraceView {
    /// The live capture session; `None` after Stop (the list stays visible).
    pub session: Option<TraceSession>,
    /// Cloneable handle for off-thread `GetPacketBytes` fetches.
    pub query: TraceQuery,
    /// The pure list/filter/selection state.
    pub model: TraceModel,
    /// The daemon-reported packet source (live vs. demo). Last-known value,
    /// refreshed from the session each drain so it survives Stop; drives the
    /// honest capture badge and the demo disclosure banner.
    pub source: WireTraceSource,
}

impl TraceView {
    /// Whether the capture is still running.
    pub(super) fn capturing(&self) -> bool {
        self.session.is_some()
    }

    /// Whether this trace is backed by real live capture (not the demo stream).
    pub(super) fn is_live(&self) -> bool {
        self.source.is_live()
    }
}

impl Panel {
    /// Start a trace for `app_id` and push its view. A no-op when the active
    /// source cannot capture (no [`crate::data::source::TraceBackend`]). The app's
    /// identity is shown by the inspector pane on the left of the split, so no
    /// display name is needed here.
    pub(super) fn enter_trace(&mut self, app_id: String, cx: &mut Context<Self>) {
        let Some(backend) = self.source.trace_backend() else {
            return;
        };
        let Some(session) = backend.start_trace(&app_id) else {
            return;
        };
        let query = session.query();
        let source = session.source();
        self.trace = Some(TraceView {
            session: Some(session),
            query,
            model: TraceModel::new(),
            source,
        });
        self.state.push(Route::Trace(app_id));
        // Prime the list with any packets already buffered by the capture so the
        // first frame is not empty; the tick keeps draining thereafter.
        self.drain_trace(cx);
        cx.notify();
    }

    /// Close the trace view: drop the session (sends `StopTrace`), pop the route,
    /// and let the next render restore the compact window.
    fn close_trace(&mut self, cx: &mut Context<Self>) {
        self.trace = None;
        self.state.pop();
        cx.notify();
    }

    /// Drain newly-streamed packets into the model (called on the panel tick).
    pub(super) fn drain_trace(&mut self, cx: &mut Context<Self>) {
        let Some(tv) = self.trace.as_mut() else {
            return;
        };
        let Some(session) = tv.session.as_ref() else {
            return;
        };
        // Refresh the reported source: it starts `Unknown` and resolves once the
        // daemon's `TraceStarted` ack lands (typically the first frame), so the
        // badge/banner flip to the truth as soon as it is known.
        let source = session.source();
        let recs = session.drain(DRAIN_BUDGET);
        let has_recs = !recs.is_empty();
        let changed = source != tv.source;
        tv.source = source;
        if has_recs {
            tv.model.extend(recs);
        }
        if changed || has_recs {
            cx.notify();
        }
    }

    /// Select a packet and fetch its bytes + decode tree off the render thread
    /// (R8), storing the result in the model on reply.
    pub(super) fn select_packet(&mut self, seq: u64, cx: &mut Context<Self>) {
        let Some(tv) = self.trace.as_mut() else {
            return;
        };
        tv.model.select(seq);
        let query = tv.query.clone();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let bytes = cx
                .background_executor()
                .spawn(async move { query.get_packet_bytes(seq) })
                .await;
            let _ = this.update(cx, |panel, cx| {
                if let Some(tv) = panel.trace.as_mut()
                    && tv.model.selected() == Some(seq)
                {
                    // Always reach a terminal state: `Some` fills the pane, `None`
                    // (worker gone / timed out) marks the fetch failed so it never
                    // hangs on "Loading packet…".
                    match bytes {
                        Some(bytes) => tv.model.set_bytes(bytes),
                        None => tv.model.fail_bytes(),
                    }
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Stop the capture (Stop control) — drops the session (sends `StopTrace`),
    /// keeping the streamed list on screen.
    fn stop_trace(&mut self, cx: &mut Context<Self>) {
        if let Some(tv) = self.trace.as_mut() {
            tv.session = None;
        }
        cx.notify();
    }

    /// Clear the client-side list without stopping capture (Clear control).
    fn clear_trace(&mut self, cx: &mut Context<Self>) {
        if let Some(tv) = self.trace.as_mut() {
            tv.model.clear();
        }
        cx.notify();
    }

    /// Render the master-detail split: the app inspector on the left (context)
    /// and the trace beside it on the right (flex-filling). Fills the widened
    /// window.
    pub(super) fn render_trace_split(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_row()
            .child(self.render_trace_inspector_pane(cx))
            .child(self.render_trace(cx))
    }

    /// The left pane: the app inspector for context, reusing the same header +
    /// scrollable body the compact inspector shows, at a fixed width with a
    /// hairline divider on its right edge. A slim strip above it carries the back
    /// chevron, which exits the whole inspector (dropping the trace) back to the
    /// app list.
    fn render_trace_inspector_pane(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let on_back = cx.listener(|panel, _ev, _win, cx| {
            // The left chevron leaves the inspector entirely: drop the trace
            // (stops the capture) and unwind the whole nav stack to the list.
            panel.trace = None;
            while panel.state.in_detail() {
                panel.state.pop();
            }
            cx.notify();
        });
        div()
            .flex_shrink_0()
            .w(INSPECTOR_PANE_WIDTH)
            .flex()
            .flex_col()
            .border_r_1()
            .border_color(p.hairline)
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .h(px(36.0))
                    .px(px(8.0))
                    .child(back_chevron(p, on_back)),
            )
            .child(self.render_detail_header(cx))
            .child(self.render_detail_body(cx))
    }

    /// Render the trace itself (the right pane of the split): the slim header, the
    /// protocol filter tabs, the columnar packet list, the decode/hex detail, the
    /// Tier-1 note, and the capture footer.
    pub(super) fn render_trace(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let disclosure = self
            .trace
            .as_ref()
            .and_then(|tv| demo_disclosure(tv.source));
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .child(self.render_trace_header(cx))
            .children(disclosure.map(|text| demo_banner(p, text)))
            .child(self.render_trace_filters(cx))
            .child(super::trace_list::column_header(p))
            .child(self.render_trace_list(cx))
            .children(self.render_trace_detail(cx))
            .child(tier1_note(p))
            .child(self.render_trace_footer(cx))
    }

    /// The slim trace header. The traced app's identity lives in the left pane, so
    /// this drops the redundant `Trace: <app>` title — just a subtle `PACKETS`
    /// label, the live capture indicator, and the ✕ that closes the trace back to
    /// the compact inspector.
    fn render_trace_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let capturing = self.trace.as_ref().is_some_and(TraceView::capturing);
        let live = self.trace.as_ref().is_some_and(TraceView::is_live);
        let on_close = cx.listener(|panel, _ev, _win, cx| panel.close_trace(cx));
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(10.0))
            .px(SPACE_LG)
            .h(px(36.0))
            .border_b_1()
            .border_color(p.hairline)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_faint)
                    .child("PACKETS"),
            )
            .child(capture_indicator(p, capturing, live))
            .child(close_control(p, on_close))
    }

    /// The protocol filter tab row (stays — these belong to the trace).
    fn render_trace_filters(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let active = self
            .trace
            .as_ref()
            .map_or(ProtoFilter::All, |tv| tv.model.filter());
        let view = cx.entity();
        let on_select = move |f: ProtoFilter, _win: &mut Window, cx: &mut App| {
            view.update(cx, |panel, cx| {
                if let Some(tv) = panel.trace.as_mut() {
                    tv.model.set_filter(f);
                    cx.notify();
                }
            });
        };
        let segments = ProtoFilter::all()
            .into_iter()
            .map(|f| Seg {
                value: f,
                label: f.label().into(),
            })
            .collect();
        div()
            .px(SPACE_LG)
            .py(SPACE_SM)
            .border_b_1()
            .border_color(p.hairline)
            .child(segmented(p, "trace-filter", segments, active, on_select))
    }

    /// The footer: packet/drop counts and the Clear / Stop controls, spanning the
    /// wider width.
    fn render_trace_footer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let (retained, total, dropped, capturing) =
            self.trace.as_ref().map_or((0, 0, 0, false), |tv| {
                (
                    tv.model.retained(),
                    tv.model.total(),
                    tv.model.dropped(),
                    tv.capturing(),
                )
            });
        div()
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .px(SPACE_LG)
            .h(px(30.0))
            .border_t_1()
            .border_color(p.hairline)
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(8.0))
                    .child(footer_stat(p, "shown", retained.to_string()))
                    .child(footer_divider(p))
                    .child(footer_stat(p, "total", total.to_string()))
                    .child(footer_divider(p))
                    .child(footer_stat(p, "dropped", dropped.to_string())),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .child(footer_button(p, "trace-clear", "Clear", true, {
                        let view = cx.entity();
                        move |_ev, _win, cx: &mut App| {
                            view.update(cx, Panel::clear_trace);
                        }
                    }))
                    .child(footer_button(p, "trace-stop", "Stop", capturing, {
                        let view = cx.entity();
                        move |_ev, _win, cx: &mut App| {
                            view.update(cx, Panel::stop_trace);
                        }
                    })),
            )
    }
}

/// The capture-state indicator, **honest** about the source: a green "● Live
/// capture" only for real BPF capture; an amber "● Demo stream" for the synthetic
/// source (never green — color carries meaning); gray "Stopped" once stopped.
fn capture_indicator(p: Palette, capturing: bool, live: bool) -> impl IntoElement {
    let (color, label) = if !live {
        // Synthetic source: amber, never the green "capturing" of real traffic.
        (p.amber, "Demo stream")
    } else if capturing {
        (p.accent, "Live capture")
    } else {
        (p.text_faint, "Stopped")
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(5.0))
        .flex_shrink_0()
        .child(div().w(px(7.0)).h(px(7.0)).rounded(px(4.0)).bg(color))
        .child(div().text_size(FONT_CAPTION).text_color(color).child(label))
}

/// The amber demo-disclosure banner shown across the top of a synthetic trace, so
/// the fabricated stream is unmistakably labeled — never presentable as real.
fn demo_banner(p: Palette, text: &'static str) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .px(SPACE_LG)
        .py(SPACE_SM)
        .border_b_1()
        .border_color(p.hairline)
        .bg(p.amber.opacity(0.10))
        .text_size(FONT_MICRO)
        .text_color(p.amber)
        .child(text)
}

/// The header close control — an ✕ that drops the session and restores the panel.
fn close_control(
    p: Palette,
    on_close: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id("trace-close")
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .w(px(24.0))
        .h(px(24.0))
        .rounded(RADIUS)
        .cursor_pointer()
        .text_size(px(15.0))
        .text_color(p.text_dim)
        .hover(|s| s.bg(p.hover).text_color(p.text))
        .on_click(on_close)
        .child("✕")
}

/// The persistent Tier-1 honesty note (R1): HTTPS bodies stay encrypted.
fn tier1_note(p: Palette) -> impl IntoElement {
    div()
        .px(SPACE_LG)
        .py(SPACE_SM)
        .border_t_1()
        .border_color(p.hairline)
        .text_size(px(9.0))
        .text_color(p.text_faint)
        .child("Tier 1 · TLS handshake + headers only. HTTPS bodies stay encrypted (decryption is a separate mode).")
}

/// One footer stat cell: dim label + tabular value.
fn footer_stat(p: Palette, label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .child(
            div()
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(label),
        )
        .child(
            div()
                .font_family("ui-monospace")
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .child(value),
        )
}

/// A small bordered footer control (Clear / Stop).
fn footer_button(
    p: Palette,
    id: &'static str,
    label: &'static str,
    enabled: bool,
    handler: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let text = if enabled { p.text } else { p.text_faint };
    div()
        .id(id)
        .flex()
        .items_center()
        .justify_center()
        .px(px(9.0))
        .h(px(20.0))
        .rounded(RADIUS_XS)
        .bg(p.surface.opacity(0.6))
        .border_1()
        .border_color(p.hairline)
        .text_size(FONT_CAPTION)
        .text_color(text)
        .when(enabled, |el| {
            el.cursor_pointer()
                .hover(|s| s.border_color(p.text_faint))
                .on_click(handler)
        })
        .child(label)
}

#[cfg(test)]
#[path = "trace_view_test.rs"]
mod trace_view_test;
