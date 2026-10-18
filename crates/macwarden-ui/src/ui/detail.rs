//! The in-panel inspector. Resolves the pushed [`Route`] to a [`Detail`] and
//! renders a spacious header (left-aligned large icon, name, bundle id, In/Out
//! totals — the back chevron lives in the titlebar), a focal openbinary verdict
//! hero, then the PROCESS / RESOURCES /
//! CONNECTIONS fact cards and the ACTIONS controls.

use std::path::Path;

use ipc::protocol::RuleTarget;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, Context, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _,
    SharedString, StatefulInteractiveElement as _, Styled as _, div, px,
};

use super::detail_ob::{verdict_hero, verdict_hero_static};
use super::detail_sections::{connections_section, process_section, resource_section, section};
use super::panel::Panel;
use super::theme::{
    APP_TILE_LG, FONT_CAPTION, FONT_MICRO, FONT_TITLE, Palette, RADIUS, RADIUS_SM, SPACE_LG,
    palette,
};
use super::widgets::{severity_dot, tile, tip};
use crate::data::model::{Detail, format_bytes};
use crate::data::openbinary::ObTone;
use crate::state::Route;

impl Panel {
    fn is_app_route(&self) -> Option<String> {
        match self.state.current_route()? {
            Route::App(id) => Some(id.clone()),
            _ => None,
        }
    }

    /// Push an app block/unblock to the live policy backend off the render
    /// thread, then reconcile the optimistic toggle. Sources with no live
    /// backend (demo / `nettop` live) keep the local-only override — the toggle
    /// is a preview there — so this returns without touching state. When the
    /// daemon *rejects* the mutation the optimistic flip is reverted.
    pub(super) fn commit_app_rule(&mut self, id: String, allow: bool, cx: &mut Context<Self>) {
        let Some(backend) = self.source.detail_backend() else {
            return;
        };
        let target = RuleTarget::App {
            code_id: id.clone(),
        };
        cx.spawn(async move |this, cx| {
            let applied = cx
                .background_executor()
                .spawn(async move { backend.set_rule(&target, allow) })
                .await;
            if !applied {
                let _ = this.update(cx, |panel, cx| {
                    panel.state.set_app_allow(&id, !allow);
                    cx.notify();
                });
            }
        })
        .detach();
    }

    /// Push a per-app destination block/unblock to the live policy backend off
    /// the render thread, scoped to this app *and* host via
    /// [`RuleTarget::AppDomain`] so it never blocks the destination for every
    /// app. Mirrors [`Self::commit_app_rule`]: optimistic, background, revert on
    /// daemon rejection. A no-op without a live backend (demo / `nettop`).
    pub(super) fn commit_domain_rule(
        &mut self,
        code_id: String,
        host: String,
        allow: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(backend) = self.source.detail_backend() else {
            return;
        };
        let target = RuleTarget::AppDomain {
            code_id,
            host: host.clone(),
        };
        cx.spawn(async move |this, cx| {
            let applied = cx
                .background_executor()
                .spawn(async move { backend.set_rule(&target, allow) })
                .await;
            if !applied {
                let _ = this.update(cx, |panel, cx| {
                    panel.state.set_domain_allow(&host, !allow);
                    cx.notify();
                });
            }
        })
        .detach();
    }

    /// Block or allow every member of a group in one batch mutation (the "macOS
    /// System" aggregate toggle). Optimistically flips each member's local allow
    /// override so the rows read the intent this frame, then sends a single
    /// `SetRules` batch off the render thread; on daemon rejection every member is
    /// reverted to its pre-flip state. A no-op without a live backend.
    pub(super) fn commit_system_group(
        &mut self,
        ids: &[String],
        defaults: &[bool],
        allow: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(backend) = self.source.detail_backend() else {
            return;
        };
        // Capture each member's pre-flip effective state for a clean revert.
        let prev: Vec<bool> = ids
            .iter()
            .zip(defaults)
            .map(|(id, def)| self.state.app_allowed(id, *def))
            .collect();
        for id in ids {
            self.state.set_app_allow(id, allow);
        }
        let changes: Vec<(RuleTarget, bool)> = ids
            .iter()
            .map(|id| {
                (
                    RuleTarget::App {
                        code_id: id.clone(),
                    },
                    allow,
                )
            })
            .collect();
        let ids_owned = ids.to_vec();
        cx.spawn(async move |this, cx| {
            let applied = cx
                .background_executor()
                .spawn(async move { backend.set_rules(&changes) })
                .await;
            if !applied {
                let _ = this.update(cx, |panel, cx| {
                    for (id, was) in ids_owned.iter().zip(prev.iter()) {
                        panel.state.set_app_allow(id, *was);
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    }

    /// The inspector header, replacing the tab header while a route is pushed.
    pub(super) fn render_detail_header(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let detail = self.detail.clone();

        let Some(detail) = detail else {
            let placeholder = if self.detail_loading {
                "Loading…"
            } else {
                "—"
            };
            return div()
                .flex()
                .items_center()
                .gap(px(10.0))
                .px(SPACE_LG)
                .h(px(64.0))
                .border_b_1()
                .border_color(p.hairline)
                .child(div().text_color(p.text_faint).child(placeholder));
        };

        let initial = detail
            .name
            .chars()
            .next()
            .unwrap_or('?')
            .to_ascii_uppercase();
        let icon = self.icon_for(detail.bundle_path.as_deref());
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(12.0))
            .px(SPACE_LG)
            .h(px(72.0))
            .border_b_1()
            .border_color(p.hairline)
            .child(tile(p, icon, initial, APP_TILE_LG))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .text_size(FONT_TITLE)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(p.text)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(detail.name.clone()),
                    )
                    .child(
                        div()
                            .text_size(FONT_MICRO)
                            .text_color(p.text_faint)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(detail.bundle_id.clone()),
                    ),
            )
            .child(io_totals(p, detail.in_bytes, detail.out_bytes))
    }

    /// The scrollable inspector body.
    pub(super) fn render_detail_body(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(detail) = self.detail.clone() else {
            return div().id("detail-body").flex_1().overflow_y_scroll();
        };
        let p = palette(cx);
        div()
            .id("detail-body")
            .flex_1()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(SPACE_LG)
            .px(SPACE_LG)
            .py(SPACE_LG)
            .children(self.detail_unavailable.then(|| unavailable_note(p)))
            .child(self.render_verdict_hero(&detail, cx))
            .child(process_section(p, &detail))
            .children(self.resource_section(&detail, cx))
            .child(connections_section(p, &detail))
            .child(self.render_actions_section(&detail, cx))
    }

    /// The RESOURCES section, present only for an app route whose id (or bundle
    /// path) resolves to a live process group; `None` otherwise.
    fn resource_section(&self, d: &Detail, cx: &mut Context<Self>) -> Option<AnyElement> {
        let id = self.is_app_route()?;
        let group =
            self.source.proc_groups().into_iter().find(|g| {
                g.id == id || (g.bundle_path.is_some() && g.bundle_path == d.bundle_path)
            })?;
        Some(resource_section(palette(cx), &group))
    }

    /// The focal openbinary verdict hero. In live mode this drives a real hash →
    /// lookup on a background thread (never blocking render) and renders the
    /// cached state — clickable to the binary's openbinary.ai page when a SHA is
    /// cached. Demo / non-binary details fall back to the curated static line.
    fn render_verdict_hero(&self, d: &Detail, cx: &mut Context<Self>) -> AnyElement {
        let p = palette(cx);
        let Some(key) = d.bundle_path.clone().filter(|_| self.source.is_live()) else {
            return verdict_hero_static(p, &d.openbinary);
        };
        self.ob.request(&key);
        let state = self.ob.get(&key);
        let sha = self.ob.sha256(&key);
        let auto = self.ob.auto_upload();
        verdict_hero(p, &key, state.as_ref(), sha, auto, cx)
    }

    /// The passive row badge: a small red dot for malicious, an amber dot for
    /// suspicious, nothing otherwise. List rows carry only a colored dot — never a
    /// text chip (per the brand rule); the full openbinary banner lives in the
    /// DETAIL view. Reads the cache only — never triggers a fetch.
    pub(super) fn ob_badge(&self, p: Palette, path: Option<&Path>) -> Option<AnyElement> {
        let verdict = self.ob.get(path?)?.verdict()?;
        let tone = row_dot_tone(verdict.tone())?;
        Some(severity_dot(super::widgets::tone_color(p, tone)).into_any_element())
    }

    fn render_actions_section(&self, d: &Detail, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let app_id = self.is_app_route();
        let block_label: SharedString = if d.allowed {
            "Block network".into()
        } else {
            "Allow network".into()
        };

        let block_btn = if let Some(id) = app_id {
            let default = d.allowed;
            let handler = cx.listener(move |panel, _ev, _win, cx| {
                let desired = !panel.state.app_allowed(&id, default);
                // Optimistic: flip the local override instantly so the button
                // reflects the intent this frame, then confirm/reconcile with
                // the daemon off the render thread.
                panel.state.set_app_allow(&id, desired);
                cx.notify();
                panel.commit_app_rule(id.clone(), desired, cx);
            });
            action_button(p, "block", block_label, d.allowed, true, handler)
        } else {
            action_button(p, "block", block_label, false, false, |_, _, _| {})
        };

        let live = self.source.is_live();
        let enforcing = self.source.enforcement_active();
        section(p, "ACTIONS")
            .child(self.trace_action_row(p, cx))
            .child(
                div().flex().flex_row().gap(px(8.0)).child(block_btn).child(
                    div()
                        .id("prevent")
                        .flex_1()
                        .tooltip(tip("requires the macwarden daemon (soon)"))
                        .child(action_button(
                            p,
                            "prevent",
                            "Prevent launch".into(),
                            false,
                            false,
                            |_, _, _| {},
                        )),
                ),
            )
            .child(
                div()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_faint)
                    .child(enforcement_hint(enforcing, live)),
            )
    }
}

impl Panel {
    /// The full-width "Trace packets" action (R11). Enabled only for an app
    /// route whose source can capture — the demo's synthetic stream, or a daemon
    /// advertising [`ipc::protocol::Capability::Trace`]; disabled and explained
    /// otherwise so the affordance is honest.
    fn trace_action_row(&self, p: Palette, cx: &mut Context<Self>) -> AnyElement {
        let app_id = self.is_app_route();
        let can_trace = self.source.trace_backend().is_some();
        let btn = match (can_trace, app_id) {
            (true, Some(id)) => {
                let handler = cx.listener(move |panel, _ev, _win, cx| {
                    panel.enter_trace(id.clone(), cx);
                });
                action_button(p, "trace", "Trace packets".into(), false, true, handler)
            }
            _ => action_button(
                p,
                "trace",
                "Trace packets".into(),
                false,
                false,
                |_, _, _| {},
            ),
        };
        let mut row = div().flex().flex_row().gap(px(8.0)).child(btn);
        if !can_trace {
            row = row.child(
                div()
                    .flex()
                    .items_center()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_faint)
                    .child("requires a daemon with BPF capture"),
            );
        }
        row.into_any_element()
    }
}

/// Which openbinary tones earn a passive **row** dot: malicious (red) and
/// suspicious (amber). Good/neutral get nothing. Returns the tone to colour from,
/// so the row only ever renders a colored dot — never a text chip (brand rule).
/// Pure, so the "rows never chip" policy is unit-tested.
#[must_use]
fn row_dot_tone(tone: ObTone) -> Option<ObTone> {
    matches!(tone, ObTone::Bad | ObTone::Warn).then_some(tone)
}

/// The honest one-line hint under the block/prevent actions (spec 009 R4).
///
/// - `enforcing` (the daemon advertises
///   [`ipc::protocol::Capability::NetworkEnforcement`]): the NE filter is live, so
///   toggles enforce — no "preview only" wording.
/// - `live` but not enforcing: a real daemon is attached but the content filter is
///   not activated, so toggles are preview only.
/// - neither (demo): toggles do nothing without a daemon.
///
/// Pure, so the "preview only copy shows only when not enforcing" invariant is
/// unit-tested rather than depending on GPUI render.
#[must_use]
fn enforcement_hint(enforcing: bool, live: bool) -> &'static str {
    if enforcing {
        "Enforcing live — the macwarden network filter is active."
    } else if live {
        "Toggles preview only — enforcement requires the macwarden daemon."
    } else {
        "Enforcement requires the macwarden daemon."
    }
}

#[cfg(test)]
#[path = "detail_test.rs"]
mod detail_test;

/// The circular back chevron. Rendered in the titlebar's left cluster while an
/// inspector route is pushed (see [`Panel::render_titlebar`]).
pub(super) fn back_chevron(
    p: Palette,
    on_back: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> impl IntoElement {
    div()
        .id("back")
        .flex()
        .items_center()
        .justify_center()
        .w(px(22.0))
        .h(px(22.0))
        .rounded(RADIUS)
        .cursor_pointer()
        .text_color(p.text_dim)
        .hover(|s| s.bg(p.hover))
        .child("‹")
        .on_click(on_back)
}

/// A subtle inline note shown when the daemon's full detail could not be fetched
/// and the inspector is rendering the row-derived seed only — so the enrichment
/// (signature, openbinary, IPs, ports) may be incomplete.
fn unavailable_note(p: Palette) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .px(px(10.0))
        .py(px(6.0))
        .rounded(RADIUS_SM)
        .bg(p.surface.opacity(0.6))
        .border_1()
        .border_color(p.hairline)
        .text_size(FONT_MICRO)
        .text_color(p.text_faint)
        .child("Live details unavailable — showing what's known from the list.")
}

/// The right-aligned In/Out session totals block: dim micro labels beside
/// tabular mono values.
fn io_totals(p: Palette, in_bytes: u64, out_bytes: u64) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_end()
        .gap(px(3.0))
        .flex_shrink_0()
        .child(io_row(p, "IN", in_bytes))
        .child(io_row(p, "OUT", out_bytes))
}

/// One In/Out total row.
fn io_row(p: Palette, label: &'static str, bytes: u64) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(p.text_faint)
                .child(label),
        )
        .child(
            div()
                .font_family("ui-monospace")
                .text_size(FONT_CAPTION)
                .text_color(p.text_dim)
                .child(format_bytes(bytes)),
        )
}

/// A bordered, clearly-tappable inspector action control. Enabled buttons carry
/// a subtle fill + hairline border and brighten on hover; disabled buttons read
/// as faint, inert chrome. `primary` gives the live block/allow control a
/// slightly stronger fill so it reads as the main action.
fn action_button(
    p: Palette,
    id: &'static str,
    label: SharedString,
    primary: bool,
    enabled: bool,
    handler: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> AnyElement {
    let fill = if !enabled {
        p.trough
    } else if primary {
        p.sel
    } else {
        p.surface.opacity(0.6)
    };
    let text = if enabled { p.text } else { p.text_faint };
    div()
        .id(id)
        .flex_1()
        .flex()
        .items_center()
        .justify_center()
        .h(px(30.0))
        .rounded(RADIUS_SM)
        .bg(fill)
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
        .into_any_element()
}
