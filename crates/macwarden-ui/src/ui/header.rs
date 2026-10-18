//! The non-detail header: one strong segmented tab control on top, a quiet
//! subordinate scope row beneath it, and the live count right-aligned and
//! vertically centred against the scope row.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    App, Context, ElementId, IntoElement, ParentElement as _, Styled as _, Window, div, px,
};

use super::panel::Panel;
use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, RADIUS_XS, SPACE_LG, SPACE_MD, palette};
use super::widgets::{Seg, scope_button, segmented};
use crate::state::{Scope, Tab};

impl Panel {
    /// Header shown on the tab views (hidden while an inspector is pushed).
    pub(super) fn render_header(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let tab = self.state.tab();
        let count_label = self.count_label();

        let view = cx.entity();
        let on_tab = move |t: Tab, _win: &mut Window, cx: &mut App| {
            view.update(cx, |panel, cx| {
                panel.state.set_tab(t);
                cx.notify();
            });
        };

        let segments = Tab::all()
            .into_iter()
            .map(|t| Seg {
                value: t,
                label: t.title().into(),
            })
            .collect();

        div()
            .flex()
            .flex_col()
            .gap(SPACE_MD)
            .px(SPACE_LG)
            .py(SPACE_MD)
            .border_b_1()
            .border_color(p.hairline)
            .child(segmented(p, "tabs", segments, tab, on_tab))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(SPACE_MD)
                    .child(self.render_scope(cx))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap(SPACE_MD)
                            .when(self.daemon_reconnecting(), |el| {
                                el.child(reconnecting_chip(p))
                            })
                            .child(
                                div()
                                    .text_size(FONT_CAPTION)
                                    .text_color(p.text_dim)
                                    .child(count_label),
                            )
                            .child(self.render_policy_controls(cx)),
                    ),
            )
    }

    /// Whether the header should show the "Reconnecting…" affordance (R8): the
    /// active source is the daemon but its worker has lost the connection, so it
    /// is serving a stale cached snapshot. Reading [`daemon_stale`] off the
    /// source's own name + liveness keeps the check honest — a live daemon or a
    /// non-daemon source never shows it.
    fn daemon_reconnecting(&self) -> bool {
        daemon_stale(self.source.name(), self.source.is_live())
    }

    fn count_label(&self) -> String {
        match self.state.tab() {
            Tab::Apps => format!("{} apps", self.source.app_count()),
            Tab::Processes => format!("{} groups", self.source.proc_group_count()),
        }
    }

    fn render_scope(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let live = self.source.is_live();
        let scope = self.state.scope();
        let mut row = div().flex().flex_row().items_center().gap(px(12.0));
        for s in scope_options(live) {
            let label = if live { s.live_label() } else { s.label() };
            let view = cx.entity();
            let handler = move |_ev: &gpui::ClickEvent, _win: &mut Window, cx: &mut App| {
                view.update(cx, |panel, cx| {
                    panel.state.set_scope(s);
                    cx.notify();
                });
            };
            row = row.child(scope_button(
                p,
                ElementId::Name(format!("scope-{}", s.label()).into()),
                label,
                scope == s,
                handler,
            ));
        }
        row
    }
}

/// The scopes offered for the active source: two in live mode (Live / Session),
/// three in demo mode (Real-time / Hour / Today).
fn scope_options(live: bool) -> Vec<Scope> {
    if live {
        Scope::live().to_vec()
    } else {
        Scope::all().to_vec()
    }
}

/// Whether the daemon source is currently disconnected (serving a stale cached
/// snapshot while its worker reconnects). Pure, so the "reconnecting affordance
/// shows iff the daemon is not live" rule is unit-tested: a live daemon or any
/// non-daemon source (demo / `nettop` live) is never "reconnecting".
#[must_use]
fn daemon_stale(source_name: &str, live: bool) -> bool {
    source_name == "daemon" && !live
}

/// The faint "Reconnecting…" chip shown in the header while the daemon source is
/// stale (R8). Grayscale — a status note, not an alarm.
fn reconnecting_chip(p: Palette) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.0))
        .px(px(5.0))
        .py(px(1.0))
        .rounded(RADIUS_XS)
        .bg(p.trough)
        .child(
            div()
                .w(px(5.0))
                .h(px(5.0))
                .rounded(px(3.0))
                .bg(p.text_faint),
        )
        .child(
            div()
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child("Reconnecting…"),
        )
}

#[cfg(test)]
#[path = "header_test.rs"]
mod header_test;
