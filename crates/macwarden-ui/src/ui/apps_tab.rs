//! The Apps tab: one row per app (helpers rolled up under their responsible
//! app) with a hover chevron, real-icon-or-monogram tile, network-access switch,
//! and disclosure to per-destination rows. Endpoints are aggregated — one row
//! per remote endpoint with a `×N` socket count — and every metric respects the
//! active scope: live rates under Real-time, accumulated totals otherwise.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    Context, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, px,
};

use super::filter;
use super::panel::Panel;
use super::theme::ICON;
use super::theme::{
    FONT_BODY, FONT_CAPTION, FONT_MICRO, GROUP_INDENT, ROW_HEIGHT, SPACE_LG, SPACE_SM,
    SUBROW_HEIGHT, palette,
};
use super::widgets::{SwitchState, dot, group_switch, switch, tile, tip};
use crate::data::model::{AppRow, DomainRow, Flow, format_bytes, format_rate, format_scoped};
use crate::state::{Route, Scope};

/// Demo heuristic: the last hour is roughly an eighth of the Today total.
const HOUR_DIVISOR: u64 = 8;

/// Derive the "macOS System" group switch state from its members' allow states:
/// every member allowed → [`SwitchState::On`], every member blocked →
/// [`SwitchState::Off`], a mix → [`SwitchState::Mixed`]. An empty group reads
/// `Off`. Pure aggregate so the derivation is unit-tested.
#[must_use]
fn group_toggle_state(member_allowed: impl IntoIterator<Item = bool>) -> SwitchState {
    let mut any_on = false;
    let mut any_off = false;
    for allowed in member_allowed {
        if allowed {
            any_on = true;
        } else {
            any_off = true;
        }
    }
    match (any_on, any_off) {
        (true, true) => SwitchState::Mixed,
        (true, false) => SwitchState::On,
        _ => SwitchState::Off,
    }
}

/// The throughput string for an app row under the active scope. Real-time shows
/// a live rate; every totals scope shows accumulated download bytes.
fn scope_label(scope: Scope, app: &AppRow, live: bool) -> String {
    match scope {
        Scope::RealTime => app.flow.label(),
        Scope::Hour if !live => format!("↓ {}", format_bytes(app.down_bytes / HOUR_DIVISOR)),
        Scope::Hour | Scope::Today | Scope::Session => {
            format!("↓ {}", format_bytes(app.down_bytes))
        }
    }
}

/// The aggregate traffic label for the "macOS System" group under the active
/// scope: a summed live rate under Real-time, summed download bytes otherwise.
fn system_aggregate(scope: Scope, members: &[AppRow]) -> String {
    match scope {
        Scope::RealTime => {
            let rate: u64 = members
                .iter()
                .map(|a| match a.flow {
                    Flow::Active(bps) => bps,
                    _ => 0,
                })
                .sum();
            format_rate(rate)
        }
        Scope::Hour | Scope::Today | Scope::Session => {
            let down: u64 = members.iter().map(|a| a.down_bytes).sum();
            format!("↓ {}", format_bytes(down))
        }
    }
}

/// Whether an app is transferring right now (drives the Real-time filter).
fn is_active(app: &AppRow) -> bool {
    matches!(app.flow, Flow::Active(_))
        || app.domains.iter().any(|d| d.rate_bps > 0 || d.sockets > 0)
}

impl Panel {
    /// Render the Apps tab list, filtered and ordered for the active scope.
    ///
    /// With no ⌘F query this honours the scope (active-only under Real-time,
    /// heaviest-first totals otherwise) and the user's manual expand state. With a
    /// query the inverse lookup takes over: every app that matches by name or by a
    /// destination is shown, transiently auto-expanded to its matching
    /// destinations — the manual expand set is left untouched.
    pub(super) fn render_apps(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let scope = self.state.scope();
        let totals = scope.shows_totals();
        let query = filter::normalize(self.state.filter());
        let mut apps = self.source.apps();

        match &query {
            Some(needle) => {
                apps.retain(|a| filter::app_matches(a, needle));
                apps.sort_by(|a, b| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                });
            }
            None if totals => {
                apps.retain(|a| a.down_bytes + a.up_bytes > 0);
                apps.sort_by(|a, b| (b.down_bytes + b.up_bytes).cmp(&(a.down_bytes + a.up_bytes)));
            }
            None => apps.retain(is_active),
        }

        // Fold Apple-signed system daemons under one collapsible "macOS System"
        // group at the top so they don't crowd out the user's real apps. Order
        // within each partition is preserved from the sort above.
        let (system, regular): (Vec<AppRow>, Vec<AppRow>) =
            apps.into_iter().partition(|a| a.is_system);

        let mut list = div().flex().flex_col().py(SPACE_SM);
        if query.is_some() && system.is_empty() && regular.is_empty() {
            return list.child(self.render_no_matches(cx));
        }

        if !system.is_empty() {
            // A live ⌘F query force-opens the group so a matched daemon surfaces
            // even while the group is collapsed in the normal (unfiltered) view.
            let group_open = query.is_some() || self.state.system_expanded();
            list = list.child(self.system_group_row(&system, group_open, cx));
            if group_open {
                for app in &system {
                    list =
                        self.push_app_rows(list, app, query.as_deref(), totals, GROUP_INDENT, cx);
                }
            }
        }
        for app in &regular {
            list = self.push_app_rows(list, app, query.as_deref(), totals, px(0.0), cx);
        }
        list
    }

    /// Append an app row and — when the app is expanded (manually or by an
    /// active ⌘F query) — its scoped destination subrows. Shared by the system
    /// group's members and the top-level regular apps.
    fn push_app_rows(
        &self,
        mut list: gpui::Div,
        app: &AppRow,
        query: Option<&str>,
        totals: bool,
        indent: gpui::Pixels,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let expanded = query.is_some() || self.state.is_expanded(&app.id);
        list = list.child(self.app_row(app, indent, cx));
        if !expanded {
            return list;
        }
        let candidates = scoped_domains(app, totals, query.is_some());
        let shown = match query {
            Some(needle) => filter::matched_domains(&candidates, needle),
            None => candidates,
        };
        let parent_allowed = self.state.app_allowed(&app.id, app.allowed);
        for d in shown {
            list = list.child(self.domain_subrow(d, &app.id, parent_allowed, totals, indent, cx));
        }
        list
    }

    /// The collapsible "macOS System" parent row: an Apple glyph tile, the group
    /// name with a member count, the scoped aggregate traffic, a disclosure
    /// chevron, and a group-level allow/block switch. The left cluster toggles the
    /// group open/closed; the trailing switch is an **aggregate** of its members —
    /// on when all are allowed, off when all blocked, mixed otherwise — and
    /// flipping it blocks or allows every member in one batch mutation.
    fn system_group_row(
        &self,
        members: &[AppRow],
        expanded: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = palette(cx);
        let count = members.len();
        let value = system_aggregate(self.state.scope(), members);
        let on_toggle = cx.listener(|panel, _ev, _win, cx| {
            panel.state.toggle_system_expanded();
            cx.notify();
        });
        // The switch aggregates the members' effective allow states (honoring
        // optimistic local overrides). Flipping ON→blocks all; OFF/Mixed→allows
        // all. Interactive in every posture — a toggle always stages locally
        // (like the per-app switches); whether the staged block is *live* is
        // shown by the verdict dot and mode pill via [`Panel::enforce_mode`], not
        // by disabling the control. This unifies the group switch with the
        // per-app switches, which were already always interactive.
        let switch_state = group_toggle_state(
            members
                .iter()
                .map(|m| self.state.app_allowed(&m.id, m.allowed)),
        );
        let can_mutate = true;
        let ids: Vec<String> = members.iter().map(|m| m.id.clone()).collect();
        let defaults: Vec<bool> = members.iter().map(|m| m.allowed).collect();
        let desired_allow = switch_state != SwitchState::On;
        let on_switch = cx.listener(move |panel, _ev, _win, cx| {
            panel.commit_system_group(&ids, &defaults, desired_allow, cx);
            cx.notify();
        });
        div()
            .id("macos-system-row")
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .h(ROW_HEIGHT)
            .px(SPACE_LG)
            .hover(|s| s.bg(p.hover))
            .child(
                div()
                    .id("macos-system-toggle")
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .flex_1()
                    .min_w_0()
                    .cursor_pointer()
                    .on_click(on_toggle)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .w(px(12.0))
                            .text_size(px(9.0))
                            .text_color(p.text_faint)
                            .child(if expanded { "▼" } else { "▶" }),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .w(ICON)
                            .h(ICON)
                            .rounded(super::theme::RADIUS_SM)
                            .bg(p.tile)
                            .text_size(px(12.0))
                            .text_color(p.text_dim)
                            .child("⚙"),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(FONT_BODY)
                                    .text_color(p.text)
                                    .child("macOS System"),
                            )
                            .child(
                                div()
                                    .text_size(FONT_MICRO)
                                    .text_color(p.text_faint)
                                    .child(format!("{count} apps")),
                            ),
                    )
                    .child(
                        div()
                            .font_family("ui-monospace")
                            .text_size(FONT_CAPTION)
                            .text_color(p.text_dim)
                            .child(value),
                    ),
            )
            .child(
                div()
                    .id("macos-system-switch")
                    .tooltip(tip("Allow or block every macOS System app"))
                    .child(group_switch(
                        p,
                        ElementId::Name("macos-system-switch-ctl".into()),
                        switch_state,
                        can_mutate,
                        on_switch,
                    )),
            )
    }

    fn app_row(
        &self,
        app: &AppRow,
        indent: gpui::Pixels,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = palette(cx);
        let id = app.id.clone();
        let allowed = self.state.app_allowed(&app.id, app.allowed);
        let filtering = filter::normalize(self.state.filter()).is_some();
        let expanded = filtering || self.state.is_expanded(&app.id);
        let throughput = scope_label(self.state.scope(), app, self.source.is_live());

        let toggle_id = id.clone();
        let on_chevron = cx.listener(move |panel, _ev, _win, cx| {
            panel.state.toggle_expanded(&toggle_id);
            cx.notify();
        });

        let body_id = id.clone();
        let on_body = cx.listener(move |panel, _ev, _win, cx| {
            panel.navigate(Route::App(body_id.clone()), cx);
        });

        let switch_id = id.clone();
        let switch_default = app.allowed;
        let on_switch = cx.listener(move |panel, _ev, _win, cx| {
            panel.state.toggle_app_allow(&switch_id, switch_default);
            let allow = panel.state.app_allowed(&switch_id, switch_default);
            cx.notify();
            // Enforce the flip on the daemon (writes the rule + hot-reloads);
            // the next snapshot's per-destination verdicts flip to Blocked and
            // the child rows follow. Optimistic — never blocks render.
            panel.commit_app_rule(switch_id.clone(), allow, cx);
        });

        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .h(ROW_HEIGHT)
            .pl(SPACE_LG + indent)
            .pr(SPACE_LG)
            .hover(|s| s.bg(p.hover))
            .child(
                div()
                    .id(ElementId::Name(format!("chev-{id}").into()))
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(12.0))
                    .cursor_pointer()
                    .text_size(px(9.0))
                    .text_color(p.text_faint)
                    .child(if expanded { "▼" } else { "▶" })
                    .on_click(on_chevron),
            )
            .child(tile(
                p,
                self.icon_for(app.bundle_path.as_deref()),
                app.monogram(),
                ICON,
            ))
            .child(
                div()
                    .id(ElementId::Name(format!("body-{id}").into()))
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .flex_1()
                    .min_w_0()
                    .cursor_pointer()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_size(FONT_BODY)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(app.name.clone()),
                    )
                    .children(self.ob_badge(p, app.bundle_path.as_deref()))
                    .on_click(on_body),
            )
            .child(
                div()
                    .font_family("ui-monospace")
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_dim)
                    .child(throughput),
            )
            .child(
                div()
                    .id(ElementId::Name(format!("sw-{id}").into()))
                    .tooltip(tip("Allow network"))
                    .child(switch(
                        p,
                        ElementId::Name(format!("swc-{id}").into()),
                        allowed,
                        true,
                        on_switch,
                    )),
            )
    }

    fn domain_subrow(
        &self,
        d: &DomainRow,
        code_id: &str,
        parent_allowed: bool,
        totals: bool,
        indent: gpui::Pixels,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = palette(cx);
        let host = d.host.clone();
        // A destination's effective state is the AND of the app's allow and its
        // own override: a blocked app forces every child OFF regardless of the
        // per-destination override, so there is no "app blocked but destinations
        // green" contradiction while the daemon snapshot catches up.
        let allowed = parent_allowed && self.state.domain_allowed(&d.host, d.allowed);

        let sw_host = host.clone();
        let sw_code = code_id.to_string();
        let on_switch = cx.listener(move |panel, _ev, _win, cx| {
            // Toggle relative to the effective (shown) state, then enforce a
            // scoped App+Domain rule for THIS app and THIS host — allowing a
            // child of a blocked app is a valid per-destination exception.
            let desired = !allowed;
            panel.state.set_domain_allow(&sw_host, desired);
            cx.notify();
            panel.commit_domain_rule(sw_code.clone(), sw_host.clone(), desired, cx);
        });

        // Honest verdict (spec 009 R4): only paint the red "Blocked" dot when the
        // firewall is genuinely enforcing. In preview/monitor mode a blocked
        // toggle is staged, not live — the destination is still flowing — so the
        // row shows its real observed verdict instead of a fabricated block.
        let shown_verdict = super::enforce::shown_verdict(self.enforce_mode(), allowed, d.verdict);
        let value = format_scoped(totals, d.rate_bps, d.total_bytes);
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .h(SUBROW_HEIGHT)
            .pl(px(40.0) + indent)
            .pr(SPACE_LG)
            .child(dot(p, shown_verdict))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        div()
                            .min_w_0()
                            .text_size(FONT_CAPTION)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(host.clone()),
                    )
                    .when(d.sockets > 1, |el| {
                        el.child(
                            div()
                                .text_size(px(9.0))
                                .text_color(p.text_faint)
                                .child(format!("×{}", d.sockets)),
                        )
                    }),
            )
            .child(
                div()
                    .font_family("ui-monospace")
                    .text_size(px(10.0))
                    .text_color(p.text_faint)
                    .child(value),
            )
            .child(switch(
                p,
                ElementId::Name(format!("dsw-{host}").into()),
                allowed,
                true,
                on_switch,
            ))
    }
}

/// The destinations to show under an app for the active scope: active endpoints
/// only under Real-time, all persisted endpoints (heaviest first) otherwise.
///
/// While a ⌘F query is active the scope gate is dropped so the inverse lookup
/// can surface an idle or quiet destination the user is searching for.
fn scoped_domains(app: &AppRow, totals: bool, filtering: bool) -> Vec<&DomainRow> {
    let mut domains: Vec<&DomainRow> = app
        .domains
        .iter()
        .filter(|d| {
            if filtering {
                true
            } else if totals {
                d.total_bytes > 0
            } else {
                d.rate_bps > 0 || d.sockets > 0
            }
        })
        .collect();
    if totals || filtering {
        domains.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
    }
    domains
}

#[cfg(test)]
#[path = "apps_tab_test.rs"]
mod apps_tab_test;
