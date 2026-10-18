//! The full-panel **Rules & Settings** view — a pushed route that reuses the
//! inspector's nav stack + back-chevron chrome instead of a cramped popover.
//!
//! Three scrollable sections: GROUPS (each an expandable row showing its
//! description, domain count, and an enable toggle), ALLOW LIST (exceptions —
//! delegated to [`super::allowlist`]), and BLOCK LIST (globally-blocked domains
//! added via the `SetRule` path). The view captures key-downs and routes them to
//! whichever add-field the user last focused, since the panel carries no real
//! `TextInput`. All mutations are async + optimistic (see [`super::policy`]).

use gpui::prelude::FluentBuilder as _;
use gpui::{
    App, Context, ElementId, InteractiveElement as _, IntoElement, KeyDownEvent,
    ParentElement as _, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use ipc::protocol::WireGroupState;

use super::panel::Panel;
use super::policy::printable_char;
use super::theme::{
    FONT_CAPTION, FONT_MICRO, FONT_TITLE, Palette, RADIUS, RADIUS_SM, SPACE_LG, SPACE_MD, palette,
};
use super::widgets::{Seg, segmented, switch};
use crate::state::{RefreshRate, SettingsField};

/// Copy explaining the block list (Tiny-Shield-style helper text).
const BLOCK_BLURB: &str = "Enter one or more domains to block, separated by commas.";

impl Panel {
    /// The Rules & Settings header: a back chevron and the view title, matching
    /// the inspector header's push/pop chrome.
    pub(super) fn render_rules_header(cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let on_back = cx.listener(|panel, _ev, _win, cx| {
            panel.state.set_settings_field(SettingsField::None);
            panel.state.pop();
            cx.notify();
        });
        let back = div()
            .id("rules-back")
            .flex()
            .items_center()
            .justify_center()
            .w(px(20.0))
            .h(px(20.0))
            .rounded(RADIUS)
            .cursor_pointer()
            .text_color(p.text_dim)
            .hover(|s| s.bg(p.hover))
            .child("‹")
            .on_click(on_back);
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(8.0))
            .px(SPACE_LG)
            .h(px(52.0))
            .border_b_1()
            .border_color(p.hairline)
            .child(back)
            .child(
                div()
                    .flex_1()
                    .text_size(FONT_TITLE)
                    .text_color(p.text)
                    .child("Rules & Settings"),
            )
    }

    /// The scrollable Rules & Settings body. Focusable so it captures Esc (back
    /// out) and typed characters for the add-fields.
    pub(super) fn render_rules_body(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let on_key = cx.listener(Self::on_rules_key);
        div()
            .id("rules-body")
            .track_focus(&self.rules_focus)
            .on_key_down(on_key)
            .flex_1()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(SPACE_LG)
            .px(SPACE_LG)
            .py(SPACE_LG)
            .child(self.render_general_section(cx))
            .child(self.render_groups_section(cx))
            .child(self.render_allowlist_section(cx))
            .child(self.render_block_section(cx))
    }

    /// The GENERAL section: the live-data refresh cadence. A longer interval is
    /// lighter on CPU and battery (the whole window recomposites each refreshed
    /// frame); the choice persists across launches.
    fn render_general_section(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let current = self.state.refresh_rate();
        let segments = RefreshRate::all()
            .into_iter()
            .map(|r| Seg {
                value: r,
                label: r.label().into(),
            })
            .collect();
        let view = cx.entity();
        let on_select = move |rate: RefreshRate, _win: &mut Window, cx: &mut App| {
            view.update(cx, |panel, cx| panel.set_refresh_rate(rate, cx));
        };
        section_card(p, "GENERAL")
            .child(section_blurb(
                p,
                "How often the live view refreshes. A longer interval is lighter on CPU and battery.",
            ))
            .child(segmented(p, "refresh-rate", segments, current, on_select))
            .child(
                div()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_faint)
                    .child(current.caption()),
            )
    }

    /// The GROUPS section: one expandable row per built-in network group.
    fn render_groups_section(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let groups = self
            .profile
            .as_ref()
            .map(|pr| pr.groups.clone())
            .unwrap_or_default();
        let mut card = section_card(p, "GROUPS").child(section_blurb(
            p,
            "Curated domain sets. Enable one to allow its destinations; expand a row to see what it covers.",
        ));
        if groups.is_empty() {
            return card.child(
                div()
                    .py(px(4.0))
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_faint)
                    .child("No groups reported."),
            );
        }
        for group in &groups {
            card = card.child(self.group_setting_row(p, group, cx));
        }
        card
    }

    /// One expandable group row: chevron + name + domain count + enable toggle,
    /// with the description revealed underneath when expanded.
    fn group_setting_row(
        &self,
        p: Palette,
        group: &WireGroupState,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let name = group.name.clone();
        let enabled = group.enabled;
        let expanded = self.state.is_group_expanded(&group.name);
        let description = group.description.clone();

        let expand_name = group.name.clone();
        let on_expand = cx.listener(move |panel, _ev, _win, cx| {
            panel.state.toggle_group_expanded(&expand_name);
            cx.notify();
        });
        let toggle_name = group.name.clone();
        let on_toggle = cx.listener(move |panel, _ev, _win, cx| {
            panel.commit_group(toggle_name.clone(), !enabled, cx);
            cx.notify();
        });

        let header = div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(8.0))
            .child(
                div()
                    .id(ElementId::Name(format!("grp-open-{name}").into()))
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .cursor_pointer()
                    .on_click(on_expand)
                    .child(
                        div()
                            .w(px(10.0))
                            .text_size(px(9.0))
                            .text_color(p.text_dim)
                            .child(if expanded { "▾" } else { "▸" }),
                    )
                    .child(
                        div()
                            .text_size(FONT_CAPTION)
                            .text_color(p.text)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(name.clone()),
                    )
                    .child(
                        div()
                            .text_size(px(9.0))
                            .text_color(p.text_faint)
                            .child(format!("{} domains", group.domain_count)),
                    ),
            )
            .child(switch(
                p,
                ElementId::Name(format!("grp-sw-{name}").into()),
                enabled,
                true,
                on_toggle,
            ));

        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .py(px(3.0))
            .child(header)
            .when(expanded, |el| {
                let text = if description.is_empty() {
                    "No description available.".to_string()
                } else {
                    description.clone()
                };
                el.child(
                    div()
                        .pl(px(16.0))
                        .text_size(FONT_MICRO)
                        .text_color(p.text_dim)
                        .child(text),
                )
            })
    }

    /// The BLOCK LIST section: globally-blocked domains plus an add field.
    fn render_block_section(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let blocked = self.state.blocked_domains().to_vec();
        let mut card = section_card(p, "BLOCK LIST").child(section_blurb(p, BLOCK_BLURB));
        if blocked.is_empty() {
            card = card.child(
                div()
                    .py(px(4.0))
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_faint)
                    .child("No blocked domains yet."),
            );
        } else {
            for host in &blocked {
                card = card.child(Self::block_row(p, host, cx));
            }
        }
        if let Some(err) = self.state.block_error() {
            card = card.child(
                div()
                    .text_size(FONT_MICRO)
                    .text_color(p.red)
                    .child(err.to_string()),
            );
        }
        card.child(self.block_add_row(p, cx))
    }

    /// One blocked-domain row: the host and a red remove (−) affordance.
    fn block_row(p: Palette, host: &str, cx: &mut Context<Self>) -> impl IntoElement {
        let value = host.to_string();
        let remove = host.to_string();
        let on_remove = cx.listener(move |panel, _ev, _win, cx| {
            panel.commit_block_domain(remove.clone(), false, cx);
            cx.notify();
        });
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(7.0))
            .py(px(3.0))
            .child(div().text_size(FONT_MICRO).text_color(p.red).child("⦸"))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_size(FONT_CAPTION)
                    .text_color(p.text)
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(value),
            )
            .child(
                div()
                    .id(ElementId::Name(format!("block-rm-{host}").into()))
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(18.0))
                    .h(px(18.0))
                    .rounded(RADIUS_SM)
                    .cursor_pointer()
                    .text_color(p.red)
                    .hover(|s| s.bg(p.red.opacity(0.16)))
                    .child("−")
                    .on_click(on_remove),
            )
    }

    /// The block-list add row: the draft field (focus-to-type) and a red (+).
    fn block_add_row(&self, p: Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let draft = self.state.block_draft().to_string();
        let has_draft = !draft.trim().is_empty();
        let active = self.state.settings_field() == SettingsField::Block;
        let on_add = cx.listener(|panel, _ev, _win, cx| {
            panel.submit_block_draft(cx);
        });
        let on_focus = cx.listener(|panel, _ev, window: &mut Window, cx| {
            panel.state.set_settings_field(SettingsField::Block);
            window.focus(&panel.rules_focus);
            cx.notify();
        });
        let field_text = if draft.is_empty() {
            "example.com, ads.example.net…".to_string()
        } else {
            draft.clone()
        };
        let field_dim = draft.is_empty();
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .child(
                div()
                    .id("block-field")
                    .flex_1()
                    .min_w_0()
                    .h(px(24.0))
                    .flex()
                    .items_center()
                    .px(px(7.0))
                    .rounded(RADIUS_SM)
                    .bg(p.trough)
                    .border_1()
                    .border_color(if active { p.text_dim } else { p.hairline })
                    .cursor_text()
                    .text_size(FONT_CAPTION)
                    .text_color(if field_dim { p.text_faint } else { p.text })
                    .on_click(on_focus)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(field_text),
                    )
                    .when(active, |el| {
                        el.child(div().w(px(1.0)).h(px(13.0)).bg(p.text_dim))
                    }),
            )
            .child(
                div()
                    .id("block-add")
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(24.0))
                    .h(px(24.0))
                    .rounded(RADIUS_SM)
                    .text_size(px(15.0))
                    .text_color(if has_draft { p.red } else { p.text_faint })
                    .when(has_draft, |el| {
                        el.cursor_pointer()
                            .hover(|s| s.bg(p.red.opacity(0.16)))
                            .on_click(on_add)
                    })
                    .child("+"),
            )
    }

    /// Parse the block draft's comma-separated domains and block each globally.
    /// Duplicates and blanks are skipped; the daemon does the authoritative host
    /// validation (a rejected exact domain surfaces an inline error, and
    /// wildcards are rejected outright by the current validator).
    pub(super) fn submit_block_draft(&mut self, cx: &mut Context<Self>) {
        let draft = self.state.block_draft().trim().to_string();
        if draft.is_empty() {
            return;
        }
        self.state.clear_block_draft();
        self.state.clear_block_error();
        let hosts: Vec<String> = draft
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
        for host in hosts {
            if self.state.blocked_domains().iter().any(|d| d == &host) {
                continue;
            }
            self.commit_block_domain(host, true, cx);
        }
        cx.notify();
    }

    /// Route key presses while the Rules view is focused: Esc backs out; a
    /// focused add-field takes Enter (commit), Backspace (delete), and printable
    /// characters (append).
    fn on_rules_key(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        if key == "escape" {
            self.state.set_settings_field(SettingsField::None);
            self.state.pop();
            cx.notify();
            return;
        }
        let field = self.state.settings_field();
        if field == SettingsField::None {
            return;
        }
        let mods = event.keystroke.modifiers;
        if mods.platform || mods.control {
            return;
        }
        match key {
            "enter" => match field {
                SettingsField::Allow => self.submit_allow_draft(cx),
                SettingsField::Block => self.submit_block_draft(cx),
                SettingsField::None => {}
            },
            "backspace" => {
                match field {
                    SettingsField::Allow => self.state.pop_allow_char(),
                    SettingsField::Block => self.state.pop_block_char(),
                    SettingsField::None => {}
                }
                cx.notify();
            }
            _ => {
                if let Some(text) = printable_char(event) {
                    match field {
                        SettingsField::Allow => self.state.push_allow_text(&text),
                        SettingsField::Block => self.state.push_block_text(&text),
                        SettingsField::None => {}
                    }
                    cx.notify();
                }
            }
        }
    }
}

/// A Rules-view section card: a hairline-bordered translucent surface with a
/// micro-caps title, matching the inspector's section styling.
pub(super) fn section_card(p: Palette, title: &'static str) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .p(SPACE_MD)
        .rounded(RADIUS)
        .bg(p.surface.opacity(0.5))
        .border_1()
        .border_color(p.hairline)
        .child(
            div()
                .text_size(px(10.0))
                .text_color(p.text_faint)
                .child(title),
        )
}

/// An explanatory blurb line inside a section card.
pub(super) fn section_blurb(p: Palette, text: &'static str) -> impl IntoElement {
    div()
        .text_size(FONT_MICRO)
        .text_color(p.text_faint)
        .child(text)
}
