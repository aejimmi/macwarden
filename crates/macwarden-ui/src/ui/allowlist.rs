//! The Allow List section of the Rules & Settings view (R8): the current
//! exception entries with per-row remove, and an add field that compiles a typed
//! value into a [`WireAllowEntry`]. Exceptions are meaningful in Block-All
//! mode — they are the holes punched through the default-Deny.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use ipc::protocol::WireAllowEntry;

use super::panel::Panel;
use super::rules_view::{section_blurb, section_card};
use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, RADIUS_SM, palette};
use crate::state::SettingsField;

/// Copy explaining what the allow-list is for (R8).
const ALLOWLIST_BLURB: &str =
    "Allow List creates exceptions for apps, domains, and IPs while Block All mode is active.";

impl Panel {
    /// The Allow List section card for the Rules & Settings view.
    pub(super) fn render_allowlist_section(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let entries = self
            .profile
            .as_ref()
            .map(|pr| pr.allowlist.clone())
            .unwrap_or_default();

        let mut card = section_card(p, "ALLOW LIST").child(section_blurb(p, ALLOWLIST_BLURB));

        if entries.is_empty() {
            card = card.child(
                div()
                    .py(px(4.0))
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_faint)
                    .child("No exceptions yet."),
            );
        } else {
            for entry in &entries {
                card = card.child(Self::entry_row(p, entry, cx));
            }
        }

        card.child(self.add_row(p, cx))
    }

    /// One allow-list entry row: a kind glyph, the value, an optional note, and
    /// a red remove (−) affordance.
    fn entry_row(p: Palette, entry: &WireAllowEntry, cx: &mut Context<Self>) -> impl IntoElement {
        let (glyph, label) = describe_entry(entry);
        let remove = entry.clone();
        let on_remove = cx.listener(move |panel, _ev, _win, cx| {
            panel.commit_remove_entry(remove.clone(), cx);
            cx.notify();
        });
        let row_id = format!("entry-{label}");
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(7.0))
            .py(px(3.0))
            .child(
                div()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_dim)
                    .child(glyph),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(FONT_CAPTION)
                            .text_color(p.text)
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(label),
                    )
                    .when_some(entry.note.clone(), |el, note| {
                        el.child(
                            div()
                                .text_size(px(9.0))
                                .text_color(p.text_faint)
                                .child(note),
                        )
                    }),
            )
            .child(
                div()
                    .id(gpui::ElementId::Name(row_id.into()))
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

    /// The add row: the current draft (with a caret when focused) and a green
    /// (+) button. Clicking the field focuses the Allow List add-field so typed
    /// keys route to it (the Rules view has no real `TextInput`).
    fn add_row(&self, p: Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let draft = self.state.allow_draft().to_string();
        let has_draft = !draft.trim().is_empty();
        let active = self.state.settings_field() == SettingsField::Allow;
        let on_add = cx.listener(|panel, _ev, _win, cx| {
            panel.submit_allow_draft(cx);
        });
        let on_focus = cx.listener(|panel, _ev, window: &mut Window, cx| {
            panel.state.set_settings_field(SettingsField::Allow);
            window.focus(&panel.rules_focus);
            cx.notify();
        });
        let field_text = if draft.is_empty() {
            "host, domain, or IP…".to_string()
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
                    .id("allow-field")
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
                    .id("allow-add")
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(24.0))
                    .h(px(24.0))
                    .rounded(RADIUS_SM)
                    .text_size(px(15.0))
                    .text_color(if has_draft { p.accent } else { p.text_faint })
                    .when(has_draft, |el| {
                        el.cursor_pointer()
                            .hover(|s| s.bg(p.accent.opacity(0.16)))
                            .on_click(on_add)
                    })
                    .child("+"),
            )
    }

    /// Compile the current draft into a [`WireAllowEntry`] and add it. A value
    /// that parses as an IP/CIDR becomes an `ip` exception; anything else is a
    /// `host` pattern. Blank drafts are ignored.
    pub(super) fn submit_allow_draft(&mut self, cx: &mut Context<Self>) {
        let draft = self.state.allow_draft().trim().to_string();
        if draft.is_empty() {
            return;
        }
        let entry = if looks_like_ip(&draft) {
            empty_entry(EntryField::Ip(draft))
        } else {
            empty_entry(EntryField::Host(draft))
        };
        self.commit_add_entry(entry, cx);
        cx.notify();
    }
}

/// Which single field a freshly-typed exception populates.
enum EntryField {
    Host(String),
    Ip(String),
}

/// Build a [`WireAllowEntry`] with exactly one field set (the DTO does not
/// derive `Default`, so it is constructed field-by-field here).
fn empty_entry(field: EntryField) -> WireAllowEntry {
    let (host, ip) = match field {
        EntryField::Host(h) => (Some(h), None),
        EntryField::Ip(i) => (None, Some(i)),
    };
    WireAllowEntry {
        app: None,
        team_id: None,
        host,
        ip,
        note: None,
    }
}

/// A kind glyph + display label for an allow-list entry, choosing the most
/// specific field present.
fn describe_entry(entry: &WireAllowEntry) -> (&'static str, String) {
    if let Some(app) = &entry.app {
        return ("▦", app.clone());
    }
    if let Some(team) = &entry.team_id {
        return ("✎", format!("team {team}"));
    }
    if let Some(host) = &entry.host {
        return ("⦿", host.clone());
    }
    if let Some(ip) = &entry.ip {
        return ("◈", ip.clone());
    }
    ("•", "exception".to_string())
}

/// Heuristic: does the draft look like a bare IP or a CIDR range (contains a
/// `:` for v6, or is dotted-decimal, optionally with a `/prefix`)? The daemon
/// does the authoritative parse; this only picks the wire field.
fn looks_like_ip(s: &str) -> bool {
    let head = s.split('/').next().unwrap_or(s);
    if head.contains(':') {
        return true; // IPv6
    }
    let mut octets = 0;
    for part in head.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

#[cfg(test)]
#[path = "allowlist_test.rs"]
mod allowlist_test;
