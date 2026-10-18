//! The ⌘F search/filter field and the client-side matching over the cached
//! snapshot — the "what connects to X" inverse lookup that replaced the removed
//! Network tab. Pure matching helpers live as free functions (unit-tested); the
//! field render and key routing live on [`Panel`].
//!
//! Matching is a case-insensitive substring test over names, hostnames/IPs, and
//! pids. It never touches the network: it re-filters the same snapshot the tab
//! already renders, so it stays non-blocking.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    Context, InteractiveElement as _, IntoElement, KeyDownEvent, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};

use super::panel::Panel;
use super::policy::printable_char;
use super::theme::{FONT_CAPTION, FONT_MICRO, RADIUS_SM, RADIUS_XS, SPACE_LG, palette};
use crate::data::model::{AppRow, DomainRow, ProcGroup, ProcRow};

/// Placeholder shown in the empty filter field.
const PLACEHOLDER: &str = "Filter processes, domains, IPs";

/// Normalise a raw query into a lowercased, trimmed needle. `None` means the
/// filter is inactive (empty query) and the tab should render normally.
#[must_use]
pub fn normalize(query: &str) -> Option<String> {
    let q = query.trim().to_ascii_lowercase();
    (!q.is_empty()).then_some(q)
}

/// Whether a destination row matches the needle (host or literal IP). The `host`
/// field carries a resolved hostname or the bare IP, so one test covers both.
#[must_use]
pub fn domain_matches(d: &DomainRow, needle: &str) -> bool {
    d.host.to_ascii_lowercase().contains(needle)
}

/// Whether an app matches: its name, or any destination it talks to.
#[must_use]
pub fn app_matches(app: &AppRow, needle: &str) -> bool {
    app.name.to_ascii_lowercase().contains(needle)
        || app.domains.iter().any(|d| domain_matches(d, needle))
}

/// The destinations to show under a matched app: the ones matching the needle,
/// or — when the match was on the app name alone — every candidate destination
/// so the user still sees what the named app reaches.
#[must_use]
pub fn matched_domains<'a>(candidates: &[&'a DomainRow], needle: &str) -> Vec<&'a DomainRow> {
    let hits: Vec<&DomainRow> = candidates
        .iter()
        .copied()
        .filter(|d| domain_matches(d, needle))
        .collect();
    if hits.is_empty() {
        candidates.to_vec()
    } else {
        hits
    }
}

/// Whether a member process matches by name or pid.
#[must_use]
pub fn proc_matches(p: &ProcRow, needle: &str) -> bool {
    p.name.to_ascii_lowercase().contains(needle) || p.id.contains(needle)
}

/// Whether a group matches on its *own* identity (name or id), ignoring members.
/// A self-match shows every child; otherwise only the matching children show.
#[must_use]
pub fn group_self_matches(g: &ProcGroup, needle: &str) -> bool {
    g.name.to_ascii_lowercase().contains(needle) || g.id.to_ascii_lowercase().contains(needle)
}

/// Whether a process group matches: its own identity or any member process.
#[must_use]
pub fn group_matches(g: &ProcGroup, needle: &str) -> bool {
    group_self_matches(g, needle) || g.procs.iter().any(|p| proc_matches(p, needle))
}

/// Delete the trailing word from a query — the option+Backspace ("delete word")
/// behaviour. Trailing whitespace is dropped first, then the final run of
/// non-whitespace, leaving the query up to and including the separating space
/// (`"one two three"` → `"one two "`, `"one"` → `""`). Unicode-safe: it slices
/// on char boundaries so multibyte whitespace never panics.
#[must_use]
pub fn delete_last_word(query: &str) -> String {
    let trimmed = query.trim_end();
    match trimmed
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
    {
        Some((idx, c)) => trimmed[..idx + c.len_utf8()].to_string(),
        None => String::new(),
    }
}

impl Panel {
    /// The always-visible filter bar pinned above the list on both tabs. A
    /// hand-rolled field (the panel has no `TextInput` at this layer): icon-less
    /// on the left, the left-aligned query with the caret immediately after it
    /// while focused (or a dim placeholder while idle), a clear (✕) when it holds
    /// text, and a quiet ⌘F hint when idle. Monochrome.
    pub(super) fn render_filter_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let query = self.state.filter().to_string();
        let active = self.state.filter_active();
        let has_query = !query.is_empty();

        let on_focus = cx.listener(|panel, _ev, window: &mut Window, cx| {
            panel.state.set_filter_active(true);
            window.focus(&panel.filter_focus);
            cx.notify();
        });
        // The clear affordance clears the query *and* blurs the field (so the full
        // list returns) — then stops propagation so the field's focus handler
        // doesn't re-activate it on the same click.
        let on_clear = cx.listener(|panel, _ev, window: &mut Window, cx| {
            cx.stop_propagation();
            panel.state.clear_filter();
            panel.state.set_filter_active(false);
            window.focus(&panel.filter_focus);
            cx.notify();
        });

        div()
            .flex()
            .flex_row()
            .items_center()
            .px(SPACE_LG)
            .py(px(6.0))
            .border_b_1()
            .border_color(p.hairline)
            .child(
                div()
                    .id("filter-field")
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .h(px(26.0))
                    .px(px(8.0))
                    .rounded(RADIUS_SM)
                    .bg(p.trough)
                    .border_1()
                    .border_color(if active { p.text_dim } else { p.hairline })
                    .cursor_text()
                    .on_click(on_focus)
                    .child(filter_content(p, &query, active))
                    .when(has_query, |el| el.child(clear_button(p, on_clear)))
                    .when(!active && !has_query, |el| {
                        el.child(
                            div()
                                .text_size(FONT_MICRO)
                                .text_color(p.text_faint)
                                .child("⌘F"),
                        )
                    }),
            )
    }

    /// Route key presses while the tab body is focused. ⌘F focuses the field;
    /// once focused, Esc clears *and* blurs, Enter blurs, and printable characters
    /// append. Backspace deletes one char, option+Backspace deletes the last word,
    /// and cmd+Backspace clears the whole query (macOS "delete to start of line").
    /// Non-⌘F keys are ignored while the field is idle so they never get swallowed.
    pub(super) fn on_filter_key(
        &mut self,
        event: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let key = event.keystroke.key.as_str();
        let mods = event.keystroke.modifiers;
        if mods.platform && key == "f" {
            self.state.set_filter_active(true);
            window.focus(&self.filter_focus);
            cx.notify();
            return;
        }
        if !self.state.filter_active() {
            return;
        }
        if key == "escape" {
            self.state.clear_filter();
            self.state.set_filter_active(false);
            cx.notify();
            return;
        }
        if key == "backspace" {
            if mods.platform {
                self.state.clear_filter();
            } else if mods.alt {
                let trimmed = delete_last_word(self.state.filter());
                self.state.set_filter(trimmed);
            } else {
                self.state.pop_filter_char();
            }
            cx.notify();
            return;
        }
        if key == "enter" {
            self.state.set_filter_active(false);
            cx.notify();
            return;
        }
        if mods.platform || mods.control {
            return;
        }
        if let Some(text) = printable_char(event) {
            self.state.push_filter_text(&text);
            cx.notify();
        }
    }

    /// A subtle centred "no matches" placeholder for an empty filtered list.
    pub(super) fn render_no_matches(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        div()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .py(px(40.0))
            .gap(px(4.0))
            .child(
                div()
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_dim)
                    .child("No matches"),
            )
            .child(
                div()
                    .text_size(FONT_MICRO)
                    .text_color(p.text_faint)
                    .child(format!("Nothing matches “{}”", self.state.filter().trim())),
            )
    }
}

/// The field's left content: the left-aligned query text with the caret sitting
/// immediately after it while focused (so an empty focused field shows the caret
/// at the left), or a dim placeholder while idle and empty. `flex_1` fills the
/// field so any trailing clear/⌘F affordance is pushed to the right edge.
fn filter_content(p: super::theme::Palette, query: &str, active: bool) -> impl IntoElement {
    let has_query = !query.is_empty();
    let mut row = div()
        .flex_1()
        .min_w_0()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(1.0))
        .overflow_hidden();
    if has_query {
        row = row.child(
            div()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(query.to_string()),
        );
    } else if !active {
        row = row.child(
            div()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text_faint)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(PLACEHOLDER),
        );
    }
    if active {
        row = row.child(div().w(px(1.0)).h(px(13.0)).bg(p.text_dim));
    }
    row
}

/// The small round clear (✕) affordance shown when the field holds text.
fn clear_button(
    p: super::theme::Palette,
    on_clear: impl Fn(&gpui::ClickEvent, &mut Window, &mut gpui::App) + 'static,
) -> impl IntoElement {
    div()
        .id("filter-clear")
        .flex()
        .items_center()
        .justify_center()
        .w(px(16.0))
        .h(px(16.0))
        .rounded(RADIUS_XS)
        .cursor_pointer()
        .text_size(FONT_MICRO)
        .text_color(p.text_dim)
        .hover(|s| s.bg(p.hover))
        .child("✕")
        .on_click(on_clear)
}

#[cfg(test)]
#[path = "filter_test.rs"]
mod filter_test;
