//! The header popovers: the quick-settings popover (from the mode pill) and the
//! small `⋯` app menu.
//!
//! The quick popover is intentionally scroll-free — Allow/Block radios, the
//! coming-soon "Ask" row, the Apple/DNS toggles, and a "Rules & Settings…"
//! footer link. Groups, the allow list, and the block list moved to the pushed
//! [`super::rules_view`] so this card never crams or scrolls. All controls read
//! the cached [`ipc::protocol::WireProfile`] and drive the granular policy
//! mutations on [`Panel`]; nothing blocks render.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    ClickEvent, Context, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use ipc::protocol::WireMode;

use super::panel::Panel;
use super::policy::{popover_card, popover_title};
use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, RADIUS_SM, palette};
use super::widgets::switch;

/// What a `⋯`-menu row does when clicked.
#[derive(Clone, Copy)]
enum MenuAction {
    /// Hide the window (the app keeps running); reappears via the menu-bar shield.
    Hide,
    /// Open the pushed Rules & Settings view.
    Settings,
    /// Quit the process.
    Quit,
}

impl Panel {
    /// The quick-settings popover card (from the mode pill).
    pub(super) fn render_quick_popover(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let Some(profile) = self.profile.clone() else {
            // No profile yet. Distinguish "still loading from the daemon" from
            // "no daemon at all" so a read-only fallback never shows an eternal
            // "Loading…" spinner.
            let placeholder = if self.policy_available {
                loading_row(p)
            } else {
                unavailable_row(p)
            };
            return popover_card(p)
                .child(popover_title(p, "QUICK SETTINGS"))
                .child(placeholder);
        };
        let mode = profile.mode;

        popover_card(p)
            .child(popover_title(p, "QUICK SETTINGS"))
            .child(mode_radio(
                p,
                "Allow All",
                "Allow all connections, log traffic",
                mode == WireMode::AllowAll,
                WireMode::AllowAll,
                cx,
            ))
            .child(mode_radio(
                p,
                "Block All",
                "Deny unless an exception allows it",
                mode == WireMode::BlockAll,
                WireMode::BlockAll,
                cx,
            ))
            .child(ask_soon_row(p))
            .child(hairline(p))
            .child(check_row(
                p,
                "sw-apple",
                "Allow Apple Programs",
                profile.allow_apple_programs,
                ToggleKind::Apple,
                cx,
            ))
            .child(check_row(
                p,
                "sw-dns",
                "Allow DNS Traffic",
                profile.allow_dns_traffic,
                ToggleKind::Dns,
                cx,
            ))
            .child(hairline(p))
            .child(Self::rules_link(p, cx))
    }

    /// The `⋯` app menu card: Hide window, Rules & Settings, then Quit.
    pub(super) fn render_menu_popover(cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        popover_card(p)
            .w(px(190.0))
            .child(Self::menu_item(
                p,
                "menu-hide",
                "Hide window",
                MenuAction::Hide,
                cx,
            ))
            .child(Self::menu_item(
                p,
                "menu-rules",
                "Rules & Settings…",
                MenuAction::Settings,
                cx,
            ))
            .child(hairline(p))
            .child(Self::menu_item(
                p,
                "menu-quit",
                "Quit macwarden",
                MenuAction::Quit,
                cx,
            ))
    }

    /// The quick popover's footer link into the full Rules & Settings view.
    fn rules_link(p: Palette, cx: &mut Context<Panel>) -> impl IntoElement {
        let on_click = cx.listener(|panel, _ev: &ClickEvent, window: &mut Window, cx| {
            panel.open_settings(window, cx);
        });
        div()
            .id("quick-rules-link")
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .py(px(4.0))
            .px(px(2.0))
            .rounded(RADIUS_SM)
            .cursor_pointer()
            .hover(|s| s.bg(p.hover))
            .on_click(on_click)
            .child(
                div()
                    .text_size(FONT_CAPTION)
                    .text_color(p.text)
                    .child("Rules & Settings…"),
            )
            .child(
                div()
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_dim)
                    .child("›"),
            )
    }

    /// One `⋯`-menu row, dispatching on its [`MenuAction`]: hide the window
    /// (a firewall keeps running), open the Rules view, or quit the process.
    fn menu_item(
        p: Palette,
        id: &'static str,
        label: &'static str,
        action: MenuAction,
        cx: &mut Context<Panel>,
    ) -> impl IntoElement {
        let on_click =
            cx.listener(
                move |panel, _ev: &ClickEvent, window: &mut Window, cx| match action {
                    MenuAction::Hide => {
                        panel.state.close_popover();
                        cx.hide();
                    }
                    MenuAction::Settings => panel.open_settings(window, cx),
                    MenuAction::Quit => cx.quit(),
                },
            );
        div()
            .id(ElementId::Name(id.into()))
            .flex()
            .items_center()
            .py(px(5.0))
            .px(px(4.0))
            .rounded(RADIUS_SM)
            .cursor_pointer()
            .hover(|s| s.bg(p.hover))
            .text_size(FONT_CAPTION)
            .text_color(p.text)
            .child(label)
            .on_click(on_click)
    }
}

/// One mode radio row: a ring/filled-dot indicator, a label, and a caption.
fn mode_radio(
    p: Palette,
    label: &'static str,
    caption: &'static str,
    selected: bool,
    mode: WireMode,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let on_click = cx.listener(move |panel, _ev, _win, cx| {
        panel.commit_mode(mode, cx);
        cx.notify();
    });
    // Block-All selection reads in the semantic red; Allow-All in green.
    let fill = match mode {
        WireMode::BlockAll => p.red,
        WireMode::AllowAll => p.accent,
    };
    let id = if matches!(mode, WireMode::BlockAll) {
        "radio-block"
    } else {
        "radio-allow"
    };
    div()
        .id(id)
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .py(px(3.0))
        .cursor_pointer()
        .on_click(on_click)
        .child(radio_dot(p, selected, fill))
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .child(
                    div()
                        .text_size(FONT_CAPTION)
                        .text_color(p.text)
                        .child(label),
                )
                .child(
                    div()
                        .text_size(FONT_MICRO)
                        .text_color(p.text_faint)
                        .child(caption),
                ),
        )
}

/// A checkbox-style switch row (Apple / DNS).
fn check_row(
    p: Palette,
    id: &'static str,
    label: &'static str,
    on: bool,
    kind: ToggleKind,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let handler = cx.listener(move |panel, _ev: &ClickEvent, _win: &mut Window, cx| {
        match kind {
            ToggleKind::Apple => panel.commit_apple(!on, cx),
            ToggleKind::Dns => panel.commit_dns(!on, cx),
        }
        cx.notify();
    });
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .gap(px(8.0))
        .py(px(2.0))
        .child(
            div()
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .child(label),
        )
        .child(switch(p, ElementId::Name(id.into()), on, true, handler))
}

/// Which flag a [`check_row`] toggles.
#[derive(Clone, Copy)]
enum ToggleKind {
    Apple,
    Dns,
}

/// A radio indicator: a ring that fills with the semantic colour when selected.
fn radio_dot(p: Palette, selected: bool, fill: gpui::Hsla) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .w(px(14.0))
        .h(px(14.0))
        .rounded(px(7.0))
        .border_1()
        .border_color(if selected { fill } else { p.switch_track })
        .when(selected, |el| {
            el.child(div().w(px(7.0)).h(px(7.0)).rounded(px(4.0)).bg(fill))
        })
}

/// The disabled, coming-soon "Ask for unknown connection" row.
fn ask_soon_row(p: Palette) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .py(px(3.0))
        .child(
            div()
                .w(px(14.0))
                .h(px(14.0))
                .rounded(px(7.0))
                .border_1()
                .border_color(p.switch_track.opacity(0.5)),
        )
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .child(
                    div()
                        .text_size(FONT_CAPTION)
                        .text_color(p.text_faint)
                        .child("Ask for unknown connection"),
                )
                .child(
                    div()
                        .text_size(FONT_MICRO)
                        .text_color(p.text_faint)
                        .child("Coming soon"),
                ),
        )
}

/// A faint full-width hairline separator inside the card.
fn hairline(p: Palette) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(p.hairline)
}

/// The placeholder shown before the first profile fetch lands. Returns a concrete
/// [`gpui::Div`] so it shares one type with [`unavailable_row`] at a call site.
fn loading_row(p: Palette) -> gpui::Div {
    placeholder_row(p, "Loading…")
}

/// The placeholder shown when no daemon policy backend is available (the panel is
/// on the read-only fallback source), instead of an eternal "Loading…".
fn unavailable_row(p: Palette) -> gpui::Div {
    placeholder_row(p, "daemon unavailable — read-only")
}

/// A faint, un-interactive placeholder row carrying `label`.
fn placeholder_row(p: Palette, label: &'static str) -> gpui::Div {
    div()
        .py(px(6.0))
        .text_size(FONT_CAPTION)
        .text_color(p.text_faint)
        .child(label)
}
