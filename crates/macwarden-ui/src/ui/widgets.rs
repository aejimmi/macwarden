//! Small hand-rolled widgets — monogram tile, verdict dot, two-state switch,
//! segmented control, tooltip. gpui-component is intentionally not used; these
//! are cheap and keep the panel a lean leaf binary.

use std::sync::Arc;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, AnyView, App, AppContext as _, ClickEvent, ElementId, Hsla,
    InteractiveElement as _, IntoElement, ParentElement as _, Render, RenderImage, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div, img, px,
};

use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, RADIUS_SM, RADIUS_XS};
use crate::data::model::Verdict;
use crate::data::openbinary::ObTone;

/// A neutral rounded-square monogram tile used until a real icon is wired in.
pub fn monogram(p: Palette, initial: char, size: gpui::Pixels) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .w(size)
        .h(size)
        .rounded(RADIUS_SM)
        .bg(p.tile)
        .text_size(FONT_MICRO)
        .text_color(p.text_dim)
        .child(SharedString::from(initial.to_string()))
}

/// The single icon swap point: a real app icon when `icon` is `Some`, else the
/// neutral monogram fallback. Every row and inspector tile routes through here.
pub fn tile(
    p: Palette,
    icon: Option<Arc<RenderImage>>,
    initial: char,
    size: gpui::Pixels,
) -> AnyElement {
    match icon {
        Some(image) => div()
            .w(size)
            .h(size)
            .rounded(RADIUS_SM)
            .overflow_hidden()
            .child(img(image).w(size).h(size))
            .into_any_element(),
        None => monogram(p, initial, size).into_any_element(),
    }
}

/// A footer metric cell: a dim label and a monospace, tabular value. Cells sit
/// in a row separated by [`footer_divider`] hairlines (the FireWally
/// "In: 406 MB | Out: 14.5 MB" pattern). The value column has a fixed min-width
/// so the bar never reflows as the number ticks.
pub fn footer_cell(p: Palette, label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(5.0))
        .child(
            div()
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(label),
        )
        .child(
            div()
                .min_w(px(52.0))
                .font_family("ui-monospace")
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .child(value),
        )
}

/// A hairline vertical divider between two [`footer_cell`]s.
pub fn footer_divider(p: Palette) -> impl IntoElement {
    div().w(px(1.0)).h(px(12.0)).bg(p.hairline)
}

/// The colour a verdict dot renders in.
#[must_use]
pub fn verdict_color(p: Palette, v: Verdict) -> Hsla {
    match v {
        Verdict::Allow => p.accent,
        Verdict::Blocked => p.red,
        Verdict::Tracker => p.purple,
    }
}

/// A 6px verdict dot.
pub fn dot(p: Palette, v: Verdict) -> impl IntoElement {
    div()
        .w(px(6.0))
        .h(px(6.0))
        .rounded(RADIUS_XS)
        .bg(verdict_color(p, v))
}

/// The colour an openbinary verdict tone renders in.
#[must_use]
pub fn tone_color(p: Palette, tone: ObTone) -> Hsla {
    match tone {
        ObTone::Good => p.accent,
        ObTone::Warn => p.amber,
        ObTone::Bad => p.red,
        ObTone::Neutral => p.text_faint,
    }
}

/// A 6px status dot in the given semantic colour, flagging a binary's openbinary
/// severity on a passive list row. List rows carry only this dot — never a text
/// chip — per the brand rule (color-as-meaning in rows, no row tags).
pub fn severity_dot(color: Hsla) -> impl IntoElement {
    div().w(px(6.0)).h(px(6.0)).rounded(RADIUS_XS).bg(color)
}

/// A two-state switch. `on` = accent-tinted track, thumb to the right.
pub fn switch(
    p: Palette,
    id: impl Into<ElementId>,
    on: bool,
    enabled: bool,
    handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let track = if on { p.accent } else { p.switch_track };
    let track = if enabled { track } else { track.opacity(0.4) };
    div()
        .id(id.into())
        .flex()
        .items_center()
        .w(px(28.0))
        .h(px(17.0))
        .rounded(px(9.0))
        .px(px(2.0))
        .bg(track)
        .when(on, gpui::Styled::justify_end)
        .when(!on, gpui::Styled::justify_start)
        .when(enabled, |el| el.cursor_pointer().on_click(handler))
        .child(
            div()
                .w(px(13.0))
                .h(px(13.0))
                .rounded(px(7.0))
                .bg(if on { gpui::white() } else { p.text })
                .opacity(if enabled { 1.0 } else { 0.6 }),
        )
}

/// The three states of a group switch: every member on, every member off, or a
/// mix. Drives the aggregate "macOS System" toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchState {
    /// Every member is allowed — reads like an `on` switch.
    On,
    /// Every member is blocked — reads like an `off` switch.
    Off,
    /// Members disagree — a centered indeterminate dash.
    Mixed,
}

/// A tri-state group switch: `On` (accent track, thumb right), `Off` (thumb
/// left), or `Mixed` (a centered dash in a neutral track) — for an aggregate
/// control over many rows. Clicking it applies the group action.
pub fn group_switch(
    p: Palette,
    id: impl Into<ElementId>,
    state: SwitchState,
    enabled: bool,
    handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let track = match state {
        SwitchState::On => p.accent,
        SwitchState::Off | SwitchState::Mixed => p.switch_track,
    };
    let track = if enabled { track } else { track.opacity(0.4) };
    let base = div()
        .id(id.into())
        .flex()
        .items_center()
        .w(px(28.0))
        .h(px(17.0))
        .rounded(px(9.0))
        .px(px(2.0))
        .bg(track)
        .when(state == SwitchState::On, gpui::Styled::justify_end)
        .when(state == SwitchState::Off, gpui::Styled::justify_start)
        .when(state == SwitchState::Mixed, gpui::Styled::justify_center)
        .when(enabled, |el| el.cursor_pointer().on_click(handler));
    match state {
        // Mixed: a short centered bar reads as "indeterminate", distinct from the
        // left/right round thumb of Off/On.
        SwitchState::Mixed => base.child(
            div()
                .w(px(10.0))
                .h(px(3.0))
                .rounded(px(2.0))
                .bg(p.text)
                .opacity(if enabled { 1.0 } else { 0.6 }),
        ),
        SwitchState::On | SwitchState::Off => base.child(
            div()
                .w(px(13.0))
                .h(px(13.0))
                .rounded(px(7.0))
                .bg(if state == SwitchState::On {
                    gpui::white()
                } else {
                    p.text
                })
                .opacity(if enabled { 1.0 } else { 0.6 }),
        ),
    }
}

/// One-item metadata for [`segmented`].
pub struct Seg<T: Copy + 'static> {
    /// The value this segment selects.
    pub value: T,
    /// The visible label.
    pub label: SharedString,
}

/// The native-macOS segmented-pill control — the panel's primary affordance. A
/// rounded inset trough spanning the full width, with equal-weight segments. The
/// selected segment is a subtle light fill with the primary label colour; the
/// rest are dim gray. Grayscale only — no brand tint (see the scope row for the
/// quieter subordinate variant).
pub fn segmented<T: Copy + PartialEq + 'static>(
    p: Palette,
    id: &'static str,
    segments: Vec<Seg<T>>,
    selected: T,
    on_select: impl Fn(T, &mut Window, &mut App) + Clone + 'static,
) -> impl IntoElement {
    let mut row = div()
        .flex()
        .flex_row()
        .w_full()
        .gap(px(2.0))
        .p(px(2.0))
        .rounded(RADIUS_SM)
        .bg(p.trough);
    for (i, seg) in segments.into_iter().enumerate() {
        let is_sel = seg.value == selected;
        let value = seg.value;
        let cb = on_select.clone();
        row = row.child(
            div()
                .id(ElementId::Name(format!("{id}-{i}").into()))
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .py(px(4.0))
                .rounded(RADIUS_XS)
                .cursor_pointer()
                .when(is_sel, |el| el.bg(p.sel))
                .text_size(FONT_CAPTION)
                .text_color(if is_sel { p.text } else { p.text_dim })
                .child(seg.label)
                .on_click(move |_ev, win, cx| cb(value, win, cx)),
        );
    }
    row
}

/// The quiet subordinate control used for the scope row: grayscale text that
/// brightens to the primary colour on selection — no chip, no underline, no
/// tint. `scope_button` composes into a row beneath the segmented tabs.
pub fn scope_button(
    p: Palette,
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    active: bool,
    handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id.into())
        .px(px(2.0))
        .py(px(2.0))
        .cursor_pointer()
        .text_size(FONT_CAPTION)
        .text_color(if active { p.text } else { p.text_dim })
        .child(label.into())
        .on_click(handler)
}

/// A small text button (used for scope selection and inspector actions).
pub fn text_button(
    p: Palette,
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    active: bool,
    enabled: bool,
    handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id.into())
        .px(px(7.0))
        .py(px(2.0))
        .rounded(RADIUS_XS)
        .text_size(FONT_CAPTION)
        .text_color(if !enabled {
            p.text_faint
        } else if active {
            p.text
        } else {
            p.text_dim
        })
        .when(enabled, |el| el.cursor_pointer().on_click(handler))
        .child(label.into())
}

// -- Tooltip ------------------------------------------------------------------

/// A minimal tooltip surface.
pub struct Tip {
    text: SharedString,
    palette: Palette,
}

impl Render for Tip {
    fn render(&mut self, _window: &mut Window, _cx: &mut gpui::Context<Self>) -> impl IntoElement {
        div()
            .px(px(7.0))
            .py(px(3.0))
            .rounded(RADIUS_SM)
            .bg(self.palette.surface)
            .border_1()
            .border_color(self.palette.hairline)
            .text_size(FONT_CAPTION)
            .text_color(self.palette.text)
            .child(self.text.clone())
    }
}

/// Build a tooltip closure for `.tooltip(...)`.
pub fn tip(text: impl Into<SharedString>) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text = text.into();
    move |_window, cx| {
        let text = text.clone();
        let palette = super::theme::palette(cx);
        cx.new(|_| Tip {
            text: text.clone(),
            palette,
        })
        .into()
    }
}
