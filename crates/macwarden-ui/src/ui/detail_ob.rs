//! The inspector's openbinary **verdict hero** — the focal identity element at
//! the top of the detail body, split out of [`super::detail`].
//!
//! A settled verdict reads as a status pip + label in its semantic tone, an
//! optional title and one-line summary, and (when the binary's SHA-256 is
//! cached) a clickable affordance that opens the binary's page on
//! `openbinary.ai`. In-flight, unknown, error, and too-large states fall back to
//! a neutral hero with the matching action button.

use std::path::Path;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, Context, Hsla, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, px,
};

use super::panel::Panel;
use super::theme::{FONT_BODY, FONT_CAPTION, FONT_MICRO, Palette, RADIUS, RADIUS_XS, SPACE_MD};
use super::widgets::{text_button, tone_color};
use crate::data::openbinary::{ObState, ObVerdict};

/// The base URL for a binary's public openbinary.ai page (`/binary/<sha256>`).
const OB_BINARY_URL: &str = "https://www.openbinary.ai/binary/";

/// Render the verdict hero for the current live cache state.
///
/// Every state that has a cached SHA-256 renders a clickable link out to the
/// binary's `openbinary.ai` page — malicious, benign, "Analyzing…", "not in
/// openbinary", error — so the user can always review the internals themselves.
/// Only the pre-hash "Checking…" state (no SHA yet) is unlinked.
pub(super) fn verdict_hero(
    p: Palette,
    key: &Path,
    state: Option<&ObState>,
    sha: Option<String>,
    auto: bool,
    cx: &mut Context<Panel>,
) -> AnyElement {
    match state {
        None | Some(ObState::Pending) => hero_status(p, "Checking openbinary…", sha, cx),
        Some(ObState::Uploading | ObState::Analyzing) => hero_status(p, "Analyzing…", sha, cx),
        Some(ObState::Error) => hero_action(p, key, "openbinary unreachable", "Retry", sha, cx),
        Some(ObState::TooLarge) => hero_action(
            p,
            key,
            "Too large to auto-analyze",
            "Upload anyway",
            sha,
            cx,
        ),
        Some(ObState::Unknown) => hero_unknown(p, key, auto, sha, cx),
        Some(ObState::Known {
            verdict,
            title,
            summary,
        }) => hero_known(p, *verdict, title.as_deref(), summary.as_deref(), sha, cx),
    }
}

/// Wrap a hero frame as a clickable link to the binary's `openbinary.ai` page
/// when its SHA-256 is available; otherwise return the frame unchanged. Subtle
/// monochrome affordance — the border brightens on hover (the ↗ cue lives in the
/// headline row).
fn linkify(
    frame: gpui::Div,
    sha: Option<String>,
    hover: Hsla,
    cx: &mut Context<Panel>,
) -> AnyElement {
    let Some(sha) = sha else {
        return frame.into_any_element();
    };
    let url = format!("{OB_BINARY_URL}{sha}");
    let handler = cx.listener(move |_panel, _ev, _win, cx| cx.open_url(&url));
    frame
        .id("ob-hero-link")
        .cursor_pointer()
        .hover(move |s| s.border_color(hover))
        .on_click(handler)
        .into_any_element()
}

/// The trailing ↗ link glyph shown when a SHA is available.
fn link_glyph(sha: Option<&str>) -> Option<&'static str> {
    sha.map(|_| "↗")
}

/// The static (demo / non-live) hero: the source's pre-rendered verdict line in
/// a neutral frame. Never clickable — there is no cached SHA to link.
pub(super) fn verdict_hero_static(p: Palette, line: &str) -> AnyElement {
    hero_frame(p.hairline)
        .child(hero_line(
            p,
            p.text_faint,
            "openbinary",
            line.to_string(),
            None,
        ))
        .into_any_element()
}

/// A settled verdict. Tone-coloured pip + label, optional title and summary, and
/// — when the SHA is cached — a clickable frame that opens the binary's page.
fn hero_known(
    p: Palette,
    verdict: ObVerdict,
    title: Option<&str>,
    summary: Option<&str>,
    sha: Option<String>,
    cx: &mut Context<Panel>,
) -> AnyElement {
    let color = tone_color(p, verdict.tone());
    let head = hero_line(
        p,
        color,
        verdict.label(),
        title_or_default(title),
        link_glyph(sha.as_deref()),
    );
    let mut frame = hero_frame(color.opacity(0.32))
        .bg(color.opacity(0.12))
        .child(head);
    if let Some(s) = summary {
        frame = frame.child(
            div()
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(s.to_owned()),
        );
    }
    linkify(frame, sha, color.opacity(0.6), cx)
}

/// The "unknown to openbinary" hero. With `auto_upload` on the lookup already
/// uploaded, so this is a neutral status; otherwise it offers an explicit
/// upload button (the only way an upload happens in that mode). Either way the
/// SHA (known after the 404) still links out.
fn hero_unknown(
    p: Palette,
    key: &Path,
    auto: bool,
    sha: Option<String>,
    cx: &mut Context<Panel>,
) -> AnyElement {
    if auto {
        return hero_status(p, "Not in openbinary", sha, cx);
    }
    hero_action(p, key, "Not in openbinary", "Identify (upload)", sha, cx)
}

/// A neutral status hero (in-flight / unknown-with-auto). Links out to the
/// binary's openbinary.ai page whenever a SHA is available.
fn hero_status(
    p: Palette,
    label: &'static str,
    sha: Option<String>,
    cx: &mut Context<Panel>,
) -> AnyElement {
    let frame = hero_frame(p.hairline).child(hero_line(
        p,
        p.text_faint,
        "openbinary",
        label.to_string(),
        link_glyph(sha.as_deref()),
    ));
    linkify(frame, sha, p.text_faint, cx)
}

/// A neutral hero with a dim status line, an explicit upload/retry button, and —
/// when a SHA is available — a small ↗ link out to the binary's page (kept
/// separate from the button so the two actions don't collide).
fn hero_action(
    p: Palette,
    key: &Path,
    label: &'static str,
    action: &'static str,
    sha: Option<String>,
    cx: &mut Context<Panel>,
) -> AnyElement {
    let key = key.to_path_buf();
    let identify = cx.listener(move |panel, _ev, _win, cx| {
        panel.ob.identify(&key);
        cx.notify();
    });
    let mut row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .child(hero_pip(p.text_faint))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text_dim)
                .child(label),
        );
    if let Some(sha) = sha {
        let url = format!("{OB_BINARY_URL}{sha}");
        let open = cx.listener(move |_panel, _ev, _win, cx| cx.open_url(&url));
        row = row.child(
            div()
                .id("ob-open-link")
                .flex_shrink_0()
                .cursor_pointer()
                .text_size(FONT_CAPTION)
                .text_color(p.text_faint)
                .hover(|s| s.text_color(p.text_dim))
                .child("↗")
                .on_click(open),
        );
    }
    row = row.child(text_button(p, "ob-identify", action, true, true, identify));
    hero_frame(p.hairline).child(row).into_any_element()
}

/// The hero's headline row: a status pip, the verdict label in its tone, an
/// optional dim subtitle, and an optional trailing glyph (the ↗ link cue).
fn hero_line(
    p: Palette,
    color: Hsla,
    label: &str,
    subtitle: String,
    trailing: Option<&'static str>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .child(hero_pip(color))
        .child(
            div()
                .text_size(FONT_BODY)
                .text_color(color)
                .child(label.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text_dim)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(subtitle),
        )
        .when_some(trailing, |el, glyph| {
            el.child(
                div()
                    .flex_shrink_0()
                    .text_size(FONT_CAPTION)
                    .text_color(p.text_faint)
                    .child(glyph),
            )
        })
}

/// The hero's rounded frame at a given border tone. No fill by default — the
/// hairline border alone frames the neutral states; a settled verdict adds its
/// own semantic tint on top (see [`hero_known`]).
fn hero_frame(border: Hsla) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .p(SPACE_MD)
        .rounded(RADIUS)
        .border_1()
        .border_color(border)
}

/// An 8px filled status pip.
fn hero_pip(color: Hsla) -> impl IntoElement {
    div().w(px(8.0)).h(px(8.0)).rounded(RADIUS_XS).bg(color)
}

/// The subtitle for a known verdict — the server title, or a quiet fallback.
fn title_or_default(title: Option<&str>) -> String {
    title
        .filter(|t| !t.is_empty())
        .map_or_else(|| "analyzed by openbinary".to_string(), str::to_owned)
}

#[cfg(test)]
#[path = "detail_ob_test.rs"]
mod detail_ob_test;
