//! The panel palette — an "Apple-quiet" dark theme.
//!
//! Adapted from zero's `theme/` system but self-contained: zero's `color.rs`/
//! `surface.rs` read colours through `gpui_component::ActiveTheme`, which would
//! drag in the whole gpui-component tree. The panel needs only a fixed dark
//! palette, so it lives here as a [`Palette`] global built from the zero
//! neutrals.
//!
//! Identity: **monochrome chrome + semantic colour**. The chrome (tabs, scope
//! row, titlebar, footer) is pure grayscale — selection is a subtle light fill,
//! never a brand tint. Colour carries meaning only: system green = allowed / a
//! toggle that is on, red = blocked / known-bad, amber = suspicious, violet =
//! tracker. Flat surfaces, hairline rules, no gradients, no neon.

mod tokens;

pub use tokens::*;

use gpui::{App, Global, Hsla, Rgba, rgb, rgba};

/// The fixed dark palette. Grayscale chrome plus four semantic colours: system
/// green (allow / switch-on), red (blocked / known-bad), amber (suspicious),
/// violet (tracker). Everything else is a neutral or a hairline.
#[derive(Clone, Copy)]
pub struct Palette {
    /// Window background (`#141619`-family).
    pub bg: Hsla,
    /// Slightly raised surface for detail cards and tooltips.
    pub surface: Hsla,
    /// The inset trough of the segmented tab control.
    pub trough: Hsla,
    /// The selected-segment fill — a subtle light wash, never a brand tint.
    pub sel: Hsla,
    /// Row hover wash.
    pub hover: Hsla,
    /// Hairline separators — `rgba(255,255,255,0.06)`.
    pub hairline: Hsla,
    /// Primary text.
    pub text: Hsla,
    /// Secondary text.
    pub text_dim: Hsla,
    /// Tertiary / faint text.
    pub text_faint: Hsla,
    /// System green — the ONLY green: allow dots, openbinary "good", switch-on.
    pub accent: Hsla,
    /// Blocked / known-bad.
    pub red: Hsla,
    /// Suspicious — openbinary amber.
    pub amber: Hsla,
    /// Tracker.
    pub purple: Hsla,
    /// Switch off-track colour.
    pub switch_track: Hsla,
    /// Neutral monogram tile fill.
    pub tile: Hsla,
}

impl Global for Palette {}

fn h(c: Rgba) -> Hsla {
    c.into()
}

impl Default for Palette {
    #[allow(clippy::unreadable_literal)]
    fn default() -> Self {
        Self {
            bg: h(rgb(0x141619)),
            surface: h(rgba(0xffffff12)),
            trough: h(rgba(0x00000040)),
            sel: h(rgba(0xffffff1f)),
            hover: h(rgba(0xffffff0d)),
            hairline: h(rgba(0xffffff10)),
            text: h(rgb(0xededed)),
            text_dim: h(rgb(0x8b9096)),
            text_faint: h(rgb(0x5c6066)),
            accent: h(rgb(0x30d158)),
            red: h(rgb(0xe5595e)),
            amber: h(rgb(0xe0a852)),
            purple: h(rgb(0xa27cf0)),
            switch_track: h(rgb(0x3a3d42)),
            tile: h(rgba(0xffffff14)),
        }
    }
}

/// Install the palette global. Call once at startup.
pub fn init(cx: &mut App) {
    cx.set_global(Palette::default());
}

/// Fetch the active palette.
#[must_use]
pub fn palette(cx: &App) -> Palette {
    *cx.global::<Palette>()
}
