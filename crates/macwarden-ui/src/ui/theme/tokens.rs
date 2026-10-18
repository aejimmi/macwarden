//! Layout tokens — adapted (trimmed) from `~/code/zero/zero/crates/ui`.
//!
//! Pure `gpui` values, no theme dependency. Only the tokens the panel actually
//! uses are kept.

use gpui::{Pixels, px};

// -- Typography ---------------------------------------------------------------

/// Tag labels, tiny mono counts (10px).
pub const FONT_MICRO: Pixels = px(10.0);
/// Secondary captions, monospace numbers (11px).
pub const FONT_CAPTION: Pixels = px(11.0);
/// Default body text (13px).
pub const FONT_BODY: Pixels = px(13.0);
/// Inspector / header title (16px).
pub const FONT_TITLE: Pixels = px(16.0);

// -- Corner radii -------------------------------------------------------------

/// Verdict dots, tiny badges.
pub const RADIUS_XS: Pixels = px(3.0);
/// Chips, small controls.
pub const RADIUS_SM: Pixels = px(6.0);
/// Default rows, buttons, icon tiles.
pub const RADIUS: Pixels = px(8.0);

// -- Spacing ------------------------------------------------------------------

/// 4px.
pub const SPACE_SM: Pixels = px(4.0);
/// 8px — default padding.
pub const SPACE_MD: Pixels = px(8.0);
/// 12px — section padding.
pub const SPACE_LG: Pixels = px(12.0);

// -- Icons --------------------------------------------------------------------

/// App icon / monogram tile.
pub const ICON: Pixels = px(22.0);
/// Larger tile for the inspector header — a strong identity anchor.
pub const APP_TILE_LG: Pixels = px(40.0);
/// Left indent applied to a grouped member row (a "macOS System" child) so its
/// nesting under the group header reads clearly.
pub const GROUP_INDENT: Pixels = px(20.0);

// -- Material -----------------------------------------------------------------

// -- Layout -------------------------------------------------------------------

/// Standard row height (spec: 32).
pub const ROW_HEIGHT: Pixels = px(32.0);
/// Nested destination row height.
pub const SUBROW_HEIGHT: Pixels = px(28.0);
/// Window width (spec: ~370).
pub const WINDOW_WIDTH: Pixels = px(372.0);
/// Window height (spec: ~560).
pub const WINDOW_HEIGHT: Pixels = px(560.0);
/// Fixed width of the app-inspector pane on the left of the split trace view —
/// the same width as the compact panel so the inspector reads identically as
/// context beside the trace.
pub const INSPECTOR_PANE_WIDTH: Pixels = px(372.0);
/// Split window width for the packet-trace master-detail view: the inspector
/// pane ([`INSPECTOR_PANE_WIDTH`]) plus the columnar trace (~660). The window
/// expands to this on entering a trace and restores to [`WINDOW_WIDTH`] on close.
pub const WINDOW_WIDTH_SPLIT: Pixels = px(1032.0);
/// Split window height for the trace view — taller than the compact panel so the
/// inspector, the columnar list, and the decode/hex detail all have room.
pub const WINDOW_HEIGHT_SPLIT: Pixels = px(680.0);
