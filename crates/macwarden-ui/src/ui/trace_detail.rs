//! The selected-packet detail pane for the trace view — the decode tree and the
//! raw hex dump laid out **side by side** across the wide canvas (R5/R11).
//!
//! The decode tree (Frame → Ethernet → IP → TCP/UDP → TLS) sits on the left; the
//! offset / hex / ASCII dump on the right, each in its own scroll column so both
//! read comfortably. Clicking a decode node cross-highlights its byte range in
//! the hex (and toggles off on a second click).

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, Context, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, px,
};

use ipc::protocol::WireDecodeNode;

use super::panel::Panel;
use super::theme::{FONT_CAPTION, Palette, SPACE_LG, SPACE_SM, palette};
use crate::data::trace_model::{HexRow, TraceModel, hex_rows};

/// The fixed height of the detail region below the packet list.
const DETAIL_H: gpui::Pixels = px(248.0);

impl Panel {
    /// The decode-tree + hex detail pane for the selected packet, or `None` when
    /// nothing is selected.
    pub(super) fn render_trace_detail(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let p = palette(cx);
        let tv = self.trace.as_ref()?;
        tv.model.selected()?;
        Some(detail_pane(p, &tv.model, cx))
    }
}

/// Build the fixed-height, side-by-side detail pane from the fetched bytes.
fn detail_pane(p: Palette, model: &TraceModel, cx: &mut Context<Panel>) -> AnyElement {
    let container = div()
        .flex()
        .flex_row()
        .h(DETAIL_H)
        .border_t_1()
        .border_color(p.hairline);

    if model.bytes_loading() {
        return container
            .child(pane_note(p, "Loading packet…"))
            .into_any_element();
    }
    if model.bytes_failed() {
        // Terminal: the fetch returned nothing (connection dropped / timed out).
        return container
            .child(pane_note(
                p,
                "Couldn't load this packet — the capture connection dropped or timed out. \
                 Select it again to retry.",
            ))
            .into_any_element();
    }
    let Some(bytes) = model.bytes() else {
        return container
            .child(pane_note(p, "No packet selected."))
            .into_any_element();
    };
    if !bytes.available {
        return container
            .child(pane_note(
                p,
                "Bytes no longer available (aged out of the ring).",
            ))
            .into_any_element();
    }

    let highlight = model.highlight();
    let tree = tree_section(p, bytes.tree.as_ref(), highlight, cx);
    let hex = hex_section(p, &bytes.raw, highlight);
    container.child(tree).child(hex).into_any_element()
}

/// The left column: the expandable decode tree, cross-highlighting on click.
fn tree_section(
    p: Palette,
    tree: Option<&ipc::protocol::WireDecodeTree>,
    highlight: Option<&std::ops::Range<usize>>,
    cx: &mut Context<Panel>,
) -> AnyElement {
    let mut col = div()
        .id("trace-decode")
        .flex_1()
        .min_w_0()
        .h_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .py(SPACE_SM)
        .border_r_1()
        .border_color(p.hairline)
        .child(pane_label(p, "DECODE TREE"));
    if let Some(tree) = tree {
        let mut flat = Vec::new();
        flatten(&tree.root, 0, &mut flat);
        for (depth, node) in flat {
            let sel = highlight == Some(&node.byte_range);
            col = col.child(decode_row(p, depth, node, sel, cx));
        }
    }
    col.into_any_element()
}

/// The right column: the offset / hex / ASCII dump, rows intersecting the
/// highlighted decode node's byte range subtly filled.
fn hex_section(p: Palette, raw: &[u8], highlight: Option<&std::ops::Range<usize>>) -> AnyElement {
    let mut col = div()
        .id("trace-hex")
        .flex_1()
        .min_w_0()
        .h_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .py(SPACE_SM)
        .child(pane_label(p, "HEX"));
    for row in hex_rows(raw) {
        col = col.child(hex_line(p, &row, highlight));
    }
    col.into_any_element()
}

/// One decode-tree row: indented label + summary + byte range, clickable to
/// cross-highlight.
fn decode_row(
    p: Palette,
    depth: usize,
    node: &WireDecodeNode,
    selected: bool,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let range = node.byte_range.clone();
    let on_click = cx.listener(move |panel, _ev, _win, cx| {
        if let Some(tv) = panel.trace.as_mut() {
            tv.model.toggle_highlight(range.clone());
            cx.notify();
        }
    });
    div()
        .id(ElementId::Name(
            format!("dn-{}-{}", node.label, node.byte_range.start).into(),
        ))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .h(px(20.0))
        .pl(px(12.0) + px(12.0 * depth as f32))
        .pr(SPACE_LG)
        .cursor_pointer()
        .when(selected, |el| el.bg(p.sel))
        .hover(|s| s.bg(p.hover))
        .on_click(on_click)
        .child(
            div()
                .flex_shrink_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .child(node.label.clone()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_size(px(10.0))
                .text_color(p.text_dim)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(node.summary.clone()),
        )
        .child(
            div()
                .flex_shrink_0()
                .font_family("ui-monospace")
                .text_size(px(9.0))
                .text_color(p.text_faint)
                .child(format!(
                    "{}..{}",
                    node.byte_range.start, node.byte_range.end
                )),
        )
}

/// One hex-dump line: the offset, then the 16-byte hex column and the ASCII
/// gutter rendered as a **single** monospace run.
///
/// Keeping hex + gutter in one text run is what makes every row line up: the hex
/// column is space-padded to a full 16-byte width, so on a short last row those
/// pad spaces sit *between* the hex and the gutter (never trailing) and the
/// monospace grid holds the gutter at a fixed column. Splitting them into two
/// elements would let GPUI trim the pad's trailing whitespace and drift the
/// gutter left. The offset stays separate (it is always 4 chars, so it cannot
/// drift) to read a shade fainter than the bytes.
fn hex_line(
    p: Palette,
    row: &HexRow,
    highlight: Option<&std::ops::Range<usize>>,
) -> impl IntoElement {
    let hit = highlight.is_some_and(|h| row.range.start < h.end && h.start < row.range.end);
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .pl(SPACE_LG)
        .pr(SPACE_SM)
        .h(px(15.0))
        .when(hit, |el| el.bg(p.sel))
        .font_family("ui-monospace")
        .text_size(px(10.0))
        .child(
            div()
                .flex_shrink_0()
                .text_color(p.text_faint)
                .child(format!("{:04x}", row.offset)),
        )
        .child(
            div()
                .flex_shrink_0()
                .text_color(if hit { p.text } else { p.text_dim })
                .child(format!("{}  {}", row.hex, row.ascii)),
        )
}

/// Flatten the decode tree into `(depth, node)` pairs in display order.
fn flatten<'a>(node: &'a WireDecodeNode, depth: usize, out: &mut Vec<(usize, &'a WireDecodeNode)>) {
    out.push((depth, node));
    for child in &node.children {
        flatten(child, depth + 1, out);
    }
}

/// A dim uppercase pane section label.
fn pane_label(p: Palette, text: &'static str) -> impl IntoElement {
    div()
        .px(SPACE_LG)
        .pb(px(4.0))
        .text_size(px(9.0))
        .text_color(p.text_faint)
        .child(text)
}

/// A centred placeholder note for a pane with no renderable content.
fn pane_note(p: Palette, text: &'static str) -> impl IntoElement {
    div()
        .flex()
        .flex_1()
        .items_center()
        .justify_center()
        .text_size(FONT_CAPTION)
        .text_color(p.text_faint)
        .child(text)
}
