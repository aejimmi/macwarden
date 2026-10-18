//! The wide, columnar packet list for the trace view (R11) — a Proxyman-style
//! aligned table: `#` · Time · Protocol chip · Source · Destination · Domain ·
//! direction. A fixed column-header row sits above the scrolling body; every row
//! shares the same fixed / proportional column widths so the columns stay
//! aligned as packets stream in. Rows are monochrome; only the protocol chip
//! keeps its data-semantic hue.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    Context, ElementId, Hsla, InteractiveElement as _, IntoElement, ParentElement as _, Pixels,
    Stateful, StatefulInteractiveElement as _, Styled as _, div, px, rgb,
};

use ipc::protocol::WirePacketRecord;

use super::panel::Panel;
use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, RADIUS_XS, SPACE_LG, palette};
use crate::data::trace_model::ChipProto;

/// One packet-list row height.
const ROW_H: Pixels = px(24.0);
/// The `#` sequence column width.
const COL_SEQ: Pixels = px(56.0);
/// The capture-time column width.
const COL_TIME: Pixels = px(108.0);
/// The protocol-chip column width.
const COL_PROTO: Pixels = px(60.0);
/// The direction-arrow column width.
const COL_DIR: Pixels = px(30.0);
/// Horizontal gap between columns.
const COL_GAP: Pixels = px(10.0);

impl Panel {
    /// The scrollable, columnar packet list — the main area, appended live.
    pub(super) fn render_trace_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let Some(tv) = self.trace.as_ref() else {
            return empty_list();
        };
        let visible = tv.model.visible();
        let selected = tv.model.selected();
        let mut list = base_list();
        if visible.is_empty() {
            return list.child(empty_note(p, tv.capturing()));
        }
        for rec in visible {
            let is_sel = selected == Some(rec.seq);
            list = list.child(packet_row(p, rec, is_sel, cx));
        }
        list
    }
}

/// The empty scroll container (no active trace).
fn empty_list() -> Stateful<gpui::Div> {
    div().id("trace-list").flex_1().min_h_0()
}

/// The scroll container the rows append into.
fn base_list() -> Stateful<gpui::Div> {
    div()
        .id("trace-list")
        .flex_1()
        .min_h_0()
        .overflow_y_scroll()
        .flex()
        .flex_col()
}

/// The dim uppercase column-header row, aligned to the packet rows. Rendered as
/// a fixed strip above the scrolling body by [`Panel::render_trace`].
pub(super) fn column_header(p: Palette) -> impl IntoElement {
    row_frame()
        .h(px(22.0))
        .border_b_1()
        .border_color(p.hairline)
        .child(head_cell(p, "#", COL_SEQ))
        .child(head_cell(p, "TIME", COL_TIME))
        .child(head_cell(p, "PROTO", COL_PROTO))
        .child(flex_head_cell(p, "SOURCE"))
        .child(flex_head_cell(p, "DESTINATION"))
        .child(flex_head_cell(p, "DOMAIN (SNI)"))
        .child(head_cell(p, "", COL_DIR))
}

/// Render one packet-list row. Clicking it selects the packet and triggers the
/// off-thread `GetPacketBytes` fetch.
fn packet_row(
    p: Palette,
    rec: &WirePacketRecord,
    selected: bool,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let seq = rec.seq;
    let chip = ChipProto::of(rec);
    let domain = rec.sni.clone().unwrap_or_else(|| "—".to_string());
    let on_click = cx.listener(move |panel, _ev, _win, cx| {
        panel.select_packet(seq, cx);
    });
    row_frame()
        .id(ElementId::Name(format!("pkt-{seq}").into()))
        .h(ROW_H)
        .cursor_pointer()
        .when(selected, |el| el.bg(p.sel))
        .hover(|s| s.bg(p.hover))
        .on_click(on_click)
        .child(mono_cell(format!("{seq}"), COL_SEQ, p.text_faint))
        .child(mono_cell(
            format_time(rec.timestamp_ms),
            COL_TIME,
            p.text_faint,
        ))
        .child(proto_col(chip))
        .child(flex_mono_cell(rec.src.clone(), p.text_dim))
        .child(flex_mono_cell(rec.dst.clone(), p.text))
        .child(flex_text_cell(p, domain))
        .child(dir_col(p, direction_arrow(rec)))
}

/// The shared row frame: horizontal flex, aligned padding, column gap.
fn row_frame() -> gpui::Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(COL_GAP)
        .px(SPACE_LG)
}

/// A fixed-width dim uppercase header cell.
fn head_cell(p: Palette, label: &'static str, w: Pixels) -> impl IntoElement {
    div()
        .w(w)
        .flex_shrink_0()
        .text_size(px(9.0))
        .text_color(p.text_faint)
        .child(label)
}

/// A proportional (flex) dim uppercase header cell.
fn flex_head_cell(p: Palette, label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .min_w_0()
        .text_size(px(9.0))
        .text_color(p.text_faint)
        .child(label)
}

/// A fixed-width tabular-mono cell (seq, time).
fn mono_cell(text: String, w: Pixels, color: Hsla) -> impl IntoElement {
    div()
        .w(w)
        .flex_shrink_0()
        .font_family("ui-monospace")
        .text_size(px(10.0))
        .text_color(color)
        .child(text)
}

/// A proportional tabular-mono cell (source / destination endpoints).
fn flex_mono_cell(text: String, color: Hsla) -> impl IntoElement {
    div()
        .flex_1()
        .min_w_0()
        .font_family("ui-monospace")
        .text_size(px(10.0))
        .text_color(color)
        .text_ellipsis()
        .whitespace_nowrap()
        .child(text)
}

/// A proportional text cell (domain / SNI), ellipsised.
fn flex_text_cell(p: Palette, text: String) -> impl IntoElement {
    div()
        .flex_1()
        .min_w_0()
        .text_size(FONT_CAPTION)
        .text_color(p.text)
        .text_ellipsis()
        .whitespace_nowrap()
        .child(text)
}

/// The protocol-chip column: a fixed-width slot holding the coloured chip.
fn proto_col(chip: ChipProto) -> impl IntoElement {
    div()
        .w(COL_PROTO)
        .flex_shrink_0()
        .flex()
        .flex_row()
        .child(proto_chip(chip))
}

/// The direction-arrow column.
fn dir_col(p: Palette, arrow: &'static str) -> impl IntoElement {
    div()
        .w(COL_DIR)
        .flex_shrink_0()
        .text_size(px(10.0))
        .text_color(p.text_faint)
        .child(arrow)
}

/// The empty-list placeholder while packets have not yet arrived.
fn empty_note(p: Palette, capturing: bool) -> impl IntoElement {
    let text = if capturing {
        "Waiting for packets…"
    } else {
        "No packets captured."
    };
    div()
        .flex()
        .items_center()
        .justify_center()
        .py(px(48.0))
        .text_size(FONT_CAPTION)
        .text_color(p.text_faint)
        .child(text)
}

/// The coloured, data-semantic protocol chip. These hues carry *meaning*
/// (protocol identity), not brand — the panel's monochrome-chrome rule permits
/// them exactly as the verdict dots use semantic colour.
fn proto_chip(proto: ChipProto) -> impl IntoElement {
    let color = chip_color(proto);
    div()
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .w(px(46.0))
        .h(px(15.0))
        .rounded(RADIUS_XS)
        .bg(color.opacity(0.18))
        .text_size(FONT_MICRO)
        .text_color(color)
        .child(proto.label())
}

/// The hue for a protocol chip.
fn chip_color(proto: ChipProto) -> Hsla {
    let rgba = match proto {
        ChipProto::Tls => 0x_a2_7c_f0,
        ChipProto::Dns => 0x_e0_a8_52,
        ChipProto::Http => 0x_e0_86_4a,
        ChipProto::Quic => 0x_5a_c8_c8,
        ChipProto::Tcp => 0x_5a_9c_f0,
        ChipProto::Udp => 0x_4f_bf_8b,
        ChipProto::Icmp | ChipProto::Arp | ChipProto::Other => 0x_8b_90_96,
    };
    rgb(rgba).into()
}

/// The compact direction arrow for a record.
fn direction_arrow(rec: &WirePacketRecord) -> &'static str {
    match rec.direction {
        ipc::protocol::WireDirection::Out => "↑",
        ipc::protocol::WireDirection::In => "↓",
        ipc::protocol::WireDirection::Unknown => "·",
    }
}

/// Format a unix-millis timestamp as `HH:MM:SS.mmm` (UTC-relative).
fn format_time(ms: u64) -> String {
    let millis = ms % 1000;
    let tod = (ms / 1000) % 86_400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}
