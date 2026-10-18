//! Scrollable tab-body dispatcher and the tab-bound footer totals bar.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, px,
};

use super::panel::Panel;
use super::theme::{FONT_CAPTION, FONT_MICRO, Palette, SPACE_LG, palette};
use super::widgets::{footer_cell, footer_divider};
use crate::data::model::{Totals, format_bytes, format_rate};
use crate::state::Tab;

impl Panel {
    /// The tab content region: a pinned ⌘F filter bar over the scrollable list.
    ///
    /// The outer column holds the filter focus and key handler, so ⌘F and typed
    /// characters reach [`Panel::on_filter_key`] no matter which descendant row is
    /// focused (key events bubble up the focus path). While no header popover is
    /// open the column keeps keyboard focus, so ⌘F works on first launch and after
    /// backing out of the inspector or Rules view.
    pub(super) fn render_tab_body(
        &mut self,
        window: &mut gpui::Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        if self.state.popover() == crate::state::Popover::None
            && !self.filter_focus.is_focused(window)
        {
            window.focus(&self.filter_focus);
        }
        let content = match self.state.tab() {
            Tab::Apps => self.render_apps(cx).into_any_element(),
            Tab::Processes => self.render_procs(cx).into_any_element(),
        };
        let on_key = cx.listener(Self::on_filter_key);
        // Clicking anywhere in the list body blurs the filter field: typed keys
        // stop appending and the query (if empty) releases so the full list
        // returns. The query itself is preserved for a non-empty blur.
        let on_list_click = cx.listener(|panel, _ev, _win, cx| {
            if panel.state.filter_active() {
                panel.state.set_filter_active(false);
                cx.notify();
            }
        });
        // `min_h_0` on the column and the scroll region is load-bearing: a flex
        // child defaults to `min-height: auto`, so without it the list refuses to
        // shrink below its content height and pushes the footer off-screen instead
        // of scrolling. Zeroing the min-height lets the list clip and scroll while
        // the sibling footer stays pinned.
        div()
            .track_focus(&self.filter_focus)
            .on_key_down(on_key)
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .child(self.render_filter_bar(cx))
            .child(
                div()
                    .id("tab-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .on_click(on_list_click)
                    .child(content),
            )
    }

    /// Footer: tab-bound metric cells (label + tabular value, hairline dividers)
    /// on the left, plus the background-sweep note on the right when active.
    /// Every value has a fixed min-width so the bar never reflows as it ticks.
    pub(super) fn render_footer(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        let totals = self.source.totals();
        let live = self.source.is_live();
        let sweep = self.sweep.progress();
        let show_rate = live && !self.state.scope().shows_totals();

        let mut cells = div().flex().flex_row().items_center().gap(px(10.0));
        for (i, (label, value)) in self
            .footer_cells(&totals, show_rate)
            .into_iter()
            .enumerate()
        {
            if i > 0 {
                cells = cells.child(footer_divider(p));
            }
            cells = cells.child(footer_cell(p, label, value));
        }

        div()
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .px(SPACE_LG)
            .h(px(30.0))
            .border_t_1()
            .border_color(p.hairline)
            .text_size(FONT_CAPTION)
            .child(cells)
            .child(render_sweep_note(p, sweep))
    }

    /// The label/value pairs for the active tab. Apps shows network In/Out
    /// (rate under Live, total under Session); Network shows connection semantics;
    /// Processes shows process-appropriate counts (In/Out network makes no sense
    /// aggregated across every process).
    fn footer_cells(&self, totals: &Totals, show_rate: bool) -> Vec<(&'static str, String)> {
        match self.state.tab() {
            Tab::Apps => vec![
                ("In", down_label(totals, show_rate)),
                ("Out", up_label(totals, show_rate)),
            ],
            Tab::Processes => {
                let groups = self.source.proc_groups();
                let cpu: f32 = groups.iter().map(|g| g.cpu).sum();
                vec![
                    ("Procs", thousands(groups.len() as u64)),
                    ("CPU", format!("{cpu:.0}%")),
                ]
            }
        }
    }
}

fn down_label(totals: &Totals, show_rate: bool) -> String {
    if show_rate {
        format_rate(totals.down_bps)
    } else {
        format_bytes(totals.down_bytes)
    }
}

fn up_label(totals: &Totals, show_rate: bool) -> String {
    if show_rate {
        format_rate(totals.up_bps)
    } else {
        format_bytes(totals.up_bytes)
    }
}

/// The right-aligned sweep note: quietly shows openbinary identification
/// progress while the background sweep runs, and nothing otherwise.
fn render_sweep_note(p: Palette, sweep: Option<(usize, usize)>) -> impl IntoElement {
    div()
        .min_w(px(90.0))
        .flex()
        .justify_end()
        .text_size(FONT_MICRO)
        .text_color(p.text_faint)
        .when_some(sweep, |el, (done, total)| {
            el.child(format!("identifying {done}/{total}"))
        })
}

/// Group a number with thousands separators (`1284` -> `1,284`).
fn thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
