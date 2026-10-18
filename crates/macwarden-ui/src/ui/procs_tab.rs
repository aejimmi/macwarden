//! The Processes tab: an aggregate summary line doubling as an aligned CPU/MEM/
//! NET column header + sort control, and one row per process group (helpers
//! rolled up under their responsible app). A group's disclosure expands to its
//! member processes with per-process usage. Clicking a row pushes the shared
//! inspector for its representative process.
//!
//! The three metric columns are fixed-width, right-aligned, tabular-mono cells so
//! the header labels, group summaries, and child rows all line up in clean
//! columns that never jitter as the numbers tick.

use gpui::{
    App, Context, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};

use std::sync::Arc;

use gpui::RenderImage;

use super::filter;
use super::panel::Panel;
use super::theme::{
    FONT_BODY, FONT_CAPTION, FONT_MICRO, ICON, Palette, ROW_HEIGHT, SPACE_LG, SUBROW_HEIGHT,
    palette,
};
use super::widgets::tile;
use crate::data::model::{ProcGroup, ProcRow, format_bytes, format_scoped};
use crate::state::{Route, Sort};

/// Expansion-key prefix so process groups never collide with Apps-tab app ids.
const PG: &str = "pg:";

/// Fixed metric-column widths (px). Shared by the header cells and every data
/// row so CPU / MEM / NET form clean right-aligned columns.
const CELL_CPU: f32 = 48.0;
const CELL_MEM: f32 = 64.0;
const CELL_NET: f32 = 72.0;

/// The horizontal gap between a row's trailing metric cells — kept identical in
/// the header and data rows so the columns align.
const CELL_GAP: f32 = 8.0;

impl Panel {
    /// Render the Processes tab.
    pub(super) fn render_procs(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let totals = self.state.scope().shows_totals();
        let query = filter::normalize(self.state.filter());
        let mut groups = self.source.proc_groups();
        if let Some(needle) = &query {
            groups.retain(|g| filter::group_matches(g, needle));
        }
        self.state.sort_groups(&mut groups);

        let total_cpu: f32 = groups.iter().map(|g| g.cpu).sum();
        let total_mem: u64 = groups.iter().map(|g| g.mem_bytes).sum();
        let net_bps: u64 = groups.iter().map(|g| g.net_bps).sum();
        let net_bytes: u64 = groups.iter().map(|g| g.net_bytes).sum();
        let net = format_scoped(totals, net_bps, net_bytes);

        let mut list = div()
            .flex()
            .flex_col()
            .child(self.render_proc_header(total_cpu, total_mem, &net, cx));
        if query.is_some() && groups.is_empty() {
            return list.child(self.render_no_matches(cx));
        }
        for (i, group) in groups.into_iter().enumerate() {
            let icon = self.icon_for(group.bundle_path.as_deref());
            list = list.child(self.group_row(i, &group, totals, icon, cx));
            if !self.group_shows_children(&group, query.as_deref()) {
                continue;
            }
            for (j, proc) in group.procs.iter().enumerate() {
                if !show_child(&group, proc, query.as_deref()) {
                    continue;
                }
                let picon = self.icon_for(proc.bundle_path.as_deref());
                list = list.child(child_row(i, j, proc, totals, picon, cx));
            }
        }
        list
    }

    /// Whether a group's children are visible: a matched multi-member group is
    /// auto-expanded under an active query; otherwise the manual disclosure rules.
    fn group_shows_children(&self, group: &ProcGroup, query: Option<&str>) -> bool {
        if !group.is_group() {
            return false;
        }
        query.is_some() || self.state.is_expanded(&format!("{PG}{}", group.id))
    }

    /// The summary strip: real CPU/MEM/NET totals on the left, plus the CPU/MEM/
    /// NET sort control on the right rendered as fixed-width cells that line up
    /// directly above the data columns.
    fn render_proc_header(
        &self,
        cpu: f32,
        mem: u64,
        net: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = palette(cx);
        let sort = self.state.sort();
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(CELL_GAP))
            .px(SPACE_LG)
            .h(px(30.0))
            .border_b_1()
            .border_color(p.hairline)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .flex()
                    .flex_row()
                    .items_baseline()
                    .gap(px(6.0))
                    .child(
                        div()
                            .font_family("ui-monospace")
                            .text_size(FONT_CAPTION)
                            .text_color(p.text_dim)
                            .whitespace_nowrap()
                            .child(format!(
                                "CPU {cpu:.1}% · MEM {} · NET {net}",
                                format_bytes(mem)
                            )),
                    )
                    // Clarify these are sums over *networked* processes, not
                    // machine totals. Faint, monochrome — a hint, not a headline.
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_size(FONT_MICRO)
                            .text_color(p.text_faint)
                            .whitespace_nowrap()
                            .child("networked"),
                    ),
            )
            .child(sort_cell(p, Sort::Cpu, sort, CELL_CPU, cx))
            .child(sort_cell(p, Sort::Mem, sort, CELL_MEM, cx))
            .child(sort_cell(p, Sort::Net, sort, CELL_NET, cx))
    }

    fn group_row(
        &self,
        i: usize,
        group: &ProcGroup,
        totals: bool,
        icon: Option<Arc<RenderImage>>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let p = palette(cx);
        let key = format!("{PG}{}", group.id);
        let is_group = group.is_group();
        let filtering = filter::normalize(self.state.filter()).is_some();
        let expanded = (filtering && is_group) || self.state.is_expanded(&key);

        let toggle_key = key.clone();
        let on_chevron = cx.listener(move |panel, _ev, _win, cx| {
            panel.state.toggle_expanded(&toggle_key);
            cx.notify();
        });
        let rep = group.procs.first().map(|p| p.id.clone());
        let on_body = cx.listener(move |panel, _ev, _win, cx| {
            if let Some(id) = &rep {
                panel.navigate(Route::Proc(id.clone()), cx);
            }
        });

        let name = if is_group {
            format!("{}  ({})", group.name, group.procs.len())
        } else {
            group.name.clone()
        };

        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(CELL_GAP))
            .h(ROW_HEIGHT)
            .px(SPACE_LG)
            .hover(|s| s.bg(p.hover))
            .child(
                div()
                    .id(ElementId::Name(format!("pgchev-{i}").into()))
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(12.0))
                    .cursor_pointer()
                    .text_size(px(9.0))
                    .text_color(p.text_faint)
                    .child(if !is_group {
                        ""
                    } else if expanded {
                        "▼"
                    } else {
                        "▶"
                    })
                    .on_click(on_chevron),
            )
            .child(tile(p, icon, group.monogram(), ICON))
            .child(
                div()
                    .id(ElementId::Name(format!("pgbody-{i}").into()))
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .cursor_pointer()
                    .text_size(FONT_BODY)
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(name)
                    .on_click(on_body),
            )
            .children(self.ob_badge(p, group.bundle_path.as_deref()))
            .child(metric(p, group.cpu_label(), CELL_CPU))
            .child(metric(p, group.mem_label(), CELL_MEM))
            .child(metric(
                p,
                format_scoped(totals, group.net_bps, group.net_bytes),
                CELL_NET,
            ))
    }
}

/// One column-header cell that is also the sort toggle for that metric. The
/// active column brightens and carries a `↓` (descending) marker. Fixed width so
/// it lines up directly above the data column.
fn sort_cell(
    p: Palette,
    s: Sort,
    active: Sort,
    width: f32,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let is_active = s == active;
    let view = cx.entity();
    let handler = move |_ev: &gpui::ClickEvent, _win: &mut Window, cx: &mut App| {
        view.update(cx, |panel, cx| {
            panel.state.set_sort(s);
            cx.notify();
        });
    };
    let label = if is_active {
        format!("↓{}", s.label())
    } else {
        s.label().to_string()
    };
    div()
        .id(ElementId::Name(format!("sort-{}", s.label()).into()))
        .w(px(width))
        .flex()
        .justify_end()
        .cursor_pointer()
        .font_family("ui-monospace")
        .text_size(FONT_MICRO)
        .text_color(if is_active { p.text } else { p.text_dim })
        .child(label)
        .on_click(handler)
}

/// Whether a member process is shown under an expanded group during filtering:
/// every child when the group matched by its own name/id, else only the members
/// that match the query. With no query, every child shows.
fn show_child(group: &ProcGroup, proc: &ProcRow, needle: Option<&str>) -> bool {
    match needle {
        None => true,
        Some(n) => filter::group_self_matches(group, n) || filter::proc_matches(proc, n),
    }
}

fn child_row(
    i: usize,
    j: usize,
    proc: &ProcRow,
    totals: bool,
    icon: Option<Arc<RenderImage>>,
    cx: &mut Context<Panel>,
) -> impl IntoElement {
    let p = palette(cx);
    let id = proc.id.clone();
    let on_click = cx.listener(move |panel, _ev, _win, cx| {
        panel.navigate(Route::Proc(id.clone()), cx);
    });

    div()
        .id(ElementId::Name(format!("pgchild-{i}-{j}").into()))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(CELL_GAP))
        .h(SUBROW_HEIGHT)
        .pl(px(40.0))
        .pr(SPACE_LG)
        .cursor_pointer()
        .hover(|s| s.bg(p.hover))
        .child(tile(p, icon, proc.monogram(), px(14.0)))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .text_size(FONT_CAPTION)
                .text_color(p.text_dim)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(proc.name.clone()),
        )
        .child(metric(p, proc.cpu_label(), CELL_CPU))
        .child(metric(p, proc.mem_label(), CELL_MEM))
        .child(metric(
            p,
            format_scoped(totals, proc.net_bps, proc.net_bytes),
            CELL_NET,
        ))
        .on_click(on_click)
}

/// A right-aligned fixed-width tabular-mono metric cell — no horizontal jitter as
/// digits change under the tick, and it aligns with its column header.
fn metric(p: Palette, text: String, width: f32) -> impl IntoElement {
    div()
        .w(px(width))
        .flex()
        .justify_end()
        .font_family("ui-monospace")
        .text_size(px(11.0))
        .text_color(p.text_dim)
        .child(text)
}
