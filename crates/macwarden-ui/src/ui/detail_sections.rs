//! Free-function section builders for the inspector body, split out of
//! [`super::detail`] to keep that file under the line limit.
//!
//! Each section is a bordered card (no fill — the hairline border alone frames
//! it) with a consistent uppercase micro-label header. PROCESS leads with the
//! executable path and folds the
//! user + signature into aligned fact rows; RESOURCES renders CPU / MEM / NET as
//! a compact inline KPI strip; CONNECTIONS surfaces the allowed/denied verdict
//! tally, a clean host list, then the IP / port facts.

use gpui::prelude::FluentBuilder as _;
use gpui::{AnyElement, Hsla, IntoElement, ParentElement as _, Styled as _, div, px};

use super::theme::{FONT_BODY, FONT_CAPTION, FONT_MICRO, Palette, RADIUS, RADIUS_XS, SPACE_MD};
use crate::data::model::{Detail, ProcGroup, ProcRow, format_rate};

/// A bordered section card (no fill) with an uppercase micro-label header.
pub(super) fn section(p: Palette, label: &'static str) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .p(SPACE_MD)
        .rounded(RADIUS)
        .border_1()
        .border_color(p.hairline)
        .child(micro_label(p, label))
}

/// A dim uppercase micro-label — the shared section-header and stat-cell style.
fn micro_label(p: Palette, label: &'static str) -> impl IntoElement {
    div()
        .text_size(FONT_MICRO)
        .text_color(p.text_faint)
        .child(label)
}

/// The PROCESS card: the executable path (wrapping mono, clipped if runaway),
/// then aligned User / Signature fact rows.
pub(super) fn process_section(p: Palette, d: &Detail) -> AnyElement {
    section(p, "PROCESS")
        .child(
            div()
                .min_w_0()
                .overflow_hidden()
                .font_family("ui-monospace")
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .child(d.path.clone()),
        )
        .child(fact_row(p, "User", d.user.clone(), false))
        .child(fact_row(p, "Signature", d.signature.describe(), false))
        .into_any_element()
}

/// The RESOURCES card: the group's summed CPU / MEM / NET as an inline KPI
/// strip, then the heaviest few members when the group has more than one.
pub(super) fn resource_section(p: Palette, group: &ProcGroup) -> AnyElement {
    let mut sec = section(p, "RESOURCES").child(
        div()
            .flex()
            .flex_row()
            .items_start()
            .gap(px(6.0))
            .child(stat_cell(p, "CPU", group.cpu_label()))
            .child(stat_divider(p))
            .child(stat_cell(p, "MEM", group.mem_label()))
            .child(stat_divider(p))
            .child(stat_cell(p, "NET", format_rate(group.net_bps))),
    );
    if group.is_group() {
        for proc in group.procs.iter().take(3) {
            sec = sec.child(proc_usage_row(p, proc));
        }
    }
    sec.into_any_element()
}

/// One inline KPI cell: a dim micro-label over a mono value.
fn stat_cell(p: Palette, label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap(px(3.0))
        .child(micro_label(p, label))
        .child(
            div()
                .font_family("ui-monospace")
                .text_size(FONT_BODY)
                .text_color(p.text)
                .child(value),
        )
}

/// A hairline divider between two [`stat_cell`]s.
fn stat_divider(p: Palette) -> impl IntoElement {
    div().w(px(1.0)).h(px(26.0)).bg(p.hairline)
}

/// A compact per-process usage line under RESOURCES: name, CPU, memory.
fn proc_usage_row(p: Palette, proc: &ProcRow) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_size(FONT_MICRO)
                .text_color(p.text_dim)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(proc.name.clone()),
        )
        .child(
            div()
                .font_family("ui-monospace")
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(proc.cpu_label()),
        )
        .child(
            div()
                .w(px(56.0))
                .flex()
                .justify_end()
                .font_family("ui-monospace")
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(proc.mem_label()),
        )
}

/// The CONNECTIONS card: the allowed/denied verdict tally, a clean host list,
/// then the representative IPs and ports as fact rows.
pub(super) fn connections_section(p: Palette, d: &Detail) -> AnyElement {
    section(p, "CONNECTIONS")
        .child(verdict_tally(p, d.allowed_count, d.denied_count))
        .children(host_list(p, &d.hostnames))
        .child(fact_row(p, "IPs", join_or_dash(&d.ips), true))
        .child(fact_row(p, "Ports", join_or_dash(&d.ports), false))
        .into_any_element()
}

/// The allowed/denied pip tally row.
fn verdict_tally(p: Palette, allowed: u32, denied: u32) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .child(tally_pip(p, p.accent, format!("{allowed} allowed")))
        .child(tally_pip(p, p.red, format!("{denied} denied")))
}

/// A single semantic pip + count label.
fn tally_pip(p: Palette, color: Hsla, label: String) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(5.0))
        .child(div().w(px(6.0)).h(px(6.0)).rounded(RADIUS_XS).bg(color))
        .child(
            div()
                .text_size(FONT_CAPTION)
                .text_color(p.text_dim)
                .child(label),
        )
}

/// A vertical list of the top hostnames, or nothing when none are resolved —
/// the IP / port fact rows below still convey the connection, so an empty host
/// list would only contradict them.
fn host_list(p: Palette, hosts: &[String]) -> Option<AnyElement> {
    if hosts.is_empty() {
        return None;
    }
    let mut col = div().flex().flex_col().gap(px(3.0));
    for host in hosts.iter().take(6) {
        col = col.child(
            div()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .text_ellipsis()
                .whitespace_nowrap()
                .child(host.clone()),
        );
    }
    if hosts.len() > 6 {
        col = col.child(
            div()
                .text_size(FONT_MICRO)
                .text_color(p.text_faint)
                .child(format!("+{} more", hosts.len() - 6)),
        );
    }
    Some(col.into_any_element())
}

/// An aligned key/value fact row.
fn fact_row(p: Palette, key: &'static str, value: String, mono: bool) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap(px(10.0))
        .items_baseline()
        .child(
            div()
                .w(px(70.0))
                .flex_shrink_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text_faint)
                .child(key),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_size(FONT_CAPTION)
                .text_color(p.text)
                .when(mono, |el| el.font_family("ui-monospace"))
                .child(value),
        )
}

/// Join a list with commas, or render an em dash when empty.
fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_string()
    } else {
        items.join(", ")
    }
}
