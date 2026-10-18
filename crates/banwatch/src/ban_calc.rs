//! Escalating ban-time calculation.
//!
//! Ported from `fail2ban-rs` `src/track/ban_calc.rs` (`calc_ban_time`). The Nth
//! ban of an IP multiplies the base ban time by
//! `multipliers[min(count, len-1)]`, capped at `maxtime`. With escalation
//! disabled every ban is the base time. A negative base means "permanent" and
//! passes through unscaled.

/// Parameters that drive [`calc_ban_time`], derived from [`crate::config`].
#[derive(Debug, Clone)]
pub struct BanParams {
    /// Base ban time in seconds. A negative value means a permanent ban.
    pub ban_time: i64,
    /// Whether repeat offenders escalate.
    pub increment: bool,
    /// Per-ban multipliers, indexed by (clamped) escalation count.
    pub multipliers: Vec<u32>,
    /// Upper bound on an escalated ban time (`<= 0` disables the cap).
    pub maxtime: i64,
}

/// Compute the effective ban time for the `count`-th prior ban of an IP.
///
/// `count` is the number of times the IP has already been banned (0 for a
/// first offense). When escalation is off, or the base is permanent, the base
/// is returned unchanged.
#[must_use]
pub fn calc_ban_time(count: u32, params: &BanParams) -> i64 {
    let base = params.ban_time;
    if !params.increment || base < 0 {
        return base;
    }
    let multiplier = if params.multipliers.is_empty() {
        let exp = count.min(20);
        2_f64.powi(exp as i32)
    } else {
        let idx = (count as usize).min(params.multipliers.len().saturating_sub(1));
        params.multipliers.get(idx).copied().map_or(1.0, f64::from)
    };
    let effective = (base as f64 * multiplier) as i64;
    if params.maxtime > 0 {
        effective.min(params.maxtime)
    } else {
        effective
    }
}

#[cfg(test)]
#[path = "ban_calc_test.rs"]
mod ban_calc_test;
