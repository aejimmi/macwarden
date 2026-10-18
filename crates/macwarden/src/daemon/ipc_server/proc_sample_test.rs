//! Tests for the persistent `sysinfo` per-process CPU/MEM sampler.
#![allow(clippy::float_cmp)]

use super::*;

#[test]
fn test_sample_includes_self_with_resident_memory() {
    let sampler = ProcSampler::new();
    let stats = sampler.sample();
    let me = std::process::id();
    let stat = stats
        .get(&me)
        .cloned()
        .expect("the test process itself must appear in the sample");
    assert!(
        stat.mem_bytes > 0,
        "a running process must report non-zero resident memory"
    );
    assert!(stat.stats_known, "self is readable, so stats are known");
    assert!(
        stat.user.is_some(),
        "the test process's owner must resolve to a username"
    );
}

#[test]
fn test_sample_is_stable_across_rapid_calls() {
    // Two calls closer than MINIMUM_CPU_UPDATE_INTERVAL must not panic and must
    // both return a populated map (the second reuses the prior refresh).
    let sampler = ProcSampler::new();
    let first = sampler.sample();
    let second = sampler.sample();
    assert!(!first.is_empty(), "first sample populated");
    assert!(!second.is_empty(), "rapid second sample still populated");
}

#[test]
fn test_proc_stat_default_is_zero() {
    let stat = ProcStat::default();
    assert_eq!(stat.cpu, 0.0);
    assert_eq!(stat.mem_bytes, 0);
    assert!(
        !stat.stats_known,
        "a defaulted stat is unknown, not a real zero"
    );
    assert!(stat.user.is_none());
}
