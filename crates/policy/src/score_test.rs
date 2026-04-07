#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `ScoreInput` with all dimensions at best case.
fn best_case_input() -> ScoreInput {
    ScoreInput {
        services: Some(ServiceState {
            recommended_total: 10,
            recommended_stopped: 10,
            optional_total: 5,
            optional_stopped: 5,
        }),
        traces: Some(TraceState {
            total_bytes: 0,
            domains_total: 5,
            domains_clean: 5,
        }),
        devices: Some(DeviceState {
            camera_grants: 0,
            mic_grants: 0,
            camera_running: 0,
            mic_running: 0,
        }),
        network: Some(NetworkState {
            shield_enabled: true,
            tracker_connections: 0,
        }),
    }
}

/// Build a `ScoreInput` with all dimensions at worst case.
fn worst_case_input() -> ScoreInput {
    ScoreInput {
        services: Some(ServiceState {
            recommended_total: 20,
            recommended_stopped: 0,
            optional_total: 10,
            optional_stopped: 0,
        }),
        traces: Some(TraceState {
            total_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
            domains_total: 10,
            domains_clean: 0,
        }),
        devices: Some(DeviceState {
            camera_grants: 5,
            mic_grants: 5,
            camera_running: 3,
            mic_running: 2,
        }),
        network: Some(NetworkState {
            shield_enabled: false,
            tracker_connections: 50,
        }),
    }
}

// ---------------------------------------------------------------------------
// All dimensions present
// ---------------------------------------------------------------------------

#[test]
fn test_compute_score_all_best_case_returns_100() {
    let input = best_case_input();
    let result = compute_score(&input);
    assert_eq!(result.total, 100);
    assert!(result.services.is_some());
    assert!(result.traces.is_some());
    assert!(result.devices.is_some());
    assert!(result.network.is_some());
}

#[test]
fn test_compute_score_all_worst_case_returns_near_zero() {
    let input = worst_case_input();
    let result = compute_score(&input);
    assert!(
        result.total <= 5,
        "worst case should be near 0, got {}",
        result.total
    );
}

#[test]
fn test_compute_score_total_equals_sum_of_earned() {
    let input = ScoreInput {
        services: Some(ServiceState {
            recommended_total: 10,
            recommended_stopped: 5,
            optional_total: 4,
            optional_stopped: 2,
        }),
        traces: Some(TraceState {
            total_bytes: 5 * 1024 * 1024,
            domains_total: 3,
            domains_clean: 1,
        }),
        devices: Some(DeviceState {
            camera_grants: 2,
            mic_grants: 1,
            camera_running: 1,
            mic_running: 0,
        }),
        network: Some(NetworkState {
            shield_enabled: true,
            tracker_connections: 3,
        }),
    };
    let result = compute_score(&input);
    let sum: u32 = [
        &result.services,
        &result.traces,
        &result.devices,
        &result.network,
    ]
    .iter()
    .filter_map(|d| d.as_ref())
    .map(|d| d.earned)
    .sum();
    assert_eq!(result.total, sum.min(100));
}

// ---------------------------------------------------------------------------
// Dimension unavailability — weight redistribution
// ---------------------------------------------------------------------------

#[test]
fn test_compute_score_all_none_returns_100() {
    let input = ScoreInput {
        services: None,
        traces: None,
        devices: None,
        network: None,
    };
    let result = compute_score(&input);
    assert_eq!(result.total, 100);
}

#[test]
fn test_compute_score_one_dimension_unavailable() {
    // Network unavailable => weights redistribute to 40+25+15 = 80, scaled to 100.
    let input = ScoreInput {
        services: Some(ServiceState {
            recommended_total: 10,
            recommended_stopped: 10,
            optional_total: 0,
            optional_stopped: 0,
        }),
        traces: Some(TraceState {
            total_bytes: 0,
            domains_total: 3,
            domains_clean: 3,
        }),
        devices: Some(DeviceState {
            camera_grants: 0,
            mic_grants: 0,
            camera_running: 0,
            mic_running: 0,
        }),
        network: None,
    };
    let result = compute_score(&input);
    assert_eq!(
        result.total, 100,
        "best case with one dim unavailable should still be 100"
    );
    assert!(result.network.is_none());

    // Check redistributed weights sum to 100.
    let max_sum: u32 = [&result.services, &result.traces, &result.devices]
        .iter()
        .filter_map(|d| d.as_ref())
        .map(|d| d.max)
        .sum();
    assert_eq!(max_sum, 100);
}

#[test]
fn test_compute_score_two_dimensions_unavailable() {
    // Only services and traces available => 40+25=65, scaled to 100.
    let input = ScoreInput {
        services: Some(ServiceState {
            recommended_total: 10,
            recommended_stopped: 10,
            optional_total: 0,
            optional_stopped: 0,
        }),
        traces: Some(TraceState {
            total_bytes: 0,
            domains_total: 2,
            domains_clean: 2,
        }),
        devices: None,
        network: None,
    };
    let result = compute_score(&input);
    assert_eq!(result.total, 100);

    let svc_max = result.services.as_ref().map_or(0, |d| d.max);
    let tr_max = result.traces.as_ref().map_or(0, |d| d.max);
    // Services: 40/65*100 ~ 62, Traces: 25/65*100 ~ 38.
    assert!(
        svc_max > tr_max,
        "services weight should be larger than traces"
    );
    assert_eq!(svc_max + tr_max, 100);
}

#[test]
fn test_compute_score_only_network_available() {
    let input = ScoreInput {
        services: None,
        traces: None,
        devices: None,
        network: Some(NetworkState {
            shield_enabled: true,
            tracker_connections: 0,
        }),
    };
    let result = compute_score(&input);
    assert_eq!(result.total, 100);
    let net = result.network.as_ref().expect("network should be present");
    assert_eq!(net.max, 100);
    assert_eq!(net.earned, 100);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_compute_score_zero_groups() {
    let input = ScoreInput {
        services: Some(ServiceState {
            recommended_total: 0,
            recommended_stopped: 0,
            optional_total: 0,
            optional_stopped: 0,
        }),
        traces: None,
        devices: None,
        network: None,
    };
    let result = compute_score(&input);
    // Zero groups => denom 0 => full points.
    assert_eq!(result.total, 100);
}

#[test]
fn test_compute_score_zero_artifacts() {
    let input = ScoreInput {
        services: None,
        traces: Some(TraceState {
            total_bytes: 0,
            domains_total: 0,
            domains_clean: 0,
        }),
        devices: None,
        network: None,
    };
    let result = compute_score(&input);
    assert_eq!(result.total, 100);
}

// ---------------------------------------------------------------------------
// Earned <= max for every dimension
// ---------------------------------------------------------------------------

#[test]
fn test_earned_never_exceeds_max() {
    let inputs = [best_case_input(), worst_case_input()];
    for input in &inputs {
        let result = compute_score(input);
        for dim in [
            &result.services,
            &result.traces,
            &result.devices,
            &result.network,
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                dim.earned <= dim.max,
                "earned ({}) exceeds max ({}) for label: {}",
                dim.earned,
                dim.max,
                dim.label
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Trace tier boundaries
// ---------------------------------------------------------------------------

#[test]
fn test_traces_tier_exact_boundaries() {
    let mb: u64 = 1024 * 1024;
    let gb: u64 = 1024 * mb;

    let cases: &[(u64, f64)] = &[
        (0, 1.0),           // 0 bytes => 100%
        (1, 0.8),           // 1 byte => <1MB tier => 80%
        (mb - 1, 0.8),      // Just under 1MB => 80%
        (mb, 0.6),          // Exactly 1MB => <10MB tier => 60%
        (10 * mb - 1, 0.6), // Just under 10MB => 60%
        (10 * mb, 0.4),     // Exactly 10MB => <100MB tier => 40%
        (100 * mb - 1, 0.4),
        (100 * mb, 0.2), // Exactly 100MB => <1GB tier => 20%
        (gb - 1, 0.2),   // Just under 1GB => 20%
        (gb, 0.0),       // Exactly 1GB => 0%
        (2 * gb, 0.0),   // Above 1GB => 0%
    ];

    for &(bytes, expected_pct) in cases {
        let input = ScoreInput {
            services: None,
            traces: Some(TraceState {
                total_bytes: bytes,
                domains_total: 1,
                domains_clean: u32::from(bytes == 0),
            }),
            devices: None,
            network: None,
        };
        let result = compute_score(&input);
        let tr = result.traces.as_ref().expect("traces should be present");
        let expected = (100.0 * expected_pct).round() as u32;
        assert_eq!(
            tr.earned, expected,
            "bytes={bytes}: expected {expected}, got {}",
            tr.earned
        );
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_compute_score_is_deterministic() {
    let input = ScoreInput {
        services: Some(ServiceState {
            recommended_total: 15,
            recommended_stopped: 7,
            optional_total: 8,
            optional_stopped: 3,
        }),
        traces: Some(TraceState {
            total_bytes: 50 * 1024 * 1024,
            domains_total: 6,
            domains_clean: 2,
        }),
        devices: Some(DeviceState {
            camera_grants: 3,
            mic_grants: 4,
            camera_running: 1,
            mic_running: 2,
        }),
        network: Some(NetworkState {
            shield_enabled: false,
            tracker_connections: 5,
        }),
    };

    let a = compute_score(&input);
    let b = compute_score(&input);
    assert_eq!(a.total, b.total);
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

#[test]
fn test_recommendations_perfect_score_returns_empty() {
    let input = best_case_input();
    let result = compute_score(&input);
    let recs = result.recommendations();
    assert!(
        recs.is_empty(),
        "perfect score should have no recommendations"
    );
}

#[test]
fn test_recommendations_worst_case_returns_up_to_three() {
    let input = worst_case_input();
    let result = compute_score(&input);
    let recs = result.recommendations();
    assert!(!recs.is_empty(), "worst case should have recommendations");
    assert!(recs.len() <= 3, "at most 3 recommendations");
    // Verify sorted by points descending.
    for window in recs.windows(2) {
        assert!(window[0].points >= window[1].points);
    }
}

#[test]
fn test_recommendations_sorted_by_points_desc() {
    let input = worst_case_input();
    let result = compute_score(&input);
    let recs = result.recommendations();
    for window in recs.windows(2) {
        assert!(
            window[0].points >= window[1].points,
            "recommendations should be sorted by points desc"
        );
    }
}

#[test]
fn test_recommendations_contain_real_commands() {
    let input = worst_case_input();
    let result = compute_score(&input);
    let recs = result.recommendations();
    let valid_prefixes = ["macwarden use", "macwarden scrub", "macwarden net"];
    for rec in &recs {
        assert!(
            valid_prefixes.iter().any(|p| rec.command.starts_with(p)),
            "unexpected command: {}",
            rec.command
        );
        assert!(
            rec.points > 0,
            "each recommendation should have nonzero points"
        );
    }
}

#[test]
fn test_recommendations_points_are_nonzero() {
    let input = worst_case_input();
    let result = compute_score(&input);
    for rec in result.recommendations() {
        assert!(rec.points > 0);
    }
}

// ---------------------------------------------------------------------------
// Labels are non-empty
// ---------------------------------------------------------------------------

#[test]
fn test_dimension_labels_are_nonempty() {
    let input = best_case_input();
    let result = compute_score(&input);
    for dim in [
        &result.services,
        &result.traces,
        &result.devices,
        &result.network,
    ]
    .into_iter()
    .flatten()
    {
        assert!(!dim.label.is_empty(), "label should be non-empty");
    }
}
