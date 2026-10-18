use ipc::protocol::{RuleTarget, WireDuration, WireRuleChange};

use super::*;

fn set_rule() -> Request {
    Request::SetRule {
        target: RuleTarget::App {
            code_id: "com.example.app".to_owned(),
        },
        allow: false,
        duration: WireDuration::Session,
    }
}

fn set_rules(n: usize) -> Request {
    Request::SetRules {
        rules: (0..n)
            .map(|i| WireRuleChange {
                target: RuleTarget::App {
                    code_id: format!("com.app{i}"),
                },
                allow: false,
                duration: WireDuration::Session,
            })
            .collect(),
    }
}

#[test]
fn test_set_rules_is_classified_as_a_mutation() {
    // A batch must be gated by the mutation rate limiter exactly like a single
    // SetRule — so it is charged once, not per entry.
    assert!(is_mutation(&set_rule()));
    assert!(is_mutation(&set_rules(24)));
}

#[test]
fn test_non_mutations_are_not_rate_limited() {
    assert!(!is_mutation(&Request::GetSnapshot));
    assert!(!is_mutation(&Request::GetProfile));
}

#[test]
fn test_a_batch_charges_the_limiter_once() {
    // Applying a single SetRules request (however many entries) consumes exactly
    // one slot in the sliding window — the batch is one mutation.
    let mut times: Vec<Instant> = Vec::new();
    for _ in 0..RATE_MAX {
        assert!(!rate_limited(&mut times), "within budget");
    }
    // RATE_MAX requests recorded; the next is over budget.
    assert_eq!(times.len(), RATE_MAX);
    assert!(
        rate_limited(&mut times),
        "over budget after RATE_MAX charges"
    );
}
