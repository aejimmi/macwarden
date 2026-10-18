use super::*;

/// Spec 009 R3: `NetworkEnforcement` must be the *only* capability gated on the
/// `enforcing` flag -- the others are keyed on `history`/`openbinary` alone (and
/// `Mutations`/`Policy`/`Trace` are unconditional). This exhaustively walks all
/// eight `(history, openbinary, enforcing)` combinations so a future edit that
/// accidentally couples an unrelated capability to the enforcement probe (or
/// vice versa) fails a test rather than shipping silently.
#[test]
fn test_capabilities_matrix_gates_each_flag_independently() {
    for history in [false, true] {
        for openbinary in [false, true] {
            for enforcing in [false, true] {
                for banwatch in [false, true] {
                    let caps = capabilities(history, openbinary, enforcing, banwatch);

                    // Unconditional baseline, present in every combination.
                    assert!(caps.contains(&Capability::Mutations));
                    assert!(caps.contains(&Capability::Policy));
                    assert!(caps.contains(&Capability::Trace));

                    assert_eq!(
                        caps.contains(&Capability::History),
                        history,
                        "History must track its own flag only",
                    );
                    assert_eq!(
                        caps.contains(&Capability::Openbinary),
                        openbinary,
                        "Openbinary must track its own flag only",
                    );
                    assert_eq!(
                        caps.contains(&Capability::NetworkEnforcement),
                        enforcing,
                        "NetworkEnforcement must be present iff the R2 probe reports enforcing",
                    );
                    assert_eq!(
                        caps.contains(&Capability::BanWatch),
                        banwatch,
                        "BanWatch must track its own flag only (spec 010 R8)",
                    );

                    // ExecPolicy is never advertised (the ES exec tier is inactive).
                    assert!(!caps.contains(&Capability::ExecPolicy));
                }
            }
        }
    }
}

#[test]
fn test_capabilities_all_flags_off_is_the_minimal_honest_set() {
    // The most conservative daemon state: no metrics store, no inventory store,
    // and the NE probe reporting not-enforcing. The panel must see exactly the
    // unconditional baseline and nothing that implies a capability the daemon
    // does not actually have.
    let caps = capabilities(false, false, false, false);
    assert_eq!(
        caps.len(),
        3,
        "unexpected capabilities in the minimal set: {caps:?}"
    );
    assert!(!caps.contains(&Capability::NetworkEnforcement));
    assert!(!caps.contains(&Capability::History));
    assert!(!caps.contains(&Capability::Openbinary));
    assert!(!caps.contains(&Capability::BanWatch));
}

#[test]
fn test_capabilities_all_flags_on_advertises_network_enforcement() {
    let caps = capabilities(true, true, true, true);
    assert!(caps.contains(&Capability::NetworkEnforcement));
    assert!(caps.contains(&Capability::History));
    assert!(caps.contains(&Capability::Openbinary));
    assert!(caps.contains(&Capability::BanWatch));
}
