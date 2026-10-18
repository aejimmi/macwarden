use super::*;

/// A realistic `systemextensionsctl list` block: header, one unrelated extension,
/// and the macwarden extension in the given state token.
fn fixture(macwarden_state: &str) -> String {
    format!(
        "1 extension(s)\n\
         --- com.apple.system_extension.network_extension\n\
         enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
         *\t*\tMLZF7K7B5R\tat.obdev.littlesnitch.networkextension (6.4.1/7212)\tLittle Snitch\t[activated enabled]\n\
         *\t*\t8DKG4XB37M\t{NE_EXTENSION_ID} (0.1.0/1)\tmacwarden Network Filter\t{macwarden_state}\n"
    )
}

#[test]
fn test_parse_activated_enabled_is_enforcing() {
    assert!(parse_enforcement_active(&fixture("[activated enabled]")));
}

#[test]
fn test_parse_waiting_for_user_is_not_enforcing() {
    assert!(!parse_enforcement_active(&fixture(
        "[activated waiting for user]"
    )));
}

#[test]
fn test_parse_terminated_is_not_enforcing() {
    assert!(!parse_enforcement_active(&fixture(
        "[terminated waiting to uninstall]"
    )));
}

#[test]
fn test_parse_extension_absent_is_not_enforcing() {
    let output = "1 extension(s)\n\
         --- com.apple.system_extension.network_extension\n\
         *\t*\tMLZF7K7B5R\tat.obdev.littlesnitch.networkextension (6.4.1/7212)\tLittle Snitch\t[activated enabled]\n";
    assert!(!parse_enforcement_active(output));
}

#[test]
fn test_parse_empty_output_is_not_enforcing() {
    assert!(!parse_enforcement_active(""));
}

#[test]
fn test_parse_malformed_output_does_not_panic() {
    // Truncated / garbage lines must never panic and must fail safe.
    assert!(!parse_enforcement_active(
        "garbage without state\n\t\t\t\n[activated"
    ));
}

#[test]
fn test_parse_substring_bundle_id_does_not_false_match() {
    // A different extension whose id merely *contains* ours (as a substring, not a
    // whole token) must not be mistaken for the macwarden filter.
    let output =
        format!("*\t*\tXX\tevil.{NE_EXTENSION_ID}.spoof (1/1)\tspoof\t[activated enabled]\n");
    assert!(!parse_enforcement_active(&output));
}

#[test]
fn test_parse_enabled_but_not_activated_is_not_enforcing() {
    // Only the exact `[activated enabled]` token counts; a merely-enabled or
    // merely-activated state is not "live".
    assert!(!parse_enforcement_active(&fixture("[activated]")));
    assert!(!parse_enforcement_active(&fixture("[enabled]")));
}

#[test]
fn test_parse_crlf_output_still_matches() {
    // `systemextensionsctl` output is plain text; if the shell-out ever yields
    // CRLF line endings (a different locale, a piped-through tool), the parse
    // must still find the state token. `str::lines` strips a trailing `\r`.
    let output = fixture("[activated enabled]").replace('\n', "\r\n");
    assert!(parse_enforcement_active(&output));
}

#[test]
fn test_parse_one_of_several_macwarden_entries_activated_enabled_is_enforcing() {
    // A real upgrade-in-place transition can list the macwarden extension
    // twice: the old version terminating alongside the new version already
    // activated and enabled. Any matching line being live is enough.
    let output = format!(
        "1 extension(s)\n\
         --- com.apple.system_extension.network_extension\n\
         *\t*\t8DKG4XB37M\t{NE_EXTENSION_ID} (0.0.9/1)\tmacwarden Network Filter\t[terminated waiting to uninstall]\n\
         *\t*\t8DKG4XB37M\t{NE_EXTENSION_ID} (0.1.0/2)\tmacwarden Network Filter\t[activated enabled]\n"
    );
    assert!(parse_enforcement_active(&output));
}

#[test]
fn test_parse_trailing_annotation_after_state_token_still_matches() {
    // `line.contains` is a substring search: a hypothetical trailing annotation
    // after the exact `[activated enabled]` token (e.g. a pending-restart note)
    // does not prevent the match, since the required token is still present
    // verbatim. Documents the current (permissive) substring behavior rather
    // than a stricter "whole line equals" check.
    let output = format!(
        "*\t*\t8DKG4XB37M\t{NE_EXTENSION_ID} (0.1.0/1)\tmacwarden Network Filter\t[activated enabled] (pending restart)\n"
    );
    assert!(parse_enforcement_active(&output));
}

#[test]
fn test_parse_extension_id_in_unexpected_column_is_not_enforcing() {
    // R2 column bug, now fixed: the parser matches the bundle id in the bundle-id
    // column ONLY, not anywhere on the line. Here the real bundle-id column names
    // a different extension (`com.example.impostor`) while our id appears in the
    // *name* column — a spoof surface, since a name is attacker-chosen free text.
    // The corrected parser must NOT treat this as enforcing (the probe may never
    // claim enforcement it does not have).
    let output =
        format!("*\t*\tXX\tcom.example.impostor (1.0/1)\t{NE_EXTENSION_ID}\t[activated enabled]\n");
    assert!(
        !parse_enforcement_active(&output),
        "a bundle id in the NAME column must not be mistaken for the bundle-id column"
    );
}

#[test]
fn test_parse_extension_id_in_bundle_id_column_is_enforcing() {
    // The positive counterpart: the same id in the actual bundle-id column (with
    // its trailing `(version)`) and an activated-enabled state IS enforcing.
    let output = format!(
        "*\t*\t8DKG4XB37M\t{NE_EXTENSION_ID} (0.1.0/1)\tmacwarden Network Filter\t[activated enabled]\n"
    );
    assert!(parse_enforcement_active(&output));
}

#[test]
fn test_network_enforcement_active_fails_safe_without_installed_extension() {
    // The macwarden filter extension is never installed on a test host (CI
    // included), so the real end-to-end probe — shelling the actual
    // `systemextensionsctl` tool, not the pure fixture parser — must fail safe
    // to `false` without panicking, whether or not the tool itself exists on
    // this platform.
    assert!(!network_enforcement_active());
}
