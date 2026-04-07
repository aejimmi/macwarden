use super::*;

#[test]
fn test_exact_match_found() {
    let mut trie = DomainTrie::new();
    trie.insert_exact("ads.google.com", "blocked");
    assert_eq!(trie.lookup("ads.google.com"), Some(&"blocked"));
}

#[test]
fn test_exact_match_subdomain_not_found() {
    let mut trie = DomainTrie::new();
    trie.insert_exact("google.com", "blocked");
    assert_eq!(trie.lookup("ads.google.com"), None);
}

#[test]
fn test_domain_match_self() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("google.com", "blocked");
    assert_eq!(trie.lookup("google.com"), Some(&"blocked"));
}

#[test]
fn test_domain_match_subdomain() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("google.com", "blocked");
    assert_eq!(trie.lookup("ads.google.com"), Some(&"blocked"));
}

#[test]
fn test_domain_match_deep_subdomain() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("google.com", "blocked");
    assert_eq!(trie.lookup("x.y.z.google.com"), Some(&"blocked"));
}

#[test]
fn test_no_partial_label_match() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("google.com", "blocked");
    assert_eq!(trie.lookup("evilgoogle.com"), None);
}

#[test]
fn test_more_specific_wins() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("google.com", "v1");
    trie.insert_domain("ads.google.com", "v2");
    assert_eq!(trie.lookup("ads.google.com"), Some(&"v2"));
    // Parent should still match for non-ads subdomains.
    assert_eq!(trie.lookup("mail.google.com"), Some(&"v1"));
}

#[test]
fn test_empty_trie() {
    let trie: DomainTrie<&str> = DomainTrie::new();
    assert_eq!(trie.lookup("google.com"), None);
}

#[test]
fn test_tld_only() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("com", "tld");
    assert_eq!(trie.lookup("anything.com"), Some(&"tld"));
    assert_eq!(trie.lookup("deep.sub.anything.com"), Some(&"tld"));
    assert_eq!(trie.lookup("com"), Some(&"tld"));
}

#[test]
fn test_case_insensitive() {
    let mut trie = DomainTrie::new();
    trie.insert_domain("Google.COM", "blocked");
    assert_eq!(trie.lookup("google.com"), Some(&"blocked"));
    assert_eq!(trie.lookup("ads.google.com"), Some(&"blocked"));
}

#[test]
fn test_len_and_is_empty() {
    let mut trie: DomainTrie<&str> = DomainTrie::new();
    assert!(trie.is_empty());
    assert_eq!(trie.len(), 0);

    trie.insert_exact("example.com", "a");
    assert!(!trie.is_empty());
    assert_eq!(trie.len(), 1);

    trie.insert_domain("tracker.com", "b");
    assert_eq!(trie.len(), 2);
}
