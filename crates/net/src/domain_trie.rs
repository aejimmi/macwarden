//! Reverse-label trie for O(k) domain matching.
//!
//! k = number of labels in the domain (typically 3-5).
//! Inspired by Little Snitch's `LSBlocklistTree`.
//!
//! Supports two match modes:
//! - **Exact**: only matches the inserted domain
//! - **Domain**: matches the domain AND all subdomains
//!
//! Example: inserting `"google.com"` with domain matching
//! matches `"google.com"`, `"ads.google.com"`, `"mail.ads.google.com"`
//! but NOT `"evilgoogle.com"`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TrieNode
// ---------------------------------------------------------------------------

/// Internal trie node. Each label in a reversed domain maps to a child node.
#[derive(Debug, Clone)]
struct TrieNode<V> {
    /// Value for exact-match lookups (set by `insert_exact`).
    exact_value: Option<V>,
    /// Value for domain-match lookups (set by `insert_domain`).
    /// Matches this domain and ALL subdomains.
    wildcard_value: Option<V>,
    /// Children keyed by the next label.
    children: HashMap<String, TrieNode<V>>,
}

impl<V> Default for TrieNode<V> {
    fn default() -> Self {
        Self {
            exact_value: None,
            wildcard_value: None,
            children: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DomainTrie
// ---------------------------------------------------------------------------

/// Reverse-label trie for O(k) domain matching.
///
/// k = number of labels in the domain (typically 3-5).
///
/// Supports two match modes:
/// - **Exact**: only matches the inserted domain
/// - **Domain**: matches the domain AND all subdomains
///
/// Example: inserting `"google.com"` with domain matching
/// matches `"google.com"`, `"ads.google.com"`, `"mail.ads.google.com"`
/// but NOT `"evilgoogle.com"`.
#[derive(Debug, Clone)]
pub struct DomainTrie<V> {
    root: TrieNode<V>,
    len: usize,
}

impl<V> Default for DomainTrie<V> {
    fn default() -> Self {
        Self {
            root: TrieNode::default(),
            len: 0,
        }
    }
}

impl<V> DomainTrie<V> {
    /// Create an empty trie.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a domain for exact matching only.
    ///
    /// `"ads.google.com"` will match `"ads.google.com"` but NOT
    /// `"x.ads.google.com"`.
    ///
    /// The domain is lowercased before insertion.
    pub fn insert_exact(&mut self, domain: &str, value: V) {
        let node = self.walk_or_create(domain);
        node.exact_value = Some(value);
        self.len += 1;
    }

    /// Insert a domain for domain matching (self + all subdomains).
    ///
    /// `"google.com"` will match `"google.com"`, `"ads.google.com"`,
    /// `"x.y.z.google.com"`, but NOT `"evilgoogle.com"`.
    ///
    /// The domain is lowercased before insertion.
    pub fn insert_domain(&mut self, domain: &str, value: V) {
        let node = self.walk_or_create(domain);
        node.wildcard_value = Some(value);
        self.len += 1;
    }

    /// Look up a domain, returning the most specific match.
    ///
    /// Walks reversed labels. At each node, tracks the deepest wildcard
    /// match. If a label has no child, returns the best wildcard seen.
    /// At the terminal node, prefers exact over wildcard.
    ///
    /// Zero allocations: uses `rsplit('.')` for reverse-label iteration.
    pub fn lookup(&self, domain: &str) -> Option<&V> {
        let mut node = &self.root;
        let mut best_wildcard: Option<&V> = None;

        for label in domain.rsplit('.') {
            let Some(child) = node.children.get(label) else {
                // No child for this label — return deepest wildcard seen.
                return best_wildcard;
            };
            if child.wildcard_value.is_some() {
                best_wildcard = child.wildcard_value.as_ref();
            }
            node = child;
        }

        // Consumed all labels: exact match wins over wildcard.
        node.exact_value.as_ref().or(best_wildcard)
    }

    /// Number of entries inserted (exact + domain).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the trie contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Walk the trie to the node for `domain`, creating nodes as needed.
    ///
    /// Lowercases each label during insertion.
    fn walk_or_create(&mut self, domain: &str) -> &mut TrieNode<V> {
        let mut node = &mut self.root;
        for label in domain.rsplit('.') {
            let key = label.to_ascii_lowercase();
            node = node.children.entry(key).or_default();
        }
        node
    }
}

#[cfg(test)]
#[path = "domain_trie_test.rs"]
mod domain_trie_test;
