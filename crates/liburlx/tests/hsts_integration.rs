//! HSTS integration tests.
//!
//! Tests HSTS cache behavior: header parsing, `should_upgrade` logic,
//! includeSubDomains, max-age=0 removal, and expiry purging.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::hsts::HstsCache;

// --- Basic store and upgrade ---

#[test]
fn store_enables_upgrade() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=31536000");
    assert!(cache.should_upgrade("example.com"));
}

#[test]
fn unstored_host_not_upgraded() {
    let cache = HstsCache::new();
    assert!(!cache.should_upgrade("example.com"));
}

#[test]
fn different_host_not_upgraded() {
    let mut cache = HstsCache::new();
    cache.store("secure.example.com", "max-age=3600");
    assert!(!cache.should_upgrade("other.example.com"));
}

// --- Case insensitivity ---

#[test]
fn host_stored_case_insensitive() {
    let mut cache = HstsCache::new();
    cache.store("Example.COM", "max-age=3600");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("EXAMPLE.COM"));
    assert!(cache.should_upgrade("Example.Com"));
}

// --- includeSubDomains ---

#[test]
fn include_subdomains_upgrades_children() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600; includeSubDomains");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("www.example.com"));
    assert!(cache.should_upgrade("api.example.com"));
    assert!(cache.should_upgrade("deep.sub.example.com"));
}

#[test]
fn without_include_subdomains_no_child_upgrade() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");
    assert!(cache.should_upgrade("example.com"));
    assert!(!cache.should_upgrade("www.example.com"));
}

#[test]
fn include_subdomains_case_insensitive_directive() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600; INCLUDESUBDOMAINS");
    assert!(cache.should_upgrade("sub.example.com"));
}

// --- max-age=0 removes entry ---

#[test]
fn max_age_zero_removes_entry() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");
    assert!(cache.should_upgrade("example.com"));

    cache.store("example.com", "max-age=0");
    assert!(!cache.should_upgrade("example.com"));
}

// --- Multiple hosts ---

#[test]
fn multiple_hosts_stored_independently() {
    let mut cache = HstsCache::new();
    cache.store("a.com", "max-age=3600");
    cache.store("b.com", "max-age=3600");
    cache.store("c.com", "max-age=3600");

    assert!(cache.should_upgrade("a.com"));
    assert!(cache.should_upgrade("b.com"));
    assert!(cache.should_upgrade("c.com"));
    assert!(!cache.should_upgrade("d.com"));
}

// --- Header parsing edge cases ---

#[test]
fn whitespace_in_header_value() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "  max-age=3600 ;  includeSubDomains  ");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("sub.example.com"));
}

#[test]
fn extra_directives_ignored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600; preload; includeSubDomains");
    assert!(cache.should_upgrade("example.com"));
}

#[test]
fn invalid_max_age_not_stored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=notanumber");
    assert!(!cache.should_upgrade("example.com"));
}

#[test]
fn missing_max_age_not_stored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "includeSubDomains");
    assert!(!cache.should_upgrade("example.com"));
}

// --- purge_expired ---

#[test]
fn purge_expired_removes_zero_max_age() {
    let mut cache = HstsCache::new();
    cache.store("a.com", "max-age=3600");
    cache.store("b.com", "max-age=3600");

    // Remove one
    cache.store("a.com", "max-age=0");
    cache.purge_expired();

    assert!(!cache.should_upgrade("a.com"));
    assert!(cache.should_upgrade("b.com"));
}

// --- Clone ---

#[test]
fn cache_clone_is_independent() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");

    let mut cloned = cache.clone();
    cloned.store("other.com", "max-age=3600");

    assert!(cache.should_upgrade("example.com"));
    assert!(!cache.should_upgrade("other.com"));
    assert!(cloned.should_upgrade("example.com"));
    assert!(cloned.should_upgrade("other.com"));
}

// --- Debug ---

#[test]
fn cache_debug_format() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");
    let debug = format!("{cache:?}");
    assert!(debug.contains("HstsCache"));
}

// --- Default ---

#[test]
fn cache_default_is_empty() {
    let cache = HstsCache::default();
    assert!(!cache.should_upgrade("anything.com"));
}

// --- Update existing entry ---

#[test]
fn store_updates_existing_entry() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");
    assert!(cache.should_upgrade("example.com"));
    assert!(!cache.should_upgrade("sub.example.com"));

    // Update with includeSubDomains
    cache.store("example.com", "max-age=7200; includeSubDomains");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("sub.example.com"));
}
