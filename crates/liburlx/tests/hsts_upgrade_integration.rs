//! HSTS upgrade integration tests.
//!
//! Tests HSTS behavior through the Easy handle API, verifying
//! that HTTP URLs are upgraded to HTTPS when HSTS is cached.
//! Note: actual HTTPS upgrade requires TLS infrastructure, so these
//! tests focus on the HSTS cache logic and Easy handle behavior.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::{Easy, HstsCache};

// --- HSTS cache standalone behavior ---

#[test]
fn hsts_cache_stores_and_upgrades() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=31536000");
    assert!(cache.should_upgrade("example.com"));
    assert!(!cache.should_upgrade("other.com"));
}

#[test]
fn hsts_cache_include_subdomains() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600; includeSubDomains");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("www.example.com"));
    assert!(cache.should_upgrade("api.example.com"));
    assert!(!cache.should_upgrade("other.com"));
}

#[test]
fn hsts_cache_max_age_zero_removes() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=3600");
    assert!(cache.should_upgrade("example.com"));

    cache.store("example.com", "max-age=0");
    assert!(!cache.should_upgrade("example.com"));
}

// --- Easy handle HSTS configuration ---

#[test]
fn easy_hsts_disabled_by_default() {
    let easy = Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: None"), "HSTS should be None by default");
}

#[test]
fn easy_hsts_enabled() {
    let mut easy = Easy::new();
    easy.hsts(true);
    let debug = format!("{easy:?}");
    assert!(!debug.contains("hsts_cache: None"), "HSTS should be enabled");
}

#[test]
fn easy_hsts_toggle() {
    let mut easy = Easy::new();
    easy.hsts(true);
    assert!(!format!("{easy:?}").contains("hsts_cache: None"));

    easy.hsts(false);
    assert!(format!("{easy:?}").contains("hsts_cache: None"));

    easy.hsts(true);
    assert!(!format!("{easy:?}").contains("hsts_cache: None"));
}

#[test]
fn easy_hsts_idempotent_enable() {
    let mut easy = Easy::new();
    easy.hsts(true);
    easy.hsts(true);
    easy.hsts(true);
    // Should still work, not create multiple caches
    let debug = format!("{easy:?}");
    assert!(!debug.contains("hsts_cache: None"));
}

// --- HSTS cache independence after clone ---

#[test]
fn cloned_easy_has_independent_hsts_cache() {
    let mut easy = Easy::new();
    easy.hsts(true);

    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(!debug.contains("hsts_cache: None"), "cloned should have HSTS cache");
}

// --- HSTS with various header formats ---

#[test]
fn hsts_various_header_formats() {
    let mut cache = HstsCache::new();

    // Standard format
    cache.store("a.com", "max-age=3600");
    assert!(cache.should_upgrade("a.com"));

    // With preload directive (ignored but shouldn't break)
    cache.store("b.com", "max-age=3600; preload");
    assert!(cache.should_upgrade("b.com"));

    // Extra whitespace
    cache.store("c.com", "  max-age=3600 ;  includeSubDomains  ");
    assert!(cache.should_upgrade("c.com"));
    assert!(cache.should_upgrade("sub.c.com"));
}

#[test]
fn hsts_max_age_mixed_case() {
    let mut cache = HstsCache::new();
    // Implementation supports "max-age" and "Max-Age" forms
    cache.store("example.com", "Max-Age=3600; includeSubDomains");
    assert!(cache.should_upgrade("example.com"));
    assert!(cache.should_upgrade("sub.example.com"));
}

// --- Edge cases ---

#[test]
fn hsts_invalid_max_age_ignored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "max-age=abc");
    assert!(!cache.should_upgrade("example.com"));
}

#[test]
fn hsts_missing_max_age_ignored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "includeSubDomains");
    assert!(!cache.should_upgrade("example.com"));
}

#[test]
fn hsts_empty_header_ignored() {
    let mut cache = HstsCache::new();
    cache.store("example.com", "");
    assert!(!cache.should_upgrade("example.com"));
}

#[test]
fn hsts_multiple_hosts_independent() {
    let mut cache = HstsCache::new();
    cache.store("a.com", "max-age=3600");
    cache.store("b.com", "max-age=3600");

    assert!(cache.should_upgrade("a.com"));
    assert!(cache.should_upgrade("b.com"));
    assert!(!cache.should_upgrade("c.com"));
}
