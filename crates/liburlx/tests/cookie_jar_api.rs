//! `CookieJar` public API tests.
//!
//! Tests the `CookieJar` public API surface through `liburlx::CookieJar`
//! including `store_cookies`, `cookie_header`, `len`, `is_empty`,
//! `remove_expired`, and trait implementations.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use liburlx::CookieJar;

// --- Construction ---

#[test]
fn new_jar_is_empty() {
    let jar = CookieJar::new();
    assert!(jar.is_empty());
    assert_eq!(jar.len(), 0);
}

#[test]
fn default_jar_is_empty() {
    let jar = CookieJar::default();
    assert!(jar.is_empty());
}

// --- store_cookies ---

#[test]
fn store_single_cookie() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["session=abc123"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    assert!(!jar.is_empty());
}

#[test]
fn store_multiple_cookies() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["a=1", "b=2", "c=3"], "example.com", "/", true);
    assert_eq!(jar.len(), 3);
}

#[test]
fn store_cookie_with_domain() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["token=xyz; Domain=example.com"], "www.example.com", "/", true);
    assert_eq!(jar.len(), 1);
    // Should match subdomain
    assert!(jar.cookie_header("sub.example.com", "/", false).is_some());
}

#[test]
fn store_cookie_with_path() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["api_key=123; Path=/api"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    // Should match sub-path
    assert!(jar.cookie_header("example.com", "/api/v1", false).is_some());
    // Should not match different path
    assert!(jar.cookie_header("example.com", "/web", false).is_none());
}

// --- cookie_header ---

#[test]
fn cookie_header_returns_none_for_empty_jar() {
    let jar = CookieJar::new();
    assert!(jar.cookie_header("example.com", "/", false).is_none());
}

#[test]
fn cookie_header_returns_none_for_non_matching_domain() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["a=1"], "example.com", "/", true);
    assert!(jar.cookie_header("other.com", "/", false).is_none());
}

#[test]
fn cookie_header_joins_multiple_cookies() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["a=1", "b=2"], "example.com", "/", true);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert!(header.contains("a=1"));
    assert!(header.contains("b=2"));
    assert!(header.contains("; "));
}

#[test]
fn cookie_header_secure_filtering() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["secure_token=abc; Secure"], "example.com", "/", true);
    // Non-secure request should not get secure cookies
    assert!(jar.cookie_header("example.com", "/", false).is_none());
    // Secure request should get secure cookies
    assert!(jar.cookie_header("example.com", "/", true).is_some());
}

// --- Cookie replacement ---

#[test]
fn store_replaces_cookie_with_same_name() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=old"], "example.com", "/", true);
    jar.store_cookies(&["key=new"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    assert_eq!(jar.cookie_header("example.com", "/", false), Some("key=new".to_string()));
}

// --- remove_expired ---

#[test]
fn remove_expired_clears_max_age_zero() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["temp=1"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);

    // Set max-age=0 to expire it
    jar.store_cookies(&["temp=1; Max-Age=0"], "example.com", "/", true);
    jar.remove_expired();
    assert!(jar.is_empty());
}

#[test]
fn remove_expired_keeps_valid_cookies() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["valid=1; Max-Age=3600"], "example.com", "/", true);
    jar.store_cookies(&["session=2"], "example.com", "/", true);
    assert_eq!(jar.len(), 2);

    jar.remove_expired();
    assert_eq!(jar.len(), 2);
}

// --- Clone ---

#[test]
fn clone_is_independent() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["a=1"], "example.com", "/", true);

    let mut cloned = jar.clone();
    cloned.store_cookies(&["b=2"], "example.com", "/", true);

    assert_eq!(jar.len(), 1);
    assert_eq!(cloned.len(), 2);
}

// --- Debug ---

#[test]
fn debug_format() {
    let jar = CookieJar::new();
    let debug = format!("{jar:?}");
    assert!(debug.contains("CookieJar"));
}

// --- Edge cases ---

#[test]
fn empty_cookie_value_accepted() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["name="], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    assert_eq!(jar.cookie_header("example.com", "/", false), Some("name=".to_string()));
}

#[test]
fn cookie_with_equals_in_value() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["data=base64==abc"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
}

#[test]
fn store_from_headers_with_multiple_set_cookies() {
    use std::collections::HashMap;

    let mut jar = CookieJar::new();
    let mut headers = HashMap::new();
    headers.insert("set-cookie".to_string(), "a=1\nb=2".to_string());

    jar.store_from_headers(&headers, "example.com", "/", true);
    assert_eq!(jar.len(), 2);
}
