//! Cookie jar stress tests.
//!
//! Tests for extreme inputs, many cookies, and edge conditions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::CookieJar;

// --- Very long cookie names and values ---

#[test]
fn very_long_cookie_name() {
    let mut jar = CookieJar::new();
    let name = "x".repeat(4096);
    jar.store_cookies(&[&format!("{name}=value")], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert!(header.starts_with(&name));
}

#[test]
fn very_long_cookie_value() {
    let mut jar = CookieJar::new();
    let value = "y".repeat(4096);
    jar.store_cookies(&[&format!("key={value}")], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert!(header.contains(&value));
}

// --- Many cookies ---

#[test]
fn one_thousand_cookies() {
    let mut jar = CookieJar::new();
    for i in 0..1000 {
        jar.store_cookies(&[&format!("key{i}=val{i}")], "example.com", "/", true);
    }
    assert_eq!(jar.len(), 1000);

    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert!(header.contains("key0=val0"));
    assert!(header.contains("key999=val999"));
}

#[test]
fn many_cookies_different_domains() {
    let mut jar = CookieJar::new();
    for i in 0..100 {
        let domain = format!("host{i}.example.com");
        jar.store_cookies(&[&format!("token=val{i}")], &domain, "/", true);
    }
    assert_eq!(jar.len(), 100);

    // Only cookies for the specific domain should match
    let header = jar.cookie_header("host42.example.com", "/", false).unwrap();
    assert_eq!(header, "token=val42");
}

#[test]
fn many_cookies_different_paths() {
    let mut jar = CookieJar::new();
    for i in 0..50 {
        let path = format!("/section{i}");
        jar.store_cookies(&[&format!("page=val{i}; Path={path}")], "example.com", "/", true);
    }
    assert_eq!(jar.len(), 50);

    // Only the cookie for /section10 should match
    let header = jar.cookie_header("example.com", "/section10/page", false).unwrap();
    assert_eq!(header, "page=val10");
}

// --- Special characters in values ---

#[test]
fn cookie_value_with_spaces() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["name=hello world"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert_eq!(header, "name=hello world");
}

#[test]
fn cookie_value_with_semicolons_as_attributes() {
    // Semicolons after the value are attribute separators
    let mut jar = CookieJar::new();
    jar.store_cookies(&["name=value; Path=/; Secure"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    // Value should be just "value", not "value; Path=/; Secure"
    let header = jar.cookie_header("example.com", "/", true).unwrap();
    assert_eq!(header, "name=value");
}

#[test]
fn cookie_value_with_equals() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["token=abc=def=ghi"], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert_eq!(header, "token=abc=def=ghi");
}

#[test]
fn cookie_empty_value() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["name="], "example.com", "/", true);
    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert_eq!(header, "name=");
}

// --- Domain matching edge cases ---

#[test]
fn domain_matching_deeply_nested() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val; Domain=example.com"], "a.b.c.d.e.example.com", "/", true);

    // Should match all subdomains
    assert!(jar.cookie_header("a.b.c.d.e.example.com", "/", false).is_some());
    assert!(jar.cookie_header("example.com", "/", false).is_some());
    assert!(jar.cookie_header("other.com", "/", false).is_none());
}

#[test]
fn domain_matching_partial_suffix() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val"], "example.com", "/", true);

    // "notexample.com" should NOT match "example.com"
    assert!(jar.cookie_header("notexample.com", "/", false).is_none());
    // "myexample.com" should NOT match
    assert!(jar.cookie_header("myexample.com", "/", false).is_none());
}

// --- Path matching edge cases ---

#[test]
fn path_matching_root() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val; Path=/"], "example.com", "/", true);

    // Root path should match everything
    assert!(jar.cookie_header("example.com", "/", false).is_some());
    assert!(jar.cookie_header("example.com", "/foo", false).is_some());
    assert!(jar.cookie_header("example.com", "/foo/bar", false).is_some());
}

#[test]
fn path_matching_trailing_slash() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val; Path=/api/"], "example.com", "/", true);

    assert!(jar.cookie_header("example.com", "/api/", false).is_some());
    assert!(jar.cookie_header("example.com", "/api/v1", false).is_some());
}

#[test]
fn path_matching_no_partial_segment() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val; Path=/api"], "example.com", "/", true);

    // /api should match /api and /api/...
    assert!(jar.cookie_header("example.com", "/api", false).is_some());
    assert!(jar.cookie_header("example.com", "/api/v1", false).is_some());
    // /apifoo should NOT match /api (not a path segment boundary)
    assert!(jar.cookie_header("example.com", "/apifoo", false).is_none());
}

// --- Expiration ---

#[test]
fn negative_max_age_expires() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["key=val; Max-Age=-1"], "example.com", "/", true);
    jar.remove_expired();
    assert!(jar.is_empty());
}

#[test]
fn remove_expired_keeps_valid() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["alive=yes; Max-Age=3600"], "example.com", "/", true);
    jar.store_cookies(&["dead=no; Max-Age=0"], "example.com", "/", true);
    jar.remove_expired();

    assert_eq!(jar.len(), 1);
    let header = jar.cookie_header("example.com", "/", false).unwrap();
    assert_eq!(header, "alive=yes");
}

// --- Invalid cookie formats ---

#[test]
fn no_value_part() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["justname"], "example.com", "/", true);
    assert!(jar.is_empty(), "cookie without = should be rejected");
}

#[test]
fn whitespace_only_name() {
    let mut jar = CookieJar::new();
    jar.store_cookies(&["   =value"], "example.com", "/", true);
    assert!(jar.is_empty(), "whitespace-only name should be rejected");
}

#[test]
fn multiple_invalid_cookies_mixed_with_valid() {
    let mut jar = CookieJar::new();
    jar.store_cookies(
        &["invalid", "valid=yes", "=empty_name", "also_valid=true"],
        "example.com",
        "/",
        true,
    );
    assert_eq!(jar.len(), 2);
}
