//! URL edge case tests.
//!
//! Tests URL parsing and manipulation for edge cases including
//! IPv6, credentials with special chars, fragments, and long paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Url;

// --- IPv6 addresses ---

#[test]
fn parse_ipv6_url() {
    let url = Url::parse("http://[::1]/path").unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.path(), "/path");
}

#[test]
fn parse_ipv6_with_port() {
    let url = Url::parse("http://[::1]:8080/").unwrap();
    assert_eq!(url.port(), Some(8080));
}

// --- Fragments ---

#[test]
fn fragment_preserved() {
    let url = Url::parse("http://example.com/page#section").unwrap();
    assert_eq!(url.fragment(), Some("section"));
}

#[test]
fn empty_fragment() {
    let url = Url::parse("http://example.com/page#").unwrap();
    assert_eq!(url.fragment(), Some(""));
}

#[test]
fn no_fragment() {
    let url = Url::parse("http://example.com/page").unwrap();
    assert_eq!(url.fragment(), None);
}

// --- Query strings ---

#[test]
fn query_with_multiple_params() {
    let url = Url::parse("http://example.com/?a=1&b=2&c=3").unwrap();
    assert_eq!(url.query(), Some("a=1&b=2&c=3"));
}

#[test]
fn query_with_encoded_chars() {
    let url = Url::parse("http://example.com/?q=hello%20world").unwrap();
    assert_eq!(url.query(), Some("q=hello%20world"));
}

#[test]
fn empty_query() {
    let url = Url::parse("http://example.com/?").unwrap();
    assert_eq!(url.query(), Some(""));
}

// --- Credentials ---

#[test]
fn credentials_with_special_chars() {
    let url = Url::parse("http://user%40name:p%40ss@example.com/").unwrap();
    assert_eq!(url.username(), "user%40name");
}

#[test]
fn password_with_colon() {
    let url = Url::parse("http://user:p%3Ass%3Aword@example.com/").unwrap();
    assert!(url.password().is_some());
}

// --- Path edge cases ---

#[test]
fn root_path() {
    let url = Url::parse("http://example.com/").unwrap();
    assert_eq!(url.path(), "/");
}

#[test]
fn path_with_trailing_slash() {
    let url = Url::parse("http://example.com/api/").unwrap();
    assert_eq!(url.path(), "/api/");
}

#[test]
fn deeply_nested_path() {
    let url = Url::parse("http://example.com/a/b/c/d/e/f/g").unwrap();
    assert_eq!(url.path(), "/a/b/c/d/e/f/g");
}

#[test]
fn path_with_percent_encoding() {
    let url = Url::parse("http://example.com/path%20with%20spaces").unwrap();
    assert_eq!(url.path(), "/path%20with%20spaces");
}

// --- Port edge cases ---

#[test]
fn port_or_default_http() {
    let url = Url::parse("http://example.com/").unwrap();
    assert_eq!(url.port_or_default(), Some(80));
}

#[test]
fn port_or_default_https() {
    let url = Url::parse("https://example.com/").unwrap();
    assert_eq!(url.port_or_default(), Some(443));
}

#[test]
fn explicit_port_overrides_default() {
    let url = Url::parse("http://example.com:8080/").unwrap();
    assert_eq!(url.port(), Some(8080));
    assert_eq!(url.port_or_default(), Some(8080));
}

// --- Scheme edge cases ---

#[test]
fn ftp_scheme() {
    let url = Url::parse("ftp://files.example.com/pub/").unwrap();
    assert_eq!(url.scheme(), "ftp");
}

// --- host_and_port ---

#[test]
fn host_and_port_default_http() {
    let url = Url::parse("http://example.com/").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
}

#[test]
fn host_and_port_custom_port() {
    let url = Url::parse("http://example.com:9090/").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 9090);
}

// --- host_header_value ---

#[test]
fn host_header_default_port_omitted() {
    let url = Url::parse("http://example.com/").unwrap();
    assert_eq!(url.host_header_value(), "example.com");
}

#[test]
fn host_header_custom_port_included() {
    let url = Url::parse("http://example.com:8080/").unwrap();
    assert_eq!(url.host_header_value(), "example.com:8080");
}

// --- request_target ---

#[test]
fn request_target_with_path_and_query() {
    let url = Url::parse("http://example.com/api?key=val").unwrap();
    assert_eq!(url.request_target(), "/api?key=val");
}

#[test]
fn request_target_root_only() {
    let url = Url::parse("http://example.com").unwrap();
    assert_eq!(url.request_target(), "/");
}

// --- Display / as_str roundtrip ---

#[test]
fn display_roundtrip() {
    let input = "http://example.com/path?q=1#frag";
    let url = Url::parse(input).unwrap();
    let output = url.as_str();
    let reparsed = Url::parse(output).unwrap();
    assert_eq!(url.scheme(), reparsed.scheme());
    assert_eq!(url.path(), reparsed.path());
    assert_eq!(url.query(), reparsed.query());
    assert_eq!(url.fragment(), reparsed.fragment());
}
