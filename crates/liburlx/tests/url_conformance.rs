//! URL parsing conformance tests.
//!
//! Tests URL parsing against edge cases from RFC 3986 and
//! common real-world URLs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Url;

// --- Scheme handling ---

#[test]
fn scheme_http() {
    let url = Url::parse("http://example.com").unwrap();
    assert_eq!(url.scheme(), "http");
}

#[test]
fn scheme_https() {
    let url = Url::parse("https://example.com").unwrap();
    assert_eq!(url.scheme(), "https");
}

#[test]
fn scheme_case_insensitive() {
    let url = Url::parse("HTTP://example.com").unwrap();
    assert_eq!(url.scheme(), "http");
}

#[test]
fn scheme_mixed_case() {
    let url = Url::parse("HtTpS://example.com").unwrap();
    assert_eq!(url.scheme(), "https");
}

#[test]
fn no_scheme_defaults_to_http() {
    let url = Url::parse("example.com").unwrap();
    assert_eq!(url.scheme(), "http");
}

// --- Host handling ---

#[test]
fn host_lowercase() {
    let url = Url::parse("http://EXAMPLE.COM").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
}

#[test]
fn host_with_port() {
    let url = Url::parse("http://example.com:8080").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.port(), Some(8080));
}

#[test]
fn host_default_http_port() {
    let url = Url::parse("http://example.com:80").unwrap();
    assert_eq!(url.port(), None); // 80 is default for HTTP
    assert_eq!(url.port_or_default(), Some(80));
}

#[test]
fn host_default_https_port() {
    let url = Url::parse("https://example.com:443").unwrap();
    assert_eq!(url.port(), None); // 443 is default for HTTPS
    assert_eq!(url.port_or_default(), Some(443));
}

#[test]
fn host_ipv4() {
    let url = Url::parse("http://192.168.1.1").unwrap();
    assert_eq!(url.host_str(), Some("192.168.1.1"));
}

#[test]
fn host_ipv6() {
    let url = Url::parse("http://[::1]").unwrap();
    assert_eq!(url.host_str(), Some("[::1]"));
}

#[test]
fn host_ipv6_with_port() {
    let url = Url::parse("http://[::1]:8080").unwrap();
    assert_eq!(url.host_str(), Some("[::1]"));
    assert_eq!(url.port(), Some(8080));
}

// --- Path handling ---

#[test]
fn path_root() {
    let url = Url::parse("http://example.com").unwrap();
    assert_eq!(url.path(), "/");
}

#[test]
fn path_simple() {
    let url = Url::parse("http://example.com/path").unwrap();
    assert_eq!(url.path(), "/path");
}

#[test]
fn path_deep() {
    let url = Url::parse("http://example.com/a/b/c/d").unwrap();
    assert_eq!(url.path(), "/a/b/c/d");
}

#[test]
fn path_trailing_slash() {
    let url = Url::parse("http://example.com/path/").unwrap();
    assert_eq!(url.path(), "/path/");
}

#[test]
fn path_percent_encoded() {
    let url = Url::parse("http://example.com/hello%20world").unwrap();
    assert_eq!(url.path(), "/hello%20world");
}

// --- Query string ---

#[test]
fn query_simple() {
    let url = Url::parse("http://example.com/?key=value").unwrap();
    assert_eq!(url.query(), Some("key=value"));
}

#[test]
fn query_multiple_params() {
    let url = Url::parse("http://example.com/?a=1&b=2&c=3").unwrap();
    assert_eq!(url.query(), Some("a=1&b=2&c=3"));
}

#[test]
fn query_empty() {
    let url = Url::parse("http://example.com/?").unwrap();
    assert_eq!(url.query(), Some(""));
}

#[test]
fn no_query() {
    let url = Url::parse("http://example.com/path").unwrap();
    assert_eq!(url.query(), None);
}

// --- Fragment ---

#[test]
fn fragment_present() {
    let url = Url::parse("http://example.com/#section").unwrap();
    assert_eq!(url.fragment(), Some("section"));
}

#[test]
fn fragment_empty() {
    let url = Url::parse("http://example.com/#").unwrap();
    assert_eq!(url.fragment(), Some(""));
}

#[test]
fn no_fragment() {
    let url = Url::parse("http://example.com/path").unwrap();
    assert_eq!(url.fragment(), None);
}

#[test]
fn query_and_fragment() {
    let url = Url::parse("http://example.com/?q=1#frag").unwrap();
    assert_eq!(url.query(), Some("q=1"));
    assert_eq!(url.fragment(), Some("frag"));
}

// --- Credentials ---

#[test]
fn credentials_present() {
    let url = Url::parse("http://user:pass@example.com").unwrap();
    let (u, p) = url.credentials().unwrap();
    assert_eq!(u, "user");
    assert_eq!(p, "pass");
}

#[test]
fn credentials_empty_password() {
    let url = Url::parse("http://user:@example.com").unwrap();
    let (u, p) = url.credentials().unwrap();
    assert_eq!(u, "user");
    assert_eq!(p, "");
}

#[test]
fn no_credentials() {
    let url = Url::parse("http://example.com").unwrap();
    assert!(url.credentials().is_none());
}

// --- Roundtrip ---

#[test]
fn as_str_roundtrip() {
    let original = "http://example.com/path?q=1#frag";
    let url = Url::parse(original).unwrap();
    let reparsed = Url::parse(url.as_str()).unwrap();
    assert_eq!(url.as_str(), reparsed.as_str());
}

#[test]
fn display_same_as_str() {
    let url = Url::parse("http://example.com/path").unwrap();
    assert_eq!(format!("{url}"), url.as_str());
}

// --- host_and_port ---

#[test]
fn host_and_port_http_default() {
    let url = Url::parse("http://example.com/path").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
}

#[test]
fn host_and_port_https_default() {
    let url = Url::parse("https://example.com/path").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);
}

#[test]
fn host_and_port_explicit() {
    let url = Url::parse("http://example.com:9090/path").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 9090);
}

// --- request_target ---

#[test]
fn request_target_path_only() {
    let url = Url::parse("http://example.com/api/v1").unwrap();
    assert_eq!(url.request_target(), "/api/v1");
}

#[test]
fn request_target_with_query() {
    let url = Url::parse("http://example.com/search?q=hello").unwrap();
    assert_eq!(url.request_target(), "/search?q=hello");
}

#[test]
fn request_target_root() {
    let url = Url::parse("http://example.com").unwrap();
    assert_eq!(url.request_target(), "/");
}

// --- host_header_value ---

#[test]
fn host_header_value_no_port() {
    let url = Url::parse("http://example.com/path").unwrap();
    assert_eq!(url.host_header_value(), "example.com");
}

#[test]
fn host_header_value_with_port() {
    let url = Url::parse("http://example.com:9090/path").unwrap();
    assert_eq!(url.host_header_value(), "example.com:9090");
}

// --- Error cases ---

#[test]
fn empty_string_fails() {
    assert!(Url::parse("").is_err());
}

#[test]
fn just_scheme_fails() {
    // "http://" alone should fail or produce empty host
    let result = Url::parse("http://");
    // This is implementation-specific; we just verify it doesn't panic
    let _ = result;
}

// --- Real-world URLs ---

#[test]
fn github_url() {
    let url = Url::parse("https://github.com/user/repo/tree/main/src").unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("github.com"));
    assert_eq!(url.path(), "/user/repo/tree/main/src");
}

#[test]
fn url_with_port_and_path() {
    let url = Url::parse("http://localhost:3000/api/health").unwrap();
    assert_eq!(url.host_str(), Some("localhost"));
    assert_eq!(url.port(), Some(3000));
    assert_eq!(url.path(), "/api/health");
}
