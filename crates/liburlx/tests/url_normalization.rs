//! URL parser normalization and additional edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Url;

// --- Scheme normalization ---

#[test]
fn scheme_lowercased() {
    let url = Url::parse("HTTP://example.com").unwrap();
    assert_eq!(url.scheme(), "http");
}

#[test]
fn scheme_mixed_case_lowercased() {
    let url = Url::parse("HtTpS://example.com").unwrap();
    assert_eq!(url.scheme(), "https");
}

// --- Host normalization ---

#[test]
fn host_lowercased() {
    let url = Url::parse("http://EXAMPLE.COM").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
}

#[test]
fn host_mixed_case_lowercased() {
    let url = Url::parse("http://ExAmPlE.CoM/path").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
}

// --- Default scheme ---

#[test]
fn no_scheme_defaults_to_http() {
    let url = Url::parse("example.com").unwrap();
    assert_eq!(url.scheme(), "http");
}

#[test]
fn no_scheme_with_path() {
    let url = Url::parse("example.com/path").unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.path(), "/path");
}

#[test]
fn no_scheme_with_port() {
    let url = Url::parse("example.com:8080").unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.port(), Some(8080));
}

// --- Path normalization ---

#[test]
fn empty_path_becomes_slash() {
    let url = Url::parse("http://example.com").unwrap();
    assert_eq!(url.path(), "/");
}

#[test]
fn path_with_trailing_slash() {
    let url = Url::parse("http://example.com/dir/").unwrap();
    assert_eq!(url.path(), "/dir/");
}

#[test]
fn path_with_double_slash() {
    let url = Url::parse("http://example.com//double//slash").unwrap();
    // URL parser preserves double slashes
    assert!(url.path().contains("//"));
}

// --- Port handling ---

#[test]
fn explicit_port_80_on_http() {
    let url = Url::parse("http://example.com:80/path").unwrap();
    // Port 80 is the default for HTTP, may be normalized away
    assert_eq!(url.host_str(), Some("example.com"));
}

#[test]
fn explicit_port_443_on_https() {
    let url = Url::parse("https://example.com:443/path").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
}

#[test]
fn non_default_port() {
    let url = Url::parse("http://example.com:8080/path").unwrap();
    assert_eq!(url.port(), Some(8080));
}

// --- Query string ---

#[test]
fn query_string_preserved() {
    let url = Url::parse("http://example.com/path?key=value&other=123").unwrap();
    assert_eq!(url.query(), Some("key=value&other=123"));
}

#[test]
fn empty_query() {
    let url = Url::parse("http://example.com/path?").unwrap();
    assert_eq!(url.query(), Some(""));
}

#[test]
fn query_with_special_chars() {
    let url = Url::parse("http://example.com/?q=hello+world&lang=en").unwrap();
    let query = url.query().unwrap();
    assert!(query.contains("hello"));
    assert!(query.contains("world"));
}

// --- Fragment ---

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
fn fragment_with_query() {
    let url = Url::parse("http://example.com/page?q=1#top").unwrap();
    assert_eq!(url.query(), Some("q=1"));
    assert_eq!(url.fragment(), Some("top"));
}

// --- Credentials ---

#[test]
fn url_with_user_only() {
    let url = Url::parse("http://user@example.com").unwrap();
    let creds = url.credentials();
    assert!(creds.is_some());
    let (user, pass) = creds.unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "");
}

#[test]
fn url_with_user_and_password() {
    let url = Url::parse("http://user:pass@example.com").unwrap();
    let creds = url.credentials().unwrap();
    assert_eq!(creds.0, "user");
    assert_eq!(creds.1, "pass");
}

#[test]
fn url_without_credentials() {
    let url = Url::parse("http://example.com").unwrap();
    assert!(url.credentials().is_none());
}

// --- Host and port extraction ---

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
fn host_and_port_custom() {
    let url = Url::parse("http://example.com:9090").unwrap();
    let (host, port) = url.host_and_port().unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 9090);
}

// --- Request target ---

#[test]
fn request_target_path_only() {
    let url = Url::parse("http://example.com/api/v1/users").unwrap();
    let target = url.request_target();
    assert_eq!(target, "/api/v1/users");
}

#[test]
fn request_target_with_query() {
    let url = Url::parse("http://example.com/search?q=test").unwrap();
    let target = url.request_target();
    assert_eq!(target, "/search?q=test");
}

#[test]
fn request_target_root() {
    let url = Url::parse("http://example.com").unwrap();
    let target = url.request_target();
    assert_eq!(target, "/");
}

// --- Scheme indicates TLS ---

#[test]
fn http_scheme_is_not_tls() {
    let url = Url::parse("http://example.com").unwrap();
    assert_ne!(url.scheme(), "https");
}

#[test]
fn https_scheme_is_tls() {
    let url = Url::parse("https://example.com").unwrap();
    assert_eq!(url.scheme(), "https");
}

// --- FTP default port ---

#[test]
fn ftp_default_port_21() {
    let url = Url::parse("ftp://ftp.example.com/file.txt").unwrap();
    let (_, port) = url.host_and_port().unwrap();
    assert_eq!(port, 21);
}

// --- Roundtrip ---

#[test]
fn url_roundtrip() {
    let original = "http://example.com/path?q=1#frag";
    let url = Url::parse(original).unwrap();
    assert_eq!(url.as_str(), original);
}

#[test]
fn url_roundtrip_with_credentials() {
    let original = "http://user:pass@example.com/path";
    let url = Url::parse(original).unwrap();
    assert_eq!(url.as_str(), original);
}
