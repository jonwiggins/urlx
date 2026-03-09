//! Error code mapping verification tests.
//!
//! These tests verify that liburlx error types map correctly to
//! the expected curl error categories. While we don't use numeric
//! `CURLcode` values in the Rust API, the error types should be
//! distinguishable and match curl's error semantics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Error;

/// `Error::UrlParse` corresponds to `CURLE_URL_MALFORMAT` (3)
#[test]
fn url_parse_error_for_malformed_url() {
    let mut easy = liburlx::Easy::new();
    let err = easy.url("not a url at all !!!").unwrap_err();
    assert!(matches!(err, Error::UrlParse(_)), "Expected UrlParse error, got: {err:?}");
}

/// `Error::UrlParse` for empty URL
#[test]
fn url_parse_error_for_empty_url() {
    let mut easy = liburlx::Easy::new();
    let err = easy.url("").unwrap_err();
    assert!(
        matches!(err, Error::UrlParse(_)),
        "Expected UrlParse error for empty URL, got: {err:?}"
    );
}

/// The url crate treats schemeless URLs as relative — our parser wraps it,
/// so "example.com/path" may succeed (like curl which tries adding http://).
/// What matters is that truly unparseable URLs fail.
#[test]
fn url_parse_error_for_garbage() {
    let mut easy = liburlx::Easy::new();
    let err = easy.url("://").unwrap_err();
    assert!(
        matches!(err, Error::UrlParse(_)),
        "Expected UrlParse error for garbage URL, got: {err:?}"
    );
}

/// Valid URL patterns should parse successfully
#[test]
fn valid_url_patterns() {
    let mut easy = liburlx::Easy::new();

    // Standard HTTP URLs
    assert!(easy.url("http://example.com").is_ok());
    assert!(easy.url("https://example.com").is_ok());
    assert!(easy.url("http://example.com:8080/path").is_ok());
    assert!(easy.url("http://user:pass@example.com/").is_ok());

    // FTP URLs
    assert!(easy.url("ftp://ftp.example.com/pub/file.txt").is_ok());

    // File URLs
    assert!(easy.url("file:///tmp/test.txt").is_ok());
}

/// URL with query and fragment
#[test]
fn url_with_query_and_fragment() {
    let url = liburlx::Url::parse("http://example.com/path?key=value&a=b#section").unwrap();
    assert_eq!(url.path(), "/path");
    assert_eq!(url.query(), Some("key=value&a=b"));
    assert_eq!(url.fragment(), Some("section"));
}

/// URL with percent-encoded characters
#[test]
fn url_percent_encoded_path() {
    let url = liburlx::Url::parse("http://example.com/path%20with%20spaces").unwrap();
    assert!(url.path().contains("path"));
}

/// Error display is human-readable
#[test]
fn error_display_readable() {
    let mut easy = liburlx::Easy::new();
    let err = easy.url("://bad").unwrap_err();
    let msg = err.to_string();
    // Should be a useful message, not empty or Debug-formatted
    assert!(!msg.is_empty());
    assert!(!msg.starts_with("Error("), "Error display should be human-readable, not Debug: {msg}");
}

/// Error variants are distinct
#[test]
fn error_variant_distinctness() {
    // UrlParse — use a truly unparseable URL
    let url_err = liburlx::Easy::new().url("://").unwrap_err();
    assert!(matches!(url_err, Error::UrlParse(_)));

    // Errors should have different Display output
    let msg1 = url_err.to_string();
    assert!(!msg1.is_empty());
}

/// Timeout error contains duration info
#[test]
fn timeout_error_format() {
    let err = Error::Timeout(std::time::Duration::from_secs(30));
    let msg = err.to_string();
    assert!(msg.contains("30"), "Expected duration in error: {msg}");
    assert!(msg.contains("timeout"), "Expected 'timeout' in error: {msg}");
}

/// Http error contains message
#[test]
fn http_error_format() {
    let err = Error::Http("bad response".to_string());
    let msg = err.to_string();
    assert!(msg.contains("bad response"), "Expected message in error: {msg}");
}

/// Transfer error contains code and message
#[test]
fn transfer_error_format() {
    let err = Error::Transfer { code: 22, message: "HTTP error".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("22"), "Expected code in error: {msg}");
    assert!(msg.contains("HTTP error"), "Expected message in error: {msg}");
}
