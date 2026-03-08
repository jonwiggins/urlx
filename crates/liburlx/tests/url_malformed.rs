//! Tests for URL parsing with malformed and unusual inputs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Url;

// --- Control characters ---

#[test]
fn url_with_null_byte() {
    let result = Url::parse("http://example.com/path\0rest");
    // Should either reject or handle safely
    if let Ok(url) = result {
        // If it parses, it should not contain the null byte in a dangerous way
        assert!(!url.as_str().is_empty());
    }
}

#[test]
fn url_with_tab_in_path() {
    let result = Url::parse("http://example.com/path\twith\ttabs");
    // The url crate strips tabs per WHATWG URL spec
    if let Ok(url) = result {
        assert!(!url.path().contains('\t'));
    }
}

#[test]
fn url_with_newline() {
    let result = Url::parse("http://example.com/path\nwith\nnewlines");
    // Should strip or reject
    if let Ok(url) = result {
        assert!(!url.path().contains('\n'));
    }
}

// --- Extremely long URLs ---

#[test]
fn very_long_url() {
    let long_path = "/a".repeat(50_000);
    let url_str = format!("http://example.com{long_path}");
    let result = Url::parse(&url_str);
    if let Ok(url) = result {
        assert!(url.path().len() >= 50_000);
    }
}

#[test]
fn very_long_query_string() {
    let long_query = "k=".to_string() + &"v".repeat(50_000);
    let url_str = format!("http://example.com/?{long_query}");
    let result = Url::parse(&url_str);
    if let Ok(url) = result {
        assert!(url.query().is_some());
    }
}

#[test]
fn very_long_host() {
    let long_host = format!("{}.com", "a".repeat(255));
    let url_str = format!("http://{long_host}/");
    // Very long hostnames may or may not parse
    let _result = Url::parse(&url_str);
}

// --- Edge cases with scheme ---

#[test]
fn scheme_only_no_host() {
    let result = Url::parse("http://");
    // Should fail — no host
    assert!(result.is_err(), "http:// with no host should fail");
}

#[test]
fn double_colon_in_scheme() {
    // This will get the default http:// prepended since no :// found
    let result = Url::parse("ht:tp://example.com");
    // May fail or parse as http + path
    if let Ok(url) = result {
        // The ht:tp://example.com will get http:// prepended
        assert!(!url.as_str().is_empty());
    }
}

#[test]
fn unknown_scheme() {
    let result = Url::parse("foobar://example.com/");
    assert!(result.is_ok(), "unknown schemes should parse");
    assert_eq!(result.unwrap().scheme(), "foobar");
}

// --- IPv6 addresses ---

#[test]
fn ipv6_localhost() {
    let url = Url::parse("http://[::1]/").unwrap();
    assert_eq!(url.host_str(), Some("[::1]"));
}

#[test]
fn ipv6_full_address() {
    let url = Url::parse("http://[2001:db8:85a3::8a2e:370:7334]/").unwrap();
    assert_eq!(url.host_str(), Some("[2001:db8:85a3::8a2e:370:7334]"));
}

#[test]
fn ipv6_with_port() {
    let url = Url::parse("http://[::1]:8080/path").unwrap();
    assert_eq!(url.host_str(), Some("[::1]"));
    assert_eq!(url.port(), Some(8080));
}

#[test]
fn ipv6_zone_id() {
    // Zone IDs in IPv6 (fe80::1%25eth0) — percent-encoded
    let result = Url::parse("http://[fe80::1%25eth0]/");
    if let Ok(url) = result {
        assert!(url.host_str().is_some());
    }
}

// --- Special characters in components ---

#[test]
fn at_sign_in_path() {
    let url = Url::parse("http://example.com/user@host").unwrap();
    assert!(url.path().contains('@'));
}

#[test]
fn hash_in_query() {
    // # starts a fragment, so it shouldn't be in the query
    let url = Url::parse("http://example.com/?q=a#b").unwrap();
    assert_eq!(url.query(), Some("q=a"));
    assert_eq!(url.fragment(), Some("b"));
}

#[test]
fn percent_encoded_space() {
    let url = Url::parse("http://example.com/hello%20world").unwrap();
    assert_eq!(url.path(), "/hello%20world");
}

#[test]
fn percent_encoded_slash() {
    let url = Url::parse("http://example.com/a%2Fb").unwrap();
    assert_eq!(url.path(), "/a%2Fb");
}

#[test]
fn unicode_in_path() {
    let result = Url::parse("http://example.com/café");
    if let Ok(url) = result {
        // url crate percent-encodes non-ASCII
        assert!(url.path().contains("caf"));
    }
}

// --- Port edge cases ---

#[test]
fn port_max_valid() {
    let url = Url::parse("http://example.com:65535/").unwrap();
    assert_eq!(url.port(), Some(65535));
}

#[test]
fn port_too_large() {
    let result = Url::parse("http://example.com:65536/");
    assert!(result.is_err(), "port 65536 should be invalid");
}

#[test]
fn port_negative_like() {
    let result = Url::parse("http://example.com:-1/");
    assert!(result.is_err(), "negative port should be invalid");
}

#[test]
fn port_non_numeric() {
    let result = Url::parse("http://example.com:abc/");
    assert!(result.is_err(), "non-numeric port should be invalid");
}

#[test]
fn port_empty() {
    // "http://example.com:/" — empty port
    let result = Url::parse("http://example.com:/");
    // url crate may accept this (treats as no port)
    if let Ok(url) = result {
        assert!(url.port().is_none());
    }
}

// --- Empty and whitespace ---

#[test]
fn empty_string_rejected() {
    assert!(Url::parse("").is_err());
}

#[test]
fn whitespace_only() {
    // Will get http:// prepended, then fail to parse
    let result = Url::parse("   ");
    // May parse as http://   which should fail
    if result.is_ok() {
        // If it parses, the host should be something reasonable
    }
}

// --- Data URL-like ---

#[test]
fn data_url_scheme() {
    let result = Url::parse("data:text/plain;base64,SGVsbG8=");
    if let Ok(url) = result {
        assert_eq!(url.scheme(), "data");
    }
}

// --- Relative-like URLs with scheme defaulting ---

#[test]
fn bare_hostname() {
    let url = Url::parse("example.com").unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("example.com"));
}

#[test]
fn hostname_with_path() {
    let url = Url::parse("example.com/path/to/resource").unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.path(), "/path/to/resource");
}

#[test]
fn hostname_with_port() {
    let url = Url::parse("localhost:8080").unwrap();
    assert_eq!(url.scheme(), "http");
    // Note: the url crate may interpret "localhost:8080" differently with http:// prefix
}

// --- Multiple question marks ---

#[test]
fn multiple_question_marks() {
    let url = Url::parse("http://example.com/path?a=1?b=2").unwrap();
    // Only the first ? starts the query
    assert_eq!(url.query(), Some("a=1?b=2"));
}

// --- Trailing characters ---

#[test]
fn trailing_hash() {
    let url = Url::parse("http://example.com/path#").unwrap();
    assert_eq!(url.fragment(), Some(""));
}

#[test]
fn trailing_question_mark() {
    let url = Url::parse("http://example.com/path?").unwrap();
    assert_eq!(url.query(), Some(""));
}
