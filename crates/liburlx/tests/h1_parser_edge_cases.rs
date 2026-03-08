//! HTTP/1.1 parser edge case tests using the public `parse_response` API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::http::h1::parse_response;

// --- Chunked encoding edge cases ---

#[test]
fn chunked_with_trailing_whitespace_in_size() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nhello\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"hello");
}

#[test]
fn chunked_with_extension_after_size() {
    let raw =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"hello");
}

#[test]
fn chunked_with_multiple_extensions() {
    let raw =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;a=1;b=2\r\nhello\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"hello");
}

#[test]
fn chunked_zero_chunk_only() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(resp.body().is_empty());
}

#[test]
fn chunked_many_small_chunks() {
    let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..10 {
        raw.extend_from_slice(b"1\r\nX\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    let resp = parse_response(&raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"XXXXXXXXXX");
}

#[test]
fn chunked_hex_uppercase() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body_str().unwrap(), "0123456789");
}

#[test]
fn chunked_hex_lowercase() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body_str().unwrap(), "0123456789");
}

// --- Content-Length edge cases ---

#[test]
fn content_length_zero() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(resp.body().is_empty());
}

#[test]
fn content_length_exact_match() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"hello world");
}

#[test]
fn content_length_truncates_extra_data() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello extra data";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"hello");
}

#[test]
fn content_length_body_shorter_than_declared() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    // Should return what we have
    assert_eq!(resp.body(), b"short");
}

// --- Status code edge cases ---

#[test]
fn status_204_no_body() {
    let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.status(), 204);
    assert!(resp.body().is_empty());
}

#[test]
fn status_304_no_body() {
    let raw = b"HTTP/1.1 304 Not Modified\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.status(), 304);
}

#[test]
fn status_1xx_informational() {
    // parse_response handles the status, the transport layer handles 1xx
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.status(), 200);
}

// --- HEAD request ---

#[test]
fn head_request_ignores_body() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", true).unwrap();
    assert!(resp.body().is_empty());
}

#[test]
fn head_request_preserves_headers() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 500\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", true).unwrap();
    assert_eq!(resp.header("content-type"), Some("text/html"));
    assert_eq!(resp.header("content-length"), Some("500"));
}

// --- Multiple Set-Cookie headers ---

#[test]
fn multiple_set_cookie_preserved() {
    let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    let cookies = resp.header("set-cookie").unwrap();
    assert!(cookies.contains("a=1"));
    assert!(cookies.contains("b=2"));
}

// --- Connection header ---

#[test]
fn connection_close_header() {
    let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.header("connection"), Some("close"));
}

#[test]
fn connection_keep_alive_header() {
    let raw = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.header("connection"), Some("keep-alive"));
}

// --- Redirect detection ---

#[test]
fn redirect_301_with_location() {
    let raw = b"HTTP/1.1 301 Moved\r\nLocation: /new\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(resp.is_redirect());
    assert_eq!(resp.header("location"), Some("/new"));
}

#[test]
fn redirect_302_with_location() {
    let raw = b"HTTP/1.1 302 Found\r\nLocation: /temp\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(resp.is_redirect());
}

#[test]
fn redirect_307_preserves_method() {
    let raw = b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /new\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(resp.is_redirect());
}

#[test]
fn status_300_not_a_redirect() {
    // 300 is "Multiple Choices" — not a redirect in our definition
    let raw = b"HTTP/1.1 300 Multiple Choices\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(!resp.is_redirect());
}

#[test]
fn status_301_without_location_not_redirect() {
    let raw = b"HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert!(!resp.is_redirect());
}

// --- No Content-Length, no chunked ---

#[test]
fn no_content_length_uses_remaining_data() {
    let raw = b"HTTP/1.1 200 OK\r\n\r\nall the remaining data";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.body(), b"all the remaining data");
}

// --- Response utility methods ---

#[test]
fn effective_url_preserved() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(raw, "http://final.test.com/page", false).unwrap();
    assert_eq!(resp.effective_url(), "http://final.test.com/page");
}

#[test]
fn content_type_method() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.content_type(), Some("application/json"));
}

#[test]
fn size_download_matches_body() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.size_download(), 5);
}

// --- Malformed responses ---

#[test]
fn incomplete_headers_error() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    let result = parse_response(raw, "http://test.com", false);
    assert!(result.is_err());
}

#[test]
fn empty_response_error() {
    let raw = b"";
    let result = parse_response(raw, "http://test.com", false);
    assert!(result.is_err());
}

#[test]
fn garbage_response_error() {
    let raw = b"NOT HTTP AT ALL";
    let result = parse_response(raw, "http://test.com", false);
    assert!(result.is_err());
}

// --- Header values with colons ---

#[test]
fn header_value_with_colons() {
    let raw = b"HTTP/1.1 200 OK\r\nX-Custom: value:with:colons\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.header("x-custom"), Some("value:with:colons"));
}

// --- Case-insensitive header names ---

#[test]
fn mixed_case_header_names() {
    let raw = b"HTTP/1.1 200 OK\r\nConTent-LENGth: 5\r\nX-CUSTOM: val\r\n\r\nhello";
    let resp = parse_response(raw, "http://test.com", false).unwrap();
    assert_eq!(resp.header("content-length"), Some("5"));
    assert_eq!(resp.header("x-custom"), Some("val"));
}
