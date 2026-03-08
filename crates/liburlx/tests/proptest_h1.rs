//! Property-based tests for the HTTP/1.1 response parser.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write;

use proptest::prelude::*;

use liburlx::protocol::http::h1::parse_response;

proptest! {
    /// Any valid status code (100-599) parses correctly.
    #[test]
    fn valid_status_codes_parse(status in 100u16..600) {
        let raw = format!("HTTP/1.1 {status} Reason\r\nContent-Length: 0\r\n\r\n");
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert_eq!(resp.status(), status);
    }

    /// Content-Length body matches declared length.
    #[test]
    fn content_length_body_matches(
        body_len in 0usize..1000,
    ) {
        let body = "a".repeat(body_len);
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n{body}");
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert_eq!(resp.body().len(), body_len);
    }

    /// Response with N custom headers has all headers accessible.
    #[test]
    fn all_headers_accessible(n in 1usize..30) {
        let mut raw = "HTTP/1.1 200 OK\r\n".to_string();
        for i in 0..n {
            let _ = write!(raw, "X-H-{i}: val{i}\r\n");
        }
        raw.push_str("Content-Length: 0\r\n\r\n");

        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        for i in 0..n {
            let name = format!("x-h-{i}");
            let expected = format!("val{i}");
            prop_assert_eq!(
                resp.header(&name),
                Some(expected.as_str()),
                "header {} should be {}", name, expected
            );
        }
    }

    /// HEAD response always has empty body regardless of Content-Length.
    #[test]
    fn head_always_empty_body(cl in 0u32..10000) {
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {cl}\r\n\r\n");
        let resp = parse_response(raw.as_bytes(), "http://test.com", true).unwrap();
        prop_assert!(resp.body().is_empty(), "HEAD response should have empty body");
    }

    /// Effective URL is always preserved.
    #[test]
    fn effective_url_preserved(
        path in "/[a-z]{1,20}"
    ) {
        let url = format!("http://test.com{path}");
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw.as_bytes(), &url, false).unwrap();
        prop_assert_eq!(resp.effective_url(), url.as_str());
    }

    /// Redirect responses with Location header are detected.
    #[test]
    fn redirect_detection(
        status in prop::sample::select(vec![301u16, 302, 303, 307, 308]),
        location in "/[a-z]{1,10}"
    ) {
        let raw = format!(
            "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
        );
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert!(resp.is_redirect(), "status {} with Location should be redirect", status);
    }

    /// Non-redirect status codes are not detected as redirects.
    #[test]
    fn non_redirect_status_codes(
        status in prop::sample::select(vec![200u16, 201, 204, 400, 404, 500])
    ) {
        let raw = format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: 0\r\n\r\n"
        );
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert!(!resp.is_redirect(), "status {} should not be redirect", status);
    }

    /// `body_str()` succeeds for valid ASCII bodies.
    #[test]
    fn body_str_valid_ascii(body in "[a-zA-Z0-9 ]{0,100}") {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert_eq!(resp.body_str().unwrap(), body.as_str());
    }

    /// `size_download()` matches actual body length.
    #[test]
    fn size_download_matches(len in 0usize..500) {
        let body = "x".repeat(len);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n{body}"
        );
        let resp = parse_response(raw.as_bytes(), "http://test.com", false).unwrap();
        prop_assert_eq!(resp.size_download(), len);
    }
}
