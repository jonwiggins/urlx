//! H1 parser edge case tests.
//!
//! Tests `parse_response` with various response formats including
//! status line variations, Content-Length, chunked encoding, HEAD
//! handling, and malformed inputs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::http::h1::parse_response;

// --- Status line parsing ---

#[test]
fn parse_200_ok() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "hello");
}

#[test]
fn parse_404_not_found() {
    let data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
    let resp = parse_response(data, "http://example.com/missing", false).unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.body_str().unwrap(), "not found");
}

#[test]
fn parse_500_internal_server_error() {
    let data = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 500);
}

#[test]
fn parse_301_redirect() {
    let data = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com/old", false).unwrap();
    assert_eq!(resp.status(), 301);
    assert!(resp.is_redirect());
    assert_eq!(resp.header("location"), Some("/new"));
}

#[test]
fn parse_204_no_content() {
    let data = b"HTTP/1.1 204 No Content\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 204);
    assert!(resp.body().is_empty());
}

#[test]
fn parse_304_not_modified() {
    let data = b"HTTP/1.1 304 Not Modified\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 304);
    assert!(resp.body().is_empty());
}

// --- Content-Length body ---

#[test]
fn parse_content_length_exact() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.body_str().unwrap(), "hello world");
    assert_eq!(resp.size_download(), 11);
}

#[test]
fn parse_content_length_zero() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert!(resp.body().is_empty());
}

// --- HEAD requests ---

#[test]
fn parse_head_response_ignores_body() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
    let resp = parse_response(data, "http://example.com", true).unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
}

// --- Header parsing ---

#[test]
fn parse_multiple_headers() {
    let data =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: value\r\nContent-Length: 2\r\n\r\nok";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.header("content-type"), Some("text/html"));
    assert_eq!(resp.header("x-custom"), Some("value"));
}

#[test]
fn parse_headers_lowercase() {
    let data = b"HTTP/1.1 200 OK\r\nX-UPPER: value\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    // Headers stored lowercase
    assert_eq!(resp.header("x-upper"), Some("value"));
    assert_eq!(resp.header("X-UPPER"), Some("value"));
}

// --- Chunked transfer encoding ---

#[test]
fn parse_chunked_body() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.body_str().unwrap(), "hello world");
}

#[test]
fn parse_chunked_single_chunk() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.body_str().unwrap(), "foo");
}

#[test]
fn parse_chunked_empty() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert!(resp.body().is_empty());
}

// --- Effective URL ---

#[test]
fn parse_preserves_effective_url() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com/path?q=1", false).unwrap();
    assert_eq!(resp.effective_url(), "http://example.com/path?q=1");
}

// --- Set-Cookie joining ---

#[test]
fn parse_multiple_set_cookies_joined() {
    let data =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    let cookies = resp.header("set-cookie");
    assert!(cookies.is_some());
    let c = cookies.unwrap();
    assert!(c.contains("a=1"));
    assert!(c.contains("b=2"));
}

// --- Malformed responses ---

#[test]
fn parse_empty_response_errors() {
    let result = parse_response(b"", "http://example.com", false);
    assert!(result.is_err());
}

#[test]
fn parse_incomplete_status_line_errors() {
    let result = parse_response(b"HTTP/1.1 200", "http://example.com", false);
    assert!(result.is_err());
}

// --- Various status codes ---

#[test]
fn parse_status_201_created() {
    let data = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 201);
}

#[test]
fn parse_status_206_partial() {
    let data = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nhello";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body_str().unwrap(), "hello");
}

#[test]
fn parse_status_302_found() {
    let data = b"HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 302);
    assert!(resp.is_redirect());
}

#[test]
fn parse_status_307_temporary() {
    let data = b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /temp\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 307);
    assert!(resp.is_redirect());
}

#[test]
fn parse_status_308_permanent() {
    let data = b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /perm\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 308);
    assert!(resp.is_redirect());
}

#[test]
fn parse_status_401_unauthorized() {
    let data = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(resp.header("www-authenticate"), Some("Basic"));
}

#[test]
fn parse_status_403_forbidden() {
    let data = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 403);
}

#[test]
fn parse_status_503_service_unavailable() {
    let data = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response(data, "http://example.com", false).unwrap();
    assert_eq!(resp.status(), 503);
}
