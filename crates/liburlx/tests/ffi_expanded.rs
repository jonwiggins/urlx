//! Expanded FFI compatibility tests.
//!
//! Tests the FFI layer through the Rust-side types and error mappings.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use std::collections::HashMap;
use std::time::Duration;

use liburlx::protocol::http::response::{Response, TransferInfo};

// --- TransferInfo construction ---

#[test]
fn transfer_info_default_zeroed() {
    let info = TransferInfo::default();
    assert_eq!(info.time_connect, Duration::ZERO);
    assert_eq!(info.time_total, Duration::ZERO);
    assert_eq!(info.num_redirects, 0);
}

#[test]
fn transfer_info_custom_values() {
    let info = TransferInfo {
        time_connect: Duration::from_millis(50),
        time_total: Duration::from_millis(200),
        num_redirects: 3,
    };
    assert_eq!(info.time_connect.as_millis(), 50);
    assert_eq!(info.time_total.as_millis(), 200);
    assert_eq!(info.num_redirects, 3);
}

#[test]
fn transfer_info_clone() {
    let info = TransferInfo {
        time_connect: Duration::from_secs(1),
        time_total: Duration::from_secs(2),
        num_redirects: 5,
    };
    let cloned = info.clone();
    assert_eq!(info.time_connect, cloned.time_connect);
    assert_eq!(info.time_total, cloned.time_total);
    assert_eq!(info.num_redirects, cloned.num_redirects);
}

#[test]
fn transfer_info_debug() {
    let info = TransferInfo::default();
    let debug = format!("{info:?}");
    assert!(debug.contains("TransferInfo"));
    assert!(debug.contains("time_connect"));
    assert!(debug.contains("time_total"));
}

// --- Response with_info ---

#[test]
fn response_with_info_preserves_timing() {
    let info = TransferInfo {
        time_connect: Duration::from_millis(100),
        time_total: Duration::from_millis(500),
        num_redirects: 2,
    };
    let resp = Response::with_info(
        200,
        HashMap::new(),
        b"body".to_vec(),
        "http://example.com".to_string(),
        info,
    );
    assert_eq!(resp.transfer_info().time_connect.as_millis(), 100);
    assert_eq!(resp.transfer_info().time_total.as_millis(), 500);
    assert_eq!(resp.transfer_info().num_redirects, 2);
}

#[test]
fn response_set_transfer_info() {
    let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.transfer_info().time_total, Duration::ZERO);

    resp.set_transfer_info(TransferInfo {
        time_connect: Duration::from_millis(25),
        time_total: Duration::from_millis(100),
        num_redirects: 1,
    });
    assert_eq!(resp.transfer_info().time_total.as_millis(), 100);
    assert_eq!(resp.transfer_info().num_redirects, 1);
}

// --- Response status code ranges ---

#[test]
fn response_1xx_informational() {
    let resp = Response::new(100, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.status(), 100);
    assert!(!resp.is_redirect());
}

#[test]
fn response_2xx_success_range() {
    for code in [200, 201, 204, 206] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
        assert!(!resp.is_redirect());
    }
}

#[test]
fn response_4xx_client_error_range() {
    for code in [400, 401, 403, 404, 405, 429, 499] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
        assert!(!resp.is_redirect());
    }
}

#[test]
fn response_5xx_server_error_range() {
    for code in [500, 502, 503, 504] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
    }
}

// --- Response redirect detection ---

#[test]
fn response_redirect_requires_location() {
    // 301 without Location is NOT a redirect
    let resp = Response::new(301, HashMap::new(), Vec::new(), String::new());
    assert!(!resp.is_redirect());
}

#[test]
fn response_redirect_with_location() {
    let mut headers = HashMap::new();
    headers.insert("location".to_string(), "/new".to_string());
    for code in [301, 302, 303, 307, 308] {
        let resp = Response::new(code, headers.clone(), Vec::new(), String::new());
        assert!(resp.is_redirect(), "code {code} with Location should be redirect");
    }
}

#[test]
fn response_non_redirect_3xx() {
    let mut headers = HashMap::new();
    headers.insert("location".to_string(), "/other".to_string());
    // 300, 304, 305, 306 should not be considered redirects
    for code in [300, 304, 305, 306] {
        let resp = Response::new(code, headers.clone(), Vec::new(), String::new());
        assert!(!resp.is_redirect(), "code {code} should NOT be redirect");
    }
}

// --- Response content_type ---

#[test]
fn response_content_type_present() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.content_type(), Some("application/json"));
}

#[test]
fn response_content_type_absent() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.content_type(), None);
}

// --- Response size_download ---

#[test]
fn response_size_download_empty() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.size_download(), 0);
}

#[test]
fn response_size_download_matches_body() {
    let body = vec![0u8; 1024];
    let resp = Response::new(200, HashMap::new(), body, String::new());
    assert_eq!(resp.size_download(), 1024);
}

// --- Error to CURLcode mapping coverage ---

#[test]
fn error_url_parse_maps_correctly() {
    let err = liburlx::Error::UrlParse("bad url".to_string());
    let msg = err.to_string();
    assert!(msg.contains("URL parse error"));
}

#[test]
fn error_connect_maps_correctly() {
    let err = liburlx::Error::Connect(std::io::Error::other("refused"));
    let msg = err.to_string();
    assert!(msg.contains("connection failed"));
}

#[test]
fn error_tls_maps_correctly() {
    let err = liburlx::Error::Tls(Box::new(std::io::Error::other("cert error")));
    let msg = err.to_string();
    assert!(msg.contains("TLS handshake failed"));
}

#[test]
fn error_http_maps_correctly() {
    let err = liburlx::Error::Http("protocol violation".to_string());
    let msg = err.to_string();
    assert!(msg.contains("HTTP protocol error"));
}

#[test]
fn error_timeout_maps_correctly() {
    let err = liburlx::Error::Timeout(Duration::from_secs(30));
    let msg = err.to_string();
    assert!(msg.contains("timeout after 30s"));
}

#[test]
fn error_transfer_maps_correctly() {
    let err = liburlx::Error::Transfer { code: 7, message: "refused".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("transfer error (code 7)"));
    assert!(msg.contains("refused"));
}

// --- Response effective_url ---

#[test]
fn response_effective_url_preserved() {
    let resp =
        Response::new(200, HashMap::new(), Vec::new(), "http://final.example.com/path".to_string());
    assert_eq!(resp.effective_url(), "http://final.example.com/path");
}

#[test]
fn response_effective_url_empty_default() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.effective_url(), "");
}

// --- Response header lookup ---

#[test]
fn response_header_case_insensitive_various() {
    let mut headers = HashMap::new();
    headers.insert("x-custom".to_string(), "value1".to_string());
    headers.insert("content-length".to_string(), "42".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());

    assert_eq!(resp.header("X-Custom"), Some("value1"));
    assert_eq!(resp.header("x-custom"), Some("value1"));
    assert_eq!(resp.header("X-CUSTOM"), Some("value1"));
    assert_eq!(resp.header("Content-Length"), Some("42"));
    assert_eq!(resp.header("x-nonexistent"), None);
}

// --- Response clone ---

#[test]
fn response_clone_independent() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let resp = Response::new(200, headers, b"hello".to_vec(), "http://example.com".to_string());
    let cloned = resp.clone();
    assert_eq!(resp.status(), cloned.status());
    assert_eq!(resp.body(), cloned.body());
    assert_eq!(resp.effective_url(), cloned.effective_url());
    assert_eq!(resp.content_type(), cloned.content_type());
}
