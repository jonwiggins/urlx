//! Response construction and manipulation tests.
//!
//! Tests `Response` and `TransferInfo` public API through `liburlx`.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use std::collections::HashMap;
use std::time::Duration;

use liburlx::{Response, TransferInfo};

// --- Response::new ---

#[test]
fn response_new_basic() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
    assert_eq!(resp.effective_url(), "");
}

#[test]
fn response_new_with_body() {
    let body = b"hello world".to_vec();
    let resp = Response::new(200, HashMap::new(), body, "http://example.com".to_string());
    assert_eq!(resp.body_str().unwrap(), "hello world");
    assert_eq!(resp.effective_url(), "http://example.com");
    assert_eq!(resp.size_download(), 11);
}

#[test]
fn response_new_with_headers() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert("x-custom".to_string(), "value".to_string());

    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.header("content-type"), Some("text/html"));
    assert_eq!(resp.header("x-custom"), Some("value"));
}

// --- Response::with_info ---

#[test]
fn response_with_info() {
    let info = TransferInfo {
        time_connect: Duration::from_millis(50),
        time_total: Duration::from_millis(100),
        num_redirects: 2,
        ..TransferInfo::default()
    };

    let resp = Response::with_info(200, HashMap::new(), Vec::new(), String::new(), info);
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.transfer_info().time_connect, Duration::from_millis(50));
    assert_eq!(resp.transfer_info().time_total, Duration::from_millis(100));
    assert_eq!(resp.transfer_info().num_redirects, 2);
}

// --- set_transfer_info ---

#[test]
fn set_transfer_info() {
    let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());

    let info = TransferInfo {
        time_connect: Duration::from_millis(25),
        time_total: Duration::from_millis(75),
        num_redirects: 1,
        ..TransferInfo::default()
    };
    resp.set_transfer_info(info);

    assert_eq!(resp.transfer_info().num_redirects, 1);
}

// --- Header case-insensitive lookup ---

#[test]
fn header_lookup_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.header("Content-Type"), Some("application/json"));
    assert_eq!(resp.header("CONTENT-TYPE"), Some("application/json"));
    assert_eq!(resp.header("content-type"), Some("application/json"));
}

#[test]
fn header_lookup_missing() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.header("x-missing"), None);
}

// --- body_str with non-UTF-8 ---

#[test]
fn body_str_valid_utf8() {
    let resp = Response::new(200, HashMap::new(), "valid utf8".into(), String::new());
    assert_eq!(resp.body_str().unwrap(), "valid utf8");
}

#[test]
fn body_str_invalid_utf8() {
    let resp = Response::new(200, HashMap::new(), vec![0xFF, 0xFE], String::new());
    assert!(resp.body_str().is_err());
}

#[test]
fn body_str_empty() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.body_str().unwrap(), "");
}

// --- is_redirect ---

#[test]
fn is_redirect_301_with_location() {
    let mut headers = HashMap::new();
    headers.insert("location".to_string(), "/new".to_string());
    let resp = Response::new(301, headers, Vec::new(), String::new());
    assert!(resp.is_redirect());
}

#[test]
fn is_redirect_302_with_location() {
    let mut headers = HashMap::new();
    headers.insert("location".to_string(), "/new".to_string());
    let resp = Response::new(302, headers, Vec::new(), String::new());
    assert!(resp.is_redirect());
}

#[test]
fn is_redirect_301_without_location() {
    let resp = Response::new(301, HashMap::new(), Vec::new(), String::new());
    assert!(!resp.is_redirect());
}

#[test]
fn is_redirect_200_not_redirect() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert!(!resp.is_redirect());
}

// --- content_type ---

#[test]
fn content_type_present() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.content_type(), Some("text/plain"));
}

#[test]
fn content_type_absent() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.content_type(), None);
}

// --- size_download ---

#[test]
fn size_download_empty() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.size_download(), 0);
}

#[test]
fn size_download_with_body() {
    let body = vec![0u8; 1024];
    let resp = Response::new(200, HashMap::new(), body, String::new());
    assert_eq!(resp.size_download(), 1024);
}

// --- TransferInfo ---

#[test]
fn transfer_info_default() {
    let info = TransferInfo::default();
    assert_eq!(info.time_connect, Duration::ZERO);
    assert_eq!(info.time_total, Duration::ZERO);
    assert_eq!(info.num_redirects, 0);
}

#[test]
fn transfer_info_clone() {
    let info = TransferInfo {
        time_connect: Duration::from_millis(10),
        time_total: Duration::from_millis(20),
        num_redirects: 3,
        ..TransferInfo::default()
    };
    let cloned = info.clone();
    // Use both to prove they are independent copies
    assert_eq!(info.time_connect, Duration::from_millis(10));
    assert_eq!(cloned.time_connect, Duration::from_millis(10));
    assert_eq!(cloned.num_redirects, 3);
}

#[test]
fn transfer_info_debug() {
    let info = TransferInfo::default();
    let debug = format!("{info:?}");
    assert!(debug.contains("TransferInfo"));
}

// --- Response clone ---

#[test]
fn response_clone_independent() {
    let mut headers = HashMap::new();
    headers.insert("x-key".to_string(), "value".to_string());
    let resp = Response::new(200, headers, b"body".to_vec(), "http://example.com".to_string());

    let cloned = resp.clone();
    // Use both to prove independence
    assert_eq!(resp.status(), 200);
    assert_eq!(cloned.status(), 200);
    assert_eq!(cloned.header("x-key"), Some("value"));
    assert_eq!(cloned.body_str().unwrap(), "body");
    assert_eq!(cloned.effective_url(), "http://example.com");
}

// --- Various status codes ---

#[test]
fn status_1xx() {
    let resp = Response::new(100, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.status(), 100);
}

#[test]
fn status_3xx() {
    let resp = Response::new(307, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.status(), 307);
}

// --- headers() method ---

#[test]
fn headers_returns_all() {
    let mut headers = HashMap::new();
    headers.insert("a".to_string(), "1".to_string());
    headers.insert("b".to_string(), "2".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.headers().len(), 2);
}
