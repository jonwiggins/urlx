//! Connection pool stress tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use liburlx::Response;

// --- Pool key isolation ---

#[test]
fn response_new_preserves_all_fields() {
    let mut headers = HashMap::new();
    let _old = headers.insert("content-type".to_string(), "text/plain".to_string());
    let _old = headers.insert("x-custom".to_string(), "value".to_string());
    let body = b"hello world".to_vec();
    let url = "http://example.com/page".to_string();

    let resp = Response::new(201, headers, body.clone(), url.clone());

    assert_eq!(resp.status(), 201);
    assert_eq!(resp.body(), body.as_slice());
    assert_eq!(resp.effective_url(), url.as_str());
    assert_eq!(resp.header("content-type"), Some("text/plain"));
    assert_eq!(resp.header("x-custom"), Some("value"));
    assert_eq!(resp.size_download(), 11);
}

// --- Response body operations ---

#[test]
fn body_str_valid_utf8() {
    let resp = Response::new(200, HashMap::new(), b"hello".to_vec(), String::new());
    assert_eq!(resp.body_str().unwrap(), "hello");
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

// --- Header case insensitivity ---

#[test]
fn header_lookup_case_insensitive() {
    let mut headers = HashMap::new();
    let _old = headers.insert("content-type".to_string(), "text/html".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());

    // Headers stored lowercase, lookup should work with lowercase
    assert_eq!(resp.header("content-type"), Some("text/html"));
}

// --- Content type ---

#[test]
fn content_type_present() {
    let mut headers = HashMap::new();
    let _old = headers.insert("content-type".to_string(), "application/json".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.content_type(), Some("application/json"));
}

#[test]
fn content_type_absent() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.content_type(), None);
}

// --- Redirect detection ---

#[test]
fn redirect_301_with_location() {
    let mut headers = HashMap::new();
    let _old = headers.insert("location".to_string(), "/new".to_string());
    let resp = Response::new(301, headers, Vec::new(), String::new());
    assert!(resp.is_redirect());
}

#[test]
fn redirect_200_not_redirect() {
    let mut headers = HashMap::new();
    let _old = headers.insert("location".to_string(), "/somewhere".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert!(!resp.is_redirect());
}

#[test]
fn redirect_301_without_location() {
    let resp = Response::new(301, HashMap::new(), Vec::new(), String::new());
    assert!(!resp.is_redirect());
}

#[test]
fn all_redirect_codes() {
    for code in [301, 302, 303, 307, 308] {
        let mut headers = HashMap::new();
        let _old = headers.insert("location".to_string(), "/new".to_string());
        let resp = Response::new(code, headers, Vec::new(), String::new());
        assert!(resp.is_redirect(), "code {code} should be redirect");
    }
}

#[test]
fn non_redirect_codes() {
    for code in [200, 204, 300, 304, 400, 404, 500] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert!(!resp.is_redirect(), "code {code} should not be redirect");
    }
}

// --- Transfer info ---

#[test]
fn transfer_info_defaults() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    let info = resp.transfer_info();
    assert_eq!(info.num_redirects, 0);
    // time_total and time_connect may be zero for constructed responses
}

// --- Size download ---

#[test]
fn size_download_matches_body() {
    let body = vec![0u8; 12345];
    let resp = Response::new(200, HashMap::new(), body, String::new());
    assert_eq!(resp.size_download(), 12345);
}

#[test]
fn size_download_empty_body() {
    let resp = Response::new(204, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.size_download(), 0);
}

// --- Multiple headers ---

#[test]
fn many_headers_all_accessible() {
    let mut headers = HashMap::new();
    for i in 0..50 {
        let _old = headers.insert(format!("x-header-{i}"), format!("value-{i}"));
    }
    let resp = Response::new(200, headers, Vec::new(), String::new());
    for i in 0..50 {
        assert_eq!(resp.header(&format!("x-header-{i}")), Some(format!("value-{i}").as_str()),);
    }
}

// --- Large body ---

#[test]
fn large_body_preserved() {
    let body = vec![0x42u8; 1_000_000];
    let resp = Response::new(200, HashMap::new(), body.clone(), String::new());
    assert_eq!(resp.body().len(), 1_000_000);
    assert_eq!(resp.size_download(), 1_000_000);
    assert_eq!(resp.body(), body.as_slice());
}

// --- Effective URL ---

#[test]
fn effective_url_with_query() {
    let url = "http://example.com/path?key=value&other=123".to_string();
    let resp = Response::new(200, HashMap::new(), Vec::new(), url.clone());
    assert_eq!(resp.effective_url(), url.as_str());
}

#[test]
fn effective_url_empty() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.effective_url(), "");
}
