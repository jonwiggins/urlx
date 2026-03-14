//! Response API completeness tests.
//!
//! Tests all public methods on `Response` and `TransferInfo`
//! to ensure complete coverage of the response data model.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp, unused_results)]

use std::collections::HashMap;
use std::time::Duration;

use liburlx::{Response, TransferInfo};

// --- Response::with_info ---

#[test]
fn with_info_preserves_all_fields() {
    let mut headers = HashMap::new();
    headers.insert("x-key".to_string(), "value".to_string());

    let info = TransferInfo {
        time_connect: Duration::from_millis(10),
        time_total: Duration::from_millis(50),
        num_redirects: 3,
        ..TransferInfo::default()
    };

    let resp = Response::with_info(
        201,
        headers,
        b"body data".to_vec(),
        "http://example.com/api".to_string(),
        info,
    );

    assert_eq!(resp.status(), 201);
    assert_eq!(resp.header("x-key"), Some("value"));
    assert_eq!(resp.body_str().unwrap(), "body data");
    assert_eq!(resp.effective_url(), "http://example.com/api");
    assert_eq!(resp.transfer_info().time_connect, Duration::from_millis(10));
    assert_eq!(resp.transfer_info().time_total, Duration::from_millis(50));
    assert_eq!(resp.transfer_info().num_redirects, 3);
}

// --- headers() method ---

#[test]
fn headers_returns_empty_for_no_headers() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert!(resp.headers().is_empty());
}

#[test]
fn headers_returns_all_inserted() {
    let mut headers = HashMap::new();
    headers.insert("a".to_string(), "1".to_string());
    headers.insert("b".to_string(), "2".to_string());
    headers.insert("c".to_string(), "3".to_string());

    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.headers().len(), 3);
    assert_eq!(resp.headers().get("a").map(String::as_str), Some("1"));
    assert_eq!(resp.headers().get("b").map(String::as_str), Some("2"));
    assert_eq!(resp.headers().get("c").map(String::as_str), Some("3"));
}

// --- set_transfer_info ---

#[test]
fn set_transfer_info_updates_values() {
    let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.transfer_info().num_redirects, 0);

    let info = TransferInfo {
        time_connect: Duration::from_millis(100),
        time_total: Duration::from_millis(500),
        num_redirects: 5,
        ..TransferInfo::default()
    };
    resp.set_transfer_info(info);

    assert_eq!(resp.transfer_info().time_connect, Duration::from_millis(100));
    assert_eq!(resp.transfer_info().time_total, Duration::from_millis(500));
    assert_eq!(resp.transfer_info().num_redirects, 5);
}

#[test]
fn set_transfer_info_overrides_previous() {
    let info1 = TransferInfo {
        time_connect: Duration::from_millis(10),
        time_total: Duration::from_millis(20),
        num_redirects: 1,
        ..TransferInfo::default()
    };
    let mut resp = Response::with_info(200, HashMap::new(), Vec::new(), String::new(), info1);
    assert_eq!(resp.transfer_info().num_redirects, 1);

    let info2 = TransferInfo {
        time_connect: Duration::from_millis(99),
        time_total: Duration::from_millis(99),
        num_redirects: 9,
        ..TransferInfo::default()
    };
    resp.set_transfer_info(info2);
    assert_eq!(resp.transfer_info().num_redirects, 9);
}

// --- Clone independence ---

#[test]
fn clone_response_independent_body() {
    let resp = Response::new(200, HashMap::new(), b"original".to_vec(), String::new());
    let cloned = resp.clone();

    // Both should have same content
    assert_eq!(resp.body_str().unwrap(), "original");
    assert_eq!(cloned.body_str().unwrap(), "original");
}

#[test]
fn clone_response_independent_headers() {
    let mut headers = HashMap::new();
    headers.insert("key".to_string(), "value".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    let cloned = resp.clone();

    assert_eq!(resp.header("key"), Some("value"));
    assert_eq!(cloned.header("key"), Some("value"));
}

// --- Status code ranges ---

#[test]
fn status_1xx() {
    let resp = Response::new(100, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.status(), 100);
    assert!(!resp.is_redirect());
}

#[test]
fn status_2xx() {
    for code in [200, 201, 204] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
        assert!(!resp.is_redirect());
    }
}

#[test]
fn status_3xx_without_location_not_redirect() {
    for code in [301, 302, 303, 307, 308] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert!(!resp.is_redirect(), "code {code} without location should not be redirect");
    }
}

#[test]
fn status_3xx_with_location_is_redirect() {
    for code in [301, 302, 303, 307, 308] {
        let mut headers = HashMap::new();
        headers.insert("location".to_string(), "/new".to_string());
        let resp = Response::new(code, headers, Vec::new(), String::new());
        assert!(resp.is_redirect(), "code {code} with location should be redirect");
    }
}

#[test]
fn status_4xx() {
    for code in [400, 401, 403, 404, 405] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
    }
}

#[test]
fn status_5xx() {
    for code in [500, 502, 503, 504] {
        let resp = Response::new(code, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), code);
    }
}

// --- content_type ---

#[test]
fn content_type_from_header() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let resp = Response::new(200, headers, Vec::new(), String::new());
    assert_eq!(resp.content_type(), Some("application/json"));
}

#[test]
fn content_type_missing() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.content_type(), None);
}

// --- size_download ---

#[test]
fn size_download_zero_for_empty() {
    let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
    assert_eq!(resp.size_download(), 0);
}

#[test]
fn size_download_matches_body_len() {
    let body = vec![0u8; 42];
    let resp = Response::new(200, HashMap::new(), body, String::new());
    assert_eq!(resp.size_download(), 42);
}

// --- TransferInfo ---

#[test]
fn transfer_info_default_all_zero() {
    let info = TransferInfo::default();
    assert_eq!(info.time_namelookup, Duration::ZERO);
    assert_eq!(info.time_connect, Duration::ZERO);
    assert_eq!(info.time_appconnect, Duration::ZERO);
    assert_eq!(info.time_pretransfer, Duration::ZERO);
    assert_eq!(info.time_starttransfer, Duration::ZERO);
    assert_eq!(info.time_total, Duration::ZERO);
    assert_eq!(info.num_redirects, 0);
    assert_eq!(info.speed_download, 0.0);
    assert_eq!(info.speed_upload, 0.0);
    assert_eq!(info.size_upload, 0);
}

#[test]
fn transfer_info_all_timing_fields() {
    let info = TransferInfo {
        time_namelookup: Duration::from_millis(5),
        time_connect: Duration::from_millis(10),
        time_appconnect: Duration::from_millis(20),
        time_pretransfer: Duration::from_millis(21),
        time_starttransfer: Duration::from_millis(50),
        time_total: Duration::from_millis(100),
        num_redirects: 1,
        speed_download: 1024.0,
        speed_upload: 512.0,
        size_upload: 2048,
        num_retries: 0,
    };

    assert_eq!(info.time_namelookup, Duration::from_millis(5));
    assert_eq!(info.time_connect, Duration::from_millis(10));
    assert_eq!(info.time_appconnect, Duration::from_millis(20));
    assert_eq!(info.time_pretransfer, Duration::from_millis(21));
    assert_eq!(info.time_starttransfer, Duration::from_millis(50));
    assert_eq!(info.time_total, Duration::from_millis(100));
    assert_eq!(info.num_redirects, 1);
    assert_eq!(info.speed_download, 1024.0);
    assert_eq!(info.speed_upload, 512.0);
    assert_eq!(info.size_upload, 2048);
}

#[test]
fn transfer_info_timing_order_invariant() {
    // Timing fields should satisfy: namelookup <= connect <= appconnect <= pretransfer <= starttransfer <= total
    let info = TransferInfo {
        time_namelookup: Duration::from_millis(5),
        time_connect: Duration::from_millis(10),
        time_appconnect: Duration::from_millis(20),
        time_pretransfer: Duration::from_millis(25),
        time_starttransfer: Duration::from_millis(50),
        time_total: Duration::from_millis(100),
        ..TransferInfo::default()
    };

    assert!(info.time_namelookup <= info.time_connect);
    assert!(info.time_connect <= info.time_appconnect);
    assert!(info.time_appconnect <= info.time_pretransfer);
    assert!(info.time_pretransfer <= info.time_starttransfer);
    assert!(info.time_starttransfer <= info.time_total);
}

#[test]
fn transfer_info_debug_output() {
    let info = TransferInfo {
        time_connect: Duration::from_millis(5),
        time_total: Duration::from_millis(10),
        num_redirects: 2,
        ..TransferInfo::default()
    };
    let debug = format!("{info:?}");
    assert!(debug.contains("TransferInfo"));
    assert!(debug.contains("time_namelookup"));
    assert!(debug.contains("time_appconnect"));
    assert!(debug.contains("speed_download"));
}

#[test]
fn transfer_info_clone_preserves_all_fields() {
    let info = TransferInfo {
        time_namelookup: Duration::from_millis(1),
        time_connect: Duration::from_millis(2),
        time_appconnect: Duration::from_millis(3),
        time_pretransfer: Duration::from_millis(4),
        time_starttransfer: Duration::from_millis(5),
        time_total: Duration::from_millis(6),
        num_redirects: 7,
        speed_download: 8.0,
        speed_upload: 9.0,
        size_upload: 10,
        num_retries: 0,
    };
    let cloned = info.clone();
    assert_eq!(cloned.time_namelookup, info.time_namelookup);
    assert_eq!(cloned.time_appconnect, info.time_appconnect);
    assert_eq!(cloned.time_pretransfer, info.time_pretransfer);
    assert_eq!(cloned.time_starttransfer, info.time_starttransfer);
    assert_eq!(cloned.speed_download, info.speed_download);
    assert_eq!(cloned.speed_upload, info.speed_upload);
    assert_eq!(cloned.size_upload, info.size_upload);
}
