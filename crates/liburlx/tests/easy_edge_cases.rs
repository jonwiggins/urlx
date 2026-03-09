//! Easy handle edge case tests.
//!
//! Tests less-common configurations and interactions on the Easy handle,
//! including form files, proxy URLs, encoding toggles, cookie jar toggling,
//! multiple headers, range, resume, and resolve overrides.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::Arc;
use std::sync::Mutex;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- form_file reads file from disk ---

#[tokio::test]
async fn form_file_sends_multipart() {
    let received_ct = Arc::new(Mutex::new(String::new()));
    let ct_clone = received_ct.clone();

    let server = TestServer::start(move |req| {
        if let Some(ct) = req.headers().get("content-type") {
            *ct_clone.lock().unwrap() = ct.to_str().unwrap_or("").to_string();
        }
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("upload.txt");
    std::fs::write(&file_path, "file contents here").unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/upload")).unwrap();
    easy.form_file("myfile", &file_path).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let ct = received_ct.lock().unwrap();
    assert!(ct.starts_with("multipart/form-data"), "should be multipart: {ct}");
}

// --- form_file with nonexistent file returns error ---

#[test]
fn form_file_nonexistent_errors() {
    let mut easy = liburlx::Easy::new();
    let result = easy.form_file("f", std::path::Path::new("/tmp/urlx_no_such_file_12345.txt"));
    assert!(result.is_err());
}

// --- proxy URL validation ---

#[test]
fn proxy_valid_url() {
    let mut easy = liburlx::Easy::new();
    easy.proxy("http://proxy.local:3128").unwrap();
}

#[test]
fn proxy_socks5_url() {
    let mut easy = liburlx::Easy::new();
    easy.proxy("socks5://proxy.local:1080").unwrap();
}

#[test]
fn proxy_invalid_url_returns_error() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("not a url").is_err());
}

// --- accept_encoding toggle ---

#[tokio::test]
async fn accept_encoding_sends_header() {
    let received_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let headers_clone = received_headers.clone();

    let server = TestServer::start(move |req| {
        for (name, value) in req.headers() {
            headers_clone
                .lock()
                .unwrap()
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let headers = received_headers.lock().unwrap();
    let has_ae = headers.iter().any(|(k, _)| k == "accept-encoding");
    assert!(has_ae, "should send Accept-Encoding header");
}

#[tokio::test]
async fn accept_encoding_disabled_no_header() {
    let received_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let headers_clone = received_headers.clone();

    let server = TestServer::start(move |req| {
        for (name, value) in req.headers() {
            headers_clone
                .lock()
                .unwrap()
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // accept_encoding is false by default

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let headers = received_headers.lock().unwrap();
    let has_ae = headers.iter().any(|(k, _)| k == "accept-encoding");
    assert!(!has_ae, "should not send Accept-Encoding when disabled");
}

// --- cookie jar toggle ---

#[test]
fn cookie_jar_enable_disable_enable() {
    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.cookie_jar(false);
    easy.cookie_jar(true);
    // Should not panic; jar re-created on re-enable
}

// --- multiple headers ---

#[tokio::test]
async fn multiple_custom_headers_sent() {
    let received_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let headers_clone = received_headers.clone();

    let server = TestServer::start(move |req| {
        for (name, value) in req.headers() {
            headers_clone
                .lock()
                .unwrap()
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-First", "one");
    easy.header("X-Second", "two");
    easy.header("X-Third", "three");

    easy.perform_async().await.unwrap();

    let headers = received_headers.lock().unwrap();
    assert!(headers.iter().any(|(k, v)| k == "x-first" && v == "one"));
    assert!(headers.iter().any(|(k, v)| k == "x-second" && v == "two"));
    assert!(headers.iter().any(|(k, v)| k == "x-third" && v == "three"));
}

// --- range header ---

#[tokio::test]
async fn range_header_sent() {
    let received_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let headers_clone = received_headers.clone();

    let server = TestServer::start(move |req| {
        for (name, value) in req.headers() {
            headers_clone
                .lock()
                .unwrap()
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        Response::new(Full::new(Bytes::from("partial")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.range("0-499");

    easy.perform_async().await.unwrap();

    let headers = received_headers.lock().unwrap();
    let range = headers.iter().find(|(k, _)| k == "range");
    assert!(range.is_some(), "should send Range header");
    assert_eq!(range.unwrap().1, "bytes=0-499");
}

// --- resume_from ---

#[tokio::test]
async fn resume_from_sends_range() {
    let received_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let headers_clone = received_headers.clone();

    let server = TestServer::start(move |req| {
        for (name, value) in req.headers() {
            headers_clone
                .lock()
                .unwrap()
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        Response::new(Full::new(Bytes::from("rest")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.resume_from(1024);

    easy.perform_async().await.unwrap();

    let headers = received_headers.lock().unwrap();
    let range = headers.iter().find(|(k, _)| k == "range");
    assert!(range.is_some(), "should send Range header");
    assert_eq!(range.unwrap().1, "bytes=1024-");
}

// --- resolve override ---

#[tokio::test]
async fn resolve_override_redirects_dns() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("resolved")))).await;

    // Extract port from server URL
    let port: u16 =
        server.url("/").split(':').next_back().unwrap().trim_matches('/').parse().unwrap();

    let mut easy = liburlx::Easy::new();
    // Use a fake hostname, resolve it to 127.0.0.1
    easy.url(&format!("http://fake-host.test:{port}/")).unwrap();
    easy.resolve("fake-host.test", "127.0.0.1");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "resolved");
}

// --- noproxy setting ---

#[test]
fn noproxy_set() {
    let mut easy = liburlx::Easy::new();
    easy.noproxy("localhost,.internal.com");
    // No panic, properly stores the value
}

// --- hsts enable/disable ---

#[test]
fn hsts_enable_disable() {
    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    easy.hsts(false);
    easy.hsts(true);
    // No panic
}

// --- verbose toggle ---

#[test]
fn verbose_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.verbose(true);
    easy.verbose(false);
}

// --- fail_on_error with 4xx ---

#[tokio::test]
async fn fail_on_error_with_404() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let result = easy.perform_async().await;
    assert!(result.is_err(), "should error on 404 with fail_on_error");
}

// --- fail_on_error with 2xx succeeds ---

#[tokio::test]
async fn fail_on_error_with_200_succeeds() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Debug formatting ---

#[test]
fn easy_debug_format() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://example.com").unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.verbose(true);
    easy.follow_redirects(true);
    easy.max_redirects(10);

    let debug = format!("{easy:?}");
    assert!(debug.contains("Easy"));
    assert!(debug.contains("example.com"));
    assert!(debug.contains("POST"));
    assert!(debug.contains("verbose: true"));
}

// --- Clone preserves settings ---

#[test]
fn clone_preserves_all_settings() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://example.com").unwrap();
    easy.method("PUT");
    easy.header("X-Test", "value");
    easy.body(b"body");
    easy.follow_redirects(true);
    easy.max_redirects(5);
    easy.verbose(true);
    easy.accept_encoding(true);
    easy.fail_on_error(true);

    let cloned = easy.clone();
    let orig_debug = format!("{easy:?}");
    let clone_debug = format!("{cloned:?}");

    // Both should contain the same settings
    assert!(orig_debug.contains("PUT"));
    assert!(clone_debug.contains("PUT"));
    assert!(orig_debug.contains("verbose: true"));
    assert!(clone_debug.contains("verbose: true"));
}
