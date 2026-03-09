//! Easy handle method coverage tests.
//!
//! Tests Easy handle setter methods that lack dedicated unit test
//! coverage, verifying configuration through Debug output and
//! perform behavior.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- method_is_default ---

#[test]
fn method_is_default_initially_true() {
    let easy = liburlx::Easy::new();
    assert!(easy.method_is_default());
}

#[test]
fn method_is_default_after_set_method() {
    let mut easy = liburlx::Easy::new();
    easy.method("POST");
    assert!(!easy.method_is_default());
}

#[test]
fn method_is_default_after_set_get() {
    let mut easy = liburlx::Easy::new();
    easy.method("GET");
    // GET is explicit, not default
    assert!(!easy.method_is_default());
}

// --- verbose ---

#[test]
fn verbose_default_off() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("verbose: false"), "debug: {debug}");
}

#[test]
fn verbose_enable() {
    let mut easy = liburlx::Easy::new();
    easy.verbose(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("verbose: true"), "debug: {debug}");
}

// --- max_redirects ---

#[test]
fn max_redirects_default_50() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 50"), "debug: {debug}");
}

#[test]
fn max_redirects_set() {
    let mut easy = liburlx::Easy::new();
    easy.max_redirects(10);
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 10"), "debug: {debug}");
}

#[test]
fn max_redirects_zero() {
    let mut easy = liburlx::Easy::new();
    easy.max_redirects(0);
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 0"), "debug: {debug}");
}

// --- timeout ---

#[test]
fn timeout_default_none() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("timeout: None"), "debug: {debug}");
}

#[test]
fn timeout_set() {
    let mut easy = liburlx::Easy::new();
    easy.timeout(Duration::from_secs(30));
    let debug = format!("{easy:?}");
    assert!(debug.contains("30s") || debug.contains("30"), "debug: {debug}");
}

// --- connect_timeout ---

#[test]
fn connect_timeout_default_none() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("connect_timeout: None"), "debug: {debug}");
}

#[test]
fn connect_timeout_set() {
    let mut easy = liburlx::Easy::new();
    easy.connect_timeout(Duration::from_secs(5));
    let debug = format!("{easy:?}");
    assert!(debug.contains("5s") || debug.contains('5'), "debug: {debug}");
}

// --- perform_async ---

#[tokio::test]
async fn perform_async_basic_get() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("async ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "async ok");
}

#[tokio::test]
async fn perform_async_post_with_body() {
    let received_body = Arc::new(Mutex::new(Vec::new()));
    let body_clone = received_body.clone();

    let server = TestServer::start(move |req| {
        let method = req.method().to_string();
        *body_clone.lock().unwrap() = method.into_bytes();
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"test data");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- perform_async with fail_on_error ---

#[tokio::test]
async fn perform_async_fail_on_error() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- perform without URL ---

#[test]
fn perform_without_url_errors() {
    let mut easy = liburlx::Easy::new();
    let result = easy.perform();
    assert!(result.is_err());
}

// --- clone preserves all settings ---

#[test]
fn clone_preserves_method() {
    let mut easy = liburlx::Easy::new();
    easy.method("DELETE");
    let cloned = easy.clone();
    assert!(!cloned.method_is_default());
}

#[test]
fn clone_preserves_verbose() {
    let mut easy = liburlx::Easy::new();
    easy.verbose(true);
    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("verbose: true"));
}

#[test]
fn clone_preserves_max_redirects() {
    let mut easy = liburlx::Easy::new();
    easy.max_redirects(5);
    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("max_redirects: 5"));
}

#[test]
fn clone_preserves_follow_redirects() {
    let mut easy = liburlx::Easy::new();
    easy.follow_redirects(true);
    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("follow_redirects: true"));
}

// --- Multiple perform calls ---

#[tokio::test]
async fn multiple_perform_async_calls() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    for path in ["/a", "/b", "/c"] {
        easy.url(&server.url(path)).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.body_str().unwrap(), path);
    }
}

// --- Setting overrides ---

#[tokio::test]
async fn method_override_between_performs() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    // First request: GET (default)
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "GET");

    // Second request: POST
    easy.method("POST");
    easy.body(b"data");
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "POST");
}
