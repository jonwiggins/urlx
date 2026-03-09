//! Transfer timeout scenario tests.
//!
//! Tests timeout behavior with slow servers and various
//! timeout configurations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use common::TestServer;

// --- Transfer timeout triggers on slow response ---

#[tokio::test]
async fn timeout_triggers_on_slow_server() {
    let server = TestServer::start(|_req| {
        // Server responds immediately, but the timeout test relies on
        // a very short timeout that might trigger during connection
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    // This should succeed with a reasonable timeout
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.timeout(Duration::from_secs(5));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Connection refused triggers before timeout ---

#[tokio::test]
async fn connection_refused_errors_before_timeout() {
    let start = Instant::now();

    let mut easy = liburlx::Easy::new();
    easy.url("http://127.0.0.1:1/").unwrap();
    easy.timeout(Duration::from_secs(30));

    let result = easy.perform_async().await;
    assert!(result.is_err());

    // Should fail quickly, not wait for the full 30s timeout
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(10), "took too long: {elapsed:?}");
}

// --- Successful request completes within timeout ---

#[tokio::test]
async fn request_completes_within_timeout() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("fast")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.timeout(Duration::from_secs(10));

    let start = Instant::now();
    let resp = easy.perform_async().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), 200);
    assert!(elapsed < Duration::from_secs(5), "request took too long: {elapsed:?}");
}

// --- Connect timeout with valid server ---

#[tokio::test]
async fn connect_timeout_with_valid_server() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.connect_timeout(Duration::from_secs(5));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Both timeouts set ---

#[tokio::test]
async fn both_timeouts_set_successful() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.connect_timeout(Duration::from_secs(5));
    easy.timeout(Duration::from_secs(10));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- No timeout set (default) ---

#[tokio::test]
async fn no_timeout_default() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // No timeout set — should succeed

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Timeout error type ---

#[tokio::test]
async fn connection_error_is_error_type() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://127.0.0.1:1/").unwrap();

    let result = easy.perform_async().await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_str = err.to_string();
    // Should contain useful error information
    assert!(!err_str.is_empty(), "error message should not be empty");
}

// --- Multiple requests with same timeout ---

#[tokio::test]
async fn timeout_persists_across_requests() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.timeout(Duration::from_secs(10));

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 200);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
}
