//! HSTS (HTTP Strict Transport Security) integration tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

/// Test that HSTS cache can be enabled and configured.
#[tokio::test]
async fn hsts_cache_enabled() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
}

/// Test that HSTS cache can be disabled.
#[tokio::test]
async fn hsts_cache_disabled() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.hsts(false);
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
}

/// Test that HSTS doesn't interfere with normal HTTP requests.
#[tokio::test]
async fn hsts_no_upgrade_for_unknown_host() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("still http")))).await;

    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    // First request to a host not in HSTS cache — should stay HTTP
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"still http");
}
