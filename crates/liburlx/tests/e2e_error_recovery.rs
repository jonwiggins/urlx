//! Error recovery scenario tests.
//!
//! Tests behavior when servers return unexpected responses,
//! various error status codes, and edge case content.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use common::TestServer;

// --- Server returns various 4xx errors ---

#[tokio::test]
async fn handles_400_bad_request() {
    let server = TestServer::start(|_req| {
        Response::builder().status(400).body(Full::new(Bytes::from("bad request"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.body_str().unwrap(), "bad request");
}

#[tokio::test]
async fn handles_405_method_not_allowed() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(405)
            .header("Allow", "GET, HEAD")
            .body(Full::new(Bytes::from("method not allowed")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("DELETE");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(resp.header("allow"), Some("GET, HEAD"));
}

#[tokio::test]
async fn handles_429_too_many_requests() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(429)
            .header("Retry-After", "60")
            .body(Full::new(Bytes::from("rate limited")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.header("retry-after"), Some("60"));
}

// --- Server returns various 5xx errors ---

#[tokio::test]
async fn handles_502_bad_gateway() {
    let server = TestServer::start(|_req| {
        Response::builder().status(502).body(Full::new(Bytes::from("bad gateway"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 502);
}

#[tokio::test]
async fn handles_503_service_unavailable() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(503)
            .header("Retry-After", "30")
            .body(Full::new(Bytes::from("unavailable")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn handles_504_gateway_timeout() {
    let server = TestServer::start(|_req| {
        Response::builder().status(504).body(Full::new(Bytes::from("gateway timeout"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 504);
}

// --- Binary content handling ---

#[tokio::test]
async fn binary_response_preserved() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let data_clone = binary_data.clone();

    let server = TestServer::start(move |_req| {
        Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(Full::new(Bytes::from(data_clone.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body(), &binary_data);
    assert_eq!(resp.content_type(), Some("application/octet-stream"));
}

// --- Content-Type variations ---

#[tokio::test]
async fn json_content_type() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(Full::new(Bytes::from(r#"{"key":"value"}"#)))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.content_type().unwrap().starts_with("application/json"));
    assert_eq!(resp.body_str().unwrap(), r#"{"key":"value"}"#);
}

// --- Multi-valued headers ---

#[tokio::test]
async fn multiple_response_headers_same_name() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("X-Custom", "value1")
            .header("X-Custom", "value2")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    // Header should be accessible (implementation may join or return first)
    let header = resp.header("x-custom");
    assert!(header.is_some());
}

// --- Connection refused error ---

#[tokio::test]
async fn connection_refused_returns_error() {
    let mut easy = liburlx::Easy::new();
    // Port 1 is very unlikely to be listening
    easy.url("http://127.0.0.1:1/").unwrap();

    let result = easy.perform_async().await;
    assert!(result.is_err(), "should fail with connection refused");
}

// --- No URL set error ---

#[tokio::test]
async fn no_url_returns_error() {
    let mut easy = liburlx::Easy::new();
    let result = easy.perform_async().await;
    assert!(result.is_err(), "should fail with no URL set");
}

// --- Invalid URL error ---

#[test]
fn invalid_url_returns_error() {
    let mut easy = liburlx::Easy::new();
    let result = easy.url("not a url at all");
    assert!(result.is_err());
}

// --- fail_on_error with various status codes ---

#[tokio::test]
async fn fail_on_error_passes_200() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn fail_on_error_fails_500() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let result = easy.perform_async().await;
    assert!(result.is_err(), "should fail on 500");
}

// --- Redirect without Location header ---

#[tokio::test]
async fn redirect_without_location_stops() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(301)
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    // Without Location header, redirect can't be followed — returns 301
    assert_eq!(resp.status(), 301);
}
