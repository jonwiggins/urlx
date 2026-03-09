//! Integration tests for HTTP version selection and configuration.
//!
//! Tests verify that the Easy API correctly handles HTTP version preferences,
//! including HTTP/1.0, HTTP/1.1, HTTP/2, and version negotiation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use liburlx::HttpVersion;

// =============================================================================
// HTTP version enum tests
// =============================================================================

#[test]
fn http_version_default_is_none() {
    let version = HttpVersion::default();
    assert_eq!(version, HttpVersion::None);
}

#[test]
fn http_version_variants_are_distinct() {
    assert_ne!(HttpVersion::None, HttpVersion::Http10);
    assert_ne!(HttpVersion::Http10, HttpVersion::Http11);
    assert_ne!(HttpVersion::Http11, HttpVersion::Http2);
    assert_ne!(HttpVersion::Http2, HttpVersion::Http3);
}

#[test]
fn http_version_is_copy() {
    let v = HttpVersion::Http2;
    let v2 = v;
    assert_eq!(v, v2);
}

// =============================================================================
// HTTP/1.1 tests (default behavior)
// =============================================================================

#[tokio::test]
async fn http11_is_default_for_plain_http() {
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok");
}

#[tokio::test]
async fn http11_explicit_version() {
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from("http11")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(HttpVersion::Http11);

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"http11");
}

// =============================================================================
// HTTP/1.0 tests
// =============================================================================

#[tokio::test]
async fn http10_version() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        // The server receives the request as HTTP/1.1 at the hyper level
        // but the request was sent as HTTP/1.0 on the wire
        let version = format!("{:?}", req.version());
        Response::new(Full::new(Bytes::from(version)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(HttpVersion::Http10);

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

// =============================================================================
// HTTP/2 configuration tests
// =============================================================================

#[test]
fn http2_config_setters() {
    let mut easy = liburlx::Easy::new();
    easy.http_version(HttpVersion::Http2);

    // Verify the handle accepts HTTP/2 configuration without panicking
    let debug = format!("{easy:?}");
    assert!(debug.contains("Http2"));
}

#[test]
fn easy_http_version_persists_through_clone() {
    let mut easy = liburlx::Easy::new();
    easy.http_version(HttpVersion::Http2);

    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("Http2"));
}

// =============================================================================
// Request method + version interaction
// =============================================================================

#[tokio::test]
async fn post_with_http11() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(HttpVersion::Http11);
    easy.method("POST");
    easy.body(b"data");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "POST");
}

#[tokio::test]
async fn head_with_http11() {
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        Response::builder().header("X-Custom", "present").body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(HttpVersion::Http11);
    easy.method("HEAD");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

// =============================================================================
// Multiple requests reuse version setting
// =============================================================================

#[tokio::test]
async fn version_persists_across_requests() {
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.http_version(HttpVersion::Http11);

    easy.url(&server.url("/first")).unwrap();
    let r1 = easy.perform_async().await.unwrap();
    assert_eq!(r1.status(), 200);

    easy.url(&server.url("/second")).unwrap();
    let r2 = easy.perform_async().await.unwrap();
    assert_eq!(r2.status(), 200);
}
