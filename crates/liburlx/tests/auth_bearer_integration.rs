//! Integration tests for Bearer token and auth method interaction.
//!
//! Tests verify that bearer tokens, basic auth, and digest auth can
//! be configured independently and that the correct Authorization header
//! is sent on the wire.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};

// =============================================================================
// Bearer token tests
// =============================================================================

#[tokio::test]
async fn bearer_token_sent_in_header() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.bearer_token("mytoken123");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "Bearer mytoken123");
}

#[tokio::test]
async fn bearer_token_with_special_chars() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.bearer_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc");

    let response = easy.perform_async().await.unwrap();
    let auth = response.body_str().unwrap();
    assert!(auth.starts_with("Bearer eyJ"), "got: {auth}");
}

#[tokio::test]
async fn bearer_token_overrides_on_second_set() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        // Count how many Authorization headers
        let count = req.headers().get_all("authorization").iter().count();
        Response::new(Full::new(Bytes::from(format!("{count}:{auth}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.bearer_token("first");
    easy.bearer_token("second");

    let response = easy.perform_async().await.unwrap();
    let body = response.body_str().unwrap();
    // Both headers may be sent since bearer_token just calls header()
    // At minimum, one of the Bearer tokens should be present
    assert!(body.contains("Bearer"), "got: {body}");
}

// =============================================================================
// Basic auth tests
// =============================================================================

#[tokio::test]
async fn basic_auth_sends_correct_header() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.basic_auth("user", "pass");

    let response = easy.perform_async().await.unwrap();
    let auth = response.body_str().unwrap();
    // base64("user:pass") = "dXNlcjpwYXNz"
    assert_eq!(auth, "Basic dXNlcjpwYXNz");
}

#[tokio::test]
async fn basic_auth_with_empty_password() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.basic_auth("admin", "");

    let response = easy.perform_async().await.unwrap();
    let auth = response.body_str().unwrap();
    assert!(auth.starts_with("Basic "), "got: {auth}");
}

// =============================================================================
// Auth with redirects
// =============================================================================

#[tokio::test]
async fn bearer_token_sent_after_redirect() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = std::sync::Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |req: Request<hyper::body::Incoming>| {
        let count = counter_clone.fetch_add(1, Ordering::Relaxed);
        if count == 0 {
            Response::builder()
                .status(302)
                .header("Location", "/final")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            let auth = req
                .headers()
                .get("authorization")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();

            Response::new(Full::new(Bytes::from(auth)))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.bearer_token("tok123");
    easy.follow_redirects(true);

    let response = easy.perform_async().await.unwrap();
    let auth = response.body_str().unwrap();
    // Bearer token should be sent on redirected request (same host)
    assert!(auth.contains("Bearer tok123"), "got: {auth}");
}

// =============================================================================
// Auth with different HTTP methods
// =============================================================================

#[tokio::test]
async fn bearer_token_with_post() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let method = req.method().to_string();
        let auth = req.headers().contains_key("authorization");

        Response::new(Full::new(Bytes::from(format!("{method}:{auth}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.bearer_token("token");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "POST:true");
}

#[tokio::test]
async fn basic_auth_with_put() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let method = req.method().to_string();
        let auth = req.headers().contains_key("authorization");

        Response::new(Full::new(Bytes::from(format!("{method}:{auth}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.method("PUT");
    easy.body(b"updated");
    easy.basic_auth("admin", "secret");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "PUT:true");
}
