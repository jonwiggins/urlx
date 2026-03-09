//! `fail_on_error` integration tests with real servers.
//!
//! Tests the boundary behavior of `fail_on_error` with various
//! HTTP status codes, redirect chains, and response patterns.

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

// --- Boundary: 399 passes, 400 fails ---

#[tokio::test]
async fn fail_on_error_399_passes() {
    let server = TestServer::start(|_req| {
        Response::builder().status(399).body(Full::new(Bytes::from("custom"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 399);
}

#[tokio::test]
async fn fail_on_error_400_fails() {
    let server = TestServer::start(|_req| {
        Response::builder().status(400).body(Full::new(Bytes::from("bad request"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- Various 4xx codes ---

#[tokio::test]
async fn fail_on_error_401() {
    let server = TestServer::start(|_req| {
        Response::builder().status(401).body(Full::new(Bytes::from("unauthorized"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

#[tokio::test]
async fn fail_on_error_403() {
    let server = TestServer::start(|_req| {
        Response::builder().status(403).body(Full::new(Bytes::from("forbidden"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

#[tokio::test]
async fn fail_on_error_404() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

// --- Various 5xx codes ---

#[tokio::test]
async fn fail_on_error_500() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

#[tokio::test]
async fn fail_on_error_502() {
    let server = TestServer::start(|_req| {
        Response::builder().status(502).body(Full::new(Bytes::from("bad gateway"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

// --- 2xx codes pass ---

#[tokio::test]
async fn fail_on_error_200_passes() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn fail_on_error_201_passes() {
    let server = TestServer::start(|_req| {
        Response::builder().status(201).body(Full::new(Bytes::from("created"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn fail_on_error_204_passes() {
    let server = TestServer::start(|_req| {
        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 204);
}

// --- 3xx redirect followed, then check final status ---

#[tokio::test]
async fn fail_on_error_redirect_to_200() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/end")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::new(Full::new(Bytes::from("success"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    easy.fail_on_error(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn fail_on_error_redirect_to_500() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/error")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    easy.fail_on_error(true);

    assert!(easy.perform_async().await.is_err());
}

// --- fail_on_error disabled preserves error responses ---

#[tokio::test]
async fn disabled_fail_on_error_returns_404_response() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // fail_on_error is false by default

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.body_str().unwrap(), "not found");
}

#[tokio::test]
async fn disabled_fail_on_error_returns_500_response() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("internal error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.body_str().unwrap(), "internal error");
}

// --- Toggle fail_on_error between requests ---

#[tokio::test]
async fn toggle_fail_on_error_between_requests() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    // First request: fail_on_error enabled
    easy.fail_on_error(true);
    assert!(easy.perform_async().await.is_err());

    // Second request: fail_on_error disabled
    easy.fail_on_error(false);
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 404);
}
