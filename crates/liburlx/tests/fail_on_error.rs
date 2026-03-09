//! Tests for the `fail_on_error` feature (curl -f behavior).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

/// `fail_on_error` should return an error for HTTP 404.
#[tokio::test]
async fn fail_on_error_404() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let result = easy.perform_async().await;
    assert!(result.is_err(), "404 with fail_on_error should error");
}

/// `fail_on_error` should succeed for HTTP 200.
#[tokio::test]
async fn fail_on_error_200_ok() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

/// `fail_on_error` should return an error for HTTP 500.
#[tokio::test]
async fn fail_on_error_500() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let result = easy.perform_async().await;
    assert!(result.is_err(), "500 with fail_on_error should error");
}

/// `fail_on_error` should succeed for 3xx (redirects are not errors).
#[tokio::test]
async fn fail_on_error_redirect_not_error() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(301)
            .header("Location", "/end")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::new(Full::new(Bytes::from("final"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    easy.fail_on_error(true);
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

/// Without `fail_on_error`, 4xx/5xx should return Ok with the status code.
#[tokio::test]
async fn no_fail_on_error_returns_response() {
    let server = TestServer::start(|_req| {
        Response::builder().status(403).body(Full::new(Bytes::from("forbidden"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // fail_on_error is false by default
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 403);
}

/// `fail_on_error` should not affect 399 (just below the threshold).
#[tokio::test]
async fn fail_on_error_399_ok() {
    let server = TestServer::start(|_req| {
        Response::builder().status(399).body(Full::new(Bytes::from("ok"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 399);
}

/// `fail_on_error` boundary: 400 is the first error.
#[tokio::test]
async fn fail_on_error_400_is_error() {
    let server = TestServer::start(|_req| {
        Response::builder().status(400).body(Full::new(Bytes::from("bad"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let result = easy.perform_async().await;
    assert!(result.is_err(), "400 with fail_on_error should error");
}

/// `fail_on_error` can be toggled off.
#[tokio::test]
async fn fail_on_error_toggle() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    easy.fail_on_error(true);
    easy.fail_on_error(false); // Disable it again

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 404);
}
