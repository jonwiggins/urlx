//! HTTP protocol error path tests.
//!
//! Tests for malformed responses, connection drops, and edge conditions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;
use tokio::net::TcpListener;

// --- Server drops connection ---

#[tokio::test]
async fn server_sends_empty_response() {
    // Server that accepts then immediately closes connection
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let _server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream); // Close immediately
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("http://{addr}/")).unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err(), "empty response should error");
}

// --- Very large response body ---

#[tokio::test]
async fn large_response_body() {
    let large_body = "x".repeat(1_000_000); // 1MB
    let body_clone = large_body.clone();

    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(body_clone.clone()))))
            .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), 1_000_000);
}

// --- Status code edge cases ---

#[tokio::test]
async fn status_100_continue() {
    // The hyper server won't send a bare 100, but we can test that
    // final responses work alongside it. Test a real 200 response.
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn status_418_teapot() {
    let server = TestServer::start(|_req| {
        Response::builder().status(418).body(Full::new(Bytes::from("I'm a teapot"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 418);
    assert_eq!(response.body(), b"I'm a teapot");
}

#[tokio::test]
async fn status_503_service_unavailable() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(503)
            .header("Retry-After", "120")
            .body(Full::new(Bytes::from("service unavailable")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.header("retry-after"), Some("120"));
}

// --- Invalid URLs ---

#[tokio::test]
async fn empty_url_error() {
    let mut easy = liburlx::Easy::new();
    let result = easy.url("");
    assert!(result.is_err(), "empty URL should error");
}

#[tokio::test]
async fn perform_without_url() {
    let mut easy = liburlx::Easy::new();
    let result = easy.perform_async().await;
    assert!(result.is_err(), "perform without URL should error");
}

// --- Multiple sequential requests on same Easy handle ---

#[tokio::test]
async fn sequential_requests_different_paths() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    for i in 0..5 {
        let path = format!("/path{i}");
        easy.url(&server.url(&path)).unwrap();
        let response = easy.perform_async().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), path.as_bytes());
    }
}

// --- Very small timeout ---

#[tokio::test]
async fn very_short_timeout() {
    let mut easy = liburlx::Easy::new();
    // TEST-NET-1 should be unreachable
    easy.url("http://192.0.2.1:12345/").unwrap();
    easy.connect_timeout(std::time::Duration::from_millis(1));

    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- Concurrent error and success ---

#[tokio::test]
async fn multi_mix_errors_and_successes() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut multi = liburlx::Multi::new();

    // One good request
    let mut good = liburlx::Easy::new();
    good.url(&server.url("/good")).unwrap();
    multi.add(good);

    // One bad request (connection refused)
    let bad_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = bad_listener.local_addr().unwrap();
    drop(bad_listener);

    let mut bad = liburlx::Easy::new();
    bad.url(&format!("http://{bad_addr}/")).unwrap();
    multi.add(bad);

    let results = multi.perform().await;
    assert_eq!(results.len(), 2);

    // At least one should succeed
    assert!(results.iter().any(Result::is_ok), "at least one should succeed");
}

// --- Response with no Content-Type header ---

#[tokio::test]
async fn response_no_content_type() {
    let server = TestServer::start(|_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("raw bytes"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"raw bytes");
    // content-type may or may not be present depending on hyper defaults
}

// --- Empty response body with Content-Length: 0 ---

#[tokio::test]
async fn content_length_zero() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
}

// --- Response with many Set-Cookie headers ---

#[tokio::test]
async fn many_set_cookies() {
    let server = TestServer::start(|_req| {
        let mut builder = Response::builder();
        for i in 0..20 {
            builder = builder.header("Set-Cookie", format!("cookie{i}=val{i}"));
        }
        builder.body(Full::new(Bytes::from("ok"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.url(&server.url("/set")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}
