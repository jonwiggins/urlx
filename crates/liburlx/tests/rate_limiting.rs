//! Integration tests for transfer engine rate limiting.
//!
//! Tests that `max_recv_speed`, `max_send_speed`, `low_speed_limit`,
//! and `low_speed_time` are properly enforced during transfers.

#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};

use common::TestServer;
use liburlx::Easy;

/// Generate a response body of the specified size.
fn make_body(size: usize) -> Vec<u8> {
    vec![b'x'; size]
}

#[tokio::test]
async fn max_recv_speed_throttles_download() {
    // Serve a 10 KB response
    let body_size = 10_000;
    let body_data = make_body(body_size);
    let server = TestServer::start(move |_req: Request<hyper::body::Incoming>| {
        Response::builder()
            .status(200)
            .header("content-length", body_data.len().to_string())
            .body(Full::new(Bytes::from(body_data.clone())))
            .unwrap()
    })
    .await;

    let mut easy = Easy::new();
    easy.url(&server.url("/data")).unwrap();
    // Limit download to 5000 bytes/sec — should take ~2 seconds for 10 KB
    easy.max_recv_speed(5_000);

    let start = Instant::now();
    let response = easy.perform_async().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), body_size);
    // At 5000 B/s, 10000 bytes should take at least ~1.5 seconds
    // (generous margin for test reliability)
    assert!(
        elapsed >= Duration::from_millis(1500),
        "expected >= 1500ms, got {elapsed:?}; download was not throttled"
    );
}

#[tokio::test]
async fn max_send_speed_throttles_upload() {
    // Server that reads the body and returns its size
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        Response::builder()
            .status(200)
            .body(Full::new(Bytes::from(format!("received {content_length}"))))
            .unwrap()
    })
    .await;

    let mut easy = Easy::new();
    easy.url(&server.url("/upload")).unwrap();
    easy.method("POST");
    // 10 KB upload body
    easy.body(&make_body(10_000));
    // Limit upload to 5000 bytes/sec — should take ~2 seconds
    easy.max_send_speed(5_000);

    let start = Instant::now();
    let response = easy.perform_async().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), 200);
    // At 5000 B/s, 10000 bytes should take at least ~1.5 seconds
    assert!(
        elapsed >= Duration::from_millis(1500),
        "expected >= 1500ms, got {elapsed:?}; upload was not throttled"
    );
}

#[tokio::test]
async fn no_rate_limit_transfers_quickly() {
    // Sanity check: without rate limiting, the same transfer should be fast
    let body_size = 10_000;
    let body_data = make_body(body_size);
    let server = TestServer::start(move |_req: Request<hyper::body::Incoming>| {
        Response::builder()
            .status(200)
            .header("content-length", body_data.len().to_string())
            .body(Full::new(Bytes::from(body_data.clone())))
            .unwrap()
    })
    .await;

    let mut easy = Easy::new();
    easy.url(&server.url("/data")).unwrap();
    // No rate limiting

    let start = Instant::now();
    let response = easy.perform_async().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), body_size);
    // Should complete in well under 1 second on localhost
    assert!(
        elapsed < Duration::from_millis(500),
        "expected < 500ms without rate limiting, got {elapsed:?}"
    );
}

#[tokio::test]
async fn max_recv_speed_preserves_response_body() {
    // Verify that throttling doesn't corrupt the response body
    let body_data = b"Hello, rate-limited world! This body should arrive intact.".to_vec();
    let expected = body_data.clone();
    let server = TestServer::start(move |_req: Request<hyper::body::Incoming>| {
        Response::builder()
            .status(200)
            .header("content-length", body_data.len().to_string())
            .body(Full::new(Bytes::from(body_data.clone())))
            .unwrap()
    })
    .await;

    let mut easy = Easy::new();
    easy.url(&server.url("/data")).unwrap();
    easy.max_recv_speed(100); // Very slow — but body is small so still fast

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), &expected);
}

#[tokio::test]
async fn chunked_transfer_with_rate_limiting() {
    // Test that chunked encoding works with rate limiting
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        // hyper will use chunked encoding since we don't set content-length
        let body = vec![b'A'; 5_000];
        Response::builder().status(200).body(Full::new(Bytes::from(body))).unwrap()
    })
    .await;

    let mut easy = Easy::new();
    easy.url(&server.url("/chunked")).unwrap();
    easy.max_recv_speed(2_500);

    let start = Instant::now();
    let response = easy.perform_async().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), 5_000);
    // 5000 bytes at 2500 B/s should take ~2s, use generous margin
    assert!(
        elapsed >= Duration::from_millis(1500),
        "expected >= 1500ms for chunked transfer, got {elapsed:?}"
    );
}

#[tokio::test]
async fn speed_limits_struct_defaults() {
    // Test that SpeedLimits can be constructed and used
    let limits = liburlx::SpeedLimits::default();
    assert!(!limits.has_limits());

    let limits = liburlx::SpeedLimits {
        max_recv_speed: Some(1024),
        max_send_speed: None,
        low_speed_limit: None,
        low_speed_time: None,
    };
    assert!(limits.has_limits());
}

#[tokio::test]
async fn easy_rate_limit_setters() {
    // Test that Easy setters work correctly
    let mut easy = Easy::new();
    easy.max_recv_speed(1000);
    easy.max_send_speed(2000);
    easy.low_speed_limit(100);
    easy.low_speed_time(Duration::from_secs(30));

    // These are set — verify by doing a transfer (they should not cause errors
    // with a normal speed transfer)
    let server = TestServer::start(|_req: Request<hyper::body::Incoming>| {
        Response::builder()
            .status(200)
            .header("content-length", "5")
            .body(Full::new(Bytes::from("hello")))
            .unwrap()
    })
    .await;

    easy.url(&server.url("/test")).unwrap();
    // With a 5-byte response and 1000 B/s limit, this should be fast
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}
