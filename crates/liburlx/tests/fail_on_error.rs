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

/// Regression test for curl test 24: `--fail` should not hang when the server
/// sends an HTTP/1.0 response without Content-Length and keeps the connection open.
///
/// Without the fix, urlx would wait for EOF to determine body end, which never
/// comes because the server holds the TCP connection open. With `fail_on_error`,
/// urlx must skip reading the body entirely when status >= 400.
#[tokio::test]
async fn fail_on_error_http10_no_content_length_no_hang() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Start a raw TCP server that sends HTTP/1.0 404 without Content-Length
    // and keeps the connection open (simulating curl test 24 scenario).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read the request (consume it)
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;

            // Send HTTP/1.0 404 without Content-Length, keep connection open
            let response = b"HTTP/1.0 404 BAD BOY\r\nContent-Type: text/html\r\n\r\nNot found.\n";
            let _ = stream.write_all(response).await;
            let _ = stream.flush().await;

            // Keep the connection open for a long time (simulating the hang scenario)
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("http://127.0.0.1:{port}/test")).unwrap();
    easy.fail_on_error(true);
    // Set a timeout so the test doesn't hang forever if the fix regresses
    easy.timeout(Duration::from_secs(5));

    let result = easy.perform_async().await;
    // Should return an HTTP error (status 404 with fail_on_error), NOT a timeout
    assert!(result.is_err(), "404 with fail_on_error should error");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("HTTP error 404"), "Expected HTTP 404 error, got: {err_msg}");

    server_task.abort();
}
