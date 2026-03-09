//! Decompression integration tests.
//!
//! Tests gzip/deflate decompression through the Easy handle API,
//! verifying that compressed responses are transparently decompressed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

/// Helper: gzip-compress data.
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

// --- Basic gzip decompression ---

#[tokio::test]
async fn gzip_response_decompressed() {
    let original = b"hello compressed world";
    let compressed = gzip_compress(original);

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Encoding", "gzip")
            .body(Full::new(Bytes::from(compressed.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "hello compressed world");
}

// --- Identity encoding passthrough ---

#[tokio::test]
async fn identity_encoding_passthrough() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("Content-Encoding", "identity")
            .body(Full::new(Bytes::from("plain text")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "plain text");
}

// --- No Content-Encoding header ---

#[tokio::test]
async fn no_encoding_header_works() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("no encoding")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "no encoding");
}

// --- Accept-Encoding header sent ---

#[tokio::test]
async fn accept_encoding_header_sent() {
    let server = TestServer::start(|req| {
        let ae = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::new(Full::new(Bytes::from(ae)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    let ae = resp.body_str().unwrap();
    assert!(ae.contains("gzip"), "Accept-Encoding should include gzip: {ae}");
    assert!(ae.contains("deflate"), "Accept-Encoding should include deflate: {ae}");
}

// --- Accept-Encoding not sent when disabled ---

#[tokio::test]
async fn no_accept_encoding_when_disabled() {
    let server = TestServer::start(|req| {
        let has_ae = req.headers().get("accept-encoding").is_some();
        Response::new(Full::new(Bytes::from(if has_ae { "yes" } else { "no" })))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // accept_encoding defaults to false

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "no");
}

// --- Large compressed response ---

#[tokio::test]
async fn large_gzip_response() {
    let original = "x".repeat(100_000);
    let compressed = gzip_compress(original.as_bytes());

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Encoding", "gzip")
            .body(Full::new(Bytes::from(compressed.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap().len(), 100_000);
}

// --- Empty gzip response ---

#[tokio::test]
async fn empty_gzip_response() {
    let compressed = gzip_compress(b"");

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Encoding", "gzip")
            .body(Full::new(Bytes::from(compressed.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "");
}
