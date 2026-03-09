//! Tests for Content-Encoding decompression.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;

use common::TestServer;
use flate2::write::GzEncoder;
use flate2::Compression;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn gzip_decompression() {
    let original = b"Hello, compressed world! This is a test of gzip decompression.";
    let compressed = gzip_compress(original);
    let compressed_clone = compressed.clone();

    let server = TestServer::start(move |req| {
        // Verify Accept-Encoding was sent
        let ae = req.headers().get("accept-encoding").map(|v| v.to_str().unwrap_or("").to_string());
        if ae.as_ref().is_some_and(|v| v.contains("gzip")) {
            Response::builder()
                .header("Content-Encoding", "gzip")
                .body(Full::new(Bytes::from(compressed_clone.clone())))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("no accept-encoding sent")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), original);
}

#[tokio::test]
async fn identity_no_decompression() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("plain text response"))))
            .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"plain text response");
}

#[tokio::test]
async fn accept_encoding_header_contains_gzip() {
    let server = TestServer::start(|req| {
        let ae = req
            .headers()
            .get("accept-encoding")
            .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("invalid").to_string());
        Response::new(Full::new(Bytes::from(ae)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let response = easy.perform_async().await.unwrap();

    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("gzip"), "expected gzip in: {body}");
    assert!(body.contains("deflate"), "expected deflate in: {body}");
}

#[tokio::test]
async fn no_accept_encoding_without_flag() {
    let server = TestServer::start(|req| {
        let has_ae = req.headers().contains_key("accept-encoding");
        Response::new(Full::new(Bytes::from(if has_ae { "yes" } else { "no" })))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // Don't enable accept_encoding
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"no");
}

#[tokio::test]
async fn gzip_empty_body() {
    let compressed = gzip_compress(b"");
    let compressed_clone = compressed.clone();

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Encoding", "gzip")
            .body(Full::new(Bytes::from(compressed_clone.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
}
