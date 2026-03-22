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

/// Test 223: broken deflate with Content-Length mismatch.
///
/// Server sends Content-Encoding: deflate + Content-Length: 1305 but only 412 bytes
/// of broken deflate data, then keeps the connection open. urlx must detect the
/// broken encoding via incremental decompression checking and return
/// `bad_content_encoding` instead of blocking forever.
#[tokio::test]
async fn broken_deflate_content_length_mismatch_returns_bad_encoding() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Broken deflate data from curl test 223: three bytes removed from the beginning
    // of a valid deflate stream, then cut short.
    let broken_deflate: Vec<u8> = vec![
        0x58, 0xdb, 0x6e, 0xe3, 0x36, 0x10, 0x7d, 0x37, 0x90, 0x7f, 0x60, 0xfd, 0xd4, 0x02, 0xb6,
        0x6e, 0xb6, 0x13, 0x39, 0x70, 0xb4, 0x28, 0x72, 0xd9, 0x04, 0xcd, 0x36, 0xc1, 0xda, 0x05,
        0xba, 0x4f, 0x06, 0x2d, 0xd1, 0x36, 0x1b, 0x49, 0x14, 0x48, 0xca, 0xb9, 0x3c, 0xf4, 0xdb,
        0x3b, 0x94, 0x28, 0x89, 0xb1, 0x1c, 0xaf, 0x77, 0x83, 0xbe, 0x04, 0x48, 0x62, 0x72, 0xe6,
        0x9c, 0xc3, 0xe1, 0x0c, 0x49, 0x93, 0x99, 0x7c, 0x7a, 0x4a, 0x62, 0xb4, 0x21, 0x5c, 0x50,
        0x96, 0x9e, 0x75, 0x5d, 0xcb, 0xe9, 0x22, 0x92, 0x86, 0x2c, 0xa2, 0xe9, 0xea, 0xac, 0x7b,
        0x33, 0xbd, 0xeb, 0xfb, 0xfe, 0x68, 0xdc, 0x77, 0xbb, 0x9f, 0x82, 0xce, 0xe4, 0x97, 0x8b,
        0xbb, 0xf3, 0xd9, 0xb7, 0xfb, 0x4b, 0x94, 0x71, 0xf6, 0x0f, 0x09, 0x65, 0x3f, 0xa6, 0x42,
        0x02, 0x10, 0x4d, 0xbf, 0x4d, 0x67, 0x97, 0x5f, 0x50, 0x77, 0x2d, 0x65, 0x76, 0x6a, 0xdb,
        0x4b, 0x4e, 0xc4, 0x3a, 0x21, 0x58, 0x5a, 0x29, 0x91, 0xf6, 0x02, 0x87, 0x0f, 0x24, 0x8d,
        0xec, 0x65, 0xd2, 0xd7, 0x3c, 0xd1, 0x77, 0xac, 0xa1, 0x15, 0xc9, 0xa8, 0x0b, 0xa2, 0x5b,
        0x5a, 0x41, 0x07, 0xa1, 0xca, 0xa6, 0xda, 0x4d, 0x6f, 0x4e, 0xa3, 0xc0, 0x3d, 0x76, 0xbd,
        0x89, 0x6d, 0x18, 0x4a, 0x44, 0x84, 0x25, 0x99, 0xe3, 0x28, 0x22, 0x80, 0x18, 0x8f, 0xfd,
        0xbe, 0xe3, 0xf7, 0x3d, 0x17, 0x39, 0xc3, 0x53, 0xc7, 0x3d, 0xf5, 0xc6, 0x13, 0xdb, 0xf0,
        0x1b, 0x84, 0x3c, 0x53, 0x1f, 0x51, 0xe0, 0x39, 0xce, 0xb0, 0xef, 0x3a, 0x7d, 0xd7, 0x47,
        0x8e, 0x77, 0xea, 0xc1, 0xcf, 0x40, 0x53, 0x2a, 0xc4, 0xab, 0x38, 0x52, 0x9c, 0x90, 0xb9,
        0x58, 0x33, 0x2e, 0x83, 0x30, 0xe7, 0x71, 0x1d, 0x8e, 0x61, 0x6f, 0xe3, 0x97, 0x79, 0x1c,
        0x17, 0x70, 0x84, 0xd3, 0x08, 0xc5, 0x74, 0xd1, 0xa6, 0x16, 0x10, 0x1d, 0x1e, 0x11, 0xa1,
        0x96, 0x3a, 0x67, 0x49, 0x52, 0x52, 0x52, 0x82, 0x24, 0x63, 0xb5, 0x00, 0xc7, 0xfc, 0x19,
        0x2d, 0x19, 0x47, 0x61, 0x4c, 0x49, 0x2a, 0xfb, 0x82, 0x46, 0x04, 0xfd, 0xf5, 0xf5, 0x16,
        0x49, 0x8e, 0x53, 0xb1, 0x84, 0x8a, 0x5a, 0x30, 0x8b, 0x46, 0xc8, 0x50, 0xde, 0x19, 0x0c,
        0xa2, 0x02, 0xe1, 0x72, 0x04, 0xa5, 0x5a, 0xa9, 0x70, 0x55, 0xdf, 0x25, 0x8d, 0x89, 0x38,
        0xea, 0xe4, 0x42, 0x75, 0xd4, 0x18, 0xe2, 0x39, 0x95, 0xf8, 0xc9, 0x42, 0x37, 0x12, 0x89,
        0x3c, 0xcb, 0x40, 0x5f, 0xa0, 0xeb, 0xd9, 0xec, 0xbe, 0x57, 0xfc, 0x9d, 0xf6, 0xd0, 0x15,
        0xb4, 0x8f, 0x3a, 0x57, 0x45, 0xfb, 0xe2, 0xe6, 0x7c, 0xd6, 0x43, 0xb3, 0xcb, 0xdb, 0x3f,
        0x2f, 0xe1, 0xf3, 0xf6, 0xe2, 0x77, 0x80, 0x5d, 0xdd, 0xdc, 0x5e, 0xf6, 0x8a, 0xe1, 0x3f,
        0xdf, 0xdd, 0x5f, 0x5f, 0x7e, 0x85, 0x36, 0x0c, 0xf0, 0x48, 0x62, 0x88, 0xa9, 0x94, 0xea,
        0x67, 0x4c, 0xc8, 0x9e, 0x6e, 0xe6, 0xd0,
    ];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read the request (just drain it)
        let mut buf = [0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

        // Send response with Content-Length: 1305 but only broken_deflate.len() bytes of body
        let headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Encoding: deflate\r\n\
             Content-Length: 1305\r\n\
             \r\n"
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&broken_deflate).await.unwrap();
        stream.flush().await.unwrap();

        // Keep the connection open (don't close) to simulate the test server
        // Wait for the client to disconnect or timeout
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let url = format!("http://127.0.0.1:{}/223", addr.port());
    let mut easy = liburlx::Easy::new();
    easy.url(&url).unwrap();
    easy.accept_encoding(true);

    // Must complete within 5 seconds — if it hangs, the test fails
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(5), easy.perform_async()).await;

    // Should NOT timeout
    let response =
        result.expect("request should not hang on broken deflate with Content-Length mismatch");
    let response = response.unwrap();

    // Should have body_error indicating bad content encoding
    assert!(
        response.body_error().is_some_and(|e| e.contains("bad_content_encoding")),
        "Expected bad_content_encoding error, got body_error={:?}, status={}",
        response.body_error(),
        response.status()
    );

    server_handle.abort();
}
