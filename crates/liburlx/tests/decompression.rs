//! Tests for Content-Encoding decompression.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;

use flate2::write::GzEncoder;
use flate2::Compression;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

struct TestServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>>
            + Send
            + Sync
            + 'static
            + Clone,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let _server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let handler = handler.clone();
                            let _conn_task = tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let svc = service_fn(move |req| {
                                    let resp = handler(req);
                                    async move { Ok::<_, Infallible>(resp) }
                                });
                                let _result = http1::Builder::new()
                                    .serve_connection(io, svc)
                                    .await;
                            });
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Self { addr, _shutdown: shutdown_tx }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

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
