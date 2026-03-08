//! Multi API stress tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;

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

// --- Multi with empty handles ---

#[tokio::test]
async fn multi_empty_returns_empty() {
    let mut multi = liburlx::Multi::new();
    let results = multi.perform().await;
    assert!(results.is_empty());
}

// --- Multi with single handle ---

#[tokio::test]
async fn multi_single_handle() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut multi = liburlx::Multi::new();
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    multi.add(easy);

    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
    assert_eq!(results[0].as_ref().unwrap().status(), 200);
}

// --- Multi with many concurrent transfers ---

#[tokio::test]
async fn multi_ten_concurrent_transfers() {
    let server = TestServer::start(|req| {
        let body = format!("path={}", req.uri().path());
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    for i in 0..10 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{i}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 10);
    for result in &results {
        assert!(result.is_ok(), "all transfers should succeed");
        assert_eq!(result.as_ref().unwrap().status(), 200);
    }
}

// --- Multi with mixed success/failure ---

#[tokio::test]
async fn multi_mixed_success_failure() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/ok" => Response::new(Full::new(Bytes::from("success"))),
        "/error" => Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap(),
        _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut easy_ok = liburlx::Easy::new();
    easy_ok.url(&server.url("/ok")).unwrap();
    multi.add(easy_ok);

    let mut easy_err = liburlx::Easy::new();
    easy_err.url(&server.url("/error")).unwrap();
    multi.add(easy_err);

    let mut easy_404 = liburlx::Easy::new();
    easy_404.url(&server.url("/notfound")).unwrap();
    multi.add(easy_404);

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);

    // All should be Ok (no fail_on_error)
    assert_eq!(results[0].as_ref().unwrap().status(), 200);
    assert_eq!(results[1].as_ref().unwrap().status(), 500);
    assert_eq!(results[2].as_ref().unwrap().status(), 404);
}

// --- Multi add increases count ---

#[test]
fn multi_add_count() {
    let mut multi = liburlx::Multi::new();
    assert_eq!(multi.len(), 0);

    let easy1 = liburlx::Easy::new();
    multi.add(easy1);
    assert_eq!(multi.len(), 1);

    let easy2 = liburlx::Easy::new();
    multi.add(easy2);
    assert_eq!(multi.len(), 2);
}

// --- Multi with different response bodies ---

#[tokio::test]
async fn multi_varied_body_sizes() {
    let server = TestServer::start(|req| {
        let size: usize = req.uri().path().trim_start_matches('/').parse().unwrap_or(0);
        let body = "x".repeat(size);
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    let sizes = [0, 1, 100, 1000, 5000];
    for size in sizes {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{size}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), sizes.len());
    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.body().len(), sizes[i], "body size mismatch for index {i}");
    }
}
