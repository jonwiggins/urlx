//! Multi API concurrent transfer stress tests.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

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

// --- Empty Multi ---

#[tokio::test]
async fn multi_empty_returns_empty() {
    let mut multi = liburlx::Multi::new();
    assert!(multi.is_empty());
    assert_eq!(multi.len(), 0);
    let results = multi.perform().await;
    assert!(results.is_empty());
}

// --- Single transfer via Multi ---

#[tokio::test]
async fn multi_single_transfer() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("single")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let mut multi = liburlx::Multi::new();
    multi.add(easy);
    assert_eq!(multi.len(), 1);

    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    let resp = results[0].as_ref().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "single");
}

// --- Multiple concurrent transfers ---

#[tokio::test]
async fn multi_three_concurrent_transfers() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    for path in ["/a", "/b", "/c"] {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(path)).unwrap();
        multi.add(easy);
    }

    assert_eq!(multi.len(), 3);
    let results = multi.perform().await;
    assert_eq!(results.len(), 3);

    // All should succeed
    for result in &results {
        assert!(result.is_ok());
    }

    // Results should be in order
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "/a");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "/b");
    assert_eq!(results[2].as_ref().unwrap().body_str().unwrap(), "/c");
}

// --- Ten concurrent transfers ---

#[tokio::test]
async fn multi_ten_concurrent_transfers() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    for i in 0..10 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/item/{i}"))).unwrap();
        multi.add(easy);
    }

    assert_eq!(multi.len(), 10);
    let results = multi.perform().await;
    assert_eq!(results.len(), 10);

    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 10, "all 10 transfers should succeed");
    assert_eq!(counter.load(Ordering::SeqCst), 10);
}

// --- Multi with mixed results ---

#[tokio::test]
async fn multi_mixed_status_codes() {
    let server = TestServer::start(|req| {
        let status = match req.uri().path() {
            "/not_found" => 404,
            "/error" => 500,
            _ => 200,
        };
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(format!("{status}"))))
            .unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();
    for path in ["/ok", "/not_found", "/error"] {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(path)).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);

    assert_eq!(results[0].as_ref().unwrap().status(), 200);
    assert_eq!(results[1].as_ref().unwrap().status(), 404);
    assert_eq!(results[2].as_ref().unwrap().status(), 500);
}

// --- Multi drains handles after perform ---

#[tokio::test]
async fn multi_drained_after_perform() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut multi = liburlx::Multi::new();
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    multi.add(easy);

    assert_eq!(multi.len(), 1);
    let _results = multi.perform().await;

    // After perform, multi should be empty
    assert!(multi.is_empty());
    assert_eq!(multi.len(), 0);
}

// --- Multi with different methods ---

#[tokio::test]
async fn multi_different_methods() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut get = liburlx::Easy::new();
    get.url(&server.url("/")).unwrap();
    multi.add(get);

    let mut post = liburlx::Easy::new();
    post.url(&server.url("/")).unwrap();
    post.method("POST");
    post.body(b"data");
    multi.add(post);

    let mut put = liburlx::Easy::new();
    put.url(&server.url("/")).unwrap();
    put.method("PUT");
    multi.add(put);

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "GET");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "POST");
    assert_eq!(results[2].as_ref().unwrap().body_str().unwrap(), "PUT");
}

// --- Multi Default trait ---

#[test]
fn multi_default_is_empty() {
    let multi = liburlx::Multi::default();
    assert!(multi.is_empty());
}

// --- Multi with large bodies ---

#[tokio::test]
async fn multi_large_bodies() {
    let server = TestServer::start(|req| {
        let size: usize = req.uri().path().trim_start_matches('/').parse().unwrap_or(100);
        Response::new(Full::new(Bytes::from(vec![b'X'; size])))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    for size in [100, 1000, 10_000, 50_000] {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{size}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 4);
    assert_eq!(results[0].as_ref().unwrap().size_download(), 100);
    assert_eq!(results[1].as_ref().unwrap().size_download(), 1000);
    assert_eq!(results[2].as_ref().unwrap().size_download(), 10_000);
    assert_eq!(results[3].as_ref().unwrap().size_download(), 50_000);
}
