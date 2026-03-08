//! Integration tests for the Multi (concurrent transfer) API.

#![allow(clippy::unwrap_used, unused_results, clippy::significant_drop_tightening)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A simple test HTTP server.
struct TestServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let (tx, mut rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            let handler = handler.clone();
                            let io = hyper_util::rt::TokioIo::new(stream);
                            tokio::spawn(async move {
                                let _ = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| {
                                            let handler = handler.clone();
                                            async move {
                                                Ok::<_, Infallible>(handler(req))
                                            }
                                        }),
                                    )
                                    .await;
                            });
                        }
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
        });

        Self { addr, shutdown: Some(tx) }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn multi_concurrent_gets() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        let body = format!("response for {path}");
        Response::builder().status(200).body(Full::new(Bytes::from(body))).unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();

    for i in 0..5 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/path{i}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 5);

    // Results should be in order
    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), format!("response for /path{i}"));
    }
}

#[tokio::test]
async fn multi_mix_success_and_failure() {
    let server = TestServer::start(|_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("ok"))).unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();

    // First: successful request
    let mut easy1 = liburlx::Easy::new();
    easy1.url(&server.url("/good")).unwrap();
    multi.add(easy1);

    // Second: will fail (connection refused)
    let mut easy2 = liburlx::Easy::new();
    easy2.url("http://127.0.0.1:1/bad").unwrap();
    multi.add(easy2);

    // Third: successful request
    let mut easy3 = liburlx::Easy::new();
    easy3.url(&server.url("/also-good")).unwrap();
    multi.add(easy3);

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);

    assert!(results[0].is_ok(), "first should succeed");
    assert!(results[1].is_err(), "second should fail");
    assert!(results[2].is_ok(), "third should succeed");
}

#[tokio::test]
async fn multi_empty_returns_empty() {
    let mut multi = liburlx::Multi::new();
    let results = multi.perform().await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn multi_single_transfer() {
    let server = TestServer::start(|_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("single"))).unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    multi.add(easy);

    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "single");
}

#[tokio::test]
async fn multi_can_be_reused() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::builder().status(200).body(Full::new(Bytes::from(path))).unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();

    // First batch
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/first")).unwrap();
    multi.add(easy);
    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "/first");

    // Multi should be empty now
    assert!(multi.is_empty());

    // Second batch
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/second")).unwrap();
    multi.add(easy);
    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "/second");
}
