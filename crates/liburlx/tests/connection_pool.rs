//! Integration tests for connection pooling (HTTP keep-alive).

#![allow(clippy::unwrap_used, unused_results, clippy::significant_drop_tightening)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A test HTTP server that tracks the number of TCP connections accepted.
struct TrackingServer {
    addr: SocketAddr,
    connection_count: Arc<AtomicU32>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TrackingServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connection_count = Arc::new(AtomicU32::new(0));
        let count = connection_count.clone();
        let (tx, mut rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            count.fetch_add(1, Ordering::SeqCst);
                            let io = hyper_util::rt::TokioIo::new(stream);
                            tokio::spawn(async move {
                                let _ = http1::Builder::new()
                                    .keep_alive(true)
                                    .serve_connection(
                                        io,
                                        service_fn(|_req| async {
                                            Ok::<_, Infallible>(
                                                Response::builder()
                                                    .status(200)
                                                    .body(Full::new(Bytes::from("ok")))
                                                    .unwrap(),
                                            )
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

        Self { addr, connection_count, shutdown: Some(tx) }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }

    fn connections(&self) -> u32 {
        self.connection_count.load(Ordering::SeqCst)
    }
}

impl Drop for TrackingServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn connection_reused_for_sequential_requests() {
    let server = TrackingServer::start().await;

    let mut easy = liburlx::Easy::new();

    // First request
    easy.url(&server.url("/first")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Second request to same host
    easy.url(&server.url("/second")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Should have reused the connection (only 1 TCP accept)
    assert_eq!(server.connections(), 1, "should reuse connection");
}

#[tokio::test]
async fn new_connection_for_different_ports() {
    let server1 = TrackingServer::start().await;
    let server2 = TrackingServer::start().await;

    let mut easy = liburlx::Easy::new();

    easy.url(&server1.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    easy.url(&server2.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Different ports → different connections
    assert_eq!(server1.connections(), 1);
    assert_eq!(server2.connections(), 1);
}

#[tokio::test]
async fn three_requests_one_connection() {
    let server = TrackingServer::start().await;

    let mut easy = liburlx::Easy::new();

    for i in 0..3 {
        easy.url(&server.url(&format!("/req{i}"))).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    assert_eq!(server.connections(), 1, "should reuse connection for all 3 requests");
}
