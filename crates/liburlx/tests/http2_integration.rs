//! Integration tests for HTTP/2 transfers.
//!
//! Tests exercise HTTP/2 over TLS using ALPN negotiation against
//! a local hyper-based h2 test server.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use common::TestCerts;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// An HTTPS test server that speaks HTTP/2 only.
struct H2TestServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl H2TestServer {
    async fn start<F>(server_config: Arc<rustls::ServerConfig>, handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>>
            + Send
            + Sync
            + 'static
            + Clone,
    {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
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
                            let acceptor = tls_acceptor.clone();
                            tokio::spawn(async move {
                                let Ok(tls_stream) = acceptor.accept(stream).await else {
                                    return;
                                };
                                let io = TokioIo::new(tls_stream);
                                let _ = http2::Builder::new(TokioExecutor)
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
                    _ = &mut rx => break,
                }
            }
        });

        Self { addr, shutdown: Some(tx) }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.addr.port())
    }
}

impl Drop for H2TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Executor for hyper's HTTP/2 server.
#[derive(Clone, Copy)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

/// Create a rustls `ServerConfig` with ALPN set to h2.
///
/// Clones the existing server config from `TestCerts` and adds h2 ALPN.
fn h2_server_config(certs: &TestCerts) -> Arc<rustls::ServerConfig> {
    let mut config = (*certs.server_config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

// =============================================================================
// HTTP/2 tests
// =============================================================================

#[tokio::test]
async fn h2_basic_get() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |_req: Request<hyper::body::Incoming>| {
        Response::new(Full::new(Bytes::from("hello from h2")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello from h2");
}

#[tokio::test]
async fn h2_post_with_body() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |req: Request<hyper::body::Incoming>| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());
    easy.method("POST");
    easy.body(b"payload");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body_str().unwrap(), "POST");
}

#[tokio::test]
async fn h2_custom_headers() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |req: Request<hyper::body::Incoming>| {
        let custom = req
            .headers()
            .get("x-custom")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        Response::new(Full::new(Bytes::from(custom)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());
    easy.header("X-Custom", "h2-value");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "h2-value");
}

#[tokio::test]
async fn h2_large_response() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |_req: Request<hyper::body::Incoming>| {
        // 100KB response
        let body = vec![b'X'; 100_000];
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/large")).unwrap();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), 100_000);
}

#[tokio::test]
async fn h2_multiple_sequential_requests() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |req: Request<hyper::body::Incoming>| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());

    easy.url(&server.url("/first")).unwrap();
    let r1 = easy.perform_async().await.unwrap();
    assert_eq!(r1.body_str().unwrap(), "/first");

    easy.url(&server.url("/second")).unwrap();
    let r2 = easy.perform_async().await.unwrap();
    assert_eq!(r2.body_str().unwrap(), "/second");
}

#[tokio::test]
async fn h2_status_codes() {
    let certs = TestCerts::generate();
    let ca_file = certs.write_ca_cert();
    let server_config = h2_server_config(&certs);

    let server = H2TestServer::start(server_config, |req: Request<hyper::body::Incoming>| {
        let status = match req.uri().path() {
            "/404" => 404,
            "/500" => 500,
            "/201" => 201,
            _ => 200,
        };
        Response::builder().status(status).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.http_version(liburlx::HttpVersion::Http2);
    easy.ssl_ca_cert(ca_file.path());

    easy.url(&server.url("/404")).unwrap();
    let r = easy.perform_async().await.unwrap();
    assert_eq!(r.status(), 404);

    easy.url(&server.url("/201")).unwrap();
    let r = easy.perform_async().await.unwrap();
    assert_eq!(r.status(), 201);
}
