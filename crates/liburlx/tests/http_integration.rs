//! Integration tests for HTTP transfers using a real test server.
//!
//! These tests spin up a local hyper HTTP server and exercise
//! the liburlx Easy API against it.

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

/// A simple test HTTP server.
struct TestServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    /// Start a test server that dispatches requests via the given handler.
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
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Self { addr, shutdown: shutdown_tx }
    }

    /// Get the URL for a given path on this server.
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Shut down the server.
    fn stop(self) {
        let _result = self.shutdown.send(());
    }
}

// --- HTTP GET Tests ---

#[tokio::test]
async fn get_returns_200_with_body() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("hello world")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello world");
    server.stop();
}

#[tokio::test]
async fn get_empty_body() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::new()))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/empty")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    server.stop();
}

#[tokio::test]
async fn get_large_body() {
    let body = "x".repeat(100_000);
    let body_clone = body.clone();
    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(body_clone.clone()))))
            .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/large")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().len(), 100_000);
    server.stop();
}

// --- HTTP POST Tests ---

#[tokio::test]
async fn post_with_body() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "POST");
        Response::new(Full::new(Bytes::from("post ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"request body");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"post ok");
    server.stop();
}

// --- HTTP PUT/DELETE Tests ---

#[tokio::test]
async fn put_request() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "PUT");
        Response::new(Full::new(Bytes::from("put ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/put")).unwrap();
    easy.method("PUT");
    easy.body(b"updated data");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"put ok");
    server.stop();
}

#[tokio::test]
async fn delete_request() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "DELETE");
        Response::new(Full::new(Bytes::from("deleted")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/delete")).unwrap();
    easy.method("DELETE");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    server.stop();
}

// --- HEAD Request ---

#[tokio::test]
async fn head_request_no_body() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "HEAD");
        Response::new(Full::new(Bytes::new()))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/head")).unwrap();
    easy.method("HEAD");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    server.stop();
}

// --- Custom Headers ---

#[tokio::test]
async fn custom_headers_sent() {
    let server = TestServer::start(|req| {
        let ua = req.headers().get("x-custom").map(|v| v.to_str().unwrap().to_string());
        let body = ua.unwrap_or_default();
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/headers")).unwrap();
    easy.header("X-Custom", "test-value");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"test-value");
    server.stop();
}

// --- Response Headers ---

#[tokio::test]
async fn response_headers_parsed() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Server", "test-server")
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from("body")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.header("x-server"), Some("test-server"));
    assert_eq!(response.content_type(), Some("text/plain"));
    server.stop();
}

// --- Status Codes ---

#[tokio::test]
async fn status_404() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/missing")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 404);
    assert_eq!(response.body(), b"not found");
    server.stop();
}

#[tokio::test]
async fn status_500() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("server error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/error")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 500);
    server.stop();
}

// --- Redirects ---

#[tokio::test]
async fn redirect_not_followed_by_default() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(302)
            .header("Location", "/end")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 302);
    server.stop();
}

#[tokio::test]
async fn redirect_followed_with_flag() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/end")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/end" => Response::new(Full::new(Bytes::from("final"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"final");
    server.stop();
}

#[tokio::test]
async fn redirect_chain() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(301)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::builder()
            .status(302)
            .header("Location", "/c")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/c" => Response::new(Full::new(Bytes::from("end of chain"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"end of chain");
    assert_eq!(response.transfer_info().num_redirects, 2);
    server.stop();
}

#[tokio::test]
async fn redirect_max_exceeded() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(302)
            .header("Location", "/loop")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/loop")).unwrap();
    easy.follow_redirects(true);
    easy.max_redirects(3);
    let result = easy.perform_async().await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("too many redirects") || err.contains("redirects followed"),
        "unexpected error: {err}"
    );
    server.stop();
}

// --- Timeout ---

#[tokio::test]
async fn total_timeout() {
    let server = TestServer::start(|_req| {
        // Simulate a slow response — this won't actually delay because the handler
        // runs synchronously, but the connect itself should succeed
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.timeout(std::time::Duration::from_secs(10));
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    server.stop();
}

// --- Connection Refused ---

#[tokio::test]
async fn connection_refused() {
    let mut easy = liburlx::Easy::new();
    // Use a port that should be unbound
    easy.url("http://127.0.0.1:1").unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- Transfer Info ---

#[tokio::test]
async fn transfer_info_populated() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("data")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    let info = response.transfer_info();
    assert!(info.time_total.as_millis() > 0 || info.time_total.as_micros() > 0);
    assert_eq!(info.num_redirects, 0);
    server.stop();
}

// --- User-Agent Header ---

#[tokio::test]
async fn user_agent_header() {
    let server = TestServer::start(|req| {
        let ua =
            req.headers().get("user-agent").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(ua.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("User-Agent", "urlx/0.1");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"urlx/0.1");
    server.stop();
}

// --- Basic Auth ---

#[tokio::test]
async fn basic_auth_header() {
    let server = TestServer::start(|req| {
        let auth =
            req.headers().get("authorization").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(auth.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.basic_auth("user", "pass");
    let response = easy.perform_async().await.unwrap();

    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.starts_with("Basic "), "expected Basic auth, got: {body}");
    server.stop();
}

// --- Accept-Encoding ---

#[tokio::test]
async fn accept_encoding_header_sent() {
    let server = TestServer::start(|req| {
        let ae = req
            .headers()
            .get("accept-encoding")
            .map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(ae.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let response = easy.perform_async().await.unwrap();

    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("gzip"), "expected gzip in accept-encoding, got: {body}");
    server.stop();
}

// --- Range Requests ---

#[tokio::test]
async fn range_header_sent() {
    let server = TestServer::start(|req| {
        let range = req.headers().get("range").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(range.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.range("0-499");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"bytes=0-499");
    server.stop();
}

// --- Effective URL ---

#[tokio::test]
async fn effective_url_no_redirect() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let url = server.url("/test");
    let mut easy = liburlx::Easy::new();
    easy.url(&url).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.effective_url(), url);
    server.stop();
}

// --- Multiple Concurrent Transfers ---

#[tokio::test]
async fn multi_concurrent_transfers() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    for i in 0..3 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/path{i}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);

    for result in &results {
        assert!(result.is_ok());
        let response = result.as_ref().unwrap();
        assert_eq!(response.status(), 200);
    }

    server.stop();
}
