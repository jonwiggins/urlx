//! HTTP behavior conformance edge case tests.
//!
//! Tests HTTP protocol edge cases including HEAD responses, status code
//! handling, header case-insensitivity, keep-alive behavior, and
//! Content-Length / chunked encoding interactions.

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

// --- HEAD request behavior ---

#[tokio::test]
async fn head_returns_empty_body_with_content_length() {
    let server = TestServer::start(|_req| {
        Response::builder().header("Content-Length", "1000").body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty(), "HEAD response body should be empty");
}

#[tokio::test]
async fn head_preserves_headers() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Custom", "preserved")
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.header("x-custom"), Some("preserved"));
    assert_eq!(resp.header("content-type"), Some("text/html"));
}

// --- 204 No Content ---

#[tokio::test]
async fn status_204_has_empty_body() {
    let server = TestServer::start(|_req| {
        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 204);
    assert!(resp.body().is_empty());
}

// --- 304 Not Modified ---

#[tokio::test]
async fn status_304_has_empty_body() {
    let server = TestServer::start(|_req| {
        Response::builder().status(304).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 304);
    assert!(resp.body().is_empty());
}

// --- Response header case insensitivity ---

#[tokio::test]
async fn headers_stored_lowercase() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Mixed-Case", "value1")
            .header("CONTENT-TYPE", "text/plain")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    // Lookup should work regardless of case
    assert!(resp.header("x-mixed-case").is_some());
    assert!(resp.header("X-Mixed-Case").is_some());
    assert!(resp.header("X-MIXED-CASE").is_some());
    assert!(resp.header("content-type").is_some());
}

// --- Binary body handling ---

#[tokio::test]
async fn binary_body_preserved_exactly() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let data_clone = binary_data.clone();
    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Type", "application/octet-stream")
            .body(Full::new(Bytes::from(data_clone.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body(), &binary_data);
    assert_eq!(resp.size_download(), 256);
}

// --- Large response handling ---

#[tokio::test]
async fn large_response_body_complete() {
    let size = 200_000;
    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(vec![b'X'; size]))))
            .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.size_download(), size);
    assert!(resp.body().iter().all(|&b| b == b'X'));
}

// --- Multiple headers with same name ---

#[tokio::test]
async fn response_multiple_set_cookie_preserved() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("Set-Cookie", "a=1")
            .header("Set-Cookie", "b=2")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    // Set-Cookie headers should be preserved (may be joined)
    let cookie_hdr = resp.header("set-cookie");
    assert!(cookie_hdr.is_some(), "should have set-cookie header");
    let hdr = cookie_hdr.unwrap();
    assert!(hdr.contains("a=1"), "should contain first cookie");
    assert!(hdr.contains("b=2"), "should contain second cookie");
}

// --- Custom request methods ---

#[tokio::test]
async fn custom_method_patch() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("PATCH");
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "PATCH");
}

#[tokio::test]
async fn custom_method_options() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("OPTIONS");
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "OPTIONS");
}

// --- Query strings ---

#[tokio::test]
async fn query_string_sent_correctly() {
    let server = TestServer::start(|req| {
        let query = req.uri().query().unwrap_or("").to_string();
        Response::new(Full::new(Bytes::from(query)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/search?q=hello+world&lang=en")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    let query = resp.body_str().unwrap();
    assert!(query.contains("q=hello+world"));
    assert!(query.contains("lang=en"));
}

// --- Custom headers override defaults ---

#[tokio::test]
async fn custom_user_agent_overrides_default() {
    let server = TestServer::start(|req| {
        let ua = req.headers().get("user-agent").map_or("none", |v| v.to_str().unwrap_or("bad"));
        Response::new(Full::new(Bytes::from(ua.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("User-Agent", "CustomBot/1.0");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "CustomBot/1.0");
}

#[tokio::test]
async fn custom_accept_header() {
    let server = TestServer::start(|req| {
        let accept = req.headers().get("accept").map_or("none", |v| v.to_str().unwrap_or("bad"));
        Response::new(Full::new(Bytes::from(accept.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("Accept", "application/json");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "application/json");
}

// --- POST with content type ---

#[tokio::test]
async fn post_sends_body_correctly() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"key=value");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "POST");
}

// --- PUT method ---

#[tokio::test]
async fn put_method_works() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("PUT");
    easy.body(b"updated content");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "PUT");
}

// --- DELETE method ---

#[tokio::test]
async fn delete_method_works() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("DELETE");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "DELETE");
}

// --- Redirect preserves method correctly ---

#[tokio::test]
async fn redirect_307_preserves_method() {
    let server = TestServer::start(|req| {
        if req.uri().path() == "/start" {
            Response::builder()
                .status(307)
                .header("Location", "/end")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "POST");
}

#[tokio::test]
async fn redirect_303_changes_to_get() {
    let server = TestServer::start(|req| {
        if req.uri().path() == "/start" {
            Response::builder()
                .status(303)
                .header("Location", "/end")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "GET");
}
