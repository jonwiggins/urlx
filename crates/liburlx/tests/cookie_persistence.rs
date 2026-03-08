//! Cookie persistence integration tests.
//!
//! Tests that cookies are correctly stored from responses and sent
//! on subsequent requests, with domain/path scoping.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::significant_drop_tightening)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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

// --- Cookie jar stores and sends cookies ---

#[tokio::test]
async fn cookie_stored_and_sent_on_next_request() {
    let received_cookies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cookies_clone = received_cookies.clone();

    let server = TestServer::start(move |req| {
        // Record any Cookie header received
        if let Some(cookie) = req.headers().get("cookie") {
            cookies_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        if req.uri().path() == "/set" {
            Response::builder()
                .header("Set-Cookie", "session=abc123")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("check")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // First request: server sets a cookie
    easy.url(&server.url("/set")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Second request: cookie should be sent
    easy.url(&server.url("/check")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    let cookies = received_cookies.lock().unwrap();
    // First request should have no cookie, second should have one
    assert!(
        cookies.iter().any(|c| c.contains("session=abc123")),
        "cookie should be sent on second request, got: {cookies:?}"
    );
}

// --- Multiple cookies stored ---

#[tokio::test]
async fn multiple_cookies_stored_and_sent() {
    let received_cookies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cookies_clone = received_cookies.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            cookies_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        if req.uri().path() == "/set" {
            Response::builder()
                .header("Set-Cookie", "a=1")
                .header("Set-Cookie", "b=2")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("check")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    let cookies = received_cookies.lock().unwrap();
    let last_cookie = cookies.last().expect("should have received cookies");
    assert!(last_cookie.contains("a=1"), "should contain a=1, got: {last_cookie}");
    assert!(last_cookie.contains("b=2"), "should contain b=2, got: {last_cookie}");
}

// --- Cookie replacement ---

#[tokio::test]
async fn cookie_replaced_on_same_name() {
    let received_cookies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cookies_clone = received_cookies.clone();
    let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count_clone = call_count.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            cookies_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        let n = count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            Response::builder()
                .header("Set-Cookie", "token=old")
                .body(Full::new(Bytes::from("first")))
                .unwrap()
        } else if n == 1 {
            Response::builder()
                .header("Set-Cookie", "token=new")
                .body(Full::new(Bytes::from("second")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("third")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // First: sets token=old
    easy.url(&server.url("/")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    // Second: sets token=new (replaces old)
    let _resp = easy.perform_async().await.unwrap();

    // Third: should send token=new
    let _resp = easy.perform_async().await.unwrap();

    let cookies = received_cookies.lock().unwrap();
    let last_cookie = cookies.last().expect("should have cookies");
    assert!(last_cookie.contains("token=new"), "should have new value, got: {last_cookie}");
    // Should not have both old and new
    assert!(!last_cookie.contains("token=old"), "should not have old value");
}

// --- Cookie jar disabled means no cookies ---

#[tokio::test]
async fn no_cookie_jar_means_no_cookies_sent() {
    let received_cookies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cookies_clone = received_cookies.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            cookies_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        Response::builder()
            .header("Set-Cookie", "ignored=true")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    // Cookie jar NOT enabled

    easy.url(&server.url("/")).unwrap();
    let _resp = easy.perform_async().await.unwrap();
    let _resp = easy.perform_async().await.unwrap();

    let cookies = received_cookies.lock().unwrap();
    assert!(cookies.is_empty(), "should not have sent any cookies, got: {cookies:?}");
}

// --- Cookie path scoping ---

#[tokio::test]
async fn cookie_path_scoping() {
    let received_cookies: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let cookies_clone = received_cookies.clone();

    let server = TestServer::start(move |req| {
        let path = req.uri().path().to_string();
        let cookie = req
            .headers()
            .get("cookie")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        cookies_clone.lock().unwrap().push((path.clone(), cookie));

        if path == "/api/set" {
            Response::builder()
                .header("Set-Cookie", "api_token=xyz; Path=/api")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("check")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // Set cookie with Path=/api
    easy.url(&server.url("/api/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    // Request to /api/data — should send cookie
    easy.url(&server.url("/api/data")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    // Request to / — should NOT send cookie (different path)
    easy.url(&server.url("/")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    let cookies = received_cookies.lock().unwrap();
    // Find the /api/data request — should have cookie
    let api_request = cookies.iter().find(|(p, _)| p == "/api/data");
    assert!(
        api_request.is_some() && api_request.unwrap().1.contains("api_token=xyz"),
        "cookie should be sent to /api/data"
    );

    // Find the / request — should NOT have cookie
    let root_request = cookies.iter().rev().find(|(p, _)| p == "/");
    if let Some((_, cookie)) = root_request {
        assert!(!cookie.contains("api_token"), "cookie should NOT be sent to /, got: {cookie}");
    }
}
