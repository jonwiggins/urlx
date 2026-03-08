//! Integration tests for the cookie engine.

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
async fn cookies_stored_and_sent() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            // Set a cookie
            Response::builder()
                .status(200)
                .header("set-cookie", "sid=abc123")
                .body(Full::new(Bytes::from("cookie set")))
                .unwrap()
        } else {
            // Echo back the cookie header
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // First request: get the cookie
    easy.url(&server.url("/set")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Second request: cookie should be sent
    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "sid=abc123");
}

#[tokio::test]
async fn cookies_not_sent_without_jar() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            Response::builder()
                .status(200)
                .header("set-cookie", "sid=abc123")
                .body(Full::new(Bytes::from("cookie set")))
                .unwrap()
        } else {
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    // cookie_jar NOT enabled

    easy.url(&server.url("/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    // Without cookie jar, no cookies should be sent
    assert_eq!(resp.body_str().unwrap(), "none");
}

#[tokio::test]
async fn cookies_sent_on_redirect() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/login" {
            // Set a cookie and redirect
            Response::builder()
                .status(302)
                .header("set-cookie", "token=xyz")
                .header("location", "/dashboard")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            // Echo back the cookie header
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.follow_redirects(true);
    easy.url(&server.url("/login")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    // The cookie should have been sent to /dashboard after redirect
    assert_eq!(resp.body_str().unwrap(), "token=xyz");
}

#[tokio::test]
async fn multiple_cookies() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            Response::builder()
                .status(200)
                .header("set-cookie", "a=1")
                .header("set-cookie", "b=2")
                .body(Full::new(Bytes::from("ok")))
                .unwrap()
        } else {
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    let cookies = resp.body_str().unwrap();
    assert!(cookies.contains("a=1"), "cookies: {cookies}");
    assert!(cookies.contains("b=2"), "cookies: {cookies}");
}
