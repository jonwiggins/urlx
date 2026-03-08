//! Cookie engine integration tests.

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

#[tokio::test]
async fn cookie_set_and_sent_on_next_request() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set" => Response::builder()
            .header("Set-Cookie", "token=abc123")
            .body(Full::new(Bytes::from("cookie set")))
            .unwrap(),
        "/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // First request: set the cookie
    easy.url(&server.url("/set")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);

    // Second request: cookie should be sent
    easy.url(&server.url("/check")).unwrap();
    let response = easy.perform_async().await.unwrap();
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("token=abc123"), "cookie not sent: {body}");
}

#[tokio::test]
async fn cookie_not_sent_without_jar() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set" => Response::builder()
            .header("Set-Cookie", "secret=value")
            .body(Full::new(Bytes::from("set")))
            .unwrap(),
        "/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    // Don't enable cookie jar

    easy.url(&server.url("/set")).unwrap();
    let _response = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body(), b"none");
}

#[tokio::test]
async fn multiple_cookies() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set" => Response::builder()
            .header("Set-Cookie", "a=1")
            .header("Set-Cookie", "b=2")
            .body(Full::new(Bytes::from("cookies set")))
            .unwrap(),
        "/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set")).unwrap();
    let _response = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let response = easy.perform_async().await.unwrap();
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("a=1"), "missing cookie a: {body}");
    assert!(body.contains("b=2"), "missing cookie b: {body}");
}

#[tokio::test]
async fn cookie_path_matching() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/api/set" => Response::builder()
            .header("Set-Cookie", "api_token=xyz; Path=/api")
            .body(Full::new(Bytes::from("set")))
            .unwrap(),
        "/api/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        "/other" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // Set cookie with path /api
    easy.url(&server.url("/api/set")).unwrap();
    let _response = easy.perform_async().await.unwrap();

    // Should be sent for /api/ paths
    easy.url(&server.url("/api/check")).unwrap();
    let response = easy.perform_async().await.unwrap();
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("api_token=xyz"), "cookie should match /api: {body}");

    // Should NOT be sent for /other path
    easy.url(&server.url("/other")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body(), b"none");
}

#[tokio::test]
async fn cookie_overwrite() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set1" => Response::builder()
            .header("Set-Cookie", "key=old")
            .body(Full::new(Bytes::from("set1")))
            .unwrap(),
        "/set2" => Response::builder()
            .header("Set-Cookie", "key=new")
            .body(Full::new(Bytes::from("set2")))
            .unwrap(),
        "/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set1")).unwrap();
    let _response = easy.perform_async().await.unwrap();

    easy.url(&server.url("/set2")).unwrap();
    let _response = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let response = easy.perform_async().await.unwrap();
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("key=new"), "cookie should be overwritten: {body}");
    assert!(!body.contains("key=old"), "old cookie should be gone: {body}");
}
