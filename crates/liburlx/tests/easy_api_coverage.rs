//! Comprehensive tests for the Easy API options and interactions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

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

// --- Cloned Easy handles are independent ---

#[tokio::test]
async fn cloned_handles_independent_url() {
    let mut easy1 = liburlx::Easy::new();
    easy1.url("http://example.com/a").unwrap();

    let mut easy2 = easy1.clone();
    easy2.url("http://example.com/b").unwrap();

    // easy1 should still have its original URL
    // We can't inspect URL directly, but we can verify they operate independently
    // by performing both against a server
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    easy1.url(&server.url("/first")).unwrap();
    easy2.url(&server.url("/second")).unwrap();

    let resp1 = easy1.perform_async().await.unwrap();
    let resp2 = easy2.perform_async().await.unwrap();

    assert_eq!(resp1.body_str().unwrap(), "/first");
    assert_eq!(resp2.body_str().unwrap(), "/second");
}

#[test]
fn cloned_handle_has_fresh_pool() {
    let easy1 = liburlx::Easy::new();
    let easy2 = easy1.clone();
    let debug1 = format!("{easy1:?}");
    let debug2 = format!("{easy2:?}");
    // Both should have the pool in their Debug output
    assert!(debug1.contains("pool"));
    assert!(debug2.contains("pool"));
}

// --- Multiple perform calls ---

#[tokio::test]
async fn multiple_perform_calls() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 200);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
}

// --- URL can be changed between performs ---

#[tokio::test]
async fn url_change_between_performs() {
    let server = TestServer::start(|req| {
        let body = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    easy.url(&server.url("/first")).unwrap();
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "/first");

    easy.url(&server.url("/second")).unwrap();
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "/second");
}

// --- Method and body interactions ---

#[tokio::test]
async fn post_with_body() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"data");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "POST");
}

#[tokio::test]
async fn head_has_empty_body() {
    let server = TestServer::start(|_req| {
        Response::builder().header("Content-Length", "1000").body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");

    let resp = easy.perform_async().await.unwrap();
    assert!(resp.body().is_empty());
}

// --- Verbose mode flag ---

#[test]
fn verbose_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.verbose(true);
    easy.verbose(false);
    // Should not crash and Debug should work
    let debug = format!("{easy:?}");
    assert!(debug.contains("verbose: false"));
}

// --- Accept encoding toggle ---

#[test]
fn accept_encoding_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.accept_encoding(true);
    easy.accept_encoding(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("accept_encoding: false"));
}

// --- Cookie jar enable/disable ---

#[test]
fn cookie_jar_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.cookie_jar(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("cookie_jar: None"));
}

#[test]
fn cookie_jar_double_enable() {
    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.cookie_jar(true); // Should not create a second jar
    let debug = format!("{easy:?}");
    assert!(debug.contains("cookie_jar: Some"));
}

// --- HSTS enable/disable ---

#[test]
fn hsts_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    easy.hsts(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: None"));
}

// --- Timeout options ---

#[test]
fn connect_timeout_set() {
    let mut easy = liburlx::Easy::new();
    easy.connect_timeout(Duration::from_secs(5));
    let debug = format!("{easy:?}");
    assert!(debug.contains("connect_timeout: Some(5s)"));
}

#[test]
fn total_timeout_set() {
    let mut easy = liburlx::Easy::new();
    easy.timeout(Duration::from_millis(500));
    let debug = format!("{easy:?}");
    assert!(debug.contains("timeout: Some(500ms)"));
}

// --- Max redirects ---

#[test]
fn max_redirects_default_is_50() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 50"));
}

#[test]
fn max_redirects_custom() {
    let mut easy = liburlx::Easy::new();
    easy.max_redirects(10);
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 10"));
}

// --- Proxy options ---

#[test]
fn proxy_valid_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("http://proxy:8080").is_ok());
}

#[test]
fn proxy_invalid_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("not a url").is_err());
}

#[test]
fn noproxy_set() {
    let mut easy = liburlx::Easy::new();
    easy.noproxy("localhost,127.0.0.1");
    let debug = format!("{easy:?}");
    assert!(debug.contains("noproxy: Some"));
}

// --- Auth methods ---

#[test]
fn basic_auth_adds_header() {
    let mut easy = liburlx::Easy::new();
    easy.basic_auth("user", "pass");
    let debug = format!("{easy:?}");
    assert!(debug.contains("Authorization"));
    assert!(debug.contains("Basic"));
}

#[test]
fn bearer_token_adds_header() {
    let mut easy = liburlx::Easy::new();
    easy.bearer_token("mytoken123");
    let debug = format!("{easy:?}");
    assert!(debug.contains("Authorization"));
    assert!(debug.contains("Bearer"));
}

// --- Form fields ---

#[test]
fn form_field_sets_multipart() {
    let mut easy = liburlx::Easy::new();
    easy.form_field("name", "value");
    let debug = format!("{easy:?}");
    assert!(debug.contains("multipart: Some"));
}

// --- Range ---

#[test]
fn range_set() {
    let mut easy = liburlx::Easy::new();
    easy.range("0-499");
    let debug = format!("{easy:?}");
    assert!(debug.contains("range: Some"));
}

// --- Resume from ---

#[test]
fn resume_from_set() {
    let mut easy = liburlx::Easy::new();
    easy.resume_from(1024);
    let debug = format!("{easy:?}");
    assert!(debug.contains("range: Some"));
}

// --- Fail on error ---

#[test]
fn fail_on_error_toggle() {
    let mut easy = liburlx::Easy::new();
    easy.fail_on_error(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("fail_on_error: true"));

    easy.fail_on_error(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("fail_on_error: false"));
}

// --- Fail on error in action ---

#[tokio::test]
async fn fail_on_error_returns_error_for_500() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn fail_on_error_succeeds_for_200() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Method is default ---

#[test]
fn method_is_default_initially() {
    let easy = liburlx::Easy::new();
    assert!(easy.method_is_default());
}

#[test]
fn method_is_not_default_after_set() {
    let mut easy = liburlx::Easy::new();
    easy.method("POST");
    assert!(!easy.method_is_default());
}

// --- Resolve overrides ---

#[test]
fn resolve_adds_override() {
    let mut easy = liburlx::Easy::new();
    easy.resolve("example.com:80", "127.0.0.1:8080");
    let debug = format!("{easy:?}");
    assert!(debug.contains("resolve_overrides"));
}

// --- Header accumulation ---

#[test]
fn headers_accumulate() {
    let mut easy = liburlx::Easy::new();
    easy.header("X-First", "1");
    easy.header("X-Second", "2");
    easy.header("X-Third", "3");
    let debug = format!("{easy:?}");
    assert!(debug.contains("X-First"));
    assert!(debug.contains("X-Second"));
    assert!(debug.contains("X-Third"));
}
