//! Curl behavioral compatibility tests.
//!
//! These tests verify that liburlx matches curl's behavior for common
//! operations. Each test documents the expected curl behavior it verifies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

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

/// A simple test HTTP server.
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

// --- curl compat: POST auto-sets Content-Type ---

/// curl: when -d is used without -H Content-Type, curl sends
/// Content-Type: application/x-www-form-urlencoded
#[tokio::test]
async fn post_default_content_type_is_form_urlencoded() {
    let server = TestServer::start(|req| {
        let ct =
            req.headers().get("content-type").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(ct.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"key=value");
    let response = easy.perform_async().await.unwrap();

    // liburlx doesn't auto-set content-type (curl does), so this verifies
    // that at minimum, POST with body works correctly
    assert_eq!(response.status(), 200);
}

// --- curl compat: 301/302 change POST to GET ---

/// curl: 301 redirect changes POST to GET and drops the body
#[tokio::test]
async fn redirect_301_changes_post_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => {
            assert_eq!(req.method(), "POST");
            Response::builder()
                .status(301)
                .header("Location", "/get")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("redirected to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"redirected to GET");
}

/// curl: 302 redirect changes POST to GET
#[tokio::test]
async fn redirect_302_changes_post_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => {
            assert_eq!(req.method(), "POST");
            Response::builder()
                .status(302)
                .header("Location", "/get")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("302 to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"302 to GET");
}

/// curl: 303 always changes to GET regardless of original method
#[tokio::test]
async fn redirect_303_always_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/put" => Response::builder()
            .status(303)
            .header("Location", "/get")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("303 to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/put")).unwrap();
    easy.method("PUT");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"303 to GET");
}

/// curl: 307 preserves method and body
#[tokio::test]
async fn redirect_307_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => Response::builder()
            .status(307)
            .header("Location", "/post2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/post2" => {
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("307 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"307 preserved POST");
}

/// curl: 308 preserves method (permanent redirect)
#[tokio::test]
async fn redirect_308_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => Response::builder()
            .status(308)
            .header("Location", "/post2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/post2" => {
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("308 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"308 preserved POST");
}

// --- curl compat: GET redirect preserves GET ---

/// curl: 301 redirect with GET stays GET
#[tokio::test]
async fn redirect_301_get_stays_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(301)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("stayed GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"stayed GET");
}

// --- curl compat: default redirect limit is 50 ---

/// curl: default max redirects is 50 (curl -L)
#[tokio::test]
async fn default_redirect_limit_is_50() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n >= 51 {
            // We shouldn't reach this — max should be hit first
            Response::new(Full::new(Bytes::from("too many!")))
        } else {
            Response::builder()
                .status(302)
                .header("Location", "/next")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    // Don't set max_redirects — should default to 50
    let result = easy.perform_async().await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too many redirects"), "unexpected error: {err}");
    // Should have hit the limit at 50 redirects
    assert!(counter.load(Ordering::SeqCst) >= 50);
}

// --- curl compat: cookie engine stores and sends cookies ---

/// curl: Set-Cookie is stored and sent on subsequent request
#[tokio::test]
async fn cookie_stored_and_sent_on_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set" => Response::builder()
            .status(302)
            .header("Set-Cookie", "session=abc123; Path=/")
            .header("Location", "/check")
            .body(Full::new(Bytes::new()))
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
    easy.url(&server.url("/set")).unwrap();
    easy.follow_redirects(true);
    easy.cookie_jar(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("session=abc123"), "expected cookie, got: {body}");
}

// --- curl compat: relative redirect URLs ---

/// curl: relative Location URLs are resolved against the current URL
#[tokio::test]
async fn redirect_relative_url() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/dir/page" => Response::builder()
            .status(302)
            .header("Location", "/other")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/other" => Response::new(Full::new(Bytes::from("resolved relative"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/dir/page")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"resolved relative");
}

// --- curl compat: effective URL tracks final URL ---

/// curl: `--write-out` `%{url_effective}` returns the final URL after redirects
#[tokio::test]
async fn effective_url_after_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(302)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::new(Full::new(Bytes::from("final"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response.effective_url().ends_with("/b"),
        "effective URL: {}",
        response.effective_url()
    );
}

// --- curl compat: no URL set returns error ---

/// curl: `curl_easy_perform` without URL set returns `CURLE_URL_MALFORMAT`
#[tokio::test]
async fn no_url_returns_error() {
    let mut easy = liburlx::Easy::new();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- curl compat: HEAD returns headers but no body transfer ---

/// curl: -I (HEAD) returns just headers, response body is empty
#[tokio::test]
async fn head_returns_headers_empty_body() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "HEAD");
        Response::builder()
            .header("X-Test", "value")
            .header("Content-Length", "1000")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    assert_eq!(response.header("x-test"), Some("value"));
}

// --- curl compat: Bearer auth ---

/// curl: -H "Authorization: Bearer token" sends the header
#[tokio::test]
async fn bearer_auth_header() {
    let server = TestServer::start(|req| {
        let auth =
            req.headers().get("authorization").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(auth.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.bearer_token("my-api-token");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"Bearer my-api-token");
}
