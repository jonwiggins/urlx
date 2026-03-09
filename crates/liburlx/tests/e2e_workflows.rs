//! End-to-end workflow tests.
//!
//! Tests multi-step scenarios: redirect chains with cookies,
//! auth challenges, conditional requests, connection reuse,
//! and error recovery.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use common::TestServer;

// --- Redirect chain with cookie propagation ---

#[tokio::test]
async fn redirect_sets_cookie_then_sends_on_follow() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        match path.as_str() {
            "/login" => Response::builder()
                .status(302)
                .header("Location", "/dashboard")
                .header("Set-Cookie", "session=abc123; Path=/")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            "/dashboard" => {
                let has_cookie = req
                    .headers()
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|c| c.contains("session=abc123"));
                let body = if has_cookie { "welcome" } else { "no cookie" };
                Response::new(Full::new(Bytes::from(body)))
            }
            _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/login")).unwrap();
    easy.follow_redirects(true);
    easy.cookie_jar(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "welcome");
    assert_eq!(resp.effective_url(), server.url("/dashboard"));
}

// --- Multi-hop redirect chain ---

#[tokio::test]
async fn three_hop_redirect_chain() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(301)
            .header("Location", "/b")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::builder()
            .status(302)
            .header("Location", "/c")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/c" => Response::new(Full::new(Bytes::from("final destination"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "final destination");
    assert_eq!(resp.effective_url(), server.url("/c"));
}

// --- Auth challenge flow ---

#[tokio::test]
async fn basic_auth_sent_on_first_request() {
    let server = TestServer::start(|req| {
        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        if auth.starts_with("Basic ") {
            Response::new(Full::new(Bytes::from("authenticated")))
        } else {
            Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Basic realm=\"test\"")
                .body(Full::new(Bytes::from("unauthorized")))
                .unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/secret")).unwrap();
    easy.basic_auth("user", "pass");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "authenticated");
}

// --- Sequential requests reuse connection ---

#[tokio::test]
async fn sequential_requests_track_independently() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from(format!("request-{n}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "request-0");

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "request-1");

    let resp3 = easy.perform_async().await.unwrap();
    assert_eq!(resp3.body_str().unwrap(), "request-2");

    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

// --- POST with redirect changes to GET (303) ---

#[tokio::test]
async fn post_303_redirect_becomes_get() {
    let methods = Arc::new(Mutex::new(Vec::new()));
    let methods_clone = methods.clone();

    let server = TestServer::start(move |req| {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        methods_clone.lock().unwrap().push(format!("{method} {path}"));

        match path.as_str() {
            "/submit" => Response::builder()
                .status(303)
                .header("Location", "/result")
                .header("Content-Length", "0")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            "/result" => Response::new(Full::new(Bytes::from("done"))),
            _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("POST");
    easy.body(b"data=value");
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "done");

    let recorded = methods.lock().unwrap();
    assert_eq!(recorded[0], "POST /submit");
    assert_eq!(recorded[1], "GET /result");
}

// --- POST with 307 preserves method ---

#[tokio::test]
async fn post_307_redirect_preserves_method() {
    let methods = Arc::new(Mutex::new(Vec::new()));
    let methods_clone = methods.clone();

    let server = TestServer::start(move |req| {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        methods_clone.lock().unwrap().push(format!("{method} {path}"));

        match path.as_str() {
            "/api/v1" => Response::builder()
                .status(307)
                .header("Location", "/api/v2")
                .header("Content-Length", "0")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            "/api/v2" => Response::new(Full::new(Bytes::from("v2 response"))),
            _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api/v1")).unwrap();
    easy.method("POST");
    easy.body(b"payload");
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let recorded = methods.lock().unwrap();
    assert_eq!(recorded[0], "POST /api/v1");
    assert_eq!(recorded[1], "POST /api/v2");
}

// --- Multiple cookies accumulated across requests ---

#[tokio::test]
async fn cookies_accumulate_across_requests() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        match path.as_str() {
            "/set-a" => Response::builder()
                .status(200)
                .header("Set-Cookie", "a=1; Path=/")
                .body(Full::new(Bytes::from("set a")))
                .unwrap(),
            "/set-b" => Response::builder()
                .status(200)
                .header("Set-Cookie", "b=2; Path=/")
                .body(Full::new(Bytes::from("set b")))
                .unwrap(),
            "/check" => {
                let cookies = req
                    .headers()
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                Response::new(Full::new(Bytes::from(cookies)))
            }
            _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set-a")).unwrap();
    easy.perform_async().await.unwrap();

    easy.url(&server.url("/set-b")).unwrap();
    easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();
    assert!(body.contains("a=1"), "expected a=1 in '{body}'");
    assert!(body.contains("b=2"), "expected b=2 in '{body}'");
}

// --- Concurrent transfers with Multi ---

#[tokio::test]
async fn multi_concurrent_all_succeed() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(format!("response-for{path}"))))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    for i in 0..5 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{i}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 5);

    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), format!("response-for/{i}"));
    }
}

// --- HEAD request returns headers but no body ---

#[tokio::test]
async fn head_request_no_body() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("Content-Length", "1000")
            .header("X-Custom", "present")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
    assert_eq!(resp.header("x-custom"), Some("present"));
}

// --- Custom headers sent correctly ---

#[tokio::test]
async fn custom_headers_received_by_server() {
    let server = TestServer::start(|req| {
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none")
            .to_string();
        let accept =
            req.headers().get("accept").and_then(|v| v.to_str().ok()).unwrap_or("none").to_string();
        Response::new(Full::new(Bytes::from(format!("ua={ua};accept={accept}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("User-Agent", "urlx-test/1.0");
    easy.header("Accept", "application/json");

    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();
    assert!(body.contains("ua=urlx-test/1.0"), "got: {body}");
    assert!(body.contains("accept=application/json"), "got: {body}");
}

// --- fail_on_error with redirect to error page ---

#[tokio::test]
async fn fail_on_error_after_redirect_to_404() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/missing")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    easy.fail_on_error(true);

    let result = easy.perform_async().await;
    assert!(result.is_err(), "should fail on 404 after redirect");
}

// --- Large body transfer integrity ---

#[tokio::test]
async fn large_body_integrity() {
    let size = 100_000;
    let server = TestServer::start(move |_req| {
        let body = vec![b'A'; size];
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body().len(), size);
    assert!(resp.body().iter().all(|&b| b == b'A'));
    assert_eq!(resp.size_download(), size);
}

// --- Transfer info populated ---

#[tokio::test]
async fn transfer_info_populated_after_request() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("data")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    // Transfer info should have timing data
    let debug = format!("{resp:?}");
    assert!(debug.contains("time_total"), "transfer info missing: {debug}");
}

// --- Empty response body ---

#[tokio::test]
async fn empty_response_body() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
    assert_eq!(resp.size_download(), 0);
}

// --- Multiple perform calls with different URLs ---

#[tokio::test]
async fn reuse_handle_different_urls() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
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

// --- Bearer token auth ---

#[tokio::test]
async fn bearer_token_sent_in_header() {
    let server = TestServer::start(|req| {
        let auth = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.bearer_token("my-secret-token");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "Bearer my-secret-token");
}
