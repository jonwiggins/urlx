//! Multi API edge case tests.
//!
//! Tests Multi handle behavior with various configurations
//! including `fail_on_error`, timeouts, reuse, and mixed methods.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use common::TestServer;

// --- Multi with fail_on_error ---

#[tokio::test]
async fn multi_fail_on_error_mixed() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/ok" => Response::new(Full::new(Bytes::from("ok"))),
        "/err" => Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap(),
        _ => Response::new(Full::new(Bytes::from("default"))),
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut ok_handle = liburlx::Easy::new();
    ok_handle.url(&server.url("/ok")).unwrap();
    ok_handle.fail_on_error(true);
    multi.add(ok_handle);

    let mut err_handle = liburlx::Easy::new();
    err_handle.url(&server.url("/err")).unwrap();
    err_handle.fail_on_error(true);
    multi.add(err_handle);

    let results = multi.perform().await;
    assert_eq!(results.len(), 2);

    // First should succeed
    assert!(results[0].is_ok());
    assert_eq!(results[0].as_ref().unwrap().status(), 200);

    // Second should fail
    assert!(results[1].is_err());
}

// --- Multi with timeouts ---

#[tokio::test]
async fn multi_with_timeouts() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut multi = liburlx::Multi::new();

    for _ in 0..3 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url("/")).unwrap();
        easy.timeout(std::time::Duration::from_secs(10));
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(Result::is_ok));
}

// --- Multi reuse after perform ---

#[tokio::test]
async fn multi_reuse_after_perform() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut multi = liburlx::Multi::new();

    // First batch
    let mut easy1 = liburlx::Easy::new();
    easy1.url(&server.url("/a")).unwrap();
    multi.add(easy1);

    let results1 = multi.perform().await;
    assert_eq!(results1.len(), 1);
    assert!(multi.is_empty());

    // Second batch
    let mut easy2 = liburlx::Easy::new();
    easy2.url(&server.url("/b")).unwrap();
    multi.add(easy2);

    let results2 = multi.perform().await;
    assert_eq!(results2.len(), 1);
}

// --- Multi with mixed methods and bodies ---

#[tokio::test]
async fn multi_mixed_methods_and_bodies() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(format!("{method} {path}"))))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut get = liburlx::Easy::new();
    get.url(&server.url("/get")).unwrap();
    multi.add(get);

    let mut post = liburlx::Easy::new();
    post.url(&server.url("/post")).unwrap();
    post.method("POST");
    post.body(b"data");
    multi.add(post);

    let mut delete = liburlx::Easy::new();
    delete.url(&server.url("/delete")).unwrap();
    delete.method("DELETE");
    multi.add(delete);

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "GET /get");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "POST /post");
    assert_eq!(results[2].as_ref().unwrap().body_str().unwrap(), "DELETE /delete");
}

// --- Multi with headers ---

#[tokio::test]
async fn multi_with_custom_headers() {
    let server = TestServer::start(|req| {
        let auth = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none")
            .to_string();
        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut with_auth = liburlx::Easy::new();
    with_auth.url(&server.url("/")).unwrap();
    with_auth.bearer_token("token123");
    multi.add(with_auth);

    let mut without_auth = liburlx::Easy::new();
    without_auth.url(&server.url("/")).unwrap();
    multi.add(without_auth);

    let results = multi.perform().await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "Bearer token123");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "none");
}

// --- Multi with redirect following ---

#[tokio::test]
async fn multi_with_redirects() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/redirect" => Response::builder()
            .status(302)
            .header("Location", "/final")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/final" => Response::new(Full::new(Bytes::from("redirected"))),
        _ => Response::new(Full::new(Bytes::from("direct"))),
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut redirect_handle = liburlx::Easy::new();
    redirect_handle.url(&server.url("/redirect")).unwrap();
    redirect_handle.follow_redirects(true);
    multi.add(redirect_handle);

    let mut direct_handle = liburlx::Easy::new();
    direct_handle.url(&server.url("/direct")).unwrap();
    multi.add(direct_handle);

    let results = multi.perform().await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "redirected");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "direct");
}
