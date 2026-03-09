//! Multi blocking API tests.
//!
//! Tests `Multi::perform_blocking()` which creates its own tokio runtime
//! internally, verifying basic transfers, multiple URLs, and error handling.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Basic blocking transfer ---

#[tokio::test]
async fn blocking_single_transfer() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("blocking-ok")))).await;

    // Run blocking in a spawn_blocking to avoid blocking the async runtime
    let url = server.url("/");
    let result = tokio::task::spawn_blocking(move || {
        let mut multi = liburlx::Multi::new();
        let mut easy = liburlx::Easy::new();
        easy.url(&url).unwrap();
        multi.add(easy);
        multi.perform_blocking().unwrap()
    })
    .await
    .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_ref().unwrap().body_str().unwrap(), "blocking-ok");
}

// --- Multiple blocking transfers ---

#[tokio::test]
async fn blocking_multiple_transfers() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let url = server.url("/");
    let result = tokio::task::spawn_blocking(move || {
        let mut multi = liburlx::Multi::new();
        for i in 0..5 {
            let mut easy = liburlx::Easy::new();
            easy.url(&format!("{url}item-{i}")).unwrap();
            multi.add(easy);
        }
        multi.perform_blocking().unwrap()
    })
    .await
    .unwrap();

    assert_eq!(result.len(), 5);
    for (i, r) in result.iter().enumerate() {
        assert_eq!(r.as_ref().unwrap().body_str().unwrap(), format!("/item-{i}"));
    }
}

// --- Blocking empty multi ---

#[test]
fn blocking_empty_multi() {
    let mut multi = liburlx::Multi::new();
    let results = multi.perform_blocking().unwrap();
    assert!(results.is_empty());
}

// --- Blocking with connection errors ---

#[test]
fn blocking_with_connection_error() {
    let mut multi = liburlx::Multi::new();
    let mut easy = liburlx::Easy::new();
    // Connect to a port that nothing is listening on
    easy.url("http://127.0.0.1:1/").unwrap();
    multi.add(easy);

    let results = multi.perform_blocking().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_err(), "should error on connection refused");
}

// --- Blocking drains handles ---

#[test]
fn blocking_drains_handles() {
    let mut multi = liburlx::Multi::new();
    let easy = liburlx::Easy::new();
    multi.add(easy);
    assert_eq!(multi.len(), 1);

    let _ = multi.perform_blocking();
    assert!(multi.is_empty(), "handles should be drained after perform_blocking");
}

// --- Blocking with mixed methods ---

#[tokio::test]
async fn blocking_mixed_methods() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let url = server.url("/");
    let result = tokio::task::spawn_blocking(move || {
        let mut multi = liburlx::Multi::new();

        let mut get = liburlx::Easy::new();
        get.url(&url).unwrap();
        multi.add(get);

        let mut post = liburlx::Easy::new();
        post.url(&url).unwrap();
        post.method("POST");
        post.body(b"data");
        multi.add(post);

        multi.perform_blocking().unwrap()
    })
    .await
    .unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].as_ref().unwrap().body_str().unwrap(), "GET");
    assert_eq!(result[1].as_ref().unwrap().body_str().unwrap(), "POST");
}

// --- Multi Debug format ---

#[test]
fn multi_debug_format() {
    let mut multi = liburlx::Multi::new();
    let debug = format!("{multi:?}");
    assert!(debug.contains("Multi"));

    let easy = liburlx::Easy::new();
    multi.add(easy);
    let debug = format!("{multi:?}");
    assert!(debug.contains("Multi"));
}
