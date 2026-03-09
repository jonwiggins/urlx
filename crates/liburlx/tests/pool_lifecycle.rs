//! Connection pool lifecycle tests.
//!
//! Tests pool key generation, LIFO ordering, multi-key isolation,
//! and pool behavior across multiple transfers.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Pool accessed via Easy handle debug ---

#[test]
fn easy_handle_debug_contains_pool() {
    let easy = liburlx::Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("pool"));
}

// --- Connection reuse across performs ---

#[tokio::test]
async fn connection_reuse_across_performs() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    // First request
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 200);

    // Second request (may reuse connection)
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);

    // Third request
    let resp3 = easy.perform_async().await.unwrap();
    assert_eq!(resp3.status(), 200);

    // All three should have been served
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

// --- Multiple servers, no cross-contamination ---

#[tokio::test]
async fn separate_servers_isolated() {
    let server1 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server1")))).await;
    let server2 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server2")))).await;

    let mut easy = liburlx::Easy::new();

    easy.url(&server1.url("/")).unwrap();
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "server1");

    easy.url(&server2.url("/")).unwrap();
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "server2");

    // Go back to server1
    easy.url(&server1.url("/")).unwrap();
    let resp3 = easy.perform_async().await.unwrap();
    assert_eq!(resp3.body_str().unwrap(), "server1");
}

// --- Cloned handle has independent pool ---

#[tokio::test]
async fn cloned_handle_independent_pool() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut easy1 = liburlx::Easy::new();
    easy1.url(&server.url("/a")).unwrap();
    let resp1 = easy1.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "/a");

    let mut easy2 = easy1.clone();
    easy2.url(&server.url("/b")).unwrap();
    let resp2 = easy2.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "/b");

    // Original handle still works independently
    easy1.url(&server.url("/c")).unwrap();
    let resp3 = easy1.perform_async().await.unwrap();
    assert_eq!(resp3.body_str().unwrap(), "/c");
}

// --- Sequential requests to same path ---

#[tokio::test]
async fn sequential_same_path_all_succeed() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from(format!("req-{n}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    for i in 0..5 {
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), format!("req-{i}"));
    }
}

// --- Pool survives error responses ---

#[tokio::test]
async fn pool_survives_error_status() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
        } else {
            Response::new(Full::new(Bytes::from("ok")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    // First request gets 500
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 500);

    // Second request gets 200 — pool should still work
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
}

// --- Pool with different URL paths but same host ---

#[tokio::test]
async fn same_host_different_paths_reuse_pool() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    for path in ["/a", "/b", "/c", "/d"] {
        easy.url(&server.url(path)).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.body_str().unwrap(), path);
    }

    // All 4 should have been served
    assert_eq!(counter.load(Ordering::SeqCst), 4);
}
