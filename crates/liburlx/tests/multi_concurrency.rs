//! Multi API concurrency stress tests.
//!
//! Tests Multi handle under concurrent load with many simultaneous
//! transfers, mixed results, and different servers.

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

// --- 20 concurrent requests ---

#[tokio::test]
async fn twenty_concurrent_requests() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    for i in 0..20 {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/req-{i}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 20);

    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), format!("/req-{i}"));
    }
}

// --- Results returned in order ---

#[tokio::test]
async fn results_in_insertion_order() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let paths: Vec<String> = (0..10).map(|i| format!("/order-{i}")).collect();
    for path in &paths {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(path)).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.body_str().unwrap(), paths[i]);
    }
}

// --- Mixed success and failure ---

#[tokio::test]
async fn mixed_success_and_failure() {
    let server = TestServer::start(|req| {
        let status: u16 = req.uri().path().trim_start_matches('/').parse().unwrap_or(200);
        Response::builder().status(status).body(Full::new(Bytes::from(status.to_string()))).unwrap()
    })
    .await;

    let mut multi = liburlx::Multi::new();

    for code in [200, 404, 500, 201, 302] {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{code}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    assert_eq!(results.len(), 5);
    assert_eq!(results[0].as_ref().unwrap().status(), 200);
    assert_eq!(results[1].as_ref().unwrap().status(), 404);
    assert_eq!(results[2].as_ref().unwrap().status(), 500);
    assert_eq!(results[3].as_ref().unwrap().status(), 201);
    assert_eq!(results[4].as_ref().unwrap().status(), 302);
}

// --- Different body sizes ---

#[tokio::test]
async fn concurrent_different_body_sizes() {
    let server = TestServer::start(|req| {
        let size: usize = req.uri().path().trim_start_matches('/').parse().unwrap_or(0);
        let body = "x".repeat(size);
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut multi = liburlx::Multi::new();
    let sizes = [0, 1, 100, 1000, 10_000];

    for size in sizes {
        let mut easy = liburlx::Easy::new();
        easy.url(&server.url(&format!("/{size}"))).unwrap();
        multi.add(easy);
    }

    let results = multi.perform().await;
    for (i, result) in results.iter().enumerate() {
        let resp = result.as_ref().unwrap();
        assert_eq!(resp.body().len(), sizes[i], "size mismatch at index {i}");
    }
}

// --- Concurrent to different servers ---

#[tokio::test]
async fn concurrent_to_different_servers() {
    let server1 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server-a")))).await;
    let server2 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server-b")))).await;

    let mut multi = liburlx::Multi::new();

    let mut easy1 = liburlx::Easy::new();
    easy1.url(&server1.url("/")).unwrap();
    multi.add(easy1);

    let mut easy2 = liburlx::Easy::new();
    easy2.url(&server2.url("/")).unwrap();
    multi.add(easy2);

    let results = multi.perform().await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "server-a");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "server-b");
}

// --- Empty multi returns empty results ---

#[tokio::test]
async fn empty_multi_returns_empty() {
    let mut multi = liburlx::Multi::new();
    let results = multi.perform().await;
    assert!(results.is_empty());
}

// --- Single transfer through multi ---

#[tokio::test]
async fn single_transfer_through_multi() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("single")))).await;

    let mut multi = liburlx::Multi::new();
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    multi.add(easy);

    let results = multi.perform().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "single");
}

// --- Multi with POST and GET mixed ---

#[tokio::test]
async fn multi_mixed_methods() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut multi = liburlx::Multi::new();

    let mut get_handle = liburlx::Easy::new();
    get_handle.url(&server.url("/")).unwrap();
    multi.add(get_handle);

    let mut post_handle = liburlx::Easy::new();
    post_handle.url(&server.url("/")).unwrap();
    post_handle.method("POST");
    post_handle.body(b"data");
    multi.add(post_handle);

    let mut head_handle = liburlx::Easy::new();
    head_handle.url(&server.url("/")).unwrap();
    head_handle.method("HEAD");
    multi.add(head_handle);

    let results = multi.perform().await;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap().body_str().unwrap(), "GET");
    assert_eq!(results[1].as_ref().unwrap().body_str().unwrap(), "POST");
    // HEAD returns empty body
    assert_eq!(results[2].as_ref().unwrap().status(), 200);
}

// --- Multi len and is_empty ---

#[test]
fn multi_len_tracking() {
    let mut multi = liburlx::Multi::new();
    assert!(multi.is_empty());
    assert_eq!(multi.len(), 0);

    let easy1 = liburlx::Easy::new();
    multi.add(easy1);
    assert!(!multi.is_empty());
    assert_eq!(multi.len(), 1);

    let easy2 = liburlx::Easy::new();
    multi.add(easy2);
    assert_eq!(multi.len(), 2);
}
