//! Keep-alive and connection behavior tests.
//!
//! Tests HTTP connection reuse, Connection header handling,
//! and behavior after server-side connection close.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Sequential requests reuse connection ---

#[tokio::test]
async fn sequential_requests_reuse_connection() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from(format!("req-{n}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    for i in 0..5 {
        easy.url(&server.url(&format!("/path-{i}"))).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), format!("req-{i}"));
    }

    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

// --- Different hosts use different connections ---

#[tokio::test]
async fn different_hosts_separate_connections() {
    let server1 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server1")))).await;
    let server2 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("server2")))).await;

    let mut easy = liburlx::Easy::new();

    easy.url(&server1.url("/")).unwrap();
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "server1");

    easy.url(&server2.url("/")).unwrap();
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "server2");
}

// --- Connection survives error responses ---

#[tokio::test]
async fn connection_survives_4xx() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
        } else {
            Response::new(Full::new(Bytes::from("ok")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 404);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
}

// --- Connection survives 5xx responses ---

#[tokio::test]
async fn connection_survives_5xx() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Response::builder().status(500).body(Full::new(Bytes::from("error"))).unwrap()
        } else {
            Response::new(Full::new(Bytes::from("recovered")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 500);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(resp2.body_str().unwrap(), "recovered");
}

// --- Empty body responses don't break keep-alive ---

#[tokio::test]
async fn empty_body_keepalive() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
        } else {
            Response::new(Full::new(Bytes::from("after empty")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 204);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(resp2.body_str().unwrap(), "after empty");
}

// --- HEAD request doesn't break keep-alive ---

#[tokio::test]
async fn head_request_keepalive() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        Response::new(Full::new(Bytes::from("body")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    // HEAD request
    easy.method("HEAD");
    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 200);

    // Follow up with GET
    easy.method("GET");
    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);

    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

// --- Large body doesn't break keep-alive ---

#[tokio::test]
async fn large_body_keepalive() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        let body = format!("req-{n}").repeat(10_000);
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.status(), 200);
    assert!(resp1.body().len() > 40_000);

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.status(), 200);
    assert!(resp2.body().len() > 40_000);
}

// --- Alternating hosts come back correctly ---

#[tokio::test]
async fn alternating_hosts() {
    let server1 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("host-a")))).await;
    let server2 = TestServer::start(|_req| Response::new(Full::new(Bytes::from("host-b")))).await;

    let mut easy = liburlx::Easy::new();

    for _ in 0..3 {
        easy.url(&server1.url("/")).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.body_str().unwrap(), "host-a");

        easy.url(&server2.url("/")).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.body_str().unwrap(), "host-b");
    }
}
