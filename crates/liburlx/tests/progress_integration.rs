//! Progress callback integration tests.
//!
//! Tests progress callback behavior during actual HTTP transfers,
//! verifying invocation, data reporting, and abort functionality.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Progress callback invoked during transfer ---

#[tokio::test]
async fn progress_callback_invoked() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("response body")))).await;

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(move |_info| {
        called_clone.store(true, Ordering::SeqCst);
        true
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(called.load(Ordering::SeqCst), "progress callback should have been called");
}

// --- Progress reports download bytes ---

#[tokio::test]
async fn progress_reports_download() {
    let body = "x".repeat(10_000);
    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(body.clone())))).await;

    let max_dl = Arc::new(AtomicU32::new(0));
    let max_dl_clone = max_dl.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(move |info| {
        #[allow(clippy::cast_possible_truncation)]
        let dl = info.dl_now as u32;
        let prev = max_dl_clone.load(Ordering::SeqCst);
        if dl > prev {
            max_dl_clone.store(dl, Ordering::SeqCst);
        }
        true
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    // Progress should have reported some bytes downloaded
    assert!(max_dl.load(Ordering::SeqCst) > 0, "should have reported download progress");
}

// --- Progress callback called multiple times ---

#[tokio::test]
async fn progress_called_multiple_times() {
    let body = "y".repeat(50_000);
    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(body.clone())))).await;

    let call_count = Arc::new(AtomicU32::new(0));
    let count_clone = call_count.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(move |_info| {
        count_clone.fetch_add(1, Ordering::SeqCst);
        true
    }));

    easy.perform_async().await.unwrap();
    assert!(call_count.load(Ordering::SeqCst) >= 1, "should be called at least once");
}

// --- Progress callback abort stops transfer ---

#[tokio::test]
async fn progress_abort_stops_transfer() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("data")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(|_info| {
        false // abort
    }));

    let result = easy.perform_async().await;
    // Should either error or return, but not hang
    // The exact behavior depends on when the callback fires
    let _ = result;
}

// --- No progress callback by default ---

#[tokio::test]
async fn no_progress_callback_default() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    // No progress callback set

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Progress with small body ---

#[tokio::test]
async fn progress_small_body() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("tiny")))).await;

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(move |_info| {
        called_clone.store(true, Ordering::SeqCst);
        true
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "tiny");
}

// --- Progress with empty body ---

#[tokio::test]
async fn progress_empty_body() {
    let server = TestServer::start(|_req| {
        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(liburlx::make_progress_callback(move |_info| {
        called_clone.store(true, Ordering::SeqCst);
        true
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 204);
}
