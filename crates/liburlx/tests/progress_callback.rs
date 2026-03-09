//! Progress callback tests.
//!
//! Tests that progress callbacks are called during transfers and
//! receive accurate download size information.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;
use liburlx::progress::{make_progress_callback, ProgressInfo};

// --- Progress callback is called ---

#[tokio::test]
async fn progress_callback_called_during_transfer() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("hello world")))).await;

    let call_count = Arc::new(AtomicU32::new(0));
    let count_clone = call_count.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(make_progress_callback(move |_info: &ProgressInfo| {
        count_clone.fetch_add(1, Ordering::SeqCst);
        true // continue
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(call_count.load(Ordering::SeqCst) > 0, "progress callback should have been called");
}

// --- Progress info has download data ---

#[tokio::test]
async fn progress_info_has_download_data() {
    let body_size = 1000;
    let server =
        TestServer::start(move |_req| Response::new(Full::new(Bytes::from(vec![b'x'; body_size]))))
            .await;

    let last_info =
        Arc::new(Mutex::new(ProgressInfo { dl_total: 0, dl_now: 0, ul_total: 0, ul_now: 0 }));
    let info_clone = last_info.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(make_progress_callback(move |info: &ProgressInfo| {
        let mut last = info_clone.lock().unwrap();
        *last = ProgressInfo {
            dl_total: info.dl_total,
            dl_now: info.dl_now,
            ul_total: info.ul_total,
            ul_now: info.ul_now,
        };
        true
    }));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.size_download(), body_size);

    let final_info = last_info.lock().unwrap();
    // dl_now should reflect some downloaded data
    assert!(final_info.dl_now > 0, "dl_now should be > 0, got {}", final_info.dl_now);
}

// --- Progress callback returning false ---
// Note: abort behavior depends on implementation; testing that it doesn't crash

#[tokio::test]
async fn progress_callback_can_return_true_for_all() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("data")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(make_progress_callback(|_: &ProgressInfo| true));

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- ProgressInfo struct ---

#[test]
fn progress_info_fields_accessible() {
    let info = ProgressInfo { dl_total: 1000, dl_now: 500, ul_total: 200, ul_now: 100 };
    assert_eq!(info.dl_total, 1000);
    assert_eq!(info.dl_now, 500);
    assert_eq!(info.ul_total, 200);
    assert_eq!(info.ul_now, 100);
}

// --- make_progress_callback ---

#[test]
fn make_progress_callback_creates_callable() {
    let cb = make_progress_callback(|_: &ProgressInfo| true);
    let info = ProgressInfo { dl_total: 0, dl_now: 0, ul_total: 0, ul_now: 0 };
    let result = liburlx::progress::call_progress(&cb, &info);
    assert!(result, "callback should return true");
}

#[test]
fn callback_returning_false_propagates() {
    let cb = make_progress_callback(|_: &ProgressInfo| false);
    let info = ProgressInfo { dl_total: 0, dl_now: 0, ul_total: 0, ul_now: 0 };
    let result = liburlx::progress::call_progress(&cb, &info);
    assert!(!result, "callback should return false");
}

// --- Progress with multiple transfers ---

#[tokio::test]
async fn progress_callback_works_across_transfers() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("data")))).await;

    let total_calls = Arc::new(AtomicU32::new(0));
    let calls_clone = total_calls.clone();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.progress_callback(make_progress_callback(move |_: &ProgressInfo| {
        calls_clone.fetch_add(1, Ordering::SeqCst);
        true
    }));

    // Multiple transfers
    let _resp1 = easy.perform_async().await.unwrap();
    let calls_after_first = total_calls.load(Ordering::SeqCst);

    let _resp2 = easy.perform_async().await.unwrap();
    let calls_after_second = total_calls.load(Ordering::SeqCst);

    assert!(calls_after_first > 0);
    assert!(calls_after_second > calls_after_first);
}
