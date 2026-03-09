//! Cookie wire flow integration tests.
//!
//! Tests cookie behavior through actual HTTP transfers, verifying
//! Set-Cookie storage, Cookie header sending, domain scoping,
//! and multi-cookie accumulation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::{Arc, Mutex};

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Cookie set and sent back ---

#[tokio::test]
async fn set_cookie_returned_on_next_request() {
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            received_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        if req.uri().path() == "/set" {
            Response::builder()
                .header("Set-Cookie", "token=xyz")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("get")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // Set cookie
    easy.url(&server.url("/set")).unwrap();
    easy.perform_async().await.unwrap();

    // Verify cookie sent back
    easy.url(&server.url("/check")).unwrap();
    easy.perform_async().await.unwrap();

    let cookies = received.lock().unwrap();
    assert!(!cookies.is_empty(), "should have sent cookie back");
    assert!(cookies.last().unwrap().contains("token=xyz"));
}

// --- Multiple Set-Cookie headers accumulated ---

#[tokio::test]
async fn multiple_set_cookies_accumulated() {
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            received_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        if req.uri().path() == "/set" {
            Response::builder()
                .header("Set-Cookie", "a=1")
                .header("Set-Cookie", "b=2")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("get")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set")).unwrap();
    easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    easy.perform_async().await.unwrap();

    let cookies = received.lock().unwrap();
    assert!(!cookies.is_empty());
    let last = cookies.last().unwrap();
    assert!(last.contains("a=1"), "should contain a=1: {last}");
    assert!(last.contains("b=2"), "should contain b=2: {last}");
}

// --- Cookie not sent when jar disabled ---

#[tokio::test]
async fn no_cookies_without_jar() {
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            received_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        if req.uri().path() == "/set" {
            Response::builder()
                .header("Set-Cookie", "secret=value")
                .body(Full::new(Bytes::from("set")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("get")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    // cookie_jar is disabled by default

    easy.url(&server.url("/set")).unwrap();
    easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    easy.perform_async().await.unwrap();

    let cookies = received.lock().unwrap();
    assert!(cookies.is_empty(), "should not send cookies without jar");
}

// --- Cookie replacement ---

#[tokio::test]
async fn cookie_replaced_on_second_set() {
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_clone = received.clone();

    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            received_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        let n = counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            Response::builder()
                .header("Set-Cookie", "key=old")
                .body(Full::new(Bytes::from("first")))
                .unwrap()
        } else if n == 1 {
            Response::builder()
                .header("Set-Cookie", "key=new")
                .body(Full::new(Bytes::from("second")))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("third")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // Set initial cookie
    easy.url(&server.url("/")).unwrap();
    easy.perform_async().await.unwrap();

    // Replace cookie
    easy.perform_async().await.unwrap();

    // Check final cookie value
    easy.perform_async().await.unwrap();

    let cookies = received.lock().unwrap();
    let last = cookies.last().unwrap();
    assert!(last.contains("key=new"), "should have replaced value: {last}");
    assert!(!last.contains("key=old"), "old value should be gone: {last}");
}

// --- Cookie accumulation across multiple requests ---

#[tokio::test]
async fn cookies_accumulate_across_requests() {
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_clone = received.clone();

    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |req| {
        if let Some(cookie) = req.headers().get("cookie") {
            received_clone.lock().unwrap().push(cookie.to_str().unwrap_or("").to_string());
        }

        let n = counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match n {
            0 => Response::builder()
                .header("Set-Cookie", "first=1")
                .body(Full::new(Bytes::from("1")))
                .unwrap(),
            1 => Response::builder()
                .header("Set-Cookie", "second=2")
                .body(Full::new(Bytes::from("2")))
                .unwrap(),
            _ => Response::new(Full::new(Bytes::from("3"))),
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.url(&server.url("/")).unwrap();

    // Three requests, each setting a new cookie
    easy.perform_async().await.unwrap();
    easy.perform_async().await.unwrap();
    easy.perform_async().await.unwrap();

    let cookies = received.lock().unwrap();
    let last = cookies.last().unwrap();
    assert!(last.contains("first=1"), "should have first: {last}");
    assert!(last.contains("second=2"), "should have second: {last}");
}
