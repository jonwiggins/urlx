//! HTTP header wire format tests.
//!
//! Tests that custom headers, User-Agent, Content-Type, and other
//! headers are sent correctly over the wire to the server.

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

// --- Custom header sent to server ---

#[tokio::test]
async fn custom_header_received_by_server() {
    let received = Arc::new(Mutex::new(String::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        let val =
            req.headers().get("x-custom").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        *received_clone.lock().unwrap() = val;
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-Custom", "test-value");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(*received.lock().unwrap(), "test-value");
}

// --- Multiple custom headers ---

#[tokio::test]
async fn multiple_custom_headers() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        let mut headers = Vec::new();
        for key in ["x-first", "x-second", "x-third"] {
            if let Some(val) = req.headers().get(key).and_then(|v| v.to_str().ok()) {
                headers.push(format!("{key}: {val}"));
            }
        }
        *received_clone.lock().unwrap() = headers;
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-First", "one");
    easy.header("X-Second", "two");
    easy.header("X-Third", "three");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let hdrs = received.lock().unwrap();
    assert_eq!(hdrs.len(), 3);
    assert!(hdrs.contains(&"x-first: one".to_string()));
    assert!(hdrs.contains(&"x-second: two".to_string()));
    assert!(hdrs.contains(&"x-third: three".to_string()));
}

// --- User-Agent default ---

#[tokio::test]
async fn default_user_agent_sent() {
    let server = TestServer::start(|req| {
        let ua =
            req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Response::new(Full::new(Bytes::from(ua)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let ua = resp.body_str().unwrap();
    assert!(ua.contains("urlx"), "default UA should contain urlx: {ua}");
}

// --- User-Agent override ---

#[tokio::test]
async fn user_agent_override() {
    let server = TestServer::start(|req| {
        let ua =
            req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Response::new(Full::new(Bytes::from(ua)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("User-Agent", "CustomAgent/2.0");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "CustomAgent/2.0");
}

// --- Content-Type with POST body ---

#[tokio::test]
async fn content_type_sent_with_body() {
    let received_ct = Arc::new(Mutex::new(String::new()));
    let ct_clone = received_ct.clone();

    let server = TestServer::start(move |req| {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        *ct_clone.lock().unwrap() = ct;
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.header("Content-Type", "application/json");
    easy.body(b"{\"key\": \"value\"}");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(*received_ct.lock().unwrap(), "application/json");
}

// --- Authorization header ---

#[tokio::test]
async fn basic_auth_header_sent() {
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
    easy.basic_auth("user", "pass");

    let resp = easy.perform_async().await.unwrap();
    let auth = resp.body_str().unwrap();
    assert!(auth.starts_with("Basic "), "auth: {auth}");
}

// --- Bearer token header ---

#[tokio::test]
async fn bearer_token_header_sent() {
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
    easy.bearer_token("my-token-xyz");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "Bearer my-token-xyz");
}

// --- Host header ---

#[tokio::test]
async fn host_header_sent() {
    let server = TestServer::start(|req| {
        let host =
            req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Response::new(Full::new(Bytes::from(host)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let host = resp.body_str().unwrap();
    assert!(host.contains("127.0.0.1"), "Host should contain IP: {host}");
}

// --- Accept header default ---

#[tokio::test]
async fn accept_header_default() {
    let server = TestServer::start(|req| {
        let accept =
            req.headers().get("accept").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Response::new(Full::new(Bytes::from(accept)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let accept = resp.body_str().unwrap();
    assert_eq!(accept, "*/*");
}

// --- Header with colon in value ---

#[tokio::test]
async fn header_value_with_colon() {
    let received = Arc::new(Mutex::new(String::new()));
    let received_clone = received.clone();

    let server = TestServer::start(move |req| {
        let val =
            req.headers().get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        *received_clone.lock().unwrap() = val;
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-Time", "12:30:00");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(*received.lock().unwrap(), "12:30:00");
}

// --- Content-Length header with body ---

#[tokio::test]
async fn content_length_sent_with_body() {
    let received_cl = Arc::new(Mutex::new(String::new()));
    let cl_clone = received_cl.clone();

    let server = TestServer::start(move |req| {
        let cl = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        *cl_clone.lock().unwrap() = cl;
        Response::new(Full::new(Bytes::from("ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"12345");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(*received_cl.lock().unwrap(), "5");
}
