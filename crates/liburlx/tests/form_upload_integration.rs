//! Form upload integration tests.
//!
//! Tests multipart form-data uploads through the Easy handle
//! against a real test server, verifying correct Content-Type
//! and body encoding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use common::TestServer;

// --- Form field sent correctly ---

#[tokio::test]
async fn form_field_sent_to_server() {
    let received_body = Arc::new(Mutex::new(String::new()));
    let received_ct = Arc::new(Mutex::new(String::new()));
    let body_clone = received_body.clone();
    let ct_clone = received_ct.clone();

    let server = TestServer::start(move |req| {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        *ct_clone.lock().unwrap() = ct;
        // Echo back the method
        let method = req.method().to_string();
        *body_clone.lock().unwrap() = method.clone();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.form_field("name", "value");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    // Form field should default to POST
    assert_eq!(resp.body_str().unwrap(), "POST");

    // Content-Type should be multipart/form-data with boundary
    let ct = received_ct.lock().unwrap().clone();
    assert!(ct.starts_with("multipart/form-data"), "Content-Type was: {ct}");
    assert!(ct.contains("boundary="), "Content-Type missing boundary: {ct}");
}

// --- Multiple form fields ---

#[tokio::test]
async fn multiple_form_fields() {
    let server = TestServer::start(|req| {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::new(Full::new(Bytes::from(ct)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.form_field("field1", "value1");
    easy.form_field("field2", "value2");
    easy.form_field("field3", "value3");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.body_str().unwrap();
    assert!(ct.starts_with("multipart/form-data"), "got: {ct}");
}

// --- Form field preserves explicit method ---

#[tokio::test]
async fn form_field_with_explicit_method() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("PUT");
    easy.form_field("key", "val");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "PUT");
}

// --- Form field with empty value ---

#[tokio::test]
async fn form_field_empty_value() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.form_field("empty", "");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Form field with special characters ---

#[tokio::test]
async fn form_field_special_characters() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.form_field("data", "hello world & foo=bar");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
}

// --- Multiple form requests reuse handle ---

#[tokio::test]
async fn form_field_reuse_handle() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.form_field("key", "val");

    let resp1 = easy.perform_async().await.unwrap();
    assert_eq!(resp1.body_str().unwrap(), "POST");

    let resp2 = easy.perform_async().await.unwrap();
    assert_eq!(resp2.body_str().unwrap(), "POST");
}
