//! Integration tests for AWS Signature Version 4 authentication.
//!
//! Tests verify that the Easy API correctly signs requests with `SigV4`
//! and that the server receives the expected Authorization, x-amz-date,
//! and x-amz-content-sha256 headers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};

#[tokio::test]
async fn sigv4_sends_authorization_header() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let has_auth = req.headers().contains_key("authorization");
        let body = if has_auth { "signed" } else { "unsigned" };
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.aws_sigv4("aws:us-east-1:s3");
    easy.aws_credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"signed");
}

#[tokio::test]
async fn sigv4_authorization_format() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/bucket/key")).unwrap();
    easy.aws_sigv4("aws:us-west-2:s3");
    easy.aws_credentials("AKID", "SECRET");

    let response = easy.perform_async().await.unwrap();
    let auth = response.body_str().unwrap();

    // AWS SigV4 Authorization header must follow this format
    assert!(auth.starts_with("AWS-HMAC-SHA256"), "got: {auth}");
    assert!(auth.contains("Credential=AKID/"), "got: {auth}");
    assert!(auth.contains("/us-west-2/s3/aws_request"), "got: {auth}");
    assert!(auth.contains("SignedHeaders="), "got: {auth}");
    assert!(auth.contains("Signature="), "got: {auth}");
}

#[tokio::test]
async fn sigv4_sends_amz_date_header() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let date = req
            .headers()
            .get("x-amz-date")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(date)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.aws_sigv4("aws:eu-west-1:execute-api");
    easy.aws_credentials("AKID", "SECRET");

    let response = easy.perform_async().await.unwrap();
    let date = response.body_str().unwrap();

    // x-amz-date must be in ISO 8601 basic format: YYYYMMDDTHHMMSSZ
    assert_eq!(date.len(), 16, "got: {date}");
    assert!(date.ends_with('Z'), "got: {date}");
    assert!(date.contains('T'), "got: {date}");
}

#[tokio::test]
async fn sigv4_sends_content_hash_header() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let hash = req
            .headers()
            .get("x-amz-content-sha256")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        Response::new(Full::new(Bytes::from(hash)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.aws_sigv4("aws:us-east-1:s3");
    easy.aws_credentials("AKID", "SECRET");

    let response = easy.perform_async().await.unwrap();
    let hash = response.body_str().unwrap();

    // SHA-256 of empty body should be the well-known empty hash
    assert_eq!(
        hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "empty body sha256 mismatch"
    );
}

#[tokio::test]
async fn sigv4_with_post_body() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let auth = req.headers().contains_key("authorization");
        let hash = req.headers().contains_key("x-amz-content-sha256");

        let body = format!("auth={auth}, hash={hash}");
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/api")).unwrap();
    easy.method("POST");
    easy.body(b"payload=test");
    easy.aws_sigv4("aws:us-east-1:execute-api");
    easy.aws_credentials("AKID", "SECRET");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.body_str().unwrap(), "auth=true, hash=true");
}

#[tokio::test]
async fn sigv4_without_credentials_sends_no_auth() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        let has_auth = req.headers().contains_key("authorization");
        let body = if has_auth { "signed" } else { "unsigned" };
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.aws_sigv4("aws:us-east-1:s3");
    // No credentials set

    let response = easy.perform_async().await.unwrap();
    // Without credentials, SigV4 signing should be skipped
    assert_eq!(response.body(), b"unsigned");
}
