//! Integration tests for TLS configuration (Phase 2).
//!
//! Tests certificate verification, insecure mode, custom CA bundles,
//! and client certificate authentication (mTLS).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{HttpsTestServer, TestCerts};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

/// Helper to create a basic HTTPS test server with self-signed certs.
async fn start_https_server(certs: &TestCerts) -> HttpsTestServer {
    HttpsTestServer::start(certs.server_config.clone(), |_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("hello from https"))).unwrap()
    })
    .await
}

/// Helper to create an mTLS HTTPS test server.
async fn start_mtls_server(certs: &TestCerts) -> HttpsTestServer {
    HttpsTestServer::start(certs.mtls_server_config.clone(), |_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("hello from mtls"))).unwrap()
    })
    .await
}

// =============================================================================
// Certificate verification tests
// =============================================================================

#[tokio::test]
async fn https_self_signed_fails_by_default() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();

    // Should fail because self-signed cert is not trusted
    let result = easy.perform_async().await;
    assert!(result.is_err(), "self-signed cert should fail verification");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("TLS") || err.contains("tls") || err.contains("certificate"),
        "error should mention TLS: {err}"
    );
}

#[tokio::test]
async fn https_insecure_mode_accepts_self_signed() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_verify_peer(false);

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello from https");
}

#[tokio::test]
async fn https_verify_peer_false_only() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_verify_peer(false);
    // verify_host still true, but with peer verification disabled
    // the connection should still succeed (curl behavior)

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
}

// =============================================================================
// Custom CA bundle tests
// =============================================================================

#[tokio::test]
async fn https_custom_ca_cert_trusts_self_signed() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    let ca_file = certs.write_ca_cert();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_ca_cert(ca_file.path());
    // Need to resolve 127.0.0.1 as localhost for cert matching
    easy.resolve("127.0.0.1", "127.0.0.1");

    // This should work because we trust the CA that signed the server cert.
    // The cert has SAN for 127.0.0.1, so hostname verification should pass.
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello from https");
}

#[tokio::test]
async fn https_wrong_ca_cert_fails() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    // Generate a different CA (won't match server's cert)
    let wrong_certs = TestCerts::generate();
    let wrong_ca_file = wrong_certs.write_ca_cert();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_ca_cert(wrong_ca_file.path());

    // Should fail because the CA doesn't match
    let result = easy.perform_async().await;
    assert!(result.is_err(), "wrong CA should fail verification");
}

#[tokio::test]
async fn https_nonexistent_ca_cert_file_fails() {
    let mut easy = liburlx::Easy::new();
    easy.url("https://127.0.0.1:1/test").unwrap();
    easy.ssl_ca_cert(std::path::Path::new("/nonexistent/ca.pem"));

    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// =============================================================================
// Client certificate (mTLS) tests
// =============================================================================

#[tokio::test]
async fn mtls_with_client_cert_succeeds() {
    let certs = TestCerts::generate();
    let server = start_mtls_server(&certs).await;

    let ca_file = certs.write_ca_cert();
    let cert_file = certs.write_client_cert();
    let key_file = certs.write_client_key();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_ca_cert(ca_file.path());
    easy.ssl_client_cert(cert_file.path());
    easy.ssl_client_key(key_file.path());

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello from mtls");
}

#[tokio::test]
async fn mtls_without_client_cert_fails() {
    let certs = TestCerts::generate();
    let server = start_mtls_server(&certs).await;

    let ca_file = certs.write_ca_cert();

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.ssl_ca_cert(ca_file.path());

    // Should fail because server requires client cert
    let result = easy.perform_async().await;
    assert!(result.is_err(), "mTLS server should reject client without cert");
}

// =============================================================================
// TLS config defaults tests
// =============================================================================

#[tokio::test]
async fn tls_config_defaults_are_secure() {
    let config = liburlx::TlsConfig::default();
    assert!(config.verify_peer);
    assert!(config.verify_host);
    assert!(config.ca_cert.is_none());
    assert!(config.client_cert.is_none());
    assert!(config.client_key.is_none());
}

#[tokio::test]
async fn insecure_mode_multiple_requests() {
    let certs = TestCerts::generate();
    let server = start_https_server(&certs).await;

    let mut easy = liburlx::Easy::new();
    easy.ssl_verify_peer(false);

    // First request
    easy.url(&server.url("/first")).unwrap();
    let r1 = easy.perform_async().await.unwrap();
    assert_eq!(r1.status(), 200);

    // Second request (reuse handle)
    easy.url(&server.url("/second")).unwrap();
    let r2 = easy.perform_async().await.unwrap();
    assert_eq!(r2.status(), 200);
}
