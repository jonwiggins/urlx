//! Integration tests for HTTP Digest authentication (RFC 7616).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::items_after_statements)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};

/// Verify a Digest auth response against expected credentials.
fn verify_digest_response(
    digest_params: &str,
    expected_user: &str,
    expected_pass: &str,
    realm: &str,
    nonce: &str,
    method: &str,
) -> bool {
    use md5::Digest as _;

    let parts: Vec<&str> = digest_params.split(',').map(str::trim).collect();
    let mut got_response = String::new();
    let mut got_uri = String::new();
    let mut got_nc = String::new();
    let mut got_cnonce = String::new();

    for part in &parts {
        if let Some(val) = part.strip_prefix("response=") {
            got_response = val.trim_matches('"').to_string();
        } else if let Some(val) = part.strip_prefix("uri=") {
            got_uri = val.trim_matches('"').to_string();
        } else if let Some(val) = part.strip_prefix("nc=") {
            got_nc = val.to_string();
        } else if let Some(val) = part.strip_prefix("cnonce=") {
            got_cnonce = val.trim_matches('"').to_string();
        }
    }

    let ha1 = hex::encode(md5::Md5::digest(
        format!("{expected_user}:{realm}:{expected_pass}").as_bytes(),
    ));
    let ha2 = hex::encode(md5::Md5::digest(format!("{method}:{got_uri}").as_bytes()));
    let expected_response = hex::encode(md5::Md5::digest(
        format!("{ha1}:{nonce}:{got_nc}:{got_cnonce}:auth:{ha2}").as_bytes(),
    ));

    got_response == expected_response
}

/// Create a Digest auth test server that issues 401 challenges.
///
/// First request gets 401 with WWW-Authenticate: Digest challenge.
/// Second request with correct Authorization header gets 200.
async fn start_digest_server(
    realm: &str,
    nonce: &str,
    username: &str,
    password: &str,
    algorithm: &str,
) -> TestServer {
    let realm = realm.to_string();
    let nonce = nonce.to_string();
    let expected_user = username.to_string();
    let expected_pass = password.to_string();
    let algo = algorithm.to_string();

    TestServer::start(move |req: Request<hyper::body::Incoming>| {
        // Check if the request has valid Digest auth credentials
        if let Some(auth_header) = req.headers().get("authorization") {
            let auth_str = auth_header.to_str().unwrap_or("");
            if let Some(digest_params) = auth_str.strip_prefix("Digest ") {
                if auth_str.contains(&format!("username=\"{expected_user}\""))
                    && verify_digest_response(
                        digest_params,
                        &expected_user,
                        &expected_pass,
                        &realm,
                        &nonce,
                        req.method().as_str(),
                    )
                {
                    return Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from("authenticated")))
                        .unwrap();
                }
            }
        }

        // Either no auth or invalid auth — issue challenge
        Response::builder()
            .status(401)
            .header(
                "WWW-Authenticate",
                format!(
                    "Digest realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\", algorithm={algo}"
                ),
            )
            .body(Full::new(Bytes::from("Unauthorized")))
            .unwrap()
    })
    .await
}

// =============================================================================
// Basic Digest auth flow tests
// =============================================================================

#[tokio::test]
async fn digest_auth_md5_succeeds() {
    let server =
        start_digest_server("test@example.com", "testnonce123", "admin", "secret", "MD5").await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/protected")).unwrap();
    easy.digest_auth("admin", "secret");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"authenticated");
}

#[tokio::test]
async fn digest_auth_wrong_password_fails() {
    let server =
        start_digest_server("test@example.com", "testnonce123", "admin", "secret", "MD5").await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/protected")).unwrap();
    easy.digest_auth("admin", "wrongpassword");

    let response = easy.perform_async().await.unwrap();
    // Should get 401 back since the response hash won't match
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn digest_auth_without_credentials_gets_401() {
    let server =
        start_digest_server("test@example.com", "testnonce123", "admin", "secret", "MD5").await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/protected")).unwrap();
    // No auth configured

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn digest_auth_sends_two_requests() {
    let request_count = Arc::new(AtomicU32::new(0));
    let counter = request_count.clone();

    let server = TestServer::start(move |_req: Request<hyper::body::Incoming>| {
        let count = counter.fetch_add(1, Ordering::Relaxed);
        if count == 0 {
            // First request: issue challenge
            Response::builder()
                .status(401)
                .header(
                    "WWW-Authenticate",
                    "Digest realm=\"test\", nonce=\"nonce1\", qop=\"auth\", algorithm=MD5",
                )
                .body(Full::new(Bytes::from("challenge")))
                .unwrap()
        } else {
            // Second request: accept
            Response::builder().status(200).body(Full::new(Bytes::from("ok"))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.digest_auth("user", "pass");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(request_count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn basic_auth_still_works() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        if let Some(auth) = req.headers().get("authorization") {
            let auth_str = auth.to_str().unwrap_or("");
            if auth_str == "Basic YWRtaW46c2VjcmV0" {
                return Response::builder()
                    .status(200)
                    .body(Full::new(Bytes::from("basic ok")))
                    .unwrap();
            }
        }
        Response::builder().status(401).body(Full::new(Bytes::from("Unauthorized"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.basic_auth("admin", "secret");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"basic ok");
}

#[tokio::test]
async fn digest_auth_with_opaque() {
    let server = TestServer::start(|req: Request<hyper::body::Incoming>| {
        if let Some(auth) = req.headers().get("authorization") {
            let auth_str = auth.to_str().unwrap_or("");
            if auth_str.contains("opaque=\"serveropaque\"") {
                return Response::builder()
                    .status(200)
                    .body(Full::new(Bytes::from("ok with opaque")))
                    .unwrap();
            }
        }
        Response::builder()
            .status(401)
            .header(
                "WWW-Authenticate",
                "Digest realm=\"test\", nonce=\"n1\", qop=\"auth\", opaque=\"serveropaque\"",
            )
            .body(Full::new(Bytes::from("challenge")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/test")).unwrap();
    easy.digest_auth("user", "pass");

    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok with opaque");
}
