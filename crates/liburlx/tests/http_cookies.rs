//! Integration tests for the cookie engine.

#![allow(clippy::unwrap_used, unused_results, clippy::significant_drop_tightening)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

#[tokio::test]
async fn cookies_stored_and_sent() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            // Set a cookie
            Response::builder()
                .status(200)
                .header("set-cookie", "sid=abc123")
                .body(Full::new(Bytes::from("cookie set")))
                .unwrap()
        } else {
            // Echo back the cookie header
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    // First request: get the cookie
    easy.url(&server.url("/set")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Second request: cookie should be sent
    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.body_str().unwrap(), "sid=abc123");
}

#[tokio::test]
async fn cookies_not_sent_without_jar() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            Response::builder()
                .status(200)
                .header("set-cookie", "sid=abc123")
                .body(Full::new(Bytes::from("cookie set")))
                .unwrap()
        } else {
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    // cookie_jar NOT enabled

    easy.url(&server.url("/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    // Without cookie jar, no cookies should be sent
    assert_eq!(resp.body_str().unwrap(), "none");
}

#[tokio::test]
async fn cookies_sent_on_redirect() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/login" {
            // Set a cookie and redirect
            Response::builder()
                .status(302)
                .header("set-cookie", "token=xyz")
                .header("location", "/dashboard")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            // Echo back the cookie header
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.follow_redirects(true);
    easy.url(&server.url("/login")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    // The cookie should have been sent to /dashboard after redirect
    assert_eq!(resp.body_str().unwrap(), "token=xyz");
}

#[tokio::test]
async fn multiple_cookies() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/set" {
            Response::builder()
                .status(200)
                .header("set-cookie", "a=1")
                .header("set-cookie", "b=2")
                .body(Full::new(Bytes::from("ok")))
                .unwrap()
        } else {
            let cookies = req
                .headers()
                .get("cookie")
                .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("").to_string());
            Response::builder().status(200).body(Full::new(Bytes::from(cookies))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);

    easy.url(&server.url("/set")).unwrap();
    let _resp = easy.perform_async().await.unwrap();

    easy.url(&server.url("/check")).unwrap();
    let resp = easy.perform_async().await.unwrap();
    let cookies = resp.body_str().unwrap();
    assert!(cookies.contains("a=1"), "cookies: {cookies}");
    assert!(cookies.contains("b=2"), "cookies: {cookies}");
}
