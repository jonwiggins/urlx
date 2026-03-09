//! HTTP edge case tests.
//!
//! Tests for unusual server responses, malformed data, and boundary conditions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;
use tokio::net::TcpListener;

// --- Empty body responses ---

#[tokio::test]
async fn response_204_no_content() {
    let server = TestServer::start(|_req| {
        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 204);
    assert!(response.body().is_empty());
}

#[tokio::test]
async fn response_304_not_modified() {
    let server = TestServer::start(|_req| {
        Response::builder().status(304).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 304);
}

// --- Multiple headers with same name ---

#[tokio::test]
async fn multiple_response_headers() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Custom", "value1")
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-custom"), Some("value1"));
}

// --- Binary body ---

#[tokio::test]
async fn binary_response_body() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let data_clone = binary_data.clone();

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("Content-Type", "application/octet-stream")
            .body(Full::new(Bytes::from(data_clone.clone())))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), &binary_data);
}

// --- Long header values ---

#[tokio::test]
async fn long_header_value() {
    let long_value = "x".repeat(8000);
    let value_clone = long_value.clone();

    let server = TestServer::start(move |_req| {
        Response::builder()
            .header("X-Long", value_clone.as_str())
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-long").map(str::len), Some(8000));
}

// --- Many headers ---

#[tokio::test]
async fn many_response_headers() {
    let server = TestServer::start(|_req| {
        let mut builder = Response::builder();
        for i in 0..50 {
            builder = builder.header(format!("X-Header-{i}"), format!("value-{i}"));
        }
        builder.body(Full::new(Bytes::from("ok"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-header-0"), Some("value-0"));
    assert_eq!(response.header("x-header-49"), Some("value-49"));
}

// --- Status codes ---

#[tokio::test]
async fn status_201_created() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(201)
            .header("Location", "/resource/1")
            .body(Full::new(Bytes::from("created")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 201);
    assert_eq!(response.header("location"), Some("/resource/1"));
}

#[tokio::test]
async fn status_400_bad_request() {
    let server = TestServer::start(|_req| {
        Response::builder().status(400).body(Full::new(Bytes::from("bad request"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn status_401_unauthorized() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(401)
            .header("WWW-Authenticate", "Basic realm=\"test\"")
            .body(Full::new(Bytes::from("unauthorized")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 401);
    assert!(response.header("www-authenticate").is_some());
}

#[tokio::test]
async fn status_403_forbidden() {
    let server = TestServer::start(|_req| {
        Response::builder().status(403).body(Full::new(Bytes::from("forbidden"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 403);
}

// --- PATCH and OPTIONS methods ---

#[tokio::test]
async fn patch_request() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "PATCH");
        Response::new(Full::new(Bytes::from("patched")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("PATCH");
    easy.body(b"patch data");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"patched");
}

#[tokio::test]
async fn options_request() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "OPTIONS");
        Response::builder()
            .header("Allow", "GET, POST, OPTIONS")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("OPTIONS");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("allow"), Some("GET, POST, OPTIONS"));
}

// --- Multiple custom headers ---

#[tokio::test]
async fn multiple_custom_request_headers() {
    let server = TestServer::start(|req| {
        let h1 = req.headers().get("x-first").map_or("", |v| v.to_str().unwrap_or(""));
        let h2 = req.headers().get("x-second").map_or("", |v| v.to_str().unwrap_or(""));
        Response::new(Full::new(Bytes::from(format!("{h1},{h2}"))))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-First", "one");
    easy.header("X-Second", "two");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"one,two");
}

// --- Query string in URL ---

#[tokio::test]
async fn query_string_sent_correctly() {
    let server = TestServer::start(|req| {
        let query = req.uri().query().unwrap_or("none");
        Response::new(Full::new(Bytes::from(query.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/search?q=hello&lang=en")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"q=hello&lang=en");
}

// --- Connection refused to specific port ---

#[tokio::test]
async fn connection_refused_specific_port() {
    let mut easy = liburlx::Easy::new();
    // Bind to a port to know it's valid, then close, then try to connect
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Close the listener so the port is refused

    easy.url(&format!("http://{addr}/")).unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- Connect timeout on unreachable ---

#[tokio::test]
async fn connect_timeout_fires() {
    let mut easy = liburlx::Easy::new();
    // 192.0.2.1 is TEST-NET-1 (should be unreachable and timeout)
    easy.url("http://192.0.2.1:12345/").unwrap();
    easy.connect_timeout(std::time::Duration::from_millis(100));

    let start = std::time::Instant::now();
    let result = easy.perform_async().await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Should complete within ~200ms (100ms timeout + overhead)
    assert!(elapsed.as_millis() < 2000, "took too long: {elapsed:?}");
}
