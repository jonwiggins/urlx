//! Transfer info accuracy tests.
//!
//! Verifies that transfer timing, redirect counting, and size info are
//! correctly tracked through actual HTTP transfers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Timing info ---

#[tokio::test]
async fn total_time_is_nonzero() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert!(resp.transfer_info().time_total > Duration::ZERO);
}

#[tokio::test]
async fn connect_time_is_nonzero() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert!(resp.transfer_info().time_connect > Duration::ZERO);
}

#[tokio::test]
async fn connect_time_lte_total_time() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    let info = resp.transfer_info();
    assert!(
        info.time_connect <= info.time_total,
        "connect ({:?}) should be <= total ({:?})",
        info.time_connect,
        info.time_total
    );
}

// --- Redirect counting ---

#[tokio::test]
async fn no_redirects_count_zero() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.transfer_info().num_redirects, 0);
}

#[tokio::test]
async fn single_redirect_counted() {
    let server = TestServer::start(|req| {
        if req.uri().path() == "/start" {
            Response::builder()
                .status(302)
                .header("Location", "/end")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("final")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.transfer_info().num_redirects, 1);
}

#[tokio::test]
async fn multiple_redirects_counted() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(301)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::builder()
            .status(302)
            .header("Location", "/c")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/c" => Response::builder()
            .status(307)
            .header("Location", "/d")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::new(Full::new(Bytes::from("end"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.transfer_info().num_redirects, 3);
}

// --- Effective URL tracking ---

#[tokio::test]
async fn effective_url_no_redirect() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let url = server.url("/page");
    let mut easy = liburlx::Easy::new();
    easy.url(&url).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.effective_url(), url);
}

#[tokio::test]
async fn effective_url_after_redirect() {
    let server = TestServer::start(|req| {
        if req.uri().path() == "/old" {
            Response::builder()
                .status(301)
                .header("Location", "/new")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("ok")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/old")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert!(resp.effective_url().contains("/new"), "effective URL should point to /new");
}

// --- Size download accuracy ---

#[tokio::test]
async fn size_download_empty_body() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::new()))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.size_download(), 0);
}

#[tokio::test]
async fn size_download_known_body() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from("x".repeat(512))))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.size_download(), 512);
}

#[tokio::test]
async fn size_download_large_body() {
    let server =
        TestServer::start(|_req| Response::new(Full::new(Bytes::from(vec![b'A'; 100_000])))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.size_download(), 100_000);
}

// --- Multiple performs reset info ---

#[tokio::test]
async fn multiple_performs_independent_info() {
    let server = TestServer::start(|req| {
        let body = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();

    easy.url(&server.url("/first")).unwrap();
    let resp1 = easy.perform_async().await.unwrap();

    easy.url(&server.url("/second")).unwrap();
    let resp2 = easy.perform_async().await.unwrap();

    // Both should have valid timing
    assert!(resp1.transfer_info().time_total > Duration::ZERO);
    assert!(resp2.transfer_info().time_total > Duration::ZERO);

    // Both should have correct body sizes
    assert_eq!(resp1.size_download(), "/first".len());
    assert_eq!(resp2.size_download(), "/second".len());
}

// --- Status code preserved through info ---

#[tokio::test]
async fn status_code_preserved_in_response() {
    for code in [200, 201, 204, 301, 404, 500] {
        let server = TestServer::start(move |_req| {
            Response::builder().status(code).body(Full::new(Bytes::new())).unwrap()
        })
        .await;

        let mut easy = liburlx::Easy::new();
        easy.url(&server.url("/")).unwrap();
        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), code, "expected status {code}");
    }
}
