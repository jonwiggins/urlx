//! Redirect chain integration tests.
//!
//! Tests redirect following behavior through the Easy handle API,
//! including multi-hop chains, redirect loops, max redirect limits,
//! and method/body semantics across redirects.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- Basic redirect chain ---

#[tokio::test]
async fn single_redirect_followed() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/end")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/end" => Response::new(Full::new(Bytes::from("done"))),
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "done");
}

// --- Multi-hop redirect chain ---

#[tokio::test]
async fn three_hop_redirect_chain() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/hop1" => Response::builder()
            .status(302)
            .header("Location", "/hop2")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/hop2" => Response::builder()
            .status(301)
            .header("Location", "/hop3")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/hop3" => Response::new(Full::new(Bytes::from("final"))),
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/hop1")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "final");
}

// --- Redirect without follow ---

#[tokio::test]
async fn redirect_not_followed_by_default() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/end")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/end" => Response::new(Full::new(Bytes::from("end"))),
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    // follow_redirects defaults to false

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 302);
}

// --- Max redirects limit ---

#[tokio::test]
async fn max_redirects_stops_chain() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n < 100 {
            Response::builder()
                .status(302)
                .header("Location", format!("/redirect-{}", n + 1))
                .header("Content-Length", "0")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::new(Full::new(Bytes::from("reached")))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/redirect-0")).unwrap();
    easy.follow_redirects(true);
    easy.max_redirects(3);

    let result = easy.perform_async().await;
    // Should error because max redirects exceeded
    assert!(result.is_err(), "should fail when max redirects exceeded");
}

// --- 303 See Other changes method to GET ---

#[tokio::test]
async fn redirect_303_changes_post_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/submit" => Response::builder()
            .status(303)
            .header("Location", "/result")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/result" => {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "GET");
}

// --- 307 preserves method ---

#[tokio::test]
async fn redirect_307_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/submit" => Response::builder()
            .status(307)
            .header("Location", "/target")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/target" => {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "POST");
}

// --- 308 preserves method ---

#[tokio::test]
async fn redirect_308_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/old" => Response::builder()
            .status(308)
            .header("Location", "/new")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/new" => {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/old")).unwrap();
    easy.method("PUT");
    easy.body(b"data");
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "PUT");
}

// --- Redirect with effective URL tracking ---

#[tokio::test]
async fn effective_url_after_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/final")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/final" => Response::new(Full::new(Bytes::from("ok"))),
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.effective_url().contains("/final"),
        "effective URL should be final: {}",
        resp.effective_url()
    );
}

// --- Redirect counter in transfer info ---

#[tokio::test]
async fn redirect_count_in_transfer_info() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(302)
            .header("Location", "/b")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::builder()
            .status(302)
            .header("Location", "/c")
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/c" => Response::new(Full::new(Bytes::from("done"))),
        _ => Response::new(Full::new(Bytes::from("unknown"))),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.transfer_info().num_redirects, 2);
}

// --- Redirect without Location header stops ---

#[tokio::test]
async fn redirect_without_location_stops() {
    let server = TestServer::start(|_req| {
        // 302 but no Location header
        Response::builder()
            .status(302)
            .header("Content-Length", "0")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.follow_redirects(true);

    let resp = easy.perform_async().await.unwrap();
    // Should return the 302 since there's no Location to follow
    assert_eq!(resp.status(), 302);
}

// --- All redirect status codes ---

#[tokio::test]
async fn all_redirect_codes_followed() {
    for code in [301u16, 302, 303, 307, 308] {
        let server = TestServer::start(move |req| match req.uri().path() {
            "/start" => Response::builder()
                .status(code)
                .header("Location", "/end")
                .header("Content-Length", "0")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            "/end" => Response::new(Full::new(Bytes::from("ok"))),
            _ => Response::new(Full::new(Bytes::from("unknown"))),
        })
        .await;

        let mut easy = liburlx::Easy::new();
        easy.url(&server.url("/start")).unwrap();
        easy.follow_redirects(true);

        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), 200, "redirect code {code} should be followed");
    }
}

// --- Non-redirect codes not followed ---

#[tokio::test]
async fn non_redirect_codes_not_followed() {
    for code in [200u16, 204, 400, 404, 500] {
        let server = TestServer::start(move |_req| {
            Response::builder()
                .status(code)
                .header("Location", "/elsewhere")
                .body(Full::new(Bytes::from("body")))
                .unwrap()
        })
        .await;

        let mut easy = liburlx::Easy::new();
        easy.url(&server.url("/")).unwrap();
        easy.follow_redirects(true);

        let resp = easy.perform_async().await.unwrap();
        assert_eq!(resp.status(), code, "code {code} should not be followed");
    }
}
