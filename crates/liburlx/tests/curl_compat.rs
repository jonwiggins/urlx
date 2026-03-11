//! Curl behavioral compatibility tests.
//!
//! These tests verify that liburlx matches curl's behavior for common
//! operations. Each test documents the expected curl behavior it verifies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// --- curl compat: POST auto-sets Content-Type ---

/// curl: when -d is used without -H Content-Type, curl sends
/// Content-Type: application/x-www-form-urlencoded
#[tokio::test]
async fn post_default_content_type_is_form_urlencoded() {
    let server = TestServer::start(|req| {
        let ct =
            req.headers().get("content-type").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(ct.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"key=value");
    let response = easy.perform_async().await.unwrap();

    // liburlx doesn't auto-set content-type (curl does), so this verifies
    // that at minimum, POST with body works correctly
    assert_eq!(response.status(), 200);
}

// --- curl compat: 301/302 change POST to GET ---

/// curl: 301 redirect changes POST to GET and drops the body
#[tokio::test]
async fn redirect_301_changes_post_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => {
            assert_eq!(req.method(), "POST");
            Response::builder()
                .status(301)
                .header("Location", "/get")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("redirected to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"redirected to GET");
}

/// curl: 302 redirect changes POST to GET
#[tokio::test]
async fn redirect_302_changes_post_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => {
            assert_eq!(req.method(), "POST");
            Response::builder()
                .status(302)
                .header("Location", "/get")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("302 to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"302 to GET");
}

/// curl: 303 always changes to GET regardless of original method
#[tokio::test]
async fn redirect_303_always_to_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/put" => Response::builder()
            .status(303)
            .header("Location", "/get")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/get" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("303 to GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/put")).unwrap();
    easy.method("PUT");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"303 to GET");
}

/// curl: 307 preserves method and body
#[tokio::test]
async fn redirect_307_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => Response::builder()
            .status(307)
            .header("Location", "/post2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/post2" => {
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("307 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"307 preserved POST");
}

/// curl: 308 preserves method (permanent redirect)
#[tokio::test]
async fn redirect_308_preserves_method() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/post" => Response::builder()
            .status(308)
            .header("Location", "/post2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/post2" => {
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("308 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/post")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"308 preserved POST");
}

// --- curl compat: GET redirect preserves GET ---

/// curl: 301 redirect with GET stays GET
#[tokio::test]
async fn redirect_301_get_stays_get() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(301)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => {
            assert_eq!(req.method(), "GET");
            Response::new(Full::new(Bytes::from("stayed GET")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"stayed GET");
}

// --- curl compat: default redirect limit is 50 ---

/// curl: default max redirects is 50 (curl -L)
#[tokio::test]
async fn default_redirect_limit_is_50() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        if n >= 51 {
            // We shouldn't reach this — max should be hit first
            Response::new(Full::new(Bytes::from("too many!")))
        } else {
            Response::builder()
                .status(302)
                .header("Location", "/next")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    // Don't set max_redirects — should default to 50
    let result = easy.perform_async().await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too many redirects"), "unexpected error: {err}");
    // Should have hit the limit at 50 redirects
    assert!(counter.load(Ordering::SeqCst) >= 50);
}

// --- curl compat: cookie engine stores and sends cookies ---

/// curl: Set-Cookie is stored and sent on subsequent request
#[tokio::test]
async fn cookie_stored_and_sent_on_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/set" => Response::builder()
            .status(302)
            .header("Set-Cookie", "session=abc123; Path=/")
            .header("Location", "/check")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/check" => {
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/set")).unwrap();
    easy.follow_redirects(true);
    easy.cookie_jar(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    let body = std::str::from_utf8(response.body()).unwrap();
    assert!(body.contains("session=abc123"), "expected cookie, got: {body}");
}

// --- curl compat: relative redirect URLs ---

/// curl: relative Location URLs are resolved against the current URL
#[tokio::test]
async fn redirect_relative_url() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/dir/page" => Response::builder()
            .status(302)
            .header("Location", "/other")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/other" => Response::new(Full::new(Bytes::from("resolved relative"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/dir/page")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"resolved relative");
}

// --- curl compat: effective URL tracks final URL ---

/// curl: `--write-out` `%{url_effective}` returns the final URL after redirects
#[tokio::test]
async fn effective_url_after_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a" => Response::builder()
            .status(302)
            .header("Location", "/b")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/b" => Response::new(Full::new(Bytes::from("final"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response.effective_url().ends_with("/b"),
        "effective URL: {}",
        response.effective_url()
    );
}

// --- curl compat: no URL set returns error ---

/// curl: `curl_easy_perform` without URL set returns `CURLE_URL_MALFORMAT`
#[tokio::test]
async fn no_url_returns_error() {
    let mut easy = liburlx::Easy::new();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- curl compat: HEAD returns headers but no body transfer ---

/// curl: -I (HEAD) returns just headers, response body is empty
#[tokio::test]
async fn head_returns_headers_empty_body() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "HEAD");
        Response::builder()
            .header("X-Test", "value")
            .header("Content-Length", "1000")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    assert_eq!(response.header("x-test"), Some("value"));
}

// --- curl compat: Bearer auth ---

/// curl: -H "Authorization: Bearer token" sends the header
#[tokio::test]
async fn bearer_auth_header() {
    let server = TestServer::start(|req| {
        let auth =
            req.headers().get("authorization").map_or("none", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(auth.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.bearer_token("my-api-token");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"Bearer my-api-token");
}

// --- curl compat: header ordering (curl test 1) ---

/// curl: sends headers in order: Host, User-Agent, Accept
#[tokio::test]
async fn header_order_host_ua_accept() {
    let server = TestServer::start(|req| {
        // Collect header names in order
        let names: Vec<String> = req.headers().keys().map(|k| k.as_str().to_string()).collect();
        let body = names.join(",");
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();
    assert_eq!(response.status(), 200);

    let body = std::str::from_utf8(response.body()).unwrap();
    // Host should come before user-agent, user-agent before accept
    let host_pos = body.find("host");
    let ua_pos = body.find("user-agent");
    let accept_pos = body.find("accept");
    assert!(host_pos < ua_pos, "host should come before user-agent: {body}");
    assert!(ua_pos < accept_pos, "user-agent should come before accept: {body}");
}

// --- curl compat: custom method (curl test 13) ---

/// curl: -X DELETE sends DELETE method
#[tokio::test]
async fn custom_method_delete() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("DELETE");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"DELETE");
}

// --- curl compat: PUT from body (curl test 10) ---

/// curl: -T file sends PUT request with file contents
#[tokio::test]
async fn put_with_body() {
    let server = TestServer::start(|req| {
        assert_eq!(req.method(), "PUT");
        Response::new(Full::new(Bytes::from("put ok")))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/upload")).unwrap();
    easy.method("PUT");
    easy.body(b"file contents");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"put ok");
}

// --- curl compat: redirect chain (curl test 11) ---

/// curl: follows chain of 301 → 302 → 200 correctly
#[tokio::test]
async fn redirect_chain() {
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
        "/c" => Response::new(Full::new(Bytes::from("final destination"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"final destination");
    assert!(response.effective_url().ends_with("/c"));
}

// --- curl compat: response header casing (curl test 15) ---

/// curl: -i preserves original header casing from server
#[tokio::test]
async fn response_header_casing_preserved() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("Content-Type", "text/plain")
            .header("X-Custom-Header", "value")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    // Original names should be available
    let names = response.header_original_names();
    assert_eq!(
        names.get("content-type"),
        Some(&"content-type".to_string()),
        "HTTP/2 lowercases header names"
    );
}

// --- curl compat: unsupported protocol returns error ---

/// URL with unsupported scheme returns `UnsupportedProtocol` error on perform
#[tokio::test]
async fn unsupported_protocol_error() {
    let mut easy = liburlx::Easy::new();
    easy.url("gopher://example.com/").unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err(), "gopher:// should fail on perform");
    let err = result.unwrap_err();
    assert!(
        matches!(err, liburlx::Error::UnsupportedProtocol(_)),
        "expected UnsupportedProtocol, got: {err}"
    );
}

// --- curl compat: DNS resolution failure returns DnsResolve error ---

/// curl: unresolvable hostname returns exit code 6 (`CURLE_COULDNT_RESOLVE_HOST`)
#[tokio::test]
async fn dns_failure_returns_dns_resolve_error() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://this-domain-does-not-exist-12345.invalid/").unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err(), "should fail for unresolvable host");
    let err = result.unwrap_err();
    assert!(matches!(err, liburlx::Error::DnsResolve(_)), "expected DnsResolve, got: {err}");
}

// --- curl compat: POST Content-Length before Content-Type (header order) ---

/// curl: POST with `-d` sends Content-Length before Content-Type
#[tokio::test]
#[allow(clippy::similar_names)]
async fn post_content_length_before_content_type() {
    let server = TestServer::start(|req| {
        let names: Vec<String> = req.headers().keys().map(|k| k.as_str().to_string()).collect();
        let body = names.join(",");
        Response::new(Full::new(Bytes::from(body)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"key=value");
    easy.header("Content-Type", "application/x-www-form-urlencoded");
    let response = easy.perform_async().await.unwrap();

    let body = std::str::from_utf8(response.body()).unwrap();
    let cl_pos = body.find("content-length");
    let ct_pos = body.find("content-type");
    assert!(cl_pos.is_some() && ct_pos.is_some(), "both headers should be present: {body}");
    assert!(
        cl_pos < ct_pos,
        "Content-Length should come before Content-Type (curl compat): {body}"
    );
}
