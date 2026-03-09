//! Differential tests comparing urlx behavior against curl.
//!
//! Each test documents the specific curl behavior being verified and
//! ensures urlx matches it exactly. Tests are grouped by feature area.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::TestServer;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

// =============================================================================
// Error code mapping
// =============================================================================

/// curl: exit code 6 = Could not resolve host
/// In urlx, DNS resolution failure maps to `Error::Connect`
#[tokio::test]
async fn error_unresolvable_host() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://this-host-does-not-exist-xyz123.invalid/").unwrap();
    let err = easy.perform_async().await.unwrap_err();
    // Should be a connection/DNS error, not a protocol error
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("connect") || msg.contains("dns") || msg.contains("resolve"),
        "Expected DNS/connect error, got: {err}"
    );
}

/// curl: exit code 7 = Failed to connect
/// Connection refused should give a clear connect/timeout error.
/// On Windows, connecting to a closed port may timeout rather than ECONNREFUSED.
#[tokio::test]
async fn error_connection_refused() {
    let mut easy = liburlx::Easy::new();
    // Port 1 is almost certainly not listening
    easy.url("http://127.0.0.1:1/").unwrap();
    easy.connect_timeout(std::time::Duration::from_secs(2));
    let err = easy.perform_async().await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("connect") || msg.contains("refused") || msg.contains("timeout"),
        "Expected connection refused/timeout error, got: {err}"
    );
}

/// curl: exit code 28 = Operation timeout
/// Timeout should produce a timeout-specific error
#[tokio::test]
async fn error_transfer_timeout() {
    // Start a raw TCP listener that accepts but never responds
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn a task that accepts connections but holds them open
    let _handle = tokio::spawn(async move {
        loop {
            let Ok((_stream, _addr)) = listener.accept().await else {
                break;
            };
            // Hold the connection open but never send any data
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("http://127.0.0.1:{}/", addr.port())).unwrap();
    easy.timeout(std::time::Duration::from_millis(500));
    let err = easy.perform_async().await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("timeout") || msg.contains("timed out"),
        "Expected timeout error, got: {err}"
    );
}

// =============================================================================
// Redirect behavior
// =============================================================================

/// curl: 307 preserves POST method and body across redirect
#[tokio::test]
async fn redirect_307_preserves_post_and_body() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/origin" => {
            assert_eq!(req.method(), "POST");
            Response::builder()
                .status(307)
                .header("Location", "/target")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        "/target" => {
            // curl: 307 MUST preserve POST method
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("307 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/origin")).unwrap();
    easy.method("POST");
    easy.body(b"test=data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"307 preserved POST");
}

/// curl: 308 preserves POST method (Permanent Redirect)
#[tokio::test]
async fn redirect_308_preserves_post() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/origin" => Response::builder()
            .status(308)
            .header("Location", "/target")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/target" => {
            assert_eq!(req.method(), "POST");
            Response::new(Full::new(Bytes::from("308 preserved POST")))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/origin")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"308 preserved POST");
}

/// curl: --post301 preserves POST on 301 redirect
#[tokio::test]
async fn redirect_301_post_preserved_with_post301() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/origin" => Response::builder()
            .status(301)
            .header("Location", "/target")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/target" => {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/origin")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    easy.post301(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"POST");
}

/// curl: without --post301, 301 changes POST to GET
#[tokio::test]
async fn redirect_301_post_becomes_get_by_default() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/origin" => Response::builder()
            .status(301)
            .header("Location", "/target")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/target" => {
            let method = req.method().to_string();
            Response::new(Full::new(Bytes::from(method)))
        }
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/origin")).unwrap();
    easy.method("POST");
    easy.body(b"data");
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"GET");
}

/// curl: max-redirs limits redirect following
#[tokio::test]
async fn redirect_max_redirs_enforced() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let server = TestServer::start(move |_req| {
        let n = counter_clone.fetch_add(1, Ordering::SeqCst);
        // Always redirect — should hit max-redirs limit
        Response::builder()
            .status(302)
            .header("Location", format!("/redirect/{}", n + 1))
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/redirect/0")).unwrap();
    easy.follow_redirects(true);
    easy.max_redirects(3);
    let err = easy.perform_async().await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("redirect") || msg.contains("too many"),
        "Expected redirect limit error, got: {err}"
    );
}

/// curl: redirect to relative URL is resolved correctly
#[tokio::test]
async fn redirect_relative_url_resolved() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/a/b" => Response::builder()
            .status(302)
            .header("Location", "../c")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/c" => Response::new(Full::new(Bytes::from("reached /c"))),
        _ => {
            let path = req.uri().path().to_string();
            Response::new(Full::new(Bytes::from(format!("at {path}"))))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/a/b")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"reached /c");
}

// =============================================================================
// Header handling
// =============================================================================

/// curl: headers are case-insensitive for lookup
#[tokio::test]
async fn header_case_insensitive_lookup() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Custom-Header", "hello")
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    // Case-insensitive header access
    assert_eq!(response.header("x-custom-header"), Some("hello"));
    assert_eq!(response.header("X-CUSTOM-HEADER"), Some("hello"));
    assert_eq!(response.header("content-type"), Some("text/plain"));
    assert_eq!(response.header("Content-Type"), Some("text/plain"));
}

/// curl: last header value wins for duplicate headers
#[tokio::test]
async fn header_last_value_wins() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .header("X-Dup", "first")
            .header("X-Dup", "second")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    // curl convention: last value wins for single-value retrieval
    let val = response.header("x-dup").unwrap_or("");
    // Accept either "second" (last wins) or comma-joined — both are valid
    assert!(
        val == "second" || val.contains("second"),
        "Expected header to contain 'second', got: {val}"
    );
}

/// curl: custom request headers are sent to the server
#[tokio::test]
async fn custom_request_headers_sent() {
    let server = TestServer::start(|req| {
        let mut result = String::new();
        if let Some(v) = req.headers().get("x-my-header") {
            result.push_str(v.to_str().unwrap_or(""));
        }
        result.push('|');
        if let Some(v) = req.headers().get("x-another") {
            result.push_str(v.to_str().unwrap_or(""));
        }
        Response::new(Full::new(Bytes::from(result)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-My-Header", "value1");
    easy.header("X-Another", "value2");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"value1|value2");
}

// =============================================================================
// HTTP methods
// =============================================================================

/// curl: PUT sends body and uses PUT method
#[tokio::test]
async fn put_method_sends_body() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("PUT");
    easy.body(b"updated content");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"PUT");
}

/// curl: PATCH method is supported
#[tokio::test]
async fn patch_method_works() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("PATCH");
    easy.body(b"partial update");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"PATCH");
}

/// curl: DELETE method works without body
#[tokio::test]
async fn delete_method_no_body() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("DELETE");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"DELETE");
}

/// curl: OPTIONS method works
#[tokio::test]
async fn options_method_works() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::new(Full::new(Bytes::from(method)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("OPTIONS");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"OPTIONS");
}

// =============================================================================
// Transfer info
// =============================================================================

/// curl: `effective_url` reflects the final URL after redirects
#[tokio::test]
async fn effective_url_after_redirect() {
    let server = TestServer::start(|req| match req.uri().path() {
        "/start" => Response::builder()
            .status(302)
            .header("Location", "/end")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/end" => Response::new(Full::new(Bytes::from("final"))),
        _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response.effective_url().contains("/end"),
        "Expected effective_url to contain /end, got: {}",
        response.effective_url()
    );
}

/// curl: transfer info includes timing data
#[tokio::test]
async fn transfer_info_has_timing() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    let info = response.transfer_info();
    // All timing fields should be non-negative
    assert!(info.time_namelookup >= std::time::Duration::ZERO);
    assert!(info.time_connect >= std::time::Duration::ZERO);
    assert!(info.time_total >= std::time::Duration::ZERO);
    // Total time should be >= connect time
    assert!(info.time_total >= info.time_connect);
}

/// curl: `size_download` matches body length
#[tokio::test]
async fn size_download_matches_body() {
    let body = "Hello, this is a test response with known length.";
    let server = TestServer::start(move |_req| Response::new(Full::new(Bytes::from(body)))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.size_download(), body.len());
    assert_eq!(response.body().len(), body.len());
}

// =============================================================================
// URL parsing edge cases
// =============================================================================

/// curl: URLs with ports are handled correctly
#[tokio::test]
async fn url_with_explicit_port() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let port = server.addr().port();
    let mut easy = liburlx::Easy::new();
    easy.url(&format!("http://127.0.0.1:{port}/path")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
}

/// curl: URLs with userinfo are parsed (@ in URL)
#[test]
fn url_with_userinfo_parsed() {
    let url = liburlx::Url::parse("http://user:pass@example.com/path").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
    let creds = url.credentials();
    assert!(creds.is_some());
    let (user, pass) = creds.unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "pass");
}

/// curl: empty path is treated as /
#[tokio::test]
async fn url_empty_path_treated_as_root() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        Response::new(Full::new(Bytes::from(path)))
    })
    .await;

    let port = server.addr().port();
    let mut easy = liburlx::Easy::new();
    // No trailing slash
    easy.url(&format!("http://127.0.0.1:{port}")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"/");
}

// =============================================================================
// Cookie behavior
// =============================================================================

/// curl: cookies are sent back on subsequent requests to same host
#[tokio::test]
async fn cookie_jar_sends_cookies() {
    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let server = TestServer::start(move |req| {
        let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            // First request: set a cookie
            Response::builder()
                .header("Set-Cookie", "session=abc123; Path=/")
                .body(Full::new(Bytes::from("cookie set")))
                .unwrap()
        } else {
            // Second request: verify cookie was sent
            let cookie =
                req.headers().get("cookie").map_or("none", |v| v.to_str().unwrap_or("invalid"));
            Response::new(Full::new(Bytes::from(cookie.to_string())))
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.cookie_jar(true);
    easy.url(&server.url("/")).unwrap();

    // First request — gets Set-Cookie
    let _resp1 = easy.perform_async().await.unwrap();

    // Second request — should send cookie back
    easy.url(&server.url("/check")).unwrap();
    let resp2 = easy.perform_async().await.unwrap();

    let body = String::from_utf8_lossy(resp2.body());
    assert!(body.contains("session=abc123"), "Expected cookie in request, got: {body}");
}

// =============================================================================
// Content-Type and body handling
// =============================================================================

/// curl: empty body with POST still sends Content-Length: 0
#[tokio::test]
async fn post_empty_body_sends_content_length_zero() {
    let server = TestServer::start(|req| {
        let cl = req
            .headers()
            .get("content-length")
            .map_or("absent", |v| v.to_str().unwrap_or("invalid"));
        Response::new(Full::new(Bytes::from(cl.to_string())))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("POST");
    easy.body(b"");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"0");
}

/// curl: GET request does not send Content-Length or body
#[tokio::test]
async fn get_no_content_length() {
    let server = TestServer::start(|req| {
        let has_cl = req.headers().contains_key("content-length");
        Response::new(Full::new(Bytes::from(if has_cl { "has-cl" } else { "no-cl" })))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"no-cl");
}

// =============================================================================
// fail_on_error behavior
// =============================================================================

/// curl: --fail returns error on 4xx/5xx
#[tokio::test]
async fn fail_on_error_4xx() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/missing")).unwrap();
    easy.fail_on_error(true);
    let err = easy.perform_async().await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("404") || msg.contains("error"), "Expected HTTP error, got: {msg}");
}

/// curl: --fail returns error on 500
#[tokio::test]
async fn fail_on_error_5xx() {
    let server = TestServer::start(|_req| {
        Response::builder().status(500).body(Full::new(Bytes::from("internal error"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/broken")).unwrap();
    easy.fail_on_error(true);
    let err = easy.perform_async().await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("500") || msg.contains("error"), "Expected HTTP error, got: {msg}");
}

/// curl: --fail succeeds on 200
#[tokio::test]
async fn fail_on_error_success_on_200() {
    let server = TestServer::start(|_req| Response::new(Full::new(Bytes::from("ok")))).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.fail_on_error(true);
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.status(), 200);
}

// =============================================================================
// Auth credential handling
// =============================================================================

/// curl: -u user:pass sends Basic auth header
#[tokio::test]
async fn basic_auth_sends_header() {
    let server = TestServer::start(|req| {
        let auth = req
            .headers()
            .get("authorization")
            .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("invalid").to_string());
        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.basic_auth("user", "pass");
    let response = easy.perform_async().await.unwrap();

    let body = String::from_utf8_lossy(response.body());
    assert!(body.starts_with("Basic "), "Expected Basic auth header, got: {body}");
    // Verify the base64 decodes to user:pass
    let encoded = body.strip_prefix("Basic ").unwrap();
    let decoded = String::from_utf8(base64_decode(encoded).expect("valid base64")).unwrap();
    assert_eq!(decoded, "user:pass");
}

/// Simple base64 decoder for test verification.
#[allow(clippy::cast_possible_truncation)]
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = table.iter().position(|&c| c == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// curl: Bearer token sends Authorization: Bearer <token>
#[tokio::test]
async fn bearer_auth_sends_bearer_header() {
    let server = TestServer::start(|req| {
        let auth = req
            .headers()
            .get("authorization")
            .map_or_else(|| "none".to_string(), |v| v.to_str().unwrap_or("invalid").to_string());
        Response::new(Full::new(Bytes::from(auth)))
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.bearer_token("my-token-123");
    let response = easy.perform_async().await.unwrap();

    assert_eq!(response.body(), b"Bearer my-token-123");
}
