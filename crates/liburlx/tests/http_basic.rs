//! Integration tests for basic HTTP operations using a real test server.

#![allow(clippy::unwrap_used, unused_results, clippy::significant_drop_tightening)]

use std::convert::Infallible;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A simple test HTTP server.
struct TestServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    /// Start a test server with a handler function.
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let (tx, mut rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            let handler = handler.clone();
                            let io = hyper_util::rt::TokioIo::new(stream);
                            tokio::spawn(async move {
                                let _ = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| {
                                            let handler = handler.clone();
                                            async move {
                                                Ok::<_, Infallible>(handler(req))
                                            }
                                        }),
                                    )
                                    .await;
                            });
                        }
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
        });

        Self { addr, shutdown: Some(tx) }
    }

    /// Get the base URL of the server.
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn get_returns_200_with_body() {
    let server = TestServer::start(|_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("hello world"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "hello world");
}

#[tokio::test]
async fn get_returns_404() {
    let server = TestServer::start(|_req| {
        Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/missing")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 404);
    assert_eq!(resp.body_str().unwrap(), "not found");
}

#[tokio::test]
async fn post_with_body() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        let has_content_length = req.headers().contains_key("content-length");
        let body_info = format!("method={method}, has_cl={has_content_length}");
        Response::builder().status(200).body(Full::new(Bytes::from(body_info))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("POST");
    easy.body(b"test data");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.body_str().unwrap();
    assert!(body.contains("method=POST"), "body was: {body}");
    assert!(body.contains("has_cl=true"), "body was: {body}");
}

#[tokio::test]
async fn put_request() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::builder().status(200).body(Full::new(Bytes::from(method))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("PUT");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "PUT");
}

#[tokio::test]
async fn delete_request() {
    let server = TestServer::start(|req| {
        let method = req.method().to_string();
        Response::builder().status(200).body(Full::new(Bytes::from(method))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/resource")).unwrap();
    easy.method("DELETE");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "DELETE");
}

#[tokio::test]
async fn head_request_returns_no_body() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(200)
            .header("content-length", "1000")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.method("HEAD");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
}

#[tokio::test]
async fn custom_headers_are_sent() {
    let server = TestServer::start(|req| {
        let custom = req.headers().get("x-custom").map_or("missing", |v| v.to_str().unwrap_or(""));
        Response::builder().status(200).body(Full::new(Bytes::from(custom.to_string()))).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.header("X-Custom", "test-value-123");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "test-value-123");
}

#[tokio::test]
async fn redirect_301_is_followed() {
    let redirect_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let redirect_count_clone = redirect_count.clone();

    let server = TestServer::start(move |req| {
        let path = req.uri().path().to_string();
        if path == "/start" {
            redirect_count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Response::builder()
                .status(301)
                .header("location", "/end")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder().status(200).body(Full::new(Bytes::from("final"))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "final");
    assert_eq!(redirect_count.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn redirect_302_is_followed() {
    let server = TestServer::start(|req| {
        if req.uri().path() == "/old" {
            Response::builder()
                .status(302)
                .header("location", "/new")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder().status(200).body(Full::new(Bytes::from("arrived"))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/old")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "arrived");
}

#[tokio::test]
async fn redirect_not_followed_by_default() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(301)
            .header("location", "/other")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    // follow_redirects is false by default
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 301);
}

#[tokio::test]
async fn redirect_max_exceeded() {
    let server = TestServer::start(|_req| {
        Response::builder()
            .status(302)
            .header("location", "/loop")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/loop")).unwrap();
    easy.follow_redirects(true);
    easy.max_redirects(3);
    let result = easy.perform_async().await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too many redirects"), "error was: {err}");
}

#[tokio::test]
async fn redirect_303_changes_post_to_get() {
    let request_methods: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let methods_clone = request_methods.clone();

    let server = TestServer::start(move |req| {
        let method = req.method().to_string();
        methods_clone.lock().unwrap().push(method);

        if req.uri().path() == "/submit" {
            Response::builder()
                .status(303)
                .header("location", "/result")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder().status(200).body(Full::new(Bytes::from("done"))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("POST");
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    let methods = request_methods.lock().unwrap();
    assert_eq!(methods[0], "POST");
    assert_eq!(methods[1], "GET"); // 303 changes to GET
}

#[tokio::test]
async fn redirect_307_preserves_method() {
    let request_methods: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let methods_clone = request_methods.clone();

    let server = TestServer::start(move |req| {
        let method = req.method().to_string();
        methods_clone.lock().unwrap().push(method);

        if req.uri().path() == "/submit" {
            Response::builder()
                .status(307)
                .header("location", "/submit2")
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder().status(200).body(Full::new(Bytes::from("done"))).unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/submit")).unwrap();
    easy.method("PUT");
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    let methods = request_methods.lock().unwrap();
    assert_eq!(methods[0], "PUT");
    assert_eq!(methods[1], "PUT"); // 307 preserves method
}

#[tokio::test]
async fn connection_refused() {
    let mut easy = liburlx::Easy::new();
    // Use a port that's (almost certainly) not listening
    easy.url("http://127.0.0.1:1").unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn empty_response_body() {
    let server = TestServer::start(|_req| {
        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 204);
    assert!(resp.body().is_empty());
}

#[tokio::test]
async fn redirect_with_absolute_url() {
    let server = TestServer::start(|req| {
        let path = req.uri().path().to_string();
        if path == "/start" {
            // Use the Host header to construct the absolute redirect URL
            let host = req.headers().get("host").unwrap().to_str().unwrap().to_string();
            Response::builder()
                .status(302)
                .header("location", format!("http://{host}/end"))
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("final destination")))
                .unwrap()
        }
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "final destination");
}

#[tokio::test]
async fn chunked_response_is_decoded() {
    let server = TestServer::start(|_req| {
        // hyper uses chunked encoding when Content-Length is not set and body is non-empty
        Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("chunked body content")))
            .unwrap()
    })
    .await;

    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "chunked body content");
}

#[tokio::test]
async fn gzip_decompression() {
    let server = TestServer::start(|req| {
        // Only compress if client accepts gzip
        let accepts_gzip = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("gzip"));

        if accepts_gzip {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(b"compressed content").unwrap();
            let compressed = encoder.finish().unwrap();

            Response::builder()
                .status(200)
                .header("content-encoding", "gzip")
                .header("content-length", compressed.len().to_string())
                .body(Full::new(Bytes::from(compressed)))
                .unwrap()
        } else {
            Response::builder()
                .status(200)
                .header("content-length", "18")
                .body(Full::new(Bytes::from("compressed content")))
                .unwrap()
        }
    })
    .await;

    // With accept_encoding enabled, response should be decompressed
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    easy.accept_encoding(true);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "compressed content");
}

#[tokio::test]
async fn no_decompression_without_accept_encoding() {
    let server = TestServer::start(|_req| {
        Response::builder().status(200).body(Full::new(Bytes::from("plain content"))).unwrap()
    })
    .await;

    // Without accept_encoding, no Accept-Encoding header is sent
    let mut easy = liburlx::Easy::new();
    easy.url(&server.url("/")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "plain content");
}
