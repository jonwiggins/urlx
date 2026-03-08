//! Integration tests for DNS resolve overrides.

#![allow(clippy::unwrap_used, unused_results)]

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

/// Start a test HTTP server.
async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from("resolved ok"),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });

    (port, handle)
}

#[tokio::test]
async fn resolve_override_redirects_to_localhost() {
    let (port, _handle) = start_server().await;

    let mut easy = liburlx::Easy::new();
    // Use a hostname that would normally fail DNS resolution,
    // but override it to point to 127.0.0.1
    easy.resolve("fake-host.test", "127.0.0.1");
    easy.url(&format!("http://fake-host.test:{port}/test")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "resolved ok");
}

#[tokio::test]
async fn resolve_override_case_insensitive() {
    let (port, _handle) = start_server().await;

    let mut easy = liburlx::Easy::new();
    easy.resolve("FAKE-HOST.TEST", "127.0.0.1");
    easy.url(&format!("http://fake-host.test:{port}/test")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn without_resolve_override_dns_fails() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://fake-host.test:12345/test").unwrap();
    easy.connect_timeout(std::time::Duration::from_secs(1));
    let result = easy.perform_async().await;

    assert!(result.is_err());
}
