//! Integration tests for HTTP Range requests and resume downloads.

#![allow(clippy::unwrap_used, unused_results, clippy::option_if_let_else)]

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

/// Start a test server that supports Range requests.
async fn start_range_server(data: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let io = TokioIo::new(stream);
            let data = data.clone();

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let data = data.clone();
                            async move {
                                let range_header = req
                                    .headers()
                                    .get("range")
                                    .map(|v| v.to_str().unwrap_or("").to_string());

                                if let Some(range_str) = range_header {
                                    // Parse "bytes=start-end" or "bytes=start-" or "bytes=-suffix"
                                    let range_spec =
                                        range_str.strip_prefix("bytes=").unwrap_or(&range_str);

                                    let (start, end) =
                                        if let Some(suffix) = range_spec.strip_prefix('-') {
                                            let suffix_len: usize = suffix.parse().unwrap_or(0);
                                            let s = data.len().saturating_sub(suffix_len);
                                            (s, data.len() - 1)
                                        } else if let Some((s, e)) = range_spec.split_once('-') {
                                            let start: usize = s.parse().unwrap_or(0);
                                            let end = if e.is_empty() {
                                                data.len() - 1
                                            } else {
                                                e.parse::<usize>().unwrap_or(data.len() - 1)
                                            };
                                            (start, end)
                                        } else {
                                            (0, data.len() - 1)
                                        };

                                    if start >= data.len() {
                                        return Ok::<_, std::convert::Infallible>(
                                            hyper::Response::builder()
                                                .status(416) // Range Not Satisfiable
                                                .body(Full::new(Bytes::from(
                                                    "range not satisfiable",
                                                )))
                                                .unwrap(),
                                        );
                                    }

                                    let end = end.min(data.len() - 1);
                                    let slice = &data[start..=end];

                                    Ok(hyper::Response::builder()
                                        .status(206)
                                        .header(
                                            "Content-Range",
                                            format!("bytes {start}-{end}/{}", data.len()),
                                        )
                                        .header("Content-Length", slice.len().to_string())
                                        .body(Full::new(Bytes::from(slice.to_vec())))
                                        .unwrap())
                                } else {
                                    Ok(hyper::Response::builder()
                                        .status(200)
                                        .header("Content-Length", data.len().to_string())
                                        .body(Full::new(Bytes::from(data.clone())))
                                        .unwrap())
                                }
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (format!("http://127.0.0.1:{port}"), handle)
}

#[tokio::test]
async fn range_full_download() {
    let data = b"Hello, World! This is test data.".to_vec();
    let (base_url, _handle) = start_range_server(data.clone()).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body(), &data);
}

#[tokio::test]
async fn range_first_5_bytes() {
    let data = b"Hello, World! This is test data.".to_vec();
    let (base_url, _handle) = start_range_server(data).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    easy.range("0-4");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body(), b"Hello");
}

#[tokio::test]
async fn range_from_offset() {
    let data = b"Hello, World!".to_vec();
    let (base_url, _handle) = start_range_server(data).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    easy.range("7-");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body_str().unwrap(), "World!");
}

#[tokio::test]
async fn range_last_n_bytes() {
    let data = b"Hello, World!".to_vec();
    let (base_url, _handle) = start_range_server(data).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    easy.range("-6");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body_str().unwrap(), "World!");
}

#[tokio::test]
async fn resume_from_offset() {
    let data: Vec<u8> = (0..100).collect();
    let (base_url, _handle) = start_range_server(data.clone()).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    easy.resume_from(50);
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body(), &data[50..]);
}

#[tokio::test]
async fn range_has_content_range_header() {
    let data = b"abcdefghij".to_vec();
    let (base_url, _handle) = start_range_server(data).await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/file")).unwrap();
    easy.range("2-5");
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.body(), b"cdef");
    assert_eq!(resp.header("content-range").unwrap(), "bytes 2-5/10");
}
