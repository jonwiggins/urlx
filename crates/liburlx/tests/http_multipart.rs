//! Integration tests for multipart form-data uploads.

#![allow(clippy::unwrap_used, unused_results)]

use std::io::Write;

use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

/// Start a test HTTP server that echoes back the request body and content-type.
async fn start_echo_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(
                        io,
                        service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                            let content_type = req
                                .headers()
                                .get("content-type")
                                .map(|v| v.to_str().unwrap_or("").to_string())
                                .unwrap_or_default();
                            let method = req.method().to_string();
                            let body_bytes =
                                req.into_body().collect().await.unwrap().to_bytes().to_vec();

                            // Return JSON-ish response with method, content-type, and body
                            let response_body = format!(
                                "method={}\ncontent-type={}\nbody-len={}\nbody={}",
                                method,
                                content_type,
                                body_bytes.len(),
                                String::from_utf8_lossy(&body_bytes)
                            );

                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(hyper::body::Bytes::from(response_body)),
                            ))
                        }),
                    )
                    .await;
            });
        }
    });

    (format!("http://127.0.0.1:{port}"), handle)
}

#[tokio::test]
async fn multipart_single_field() {
    let (base_url, _handle) = start_echo_server().await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/upload")).unwrap();
    easy.form_field("name", "hello");

    let resp = easy.perform_async().await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.body_str().unwrap();
    assert!(body.contains("method=POST"), "should default to POST: {body}");
    assert!(
        body.contains("content-type=multipart/form-data; boundary="),
        "should have multipart content-type: {body}"
    );
    assert!(body.contains("name=\"name\""), "should contain field name: {body}");
    assert!(body.contains("hello"), "should contain field value: {body}");
}

#[tokio::test]
async fn multipart_multiple_fields() {
    let (base_url, _handle) = start_echo_server().await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/upload")).unwrap();
    easy.form_field("field1", "value1");
    easy.form_field("field2", "value2");

    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();

    assert!(body.contains("name=\"field1\""), "field1: {body}");
    assert!(body.contains("value1"), "value1: {body}");
    assert!(body.contains("name=\"field2\""), "field2: {body}");
    assert!(body.contains("value2"), "value2: {body}");
}

#[tokio::test]
async fn multipart_file_upload() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "file content here").unwrap();

    let (base_url, _handle) = start_echo_server().await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/upload")).unwrap();
    easy.form_file("upload", &file_path).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();

    assert!(body.contains("method=POST"), "POST: {body}");
    assert!(body.contains("filename=\"test.txt\""), "filename: {body}");
    assert!(body.contains("Content-Type: text/plain"), "content type: {body}");
    assert!(body.contains("file content here"), "file data: {body}");
}

#[tokio::test]
async fn multipart_mixed_fields_and_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("data.json");
    std::fs::write(&file_path, r#"{"key": "val"}"#).unwrap();

    let (base_url, _handle) = start_echo_server().await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/upload")).unwrap();
    easy.form_field("description", "my upload");
    easy.form_file("data", &file_path).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();

    assert!(body.contains("name=\"description\""), "field: {body}");
    assert!(body.contains("my upload"), "field value: {body}");
    assert!(body.contains("filename=\"data.json\""), "filename: {body}");
    assert!(body.contains(r#"{"key": "val"}"#), "file data: {body}");
}

#[tokio::test]
async fn multipart_binary_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("image.png");
    // Write a minimal valid PNG (just some bytes for testing)
    let mut f = std::fs::File::create(&file_path).unwrap();
    f.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
    drop(f);

    let (base_url, _handle) = start_echo_server().await;

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("{base_url}/upload")).unwrap();
    easy.form_file("image", &file_path).unwrap();

    let resp = easy.perform_async().await.unwrap();
    let body = resp.body_str().unwrap();

    assert!(body.contains("filename=\"image.png\""), "filename: {body}");
    assert!(body.contains("Content-Type: image/png"), "content type: {body}");
    assert!(body.contains("body-len="), "should have body: {body}");
}

#[tokio::test]
async fn multipart_nonexistent_file() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://127.0.0.1:1/unused").unwrap();
    let result = easy.form_file("f", std::path::Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
}
