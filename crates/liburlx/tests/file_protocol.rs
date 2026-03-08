//! Integration tests for the file:// protocol handler.

#![allow(clippy::unwrap_used, unused_results)]

use std::io::Write;

#[tokio::test]
async fn file_read_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "hello from file").unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "hello from file");
}

#[tokio::test]
async fn file_read_nonexistent_file() {
    let mut easy = liburlx::Easy::new();
    easy.url("file:///nonexistent/path/to/file.txt").unwrap();
    let result = easy.perform_async().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn file_read_binary_content() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("binary.bin");
    let data: Vec<u8> = (0..=255).collect();
    std::fs::write(&file_path, &data).unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body(), &data);
}

#[tokio::test]
async fn file_read_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("empty.txt");
    std::fs::File::create(&file_path).unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
}

#[tokio::test]
async fn file_read_with_spaces_in_path() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("my dir");
    std::fs::create_dir(&sub).unwrap();
    let file_path = sub.join("my file.txt");
    std::fs::write(&file_path, "spaced").unwrap();

    let mut easy = liburlx::Easy::new();
    // URL-encode the spaces
    let url = format!("file://{}", file_path.display().to_string().replace(' ', "%20"));
    easy.url(&url).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "spaced");
}

#[tokio::test]
async fn file_large_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("large.bin");
    let mut f = std::fs::File::create(&file_path).unwrap();
    // Write 1 MB of data
    let chunk = vec![b'A'; 1024];
    for _ in 0..1024 {
        f.write_all(&chunk).unwrap();
    }
    drop(f);

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body().len(), 1024 * 1024);
}
