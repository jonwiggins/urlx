//! File protocol edge case tests.
//!
//! Tests file:// URL handling for various filesystem scenarios.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

// --- File with special characters in name ---

#[tokio::test]
async fn file_with_spaces_in_name() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test file.txt");
    std::fs::write(&file_path, "space content").unwrap();

    let mut easy = liburlx::Easy::new();
    // Percent-encode the space
    let url = format!("file://{}", file_path.display().to_string().replace(' ', "%20"));
    easy.url(&url).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "space content");
}

// --- Large file ---

#[tokio::test]
async fn file_large_content() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("large.bin");
    let data = vec![0x42u8; 100_000];
    std::fs::write(&file_path, &data).unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body().len(), 100_000);
}

// --- File with unicode content ---

#[tokio::test]
async fn file_unicode_content() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("unicode.txt");
    std::fs::write(&file_path, "Hello 世界 🌍").unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body_str().unwrap(), "Hello 世界 🌍");
}

// --- File effective URL ---

#[tokio::test]
async fn file_effective_url_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "content").unwrap();

    let url = format!("file://{}", file_path.display());
    let mut easy = liburlx::Easy::new();
    easy.url(&url).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.effective_url(), &url);
}

// --- File size_download ---

#[tokio::test]
async fn file_size_download_matches() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("sized.txt");
    std::fs::write(&file_path, "12345").unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.size_download(), 5);
}

// --- Non-existent file ---

#[tokio::test]
async fn file_nonexistent_returns_error() {
    let mut easy = liburlx::Easy::new();
    easy.url("file:///tmp/urlx_definitely_not_exists_12345.txt").unwrap();
    let result = easy.perform_async().await;
    assert!(result.is_err());
}

// --- Empty file ---

#[tokio::test]
async fn file_empty_content() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("empty.txt");
    std::fs::File::create(&file_path).unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.body().is_empty());
}

// --- File with nested path ---

#[tokio::test]
async fn file_nested_directory() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a").join("b").join("c");
    std::fs::create_dir_all(&nested).unwrap();
    let file_path = nested.join("deep.txt");
    std::fs::write(&file_path, "deep content").unwrap();

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("file://{}", file_path.display())).unwrap();
    let resp = easy.perform_async().await.unwrap();

    assert_eq!(resp.body_str().unwrap(), "deep content");
}
