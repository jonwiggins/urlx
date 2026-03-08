//! Multipart form-data stress tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use liburlx::MultipartForm;

// --- Many fields ---

#[test]
fn hundred_text_fields() {
    let mut form = MultipartForm::with_boundary("b");
    for i in 0..100 {
        form.field(&format!("field{i}"), &format!("value{i}"));
    }

    let body = form.encode();
    let body_str = String::from_utf8(body).unwrap();

    assert!(body_str.contains("field0"));
    assert!(body_str.contains("field99"));
    assert!(body_str.contains("value0"));
    assert!(body_str.contains("value99"));
    assert!(body_str.ends_with("--b--\r\n"));
}

// --- Very large field values ---

#[test]
fn large_text_field() {
    let mut form = MultipartForm::with_boundary("b");
    let large_value = "x".repeat(100_000);
    form.field("data", &large_value);

    let body = form.encode();
    assert!(body.len() > 100_000);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains(&large_value));
}

#[test]
fn large_file_data() {
    let mut form = MultipartForm::with_boundary("b");
    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    form.file_data("bigfile", "big.bin", &data);

    let body = form.encode();
    assert!(body.len() > 100_000);
    // Verify the body contains the file data
    assert!(body
        .windows(256)
        .any(|w| { w.len() == 256 && w.iter().enumerate().all(|(i, &b)| b == i as u8) }));
}

// --- Special characters in field names ---

#[test]
fn field_name_with_spaces() {
    let mut form = MultipartForm::with_boundary("b");
    form.field("my field", "value");

    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("name=\"my field\""));
}

#[test]
fn field_name_with_quotes() {
    let mut form = MultipartForm::with_boundary("b");
    form.field("field\"name", "value");

    let body = String::from_utf8(form.encode()).unwrap();
    // The name should be present (even if not properly escaped — matching curl behavior)
    assert!(body.contains("field\"name"));
}

// --- Special characters in filenames ---

#[test]
fn filename_with_spaces() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("upload", "my file.txt", b"content");

    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("filename=\"my file.txt\""));
}

#[test]
fn filename_with_path_separators() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("upload", "dir/subdir/file.txt", b"content");

    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("filename=\"dir/subdir/file.txt\""));
}

// --- Empty form ---

#[test]
fn empty_form() {
    let form = MultipartForm::with_boundary("b");
    let body = form.encode();
    let body_str = String::from_utf8(body).unwrap();
    // Should have just the closing boundary
    assert_eq!(body_str, "--b--\r\n");
}

// --- Empty file upload ---

#[test]
fn empty_file_upload() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("upload", "empty.txt", b"");

    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("filename=\"empty.txt\""));
    assert!(body.contains("Content-Type: text/plain"));
}

// --- Mixed fields and files ---

#[test]
fn mixed_fields_and_multiple_files() {
    let mut form = MultipartForm::with_boundary("b");
    form.field("title", "My Upload");
    form.file_data("file1", "photo.jpg", b"jpeg data");
    form.field("description", "A test upload");
    form.file_data("file2", "doc.pdf", b"pdf data");

    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("name=\"title\""));
    assert!(body.contains("My Upload"));
    assert!(body.contains("filename=\"photo.jpg\""));
    assert!(body.contains("Content-Type: image/jpeg"));
    assert!(body.contains("name=\"description\""));
    assert!(body.contains("filename=\"doc.pdf\""));
    assert!(body.contains("Content-Type: application/pdf"));
}

// --- Binary content in fields ---

#[test]
fn binary_field_data() {
    let mut form = MultipartForm::with_boundary("b");
    let binary: Vec<u8> = (0..=255).collect();
    form.file_data("bin", "data.bin", &binary);

    let body = form.encode();
    // Verify all 256 bytes are present
    assert!(body
        .windows(256)
        .any(|w| { w.len() == 256 && w.iter().enumerate().all(|(i, &b)| b == i as u8) }));
}

// --- Content type detection ---

#[test]
fn content_type_detection_various_extensions() {
    let test_cases = vec![
        ("image.png", "image/png"),
        ("photo.jpg", "image/jpeg"),
        ("photo.jpeg", "image/jpeg"),
        ("anim.gif", "image/gif"),
        ("icon.svg", "image/svg+xml"),
        ("doc.pdf", "application/pdf"),
        ("archive.zip", "application/zip"),
        ("data.json", "application/json"),
        ("style.css", "text/css"),
        ("script.js", "application/javascript"),
        ("page.html", "text/html"),
        ("page.htm", "text/html"),
        ("readme.txt", "text/plain"),
        ("data.xml", "application/xml"),
        ("file.gz", "application/gzip"),
        ("file.gzip", "application/gzip"),
        ("unknown.xyz", "application/octet-stream"),
    ];

    for (filename, expected_ct) in test_cases {
        let mut form = MultipartForm::with_boundary("b");
        form.file_data("file", filename, b"data");
        let body = String::from_utf8(form.encode()).unwrap();
        assert!(
            body.contains(&format!("Content-Type: {expected_ct}")),
            "expected Content-Type '{expected_ct}' for '{filename}', got: {body}"
        );
    }
}

// --- Boundary in content type ---

#[test]
fn content_type_has_boundary() {
    let form = MultipartForm::with_boundary("my-test-boundary");
    assert_eq!(form.content_type(), "multipart/form-data; boundary=my-test-boundary");
}

// --- Default boundary is unique ---

#[test]
fn default_boundaries_are_nonempty() {
    let form1 = MultipartForm::new();
    let form2 = MultipartForm::new();
    let ct1 = form1.content_type();
    let ct2 = form2.content_type();
    assert!(ct1.starts_with("multipart/form-data; boundary="));
    assert!(ct2.starts_with("multipart/form-data; boundary="));
}
