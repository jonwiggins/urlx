//! Multipart form-data encoding tests.
//!
//! Tests `MultipartForm` encoding through the public API, verifying
//! boundary structure, content types, field ordering, and binary data.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use liburlx::MultipartForm;

// --- Construction ---

#[test]
fn new_creates_non_empty_boundary() {
    let form = MultipartForm::new();
    let ct = form.content_type();
    assert!(ct.starts_with("multipart/form-data; boundary="));
    // Boundary should be at least 20 chars
    let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    assert!(boundary.len() >= 20, "boundary too short: {boundary}");
}

#[test]
fn with_boundary_uses_exact_string() {
    let form = MultipartForm::with_boundary("CUSTOM-BOUNDARY-123");
    assert_eq!(form.content_type(), "multipart/form-data; boundary=CUSTOM-BOUNDARY-123");
}

#[test]
fn default_same_as_new() {
    let form = MultipartForm::default();
    let ct = form.content_type();
    assert!(ct.starts_with("multipart/form-data; boundary="));
}

// --- Single field encoding ---

#[test]
fn single_field_structure() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("key", "value");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    // Must start with boundary delimiter
    assert!(body.starts_with("--B\r\n"), "body: {body}");
    // Must have Content-Disposition
    assert!(body.contains("Content-Disposition: form-data; name=\"key\""));
    // Must have the value after headers
    assert!(body.contains("\r\n\r\nvalue\r\n"));
    // Must end with closing boundary
    assert!(body.ends_with("--B--\r\n"), "body: {body}");
}

#[test]
fn field_empty_value() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("empty", "");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();
    assert!(body.contains("name=\"empty\"\r\n\r\n\r\n"));
}

#[test]
fn field_with_spaces_and_special_chars() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("data", "hello world & foo=bar");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();
    assert!(body.contains("hello world & foo=bar"));
}

// --- Multiple fields ---

#[test]
fn multiple_fields_all_present() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("a", "1");
    form.field("b", "2");
    form.field("c", "3");

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"a\"\r\n\r\n1\r\n"));
    assert!(body.contains("name=\"b\"\r\n\r\n2\r\n"));
    assert!(body.contains("name=\"c\"\r\n\r\n3\r\n"));
}

#[test]
fn fields_preserve_order() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("first", "1");
    form.field("second", "2");
    form.field("third", "3");

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    let pos_first = body.find("name=\"first\"").unwrap();
    let pos_second = body.find("name=\"second\"").unwrap();
    let pos_third = body.find("name=\"third\"").unwrap();
    assert!(pos_first < pos_second);
    assert!(pos_second < pos_third);
}

// --- File data ---

#[test]
fn file_data_includes_filename() {
    let mut form = MultipartForm::with_boundary("B");
    form.file_data("upload", "report.pdf", b"pdf content");

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"upload\"; filename=\"report.pdf\""));
    assert!(body.contains("Content-Type: application/pdf"));
    assert!(body.contains("\r\npdf content\r\n"));
}

#[test]
fn file_data_binary_preserved() {
    let mut form = MultipartForm::with_boundary("B");
    let binary: Vec<u8> = (0..=255).collect();
    form.file_data("bin", "data.bin", &binary);

    let encoded = form.encode();
    // The binary data should appear intact in the encoded form
    assert!(encoded.windows(256).any(|w| w == binary.as_slice()));
}

#[test]
fn file_data_content_type_by_extension() {
    let mut form = MultipartForm::with_boundary("B");

    form.file_data("f1", "image.png", b"");
    form.file_data("f2", "doc.json", b"");
    form.file_data("f3", "unknown.xyz", b"");

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("Content-Type: image/png"), "body: {body}");
    assert!(body.contains("Content-Type: application/json"), "body: {body}");
    assert!(body.contains("Content-Type: application/octet-stream"), "body: {body}");
}

// --- Mixed fields and files ---

#[test]
fn mixed_fields_and_files() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("description", "test upload");
    form.file_data("attachment", "test.txt", b"file data");
    form.field("tag", "important");

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"description\"\r\n\r\ntest upload\r\n"));
    assert!(body.contains("name=\"attachment\"; filename=\"test.txt\""));
    assert!(body.contains("name=\"tag\"\r\n\r\nimportant\r\n"));
}

// --- Content-Type header ---

#[test]
fn content_type_format() {
    let form = MultipartForm::with_boundary("abc123");
    let ct = form.content_type();
    assert_eq!(ct, "multipart/form-data; boundary=abc123");
}

// --- Clone ---

#[test]
fn clone_produces_independent_copy() {
    let mut form = MultipartForm::with_boundary("B");
    form.field("key", "value");

    let mut cloned = form.clone();
    cloned.field("extra", "field");

    // Original should only have 1 part, clone should have 2
    let orig_body = String::from_utf8(form.encode()).unwrap();
    let clone_body = String::from_utf8(cloned.encode()).unwrap();

    assert!(!orig_body.contains("extra"));
    assert!(clone_body.contains("extra"));
}

// --- Debug ---

#[test]
fn debug_format_contains_boundary() {
    let form = MultipartForm::with_boundary("DBG");
    let debug = format!("{form:?}");
    assert!(debug.contains("MultipartForm"));
    assert!(debug.contains("DBG"));
}

// --- Empty form ---

#[test]
fn empty_form_encodes_closing_boundary_only() {
    let form = MultipartForm::with_boundary("B");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();
    assert_eq!(body, "--B--\r\n");
}

// --- Large data ---

#[test]
fn large_field_value() {
    let mut form = MultipartForm::with_boundary("B");
    let large_value = "x".repeat(100_000);
    form.field("big", &large_value);

    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();
    assert!(body.contains(&large_value));
}
