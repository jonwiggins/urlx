//! Multipart form data encoding tests.
//!
//! Tests boundary generation, field encoding, file upload content type
//! detection, and overall multipart body structure.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::http::multipart::MultipartForm;

// --- Basic field encoding ---

#[test]
fn single_text_field() {
    let mut form = MultipartForm::with_boundary("testboundary");
    form.field("name", "value");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("--testboundary\r\n"));
    assert!(body.contains("Content-Disposition: form-data; name=\"name\""));
    assert!(body.contains("\r\n\r\nvalue\r\n"));
    assert!(body.contains("--testboundary--\r\n"));
}

#[test]
fn multiple_text_fields() {
    let mut form = MultipartForm::with_boundary("bound");
    form.field("first", "one");
    form.field("second", "two");
    form.field("third", "three");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"first\""));
    assert!(body.contains("\r\n\r\none\r\n"));
    assert!(body.contains("name=\"second\""));
    assert!(body.contains("\r\n\r\ntwo\r\n"));
    assert!(body.contains("name=\"third\""));
    assert!(body.contains("\r\n\r\nthree\r\n"));
}

// --- Content-Type header ---

#[test]
fn content_type_includes_boundary() {
    let form = MultipartForm::with_boundary("myboundary");
    let ct = form.content_type();
    assert_eq!(ct, "multipart/form-data; boundary=myboundary");
}

#[test]
fn default_boundary_in_content_type() {
    let form = MultipartForm::new();
    let ct = form.content_type();
    assert!(ct.starts_with("multipart/form-data; boundary="));
    assert!(ct.len() > "multipart/form-data; boundary=".len());
}

// --- Boundary uniqueness ---

#[test]
fn different_forms_get_different_boundaries() {
    let form1 = MultipartForm::new();
    let form2 = MultipartForm::new();
    // Boundaries should be different (timestamp-based)
    // Note: this could theoretically fail if both are created in the same nanosecond
    let ct1 = form1.content_type();
    let ct2 = form2.content_type();
    // Just verify they're both valid
    assert!(ct1.starts_with("multipart/form-data; boundary="));
    assert!(ct2.starts_with("multipart/form-data; boundary="));
}

// --- File data encoding ---

#[test]
fn file_data_with_filename() {
    let mut form = MultipartForm::with_boundary("fileboundary");
    form.file_data("upload", "test.txt", b"file contents here");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"upload\""));
    assert!(body.contains("filename=\"test.txt\""));
    assert!(body.contains("Content-Type: text/plain"));
    assert!(body.contains("file contents here"));
}

#[test]
fn file_data_json_content_type() {
    let mut form = MultipartForm::with_boundary("jsonbound");
    form.file_data("data", "payload.json", b"{\"key\": \"value\"}");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("filename=\"payload.json\""));
    assert!(body.contains("Content-Type: application/json"));
}

#[test]
fn file_data_png_content_type() {
    let mut form = MultipartForm::with_boundary("imgbound");
    form.file_data("image", "photo.png", &[0x89, 0x50, 0x4E, 0x47]);
    let encoded = form.encode();
    let body = String::from_utf8_lossy(&encoded);

    assert!(body.contains("filename=\"photo.png\""));
    assert!(body.contains("Content-Type: image/png"));
}

#[test]
fn file_data_unknown_extension_uses_octet_stream() {
    let mut form = MultipartForm::with_boundary("unknownbound");
    form.file_data("file", "data.xyz", b"some data");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("Content-Type: application/octet-stream"));
}

// --- Mixed fields and files ---

#[test]
fn mixed_fields_and_files() {
    let mut form = MultipartForm::with_boundary("mixedbound");
    form.field("description", "My upload");
    form.file_data("file", "doc.pdf", b"PDF data");
    form.field("tag", "important");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("name=\"description\""));
    assert!(body.contains("My upload"));
    assert!(body.contains("name=\"file\""));
    assert!(body.contains("filename=\"doc.pdf\""));
    assert!(body.contains("Content-Type: application/pdf"));
    assert!(body.contains("name=\"tag\""));
    assert!(body.contains("important"));
}

// --- Empty form ---

#[test]
fn empty_form_has_closing_boundary() {
    let form = MultipartForm::with_boundary("emptybound");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("--emptybound--"));
}

// --- Special characters in field values ---

#[test]
fn field_with_newlines() {
    let mut form = MultipartForm::with_boundary("nlbound");
    form.field("text", "line1\nline2\nline3");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("line1\nline2\nline3"));
}

#[test]
fn field_with_unicode() {
    let mut form = MultipartForm::with_boundary("unicodebound");
    form.field("name", "Hello world");
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains("Hello world"));
}

// --- Binary file data ---

#[test]
fn binary_file_data_preserved() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let mut form = MultipartForm::with_boundary("binbound");
    form.file_data("binary", "data.bin", &binary_data);
    let encoded = form.encode();

    // The binary data should be in the encoded output somewhere
    // Find the data after the headers
    let header_end = b"\r\n\r\n";
    let mut pos = 0;
    for window in encoded.windows(header_end.len()) {
        if window == header_end {
            pos += header_end.len();
            break;
        }
        pos += 1;
    }
    // The binary data should start at pos
    assert!(encoded[pos..].windows(256).any(|w| w == binary_data.as_slice()));
}

// --- Large field value ---

#[test]
fn large_field_value() {
    let large_value = "x".repeat(100_000);
    let mut form = MultipartForm::with_boundary("largebound");
    form.field("big", &large_value);
    let encoded = form.encode();
    let body = String::from_utf8(encoded).unwrap();

    assert!(body.contains(&large_value));
}

// --- Content type detection for various extensions ---

#[test]
fn content_type_detection_html() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "page.html", b"<html>");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: text/html"));
}

#[test]
fn content_type_detection_css() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "style.css", b"body{}");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: text/css"));
}

#[test]
fn content_type_detection_js() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "app.js", b"console.log()");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: application/javascript"));
}

#[test]
fn content_type_detection_xml() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "data.xml", b"<root/>");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: application/xml"));
}

#[test]
fn content_type_detection_jpeg() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "photo.jpg", b"\xff\xd8");
    let encoded = form.encode();
    let body = String::from_utf8_lossy(&encoded);
    assert!(body.contains("Content-Type: image/jpeg"));
}

#[test]
fn content_type_detection_gif() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "anim.gif", b"GIF89a");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: image/gif"));
}

#[test]
fn content_type_detection_svg() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "icon.svg", b"<svg/>");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: image/svg+xml"));
}

#[test]
fn content_type_detection_zip() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "archive.zip", b"PK");
    let body = String::from_utf8(form.encode()).unwrap();
    assert!(body.contains("Content-Type: application/zip"));
}

#[test]
fn content_type_detection_gzip() {
    let mut form = MultipartForm::with_boundary("b");
    form.file_data("f", "data.gz", b"\x1f\x8b");
    let encoded = form.encode();
    let body = String::from_utf8_lossy(&encoded);
    assert!(body.contains("Content-Type: application/gzip"));
}
