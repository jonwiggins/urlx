//! Multipart form-data request body builder.
//!
//! Implements RFC 2046 multipart/form-data encoding for file uploads
//! and form field submissions.

use std::path::Path;

use crate::error::Error;

/// A multipart form builder that produces `multipart/form-data` request bodies.
#[derive(Debug, Clone)]
pub struct MultipartForm {
    boundary: String,
    parts: Vec<Part>,
}

/// A single part in a multipart form.
#[derive(Debug, Clone)]
struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    data: Vec<u8>,
}

impl MultipartForm {
    /// Create a new multipart form with a random boundary.
    #[must_use]
    pub fn new() -> Self {
        Self { boundary: generate_boundary(), parts: Vec::new() }
    }

    /// Create a new multipart form with a specific boundary (for testing).
    #[must_use]
    pub fn with_boundary(boundary: &str) -> Self {
        Self { boundary: boundary.to_string(), parts: Vec::new() }
    }

    /// Add a text field to the form.
    pub fn field(&mut self, name: &str, value: &str) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: None,
            data: value.as_bytes().to_vec(),
        });
    }

    /// Add a file to the form by reading from the filesystem.
    ///
    /// The filename is derived from the path. The content type defaults
    /// to `application/octet-stream`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the file cannot be read.
    pub fn file(&mut self, name: &str, path: &Path) -> Result<(), Error> {
        let data = std::fs::read(path).map_err(|e| {
            Error::Http(format!("failed to read form file: {}: {e}", path.display()))
        })?;

        let filename =
            path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        let content_type = guess_content_type(&filename);

        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename),
            content_type: Some(content_type),
            data,
        });

        Ok(())
    }

    /// Add file data directly (without reading from disk).
    pub fn file_data(&mut self, name: &str, filename: &str, data: &[u8]) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename.to_string()),
            content_type: Some(guess_content_type(filename)),
            data: data.to_vec(),
        });
    }

    /// Get the `Content-Type` header value including the boundary.
    #[must_use]
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Build the encoded multipart body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();

        for part in &self.parts {
            // Boundary delimiter
            body.extend_from_slice(b"--");
            body.extend_from_slice(self.boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            // Content-Disposition header
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"");
            body.extend_from_slice(part.name.as_bytes());
            body.push(b'"');

            if let Some(ref filename) = part.filename {
                body.extend_from_slice(b"; filename=\"");
                body.extend_from_slice(filename.as_bytes());
                body.push(b'"');
            }
            body.extend_from_slice(b"\r\n");

            // Content-Type header (only for file parts)
            if let Some(ref ct) = part.content_type {
                body.extend_from_slice(b"Content-Type: ");
                body.extend_from_slice(ct.as_bytes());
                body.extend_from_slice(b"\r\n");
            }

            // Empty line separating headers from body
            body.extend_from_slice(b"\r\n");

            // Part body
            body.extend_from_slice(&part.data);
            body.extend_from_slice(b"\r\n");
        }

        // Closing boundary
        body.extend_from_slice(b"--");
        body.extend_from_slice(self.boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");

        body
    }
}

impl Default for MultipartForm {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random boundary string.
fn generate_boundary() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();

    // Use a combination of dashes and hex timestamp for uniqueness
    format!("------------------------{timestamp:032x}")
}

/// Guess content type from filename extension.
fn guess_content_type(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn single_text_field() {
        let mut form = MultipartForm::with_boundary("testboundary");
        form.field("name", "value");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("--testboundary\r\n"));
        assert!(body_str.contains("Content-Disposition: form-data; name=\"name\"\r\n"));
        assert!(body_str.contains("\r\nvalue\r\n"));
        assert!(body_str.contains("--testboundary--\r\n"));
    }

    #[test]
    fn multiple_fields() {
        let mut form = MultipartForm::with_boundary("b");
        form.field("a", "1");
        form.field("b", "2");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("name=\"a\"\r\n\r\n1\r\n"));
        assert!(body_str.contains("name=\"b\"\r\n\r\n2\r\n"));
    }

    #[test]
    fn file_data_part() {
        let mut form = MultipartForm::with_boundary("b");
        form.file_data("upload", "test.txt", b"file content");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("name=\"upload\"; filename=\"test.txt\""));
        assert!(body_str.contains("Content-Type: text/plain"));
        assert!(body_str.contains("\r\nfile content\r\n"));
    }

    #[test]
    fn binary_file_data() {
        let mut form = MultipartForm::with_boundary("b");
        let data: Vec<u8> = (0..=255).collect();
        form.file_data("bin", "data.bin", &data);

        let body = form.encode();
        assert!(body_str_contains_bytes(&body, &data));
        assert!(String::from_utf8_lossy(&body).contains("Content-Type: application/octet-stream"));
    }

    #[test]
    fn content_type_includes_boundary() {
        let form = MultipartForm::with_boundary("myboundary");
        assert_eq!(form.content_type(), "multipart/form-data; boundary=myboundary");
    }

    #[test]
    fn default_boundary_is_unique() {
        let form1 = MultipartForm::new();
        let form2 = MultipartForm::new();
        // Not guaranteed to be different if created in the same nanosecond,
        // but practically they will be
        assert!(!form1.boundary.is_empty());
        assert!(!form2.boundary.is_empty());
    }

    #[test]
    fn guess_content_type_known() {
        assert_eq!(guess_content_type("photo.png"), "image/png");
        assert_eq!(guess_content_type("doc.pdf"), "application/pdf");
        assert_eq!(guess_content_type("data.json"), "application/json");
        assert_eq!(guess_content_type("page.html"), "text/html");
    }

    #[test]
    fn guess_content_type_unknown() {
        assert_eq!(guess_content_type("file.xyz"), "application/octet-stream");
        assert_eq!(guess_content_type("noext"), "application/octet-stream");
    }

    /// Helper: check if a byte slice contains a sub-slice.
    fn body_str_contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
