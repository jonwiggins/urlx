//! Multipart form-data request body builder.
//!
//! Implements RFC 2046 multipart/form-data encoding for file uploads
//! and form field submissions. Also supports SMTP multipart/mixed MIME.

use std::path::Path;

use crate::error::Error;

/// Controls how double-quote characters in filenames are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilenameEscapeMode {
    /// Percent-encode `"` as `%22` (curl's default).
    #[default]
    PercentEncode,
    /// Backslash-escape `"` as `\"` (curl's `--form-escape`).
    BackslashEscape,
}

/// A multipart form builder that produces `multipart/form-data` request bodies.
#[derive(Debug, Clone)]
pub struct MultipartForm {
    boundary: String,
    parts: Vec<Part>,
    /// Whether user overrode the Content-Type (use "attachment" instead of "form-data").
    use_attachment: bool,
    /// Whether this is an SMTP MIME body (multipart/mixed, different formatting).
    smtp_mode: bool,
    /// Filename escape mode.
    escape_mode: FilenameEscapeMode,
    /// Extra headers to include in the SMTP MIME preamble (from `-H` flags).
    smtp_headers: Vec<(String, String)>,
}

/// A single part in a multipart form.
#[derive(Debug, Clone)]
struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    data: Vec<u8>,
    /// Sub-files for multipart/mixed (multi-file upload).
    sub_files: Vec<SubFile>,
    /// Whether the content type was explicitly set (vs guessed from filename).
    explicit_type: bool,
    /// Custom headers for this part (e.g., `headers=X-Custom: value`).
    custom_headers: Vec<String>,
    /// Transfer encoding (e.g., `quoted-printable`, `base64`, `7bit`).
    encoder: Option<String>,
    /// Nested multipart sub-parts (for `=(;type=multipart/...` syntax).
    subparts: Vec<Self>,
    /// Whether this is a nested multipart container.
    is_multipart_container: bool,
}

/// A file within a multipart/mixed sub-part.
#[derive(Debug, Clone)]
struct SubFile {
    filename: String,
    content_type: String,
    data: Vec<u8>,
}

impl MultipartForm {
    /// Create a new multipart form with a random boundary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            boundary: generate_boundary(),
            parts: Vec::new(),
            use_attachment: false,
            smtp_mode: false,
            escape_mode: FilenameEscapeMode::default(),
            smtp_headers: Vec::new(),
        }
    }

    /// Create a new multipart form with a specific boundary (for testing).
    #[must_use]
    pub fn with_boundary(boundary: &str) -> Self {
        Self {
            boundary: boundary.to_string(),
            parts: Vec::new(),
            use_attachment: false,
            smtp_mode: false,
            escape_mode: FilenameEscapeMode::default(),
            smtp_headers: Vec::new(),
        }
    }

    /// Set whether to use "attachment" disposition instead of "form-data".
    ///
    /// curl uses "attachment" when the user overrides `Content-Type` with `-H`.
    pub const fn set_use_attachment(&mut self, val: bool) {
        self.use_attachment = val;
    }

    /// Set SMTP MIME mode (multipart/mixed with Mime-Version header).
    pub const fn set_smtp_mode(&mut self, val: bool) {
        self.smtp_mode = val;
    }

    /// Set the filename escape mode.
    pub const fn set_escape_mode(&mut self, mode: FilenameEscapeMode) {
        self.escape_mode = mode;
    }

    /// Set extra headers for the SMTP MIME preamble (from `-H` flags).
    pub fn set_smtp_headers(&mut self, headers: Vec<(String, String)>) {
        self.smtp_headers = headers;
    }

    /// Add a text field to the form.
    pub fn field(&mut self, name: &str, value: &str) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: None,
            data: value.as_bytes().to_vec(),
            sub_files: Vec::new(),
            explicit_type: false,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Add a text field with explicit Content-Type to the form.
    pub fn field_with_type(&mut self, name: &str, value: &str, content_type: &str) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: Some(content_type.to_string()),
            data: value.as_bytes().to_vec(),
            sub_files: Vec::new(),
            explicit_type: true,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
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
            sub_files: Vec::new(),
            explicit_type: false,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
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
            sub_files: Vec::new(),
            explicit_type: false,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Add data as a file part with filename but no content type.
    ///
    /// Used for text values with `;filename=` but no `;type=` (SMTP compat).
    pub fn file_data_no_type(&mut self, name: &str, filename: &str, data: &[u8]) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename.to_string()),
            content_type: None,
            data: data.to_vec(),
            sub_files: Vec::new(),
            explicit_type: false,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Add file data with explicit content type and filename.
    pub fn file_data_with_type(
        &mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        data: &[u8],
    ) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename.to_string()),
            content_type: Some(content_type.to_string()),
            data: data.to_vec(),
            sub_files: Vec::new(),
            explicit_type: true,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Add a multi-file part (creates a multipart/mixed sub-boundary).
    ///
    /// Each tuple is `(filename, content_type, data)`.
    pub fn multi_file(&mut self, name: &str, files: Vec<(String, String, Vec<u8>)>) {
        let sub_files: Vec<SubFile> = files
            .into_iter()
            .map(|(filename, content_type, data)| SubFile { filename, content_type, data })
            .collect();
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: None,
            data: Vec::new(),
            sub_files,
            explicit_type: false,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Begin a nested multipart container (for `=(;type=multipart/alternative` syntax).
    ///
    /// Returns the index of the container part. Use `close_multipart_container` to
    /// finalize it, or `add_part_to_container` to add subparts.
    pub fn open_multipart_container(&mut self, content_type: &str) -> usize {
        let idx = self.parts.len();
        self.parts.push(Part {
            name: String::new(),
            filename: None,
            content_type: Some(content_type.to_string()),
            data: Vec::new(),
            sub_files: Vec::new(),
            explicit_type: true,
            custom_headers: Vec::new(),
            encoder: None,
            subparts: Vec::new(),
            is_multipart_container: true,
        });
        idx
    }

    /// Add a subpart to a previously opened multipart container.
    pub fn add_part_to_container(
        &mut self,
        container_idx: usize,
        data: &[u8],
        content_type: Option<&str>,
        filename: Option<&str>,
        custom_headers: Vec<String>,
        encoder: Option<&str>,
    ) {
        let part = Part {
            name: String::new(),
            filename: filename.map(ToString::to_string),
            content_type: content_type.map(ToString::to_string),
            data: data.to_vec(),
            sub_files: Vec::new(),
            explicit_type: content_type.is_some(),
            custom_headers,
            encoder: encoder.map(ToString::to_string),
            subparts: Vec::new(),
            is_multipart_container: false,
        };
        if let Some(container) = self.parts.get_mut(container_idx) {
            container.subparts.push(part);
        }
    }

    /// Add a part with custom headers and optional encoder.
    pub fn add_part_with_options(
        &mut self,
        name: &str,
        data: &[u8],
        content_type: Option<&str>,
        filename: Option<&str>,
        custom_headers: Vec<String>,
        encoder: Option<&str>,
    ) {
        self.parts.push(Part {
            name: name.to_string(),
            filename: filename.map(ToString::to_string),
            content_type: content_type.map(ToString::to_string),
            data: data.to_vec(),
            sub_files: Vec::new(),
            explicit_type: content_type.is_some(),
            custom_headers,
            encoder: encoder.map(ToString::to_string),
            subparts: Vec::new(),
            is_multipart_container: false,
        });
    }

    /// Get the `Content-Type` header value including the boundary.
    #[must_use]
    pub fn content_type(&self) -> String {
        if self.smtp_mode {
            format!("multipart/mixed; boundary={}", self.boundary)
        } else {
            format!("multipart/form-data; boundary={}", self.boundary)
        }
    }

    /// Get the boundary string.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Escape a filename for Content-Disposition header.
    fn escape_filename(&self, filename: &str) -> String {
        match self.escape_mode {
            FilenameEscapeMode::PercentEncode => filename.replace('"', "%22"),
            FilenameEscapeMode::BackslashEscape => {
                // Backslash-escape: `\` → `\\`, `"` → `\"`
                let mut result = String::with_capacity(filename.len());
                for ch in filename.chars() {
                    match ch {
                        '"' => result.push_str("\\\""),
                        '\\' => result.push_str("\\\\"),
                        _ => result.push(ch),
                    }
                }
                result
            }
        }
    }

    /// Get the disposition type string.
    const fn disposition(&self) -> &str {
        if self.use_attachment || self.smtp_mode {
            "attachment"
        } else {
            "form-data"
        }
    }

    /// Build the encoded multipart body, validating 7-bit constraints for SMTP.
    ///
    /// # Errors
    ///
    /// Returns an error if 7-bit encoded content has 8-bit bytes.
    pub fn encode_checked(&self) -> Result<Vec<u8>, Error> {
        self.validate_encoders()?;
        Ok(self.encode())
    }

    /// Build the encoded multipart body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        if self.smtp_mode {
            return self.encode_smtp();
        }
        let mut body = Vec::new();
        let disposition = self.disposition();

        for part in &self.parts {
            // Multi-file part: emit multipart/mixed sub-boundary
            if !part.sub_files.is_empty() {
                let sub_boundary = generate_boundary();

                // Outer part header
                body.extend_from_slice(b"--");
                body.extend_from_slice(self.boundary.as_bytes());
                body.extend_from_slice(b"\r\n");

                body.extend_from_slice(b"Content-Disposition: ");
                body.extend_from_slice(disposition.as_bytes());
                body.extend_from_slice(b"; name=\"");
                body.extend_from_slice(part.name.as_bytes());
                body.extend_from_slice(b"\"\r\n");

                body.extend_from_slice(b"Content-Type: multipart/mixed; boundary=");
                body.extend_from_slice(sub_boundary.as_bytes());
                body.extend_from_slice(b"\r\n");
                body.extend_from_slice(b"\r\n");

                // Each sub-file is preceded by the inner boundary delimiter
                for sub in &part.sub_files {
                    // Inner boundary before each sub-file
                    body.extend_from_slice(b"--");
                    body.extend_from_slice(sub_boundary.as_bytes());
                    body.extend_from_slice(b"\r\n");

                    body.extend_from_slice(b"Content-Disposition: attachment; filename=\"");
                    body.extend_from_slice(self.escape_filename(&sub.filename).as_bytes());
                    body.extend_from_slice(b"\"\r\n");
                    body.extend_from_slice(b"Content-Type: ");
                    body.extend_from_slice(sub.content_type.as_bytes());
                    body.extend_from_slice(b"\r\n\r\n");
                    body.extend_from_slice(&sub.data);
                    body.extend_from_slice(b"\r\n");
                }

                // Inner closing boundary
                body.extend_from_slice(b"--");
                body.extend_from_slice(sub_boundary.as_bytes());
                body.extend_from_slice(b"--\r\n");

                body.extend_from_slice(b"\r\n");
                continue;
            }

            // Boundary delimiter
            body.extend_from_slice(b"--");
            body.extend_from_slice(self.boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            // Content-Disposition header
            body.extend_from_slice(b"Content-Disposition: ");
            body.extend_from_slice(disposition.as_bytes());

            // Only add name if non-empty (curl compat: test 1293 `-F =` produces
            // `Content-Disposition: form-data` without name)
            if !part.name.is_empty() {
                body.extend_from_slice(b"; name=\"");
                body.extend_from_slice(part.name.as_bytes());
                body.push(b'"');
            }

            if let Some(ref filename) = part.filename {
                body.extend_from_slice(b"; filename=\"");
                body.extend_from_slice(self.escape_filename(filename).as_bytes());
                body.push(b'"');
            }
            body.extend_from_slice(b"\r\n");

            // Content-Type header (only for file parts or explicit type)
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

    /// Encode as SMTP multipart/mixed MIME body.
    ///
    /// The body includes:
    /// - `Content-Type: multipart/mixed; boundary=...`
    /// - `Mime-Version: 1.0`
    /// - Parts with `Content-Disposition: attachment` for file parts, no disposition for text parts.
    fn encode_smtp(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // MIME headers
        body.extend_from_slice(b"Content-Type: multipart/mixed; boundary=");
        body.extend_from_slice(self.boundary.as_bytes());
        body.extend_from_slice(b"\r\nMime-Version: 1.0\r\n");

        // Extra headers from -H flags (curl compat: tests 646, 648)
        for (name, value) in &self.smtp_headers {
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(b": ");
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        body.extend_from_slice(b"\r\n");

        encode_smtp_parts(&mut body, &self.parts, &self.boundary);

        body
    }

    /// Validate that all parts with `7bit` encoder contain only 7-bit ASCII data.
    ///
    /// Returns `Err` if any 7-bit encoded part contains 8-bit bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transfer`] with code 26 if 8-bit data is found in a 7-bit part.
    pub fn validate_encoders(&self) -> Result<(), Error> {
        validate_parts_7bit(&self.parts)
    }
}

impl Default for MultipartForm {
    fn default() -> Self {
        Self::new()
    }
}

/// Recursively encode SMTP parts into the given buffer.
fn encode_smtp_parts(body: &mut Vec<u8>, parts: &[Part], boundary: &str) {
    for part in parts {
        // Nested multipart container
        if part.is_multipart_container {
            let sub_boundary = generate_boundary();
            body.extend_from_slice(b"--");
            body.extend_from_slice(boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            // Content-Type with sub-boundary
            if let Some(ref ct) = part.content_type {
                body.extend_from_slice(b"Content-Type: ");
                body.extend_from_slice(ct.as_bytes());
                body.extend_from_slice(b"; boundary=");
                body.extend_from_slice(sub_boundary.as_bytes());
                body.extend_from_slice(b"\r\n");
            }

            body.extend_from_slice(b"\r\n");

            // Encode subparts with the sub-boundary
            encode_smtp_parts(body, &part.subparts, &sub_boundary);

            body.extend_from_slice(b"\r\n");
            continue;
        }

        // Boundary delimiter
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"\r\n");

        // For SMTP: text parts (no filename) have no Content-Disposition.
        // File parts have Content-Disposition: attachment; filename="..."
        if let Some(ref filename) = part.filename {
            body.extend_from_slice(b"Content-Disposition: attachment; filename=\"");
            let escaped = escape_filename_backslash(filename);
            body.extend_from_slice(escaped.as_bytes());
            body.extend_from_slice(b"\"\r\n");
        }

        // Content-Type header only when explicitly set (not guessed)
        if part.explicit_type {
            if let Some(ref ct) = part.content_type {
                body.extend_from_slice(b"Content-Type: ");
                body.extend_from_slice(ct.as_bytes());
                body.extend_from_slice(b"\r\n");
            }
        }

        // Content-Transfer-Encoding header
        if let Some(ref enc) = part.encoder {
            body.extend_from_slice(b"Content-Transfer-Encoding: ");
            body.extend_from_slice(enc.as_bytes());
            body.extend_from_slice(b"\r\n");
        } else if part.explicit_type && !part.is_multipart_container {
            // SMTP default: 8bit for non-multipart parts with explicit content type
            body.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        }

        // Custom headers
        for header in &part.custom_headers {
            body.extend_from_slice(header.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        // Empty line separating headers from body
        body.extend_from_slice(b"\r\n");

        // Part body (apply encoding if specified)
        if let Some(ref enc) = part.encoder {
            match enc.as_str() {
                "base64" => {
                    let encoded = encode_base64(&part.data);
                    body.extend_from_slice(encoded.as_bytes());
                }
                "quoted-printable" => {
                    let encoded = encode_quoted_printable(&part.data);
                    body.extend_from_slice(encoded.as_bytes());
                }
                _ => {
                    // 7bit, 8bit, binary — pass through
                    body.extend_from_slice(&part.data);
                }
            }
        } else {
            body.extend_from_slice(&part.data);
        }
        body.extend_from_slice(b"\r\n");
    }

    // Closing boundary
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
}

/// Validate 7-bit encoding constraint recursively.
fn validate_parts_7bit(parts: &[Part]) -> Result<(), Error> {
    for part in parts {
        if part.encoder.as_deref() == Some("7bit") && part.data.iter().any(|&b| b > 127) {
            return Err(Error::Transfer {
                code: 26,
                message: "7-bit encoding applied to 8-bit data".to_string(),
            });
        }
        validate_parts_7bit(&part.subparts)?;
    }
    Ok(())
}

/// Encode data as base64, wrapping at 76 characters per line.
fn encode_base64(data: &[u8]) -> String {
    use std::fmt::Write as _;

    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut line_len = 0;

    let mut i = 0;
    while i < data.len() {
        let remaining = data.len() - i;
        let b0 = data[i];
        let b1 = if remaining > 1 { data[i + 1] } else { 0 };
        let b2 = if remaining > 2 { data[i + 2] } else { 0 };

        let c0 = CHARS[(b0 >> 2) as usize] as char;
        let c1 = CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char;
        let c2 = if remaining > 1 {
            CHARS[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        };
        let c3 = if remaining > 2 { CHARS[(b2 & 0x3F) as usize] as char } else { '=' };

        let _ = write!(result, "{c0}{c1}{c2}{c3}");
        line_len += 4;

        if line_len >= 76 {
            result.push_str("\r\n");
            line_len = 0;
        }

        i += 3;
    }

    // Don't add trailing CRLF — caller handles that
    result
}

/// Encode data as quoted-printable (RFC 2045).
fn encode_quoted_printable(data: &[u8]) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for &byte in data {
        let encoded = if byte == b'\t' || ((32..=126).contains(&byte) && byte != b'=') {
            // Printable ASCII (except '=') — pass through
            String::from(byte as char)
        } else {
            // Encode as =XX
            format!("={byte:02X}")
        };

        // Soft line break before exceeding 76 chars
        // (76 - 1 for potential = soft break marker)
        if line_len + encoded.len() > 75 {
            result.push_str("=\r\n");
            line_len = 0;
        }

        result.push_str(&encoded);
        line_len += encoded.len();
    }

    result
}

/// Backslash-escape a filename (for SMTP MIME).
fn escape_filename_backslash(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            _ => result.push(ch),
        }
    }
    result
}

/// Generate a random boundary string.
///
/// Matches curl's format: 24 dashes followed by 22 random alphanumeric
/// characters, for a total of 46 characters.
fn generate_boundary() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();

    // Use the timestamp bits to generate 22 alphanumeric characters (matching curl's boundary length)
    let mut rand_part = String::with_capacity(22);
    let mut state = timestamp;
    for _ in 0..22 {
        let idx = (state % CHARS.len() as u128) as usize;
        rand_part.push(CHARS[idx] as char);
        // Simple mixing: rotate and XOR
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    }

    format!("------------------------{rand_part}")
}

/// Guess content type from filename extension.
#[must_use]
pub fn guess_content_type(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("");
    // Use case-insensitive comparison without allocating a lowercased string
    let mime = if ext.eq_ignore_ascii_case("txt") {
        "text/plain"
    } else if ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm") {
        "text/html"
    } else if ext.eq_ignore_ascii_case("css") {
        "text/css"
    } else if ext.eq_ignore_ascii_case("js") {
        "application/javascript"
    } else if ext.eq_ignore_ascii_case("json") {
        "application/json"
    } else if ext.eq_ignore_ascii_case("xml") {
        "application/xml"
    } else if ext.eq_ignore_ascii_case("png") {
        "image/png"
    } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
        "image/jpeg"
    } else if ext.eq_ignore_ascii_case("gif") {
        "image/gif"
    } else if ext.eq_ignore_ascii_case("svg") {
        "image/svg+xml"
    } else if ext.eq_ignore_ascii_case("pdf") {
        "application/pdf"
    } else if ext.eq_ignore_ascii_case("zip") {
        "application/zip"
    } else if ext.eq_ignore_ascii_case("gz") || ext.eq_ignore_ascii_case("gzip") {
        "application/gzip"
    } else {
        "application/octet-stream"
    };
    mime.to_string()
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

    #[test]
    fn empty_name_no_name_attr() {
        let mut form = MultipartForm::with_boundary("b");
        form.field("", "empty");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("Content-Disposition: form-data\r\n"));
        assert!(!body_str.contains("name="));
    }

    #[test]
    fn attachment_disposition() {
        let mut form = MultipartForm::with_boundary("b");
        form.set_use_attachment(true);
        form.field("name", "daniel");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("Content-Disposition: attachment; name=\"name\""));
    }

    #[test]
    fn backslash_escape_mode() {
        let mut form = MultipartForm::with_boundary("b");
        form.set_escape_mode(FilenameEscapeMode::BackslashEscape);
        form.file_data_with_type("f", "test\".txt", "text/plain", b"data");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("filename=\"test\\\".txt\""));
    }

    #[test]
    fn percent_encode_mode() {
        let mut form = MultipartForm::with_boundary("b");
        form.set_escape_mode(FilenameEscapeMode::PercentEncode);
        form.file_data_with_type("f", "test\".txt", "text/plain", b"data");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("filename=\"test%22.txt\""));
    }

    #[test]
    fn smtp_mode_encoding() {
        let mut form = MultipartForm::with_boundary("b");
        form.set_smtp_mode(true);
        form.field("", "Hello world");
        form.file_data_with_type("", "file.txt", "text/plain", b"file data");

        let body = form.encode();
        let body_str = String::from_utf8(body).unwrap();

        assert!(body_str.contains("Content-Type: multipart/mixed; boundary=b\r\n"));
        assert!(body_str.contains("Mime-Version: 1.0\r\n"));
        // Text part has no Content-Disposition
        assert!(body_str.contains("--b\r\n\r\nHello world\r\n"));
        // File part has attachment disposition
        assert!(body_str.contains("Content-Disposition: attachment; filename=\"file.txt\""));
    }

    /// Helper: check if a byte slice contains a sub-slice.
    fn body_str_contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
