//! `file://` protocol handler.
//!
//! Reads local files and returns their contents as a response body.

use std::collections::HashMap;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Read a local file and return it as a response.
///
/// The URL path is used as the filesystem path. Percent-encoded characters
/// are decoded (e.g., `%20` → space).
///
/// # Errors
///
/// Returns [`Error::Http`] if the file cannot be read.
pub fn read_file(url: &crate::url::Url) -> Result<Response, Error> {
    let path = url.path();

    // Decode percent-encoded characters in the path
    let decoded_path = percent_decode(path);

    let data = std::fs::read(&decoded_path)
        .map_err(|e| Error::Http(format!("file read failed: {decoded_path}: {e}")))?;

    let mut headers = HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Decode percent-encoded characters in a URL path.
fn percent_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&result).to_string()
}

/// Convert a hex ASCII byte to its numeric value.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_no_encoding() {
        assert_eq!(percent_decode("/path/to/file"), "/path/to/file");
    }

    #[test]
    fn percent_decode_space() {
        assert_eq!(percent_decode("/my%20file.txt"), "/my file.txt");
    }

    #[test]
    fn percent_decode_multiple() {
        assert_eq!(percent_decode("/a%20b%2Fc"), "/a b/c");
    }

    #[test]
    fn percent_decode_incomplete() {
        // Incomplete percent sequence should be left as-is
        assert_eq!(percent_decode("/test%2"), "/test%2");
    }

    #[test]
    fn read_file_nonexistent() {
        let url = crate::url::Url::parse("file:///nonexistent/path").unwrap();
        assert!(read_file(&url).is_err());
    }
}
