//! `file://` protocol handler.
//!
//! Reads local files and returns their contents as a response body.

use std::collections::HashMap;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Read a local file and return it as a response.
///
/// The URL path is used as the filesystem path. Percent-encoded characters
/// are decoded (e.g., `%20` → space). If `resume_offset` is specified, the
/// file is read starting from that byte offset.
///
/// # Errors
///
/// Returns [`Error::FileError`] if the file cannot be read.
pub fn read_file(
    url: &crate::url::Url,
    range_start: Option<u64>,
    range_end: Option<u64>,
) -> Result<Response, Error> {
    let path = url.path();

    // Decode percent-encoded characters in the path
    let decoded_path = percent_decode(path);

    // On Windows, file:// URLs produce paths like "/C:/..." which need
    // the leading slash stripped to form a valid Windows path.
    #[cfg(windows)]
    let decoded_path = strip_windows_leading_slash(&decoded_path);

    let data = std::fs::read(&decoded_path)
        .map_err(|e| Error::FileError(format!("{decoded_path}: {e}")))?;

    // Apply byte range (e.g. -r 2-5 or resume from offset)
    #[allow(clippy::cast_possible_truncation)]
    let data = match (range_start, range_end) {
        (Some(start), Some(end)) => {
            let s = start as usize;
            let e = (end as usize).min(data.len().saturating_sub(1));
            if s <= e && s < data.len() {
                data[s..=e].to_vec()
            } else {
                // Range start beyond file size — curl returns error 36
                // (CURLE_BAD_DOWNLOAD_RESUME) for invalid ranges on file://
                return Err(Error::Transfer {
                    code: 36,
                    message: "Couldn't resume download".to_string(),
                });
            }
        }
        (Some(start), None) => {
            let s = start as usize;
            if s < data.len() {
                data[s..].to_vec()
            } else {
                // Range start beyond file size (curl compat: test 1063)
                return Err(Error::Transfer {
                    code: 36,
                    message: "Couldn't resume download".to_string(),
                });
            }
        }
        _ => data,
    };

    let mut headers = HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Write data to a local file (file:// upload / PUT).
///
/// The URL path is used as the filesystem path. Percent-encoded characters
/// are decoded.
///
/// # Errors
///
/// Returns [`Error::FileError`] if the file cannot be written.
pub fn write_file(url: &crate::url::Url, data: &[u8]) -> Result<Response, Error> {
    let path = url.path();
    let decoded_path = percent_decode(path);

    #[cfg(windows)]
    let decoded_path = strip_windows_leading_slash(&decoded_path);

    std::fs::write(&decoded_path, data).map_err(Error::Io)?;

    let headers = HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

/// Strip the leading slash from Windows drive-letter paths.
///
/// `file://` URLs produce paths like `/C:/Users/...` which need the leading
/// slash removed to form valid Windows filesystem paths.
#[cfg(windows)]
fn strip_windows_leading_slash(path: &str) -> String {
    let bytes = path.as_bytes();
    // Match "/X:" or "/X|" where X is a drive letter
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        path[1..].to_string()
    } else {
        path.to_string()
    }
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
        assert!(read_file(&url, None, None).is_err());
    }
}
