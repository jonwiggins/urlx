//! HTTP response representation.

use std::collections::HashMap;
use std::time::Duration;

/// Transfer timing and metadata information.
///
/// Timing fields follow curl's conventions:
/// - `time_namelookup`: DNS resolution completed
/// - `time_connect`: TCP connection established
/// - `time_appconnect`: TLS handshake completed (HTTPS only)
/// - `time_pretransfer`: Ready to send request
/// - `time_starttransfer`: First response byte received
/// - `time_total`: Entire transfer completed
#[derive(Debug, Clone, Default)]
pub struct TransferInfo {
    /// Time from start until DNS name resolution completed.
    pub time_namelookup: Duration,
    /// Time from start until TCP connection was established.
    pub time_connect: Duration,
    /// Time from start until TLS/SSL handshake completed (HTTPS only).
    pub time_appconnect: Duration,
    /// Time from start until the request is ready to be sent.
    pub time_pretransfer: Duration,
    /// Time from start until the first response byte was received.
    pub time_starttransfer: Duration,
    /// Total time for the entire transfer.
    pub time_total: Duration,
    /// Number of redirects followed.
    pub num_redirects: u32,
    /// Average download speed in bytes per second.
    pub speed_download: f64,
    /// Average upload speed in bytes per second.
    pub speed_upload: f64,
    /// Total bytes uploaded.
    pub size_upload: u64,
}

/// An HTTP response with status, headers, and body.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code (e.g., 200, 404).
    status: u16,
    /// Response headers.
    headers: HashMap<String, String>,
    /// Response body bytes.
    body: Vec<u8>,
    /// The effective URL after any redirects.
    effective_url: String,
    /// Transfer timing and metadata.
    info: TransferInfo,
}

impl Response {
    /// Create a new response.
    #[must_use]
    pub fn new(
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        effective_url: String,
    ) -> Self {
        Self { status, headers, body, effective_url, info: TransferInfo::default() }
    }

    /// Create a new response with transfer info.
    #[must_use]
    pub const fn with_info(
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        effective_url: String,
        info: TransferInfo,
    ) -> Self {
        Self { status, headers, body, effective_url, info }
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the response headers.
    #[must_use]
    pub const fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Returns a specific header value (case-insensitive lookup).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers.get(&lower).map(String::as_str)
    }

    /// Returns the response body as bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the response body as a UTF-8 string, if valid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`](crate::Error::Http) if the body is not valid UTF-8.
    pub fn body_str(&self) -> Result<&str, crate::Error> {
        std::str::from_utf8(&self.body)
            .map_err(|e| crate::Error::Http(format!("body is not valid UTF-8: {e}")))
    }

    /// Returns the effective URL (after redirects).
    #[must_use]
    pub fn effective_url(&self) -> &str {
        &self.effective_url
    }

    /// Returns true if this is a redirect response (3xx with Location header).
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.headers.contains_key("location")
    }

    /// Returns the Content-Type header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Returns the size of the response body in bytes.
    #[must_use]
    pub fn size_download(&self) -> usize {
        self.body.len()
    }

    /// Returns the transfer timing and metadata.
    #[must_use]
    pub const fn transfer_info(&self) -> &TransferInfo {
        &self.info
    }

    /// Set the transfer info on this response.
    pub fn set_transfer_info(&mut self, info: TransferInfo) {
        self.info = info;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn response_status() {
        let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn response_header_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let resp = Response::new(200, headers, Vec::new(), String::new());
        assert_eq!(resp.header("Content-Type"), Some("text/html"));
    }

    #[test]
    fn response_body_str() {
        let body = b"hello world".to_vec();
        let resp = Response::new(200, HashMap::new(), body, String::new());
        assert_eq!(resp.body_str().unwrap(), "hello world");
    }

    #[test]
    fn response_body_str_invalid_utf8() {
        let body = vec![0xFF, 0xFE];
        let resp = Response::new(200, HashMap::new(), body, String::new());
        assert!(resp.body_str().is_err());
    }
}
