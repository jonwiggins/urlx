//! HTTP response representation.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// The HTTP version actually used in a response.
///
/// Unlike [`HttpVersion`](crate::HttpVersion) which represents the *requested*
/// protocol version, this enum represents the version that was actually
/// negotiated and used for the transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseHttpVersion {
    /// HTTP version unknown or not applicable (e.g., non-HTTP protocols).
    #[default]
    Unknown,
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl fmt::Display for ResponseHttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "0"),
            Self::Http10 => write!(f, "1.0"),
            Self::Http11 => write!(f, "1.1"),
            Self::Http2 => write!(f, "2"),
            Self::Http3 => write!(f, "3"),
        }
    }
}

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
    /// The HTTP reason phrase from the status line (e.g., "OK", "Not Found").
    /// Preserves the server's original text. `None` if no reason was sent.
    status_reason: Option<String>,
    /// The HTTP version used in the response.
    http_version: ResponseHttpVersion,
    /// Response headers (lowercase keys for lookup).
    headers: HashMap<String, String>,
    /// Original header names preserving server casing (lowercase → original).
    header_original_names: HashMap<String, String>,
    /// Headers in wire order with original casing. Preserves duplicates.
    headers_ordered: Vec<(String, String)>,
    /// Whether the response used CRLF (`true`) or bare LF (`false`) line endings.
    uses_crlf: bool,
    /// Trailer headers from chunked transfer encoding.
    trailers: HashMap<String, String>,
    /// Response body bytes.
    body: Vec<u8>,
    /// The effective URL after any redirects.
    effective_url: String,
    /// Transfer timing and metadata.
    info: TransferInfo,
    /// HTTP/2 server-pushed responses received during this transfer.
    pushed_responses: Vec<PushedResponse>,
    /// Intermediate redirect responses (for `-L --include` output).
    redirect_responses: Vec<Self>,
    /// Error message from body reading (e.g., bad chunked encoding).
    /// When set, the response is partial — headers are valid but the body
    /// may be incomplete. Used to output partial data on error (curl compat).
    body_error: Option<String>,
}

/// An HTTP/2 server-pushed response.
///
/// Represents a resource that the server proactively sent via HTTP/2 server push
/// (`PUSH_PROMISE` frame). Contains the promised request URL and the pushed response.
#[derive(Debug, Clone)]
pub struct PushedResponse {
    /// The URL of the pushed resource (from the `PUSH_PROMISE` request headers).
    pub url: String,
    /// HTTP status code of the pushed response.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
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
        Self {
            status,
            status_reason: None,
            http_version: ResponseHttpVersion::default(),
            headers,
            header_original_names: HashMap::new(),
            headers_ordered: Vec::new(),
            uses_crlf: true,
            trailers: HashMap::new(),
            body,
            effective_url,
            info: TransferInfo::default(),
            pushed_responses: Vec::new(),
            redirect_responses: Vec::new(),
            body_error: None,
        }
    }

    /// Create a new response with transfer info.
    #[must_use]
    pub fn with_info(
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        effective_url: String,
        info: TransferInfo,
    ) -> Self {
        Self {
            status,
            status_reason: None,
            http_version: ResponseHttpVersion::default(),
            headers,
            header_original_names: HashMap::new(),
            headers_ordered: Vec::new(),
            uses_crlf: true,
            trailers: HashMap::new(),
            body,
            effective_url,
            info,
            pushed_responses: Vec::new(),
            redirect_responses: Vec::new(),
            body_error: None,
        }
    }

    /// Set the original header name casing map (lowercase → original).
    pub fn set_header_original_names(&mut self, names: HashMap<String, String>) {
        self.header_original_names = names;
    }

    /// Returns the original header names map (lowercase → original casing).
    #[must_use]
    pub const fn header_original_names(&self) -> &HashMap<String, String> {
        &self.header_original_names
    }

    /// Set headers in wire order with original casing (preserves duplicates).
    pub fn set_headers_ordered(&mut self, ordered: Vec<(String, String)>) {
        self.headers_ordered = ordered;
    }

    /// Returns headers in wire order with original casing.
    ///
    /// Empty if not set (e.g., non-HTTP protocols).
    #[must_use]
    pub fn headers_ordered(&self) -> &[(String, String)] {
        &self.headers_ordered
    }

    /// Whether the response used CRLF line endings (vs bare LF).
    #[must_use]
    pub const fn uses_crlf(&self) -> bool {
        self.uses_crlf
    }

    /// Set whether the response used CRLF line endings.
    pub const fn set_uses_crlf(&mut self, uses_crlf: bool) {
        self.uses_crlf = uses_crlf;
    }

    /// Set trailer headers on this response.
    pub fn set_trailers(&mut self, trailers: HashMap<String, String>) {
        self.trailers = trailers;
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the HTTP reason phrase from the status line (e.g., "OK").
    #[must_use]
    pub fn status_reason(&self) -> Option<&str> {
        self.status_reason.as_deref()
    }

    /// Set the HTTP reason phrase from the status line.
    pub fn set_status_reason(&mut self, reason: Option<String>) {
        self.status_reason = reason;
    }

    /// Returns the HTTP version used in the response.
    #[must_use]
    pub const fn http_version(&self) -> ResponseHttpVersion {
        self.http_version
    }

    /// Set the HTTP version used in the response.
    pub const fn set_http_version(&mut self, version: ResponseHttpVersion) {
        self.http_version = version;
    }

    /// Returns the response headers.
    #[must_use]
    pub const fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Returns a specific header value (case-insensitive lookup).
    ///
    /// Headers are stored lowercase, so this avoids allocation when the
    /// caller passes a lowercase name (common case).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        // Fast path: try direct lookup first (works when name is already lowercase)
        if let Some(v) = self.headers.get(name) {
            return Some(v.as_str());
        }
        // Slow path: lowercase and retry (only allocates if direct lookup missed)
        let lower = name.to_lowercase();
        if lower == name {
            None
        } else {
            self.headers.get(&lower).map(String::as_str)
        }
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

    /// Returns the trailer headers from chunked transfer encoding.
    #[must_use]
    pub const fn trailers(&self) -> &HashMap<String, String> {
        &self.trailers
    }

    /// Returns a specific trailer header value (case-insensitive lookup).
    #[must_use]
    pub fn trailer(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.trailers.get(&lower).map(String::as_str)
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
    pub const fn set_transfer_info(&mut self, info: TransferInfo) {
        self.info = info;
    }

    /// Returns HTTP/2 server-pushed responses received during this transfer.
    #[must_use]
    pub fn pushed_responses(&self) -> &[PushedResponse] {
        &self.pushed_responses
    }

    /// Set pushed responses on this response.
    pub fn set_pushed_responses(&mut self, pushed: Vec<PushedResponse>) {
        self.pushed_responses = pushed;
    }

    /// Returns intermediate redirect responses in the chain.
    #[must_use]
    pub fn redirect_responses(&self) -> &[Self] {
        &self.redirect_responses
    }

    /// Add an intermediate redirect response to the chain.
    pub fn push_redirect_response(&mut self, resp: Self) {
        self.redirect_responses.push(resp);
    }

    /// Set intermediate redirect responses.
    pub fn set_redirect_responses(&mut self, resps: Vec<Self>) {
        self.redirect_responses = resps;
    }

    /// Returns the body error message, if any.
    ///
    /// When set, the response is partial — headers are valid but the body
    /// may be incomplete. The caller should output available data and then
    /// return the appropriate error exit code.
    #[must_use]
    pub fn body_error(&self) -> Option<&str> {
        self.body_error.as_deref()
    }

    /// Set a body error message (for partial responses).
    pub fn set_body_error(&mut self, error: Option<String>) {
        self.body_error = error;
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

    #[test]
    fn response_trailers_empty_by_default() {
        let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        assert!(resp.trailers().is_empty());
        assert!(resp.trailer("X-Foo").is_none());
    }

    #[test]
    fn response_trailers_set_and_get() {
        let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        let mut trailers = HashMap::new();
        trailers.insert("x-checksum".to_string(), "abc123".to_string());
        trailers.insert("x-timestamp".to_string(), "1234567890".to_string());
        resp.set_trailers(trailers);

        assert_eq!(resp.trailer("X-Checksum"), Some("abc123"));
        assert_eq!(resp.trailer("X-Timestamp"), Some("1234567890"));
        assert_eq!(resp.trailers().len(), 2);
    }

    #[test]
    fn response_pushed_responses_empty_by_default() {
        let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        assert!(resp.pushed_responses().is_empty());
    }

    #[test]
    fn response_pushed_responses_set_and_get() {
        let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        let pushed = vec![PushedResponse {
            url: "https://example.com/style.css".to_string(),
            status: 200,
            headers: HashMap::new(),
            body: b"body{color:red}".to_vec(),
        }];
        resp.set_pushed_responses(pushed);
        assert_eq!(resp.pushed_responses().len(), 1);
        assert_eq!(resp.pushed_responses()[0].url, "https://example.com/style.css");
        assert_eq!(resp.pushed_responses()[0].status, 200);
        assert_eq!(resp.pushed_responses()[0].body, b"body{color:red}");
    }

    #[test]
    fn response_trailer_case_insensitive() {
        let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        let mut trailers = HashMap::new();
        trailers.insert("x-custom".to_string(), "value".to_string());
        resp.set_trailers(trailers);

        assert_eq!(resp.trailer("X-Custom"), Some("value"));
        assert_eq!(resp.trailer("x-custom"), Some("value"));
        assert_eq!(resp.trailer("X-CUSTOM"), Some("value"));
    }

    #[test]
    fn response_http_version_default() {
        let resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        assert_eq!(resp.http_version(), ResponseHttpVersion::Unknown);
    }

    #[test]
    fn response_http_version_set_and_get() {
        let mut resp = Response::new(200, HashMap::new(), Vec::new(), String::new());
        resp.set_http_version(ResponseHttpVersion::Http2);
        assert_eq!(resp.http_version(), ResponseHttpVersion::Http2);
    }

    #[test]
    fn response_http_version_display() {
        assert_eq!(ResponseHttpVersion::Unknown.to_string(), "0");
        assert_eq!(ResponseHttpVersion::Http10.to_string(), "1.0");
        assert_eq!(ResponseHttpVersion::Http11.to_string(), "1.1");
        assert_eq!(ResponseHttpVersion::Http2.to_string(), "2");
        assert_eq!(ResponseHttpVersion::Http3.to_string(), "3");
    }

    #[test]
    fn header_lookup_fast_path() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let resp = Response::new(200, headers, Vec::new(), String::new());
        // Fast path: lowercase name hits directly
        assert_eq!(resp.header("content-type"), Some("text/html"));
        // Slow path: mixed case triggers lowercase conversion
        assert_eq!(resp.header("Content-Type"), Some("text/html"));
        // Miss: both paths return None
        assert_eq!(resp.header("x-missing"), None);
        assert_eq!(resp.header("X-Missing"), None);
    }
}
