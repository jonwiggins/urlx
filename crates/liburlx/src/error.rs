//! Error types for liburlx.
//!
//! All errors are represented by the [`Error`] enum, which maps to `CURLcode`
//! values at the FFI boundary.

use std::time::Duration;

/// The main error type for liburlx operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A URL could not be parsed.
    #[error("URL parse error: {0}")]
    UrlParse(String),

    /// A connection could not be established.
    #[error("connection failed: {0}")]
    Connect(#[source] std::io::Error),

    /// A TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// An HTTP protocol error occurred.
    #[error("HTTP protocol error: {0}")]
    Http(String),

    /// The operation timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),

    /// An I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),

    /// A transfer error with a numeric code (maps to `CURLcode`).
    #[error("transfer error (code {code}): {message}")]
    Transfer {
        /// The error code.
        code: u32,
        /// A human-readable error message.
        message: String,
    },

    /// Transfer speed dropped below the minimum threshold for too long.
    /// Maps to `CURLE_OPERATION_TIMEDOUT` (28) at the FFI boundary.
    #[error("transfer speed {speed} B/s below limit {limit} B/s for {duration:?}")]
    SpeedLimit {
        /// The measured speed in bytes/sec.
        speed: u64,
        /// The configured minimum speed in bytes/sec.
        limit: u64,
        /// How long the speed has been below the limit.
        duration: Duration,
    },

    /// An SSH protocol error occurred.
    #[error("SSH error: {0}")]
    Ssh(String),

    /// An authentication error occurred.
    #[error("authentication error: {0}")]
    Auth(String),

    /// The protocol scheme is not supported.
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// DNS name resolution failed.
    #[error("could not resolve host: {0}")]
    DnsResolve(String),

    /// A file:// protocol read or write failed.
    #[error("file read/write error: {0}")]
    FileError(String),

    /// Body read failed with partial data available.
    /// The `partial_body` contains whatever was successfully decoded before
    /// the error (e.g., valid chunks before an invalid chunk size).
    #[error("partial body error: {message}")]
    PartialBody {
        /// Error description.
        message: String,
        /// Body data decoded before the error.
        partial_body: Vec<u8>,
    },

    /// An SMTP authentication error (maps to `CURLE_LOGIN_DENIED` = 67).
    #[error("SMTP auth error: {0}")]
    SmtpAuth(String),

    /// An SMTP send error (maps to `CURLE_SEND_ERROR` = 55).
    #[error("SMTP send error: {0}")]
    SmtpSend(String),

    /// A generic protocol error with a curl error code.
    #[error("protocol error (code {0})")]
    Protocol(u32),

    /// A URL glob pattern error with position info (curl-compatible format).
    /// Formats as:
    /// ```text
    /// bad range in URL position 47:
    /// http://example.com/[2-1]
    ///                         ^
    /// ```
    #[error("{}", format_url_glob_error(message, url, *position))]
    UrlGlob {
        /// Error message (e.g., "bad range in URL position 47:").
        message: String,
        /// The original URL pattern.
        url: String,
        /// Character position (0-indexed) for the caret indicator.
        position: usize,
    },
}

/// Format a URL glob error with position caret.
fn format_url_glob_error(message: &str, url: &str, position: usize) -> String {
    if url.is_empty() {
        return message.to_string();
    }
    format!("{message}\n{url}\n{:>width$}", "^", width = position + 1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn error_display_url_parse() {
        let err = Error::UrlParse("missing scheme".to_string());
        assert_eq!(err.to_string(), "URL parse error: missing scheme");
    }

    #[test]
    fn error_display_timeout() {
        let err = Error::Timeout(Duration::from_secs(30));
        assert_eq!(err.to_string(), "timeout after 30s");
    }

    #[test]
    fn error_display_transfer() {
        let err = Error::Transfer { code: 7, message: "connection refused".to_string() };
        assert_eq!(err.to_string(), "transfer error (code 7): connection refused");
    }

    #[test]
    fn error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::Io(io_err);
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn error_display_speed_limit() {
        let err = Error::SpeedLimit { speed: 50, limit: 100, duration: Duration::from_secs(10) };
        assert_eq!(err.to_string(), "transfer speed 50 B/s below limit 100 B/s for 10s");
    }

    #[test]
    fn error_display_ssh() {
        let err = Error::Ssh("authentication failed".to_string());
        assert_eq!(err.to_string(), "SSH error: authentication failed");
    }

    #[test]
    fn error_display_auth() {
        let err = Error::Auth("SCRAM nonce mismatch".to_string());
        assert_eq!(err.to_string(), "authentication error: SCRAM nonce mismatch");
    }

    #[test]
    fn error_display_unsupported_protocol() {
        let err = Error::UnsupportedProtocol("gopher".to_string());
        assert_eq!(err.to_string(), "unsupported protocol: gopher");
    }

    #[test]
    fn error_display_dns_resolve() {
        let err = Error::DnsResolve("nonexistent.example.com".to_string());
        assert_eq!(err.to_string(), "could not resolve host: nonexistent.example.com");
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
