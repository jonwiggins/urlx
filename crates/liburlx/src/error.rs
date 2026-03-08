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

    /// A transfer error with a numeric code (maps to `CURLcode`).
    #[error("transfer error (code {code}): {message}")]
    Transfer {
        /// The error code.
        code: u32,
        /// A human-readable error message.
        message: String,
    },
}

#[cfg(test)]
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
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
