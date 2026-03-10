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
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
