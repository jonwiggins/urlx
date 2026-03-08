//! Tests for error type coverage and display formatting.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use liburlx::Error;

// --- All error variants display correctly ---

#[test]
fn url_parse_error_display() {
    let err = Error::UrlParse("missing scheme".to_string());
    let msg = err.to_string();
    assert!(msg.contains("URL parse error"));
    assert!(msg.contains("missing scheme"));
}

#[test]
fn connect_error_display() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err = Error::Connect(io_err);
    let msg = err.to_string();
    assert!(msg.contains("connection failed"));
    assert!(msg.contains("refused"));
}

#[test]
fn tls_error_display() {
    let inner: Box<dyn std::error::Error + Send + Sync> = "cert expired".into();
    let err = Error::Tls(inner);
    let msg = err.to_string();
    assert!(msg.contains("TLS handshake failed"));
    assert!(msg.contains("cert expired"));
}

#[test]
fn http_error_display() {
    let err = Error::Http("invalid status line".to_string());
    let msg = err.to_string();
    assert!(msg.contains("HTTP protocol error"));
    assert!(msg.contains("invalid status line"));
}

#[test]
fn timeout_error_display() {
    let err = Error::Timeout(Duration::from_millis(500));
    let msg = err.to_string();
    assert!(msg.contains("timeout after"));
    assert!(msg.contains("500ms"));
}

#[test]
fn timeout_error_display_seconds() {
    let err = Error::Timeout(Duration::from_secs(10));
    let msg = err.to_string();
    assert!(msg.contains("timeout after"));
    assert!(msg.contains("10s"));
}

#[test]
fn transfer_error_display() {
    let err = Error::Transfer { code: 28, message: "operation timed out".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("transfer error"));
    assert!(msg.contains("code 28"));
    assert!(msg.contains("operation timed out"));
}

// --- Error is Send + Sync ---

#[test]
fn error_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Error>();
}

#[test]
fn error_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<Error>();
}

// --- Error Debug format ---

#[test]
fn error_debug_format() {
    let err = Error::Http("test".to_string());
    let debug = format!("{err:?}");
    assert!(debug.contains("Http"));
    assert!(debug.contains("test"));
}

#[test]
fn url_parse_error_debug() {
    let err = Error::UrlParse("bad url".to_string());
    let debug = format!("{err:?}");
    assert!(debug.contains("UrlParse"));
}

#[test]
fn connect_error_debug() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err = Error::Connect(io_err);
    let debug = format!("{err:?}");
    assert!(debug.contains("Connect"));
}

#[test]
fn transfer_error_debug() {
    let err = Error::Transfer { code: 7, message: "msg".to_string() };
    let debug = format!("{err:?}");
    assert!(debug.contains("Transfer"));
    assert!(debug.contains('7'));
}

// --- Error source chain ---

#[test]
fn connect_error_source() {
    use std::error::Error as StdError;
    let io_err = std::io::Error::other("inner");
    let err = Error::Connect(io_err);
    let source = err.source();
    assert!(source.is_some());
    assert!(source.unwrap().to_string().contains("inner"));
}

#[test]
fn tls_error_source() {
    use std::error::Error as StdError;
    let inner: Box<dyn std::error::Error + Send + Sync> = "tls inner".into();
    let err = Error::Tls(inner);
    let source = err.source();
    assert!(source.is_some());
}

#[test]
fn http_error_no_source() {
    use std::error::Error as StdError;
    let err = Error::Http("test".to_string());
    assert!(err.source().is_none());
}

#[test]
fn url_parse_error_no_source() {
    use std::error::Error as StdError;
    let err = Error::UrlParse("test".to_string());
    assert!(err.source().is_none());
}

#[test]
fn timeout_error_no_source() {
    use std::error::Error as StdError;
    let err = Error::Timeout(Duration::from_secs(1));
    assert!(err.source().is_none());
}
