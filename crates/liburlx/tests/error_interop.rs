//! Error type interoperability and pattern matching tests.
//!
//! Tests Error variant construction, pattern matching, Display/Debug
//! formatting edge cases, and `std::error::Error` trait compliance.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error as StdError;
use std::time::Duration;

use liburlx::Error;

// --- Pattern matching exhaustiveness ---

#[test]
fn match_all_variants() {
    let errors: Vec<Error> = vec![
        Error::UrlParse("bad".into()),
        Error::Connect(std::io::Error::other("fail")),
        Error::Tls("tls fail".into()),
        Error::Http("http fail".into()),
        Error::Timeout(Duration::from_secs(1)),
        Error::Transfer { code: 7, message: "connect".into() },
    ];

    for err in &errors {
        // Every variant must produce a non-empty display string
        let msg = err.to_string();
        assert!(!msg.is_empty(), "empty display for {err:?}");
    }
}

// --- Display format specifics ---

#[test]
fn url_parse_display_includes_reason() {
    let err = Error::UrlParse("no scheme found".into());
    assert_eq!(err.to_string(), "URL parse error: no scheme found");
}

#[test]
fn connect_display_includes_io_message() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
    let err = Error::Connect(io_err);
    let msg = err.to_string();
    assert!(msg.contains("connection failed"), "msg: {msg}");
    assert!(msg.contains("connection refused"), "msg: {msg}");
}

#[test]
fn tls_display_includes_inner() {
    let inner: Box<dyn StdError + Send + Sync> = "certificate has expired".into();
    let err = Error::Tls(inner);
    let msg = err.to_string();
    assert!(msg.contains("TLS handshake failed"), "msg: {msg}");
    assert!(msg.contains("certificate has expired"), "msg: {msg}");
}

#[test]
fn http_display_includes_detail() {
    let err = Error::Http("invalid header name".into());
    assert_eq!(err.to_string(), "HTTP protocol error: invalid header name");
}

#[test]
fn timeout_display_millis() {
    let err = Error::Timeout(Duration::from_millis(250));
    let msg = err.to_string();
    assert!(msg.contains("250ms"), "msg: {msg}");
}

#[test]
fn timeout_display_zero() {
    let err = Error::Timeout(Duration::ZERO);
    let msg = err.to_string();
    assert!(msg.contains("timeout"), "msg: {msg}");
}

#[test]
fn transfer_display_code_and_message() {
    let err = Error::Transfer { code: 56, message: "recv failure".into() };
    let msg = err.to_string();
    assert!(msg.contains("56"), "msg: {msg}");
    assert!(msg.contains("recv failure"), "msg: {msg}");
}

// --- Source chain ---

#[test]
fn connect_source_is_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
    let err = Error::Connect(io_err);
    let source = err.source().unwrap();
    assert!(source.to_string().contains("timed out"));
}

#[test]
fn tls_source_is_inner_error() {
    let inner: Box<dyn StdError + Send + Sync> = "cert chain".into();
    let err = Error::Tls(inner);
    let source = err.source().unwrap();
    assert!(source.to_string().contains("cert chain"));
}

#[test]
fn url_parse_has_no_source() {
    let err = Error::UrlParse("bad".into());
    assert!(err.source().is_none());
}

#[test]
fn http_has_no_source() {
    let err = Error::Http("bad".into());
    assert!(err.source().is_none());
}

#[test]
fn timeout_has_no_source() {
    let err = Error::Timeout(Duration::from_secs(5));
    assert!(err.source().is_none());
}

#[test]
fn transfer_has_no_source() {
    let err = Error::Transfer { code: 0, message: String::new() };
    assert!(err.source().is_none());
}

// --- Thread safety ---

#[test]
fn error_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
}

#[test]
fn error_can_cross_thread_boundary() {
    let err = Error::Http("cross-thread".into());
    let handle = std::thread::spawn(move || err.to_string());
    let msg = handle.join().unwrap();
    assert!(msg.contains("cross-thread"));
}

// --- Debug format ---

#[test]
fn debug_all_variants() {
    let variants: Vec<Error> = vec![
        Error::UrlParse("x".into()),
        Error::Connect(std::io::Error::other("x")),
        Error::Tls("x".into()),
        Error::Http("x".into()),
        Error::Timeout(Duration::from_secs(1)),
        Error::Transfer { code: 1, message: "x".into() },
    ];

    for err in &variants {
        let debug = format!("{err:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn debug_connect_contains_variant_name() {
    let err = Error::Connect(std::io::Error::other("test"));
    let debug = format!("{err:?}");
    assert!(debug.contains("Connect"), "debug: {debug}");
}

#[test]
fn debug_transfer_contains_code() {
    let err = Error::Transfer { code: 42, message: "test".into() };
    let debug = format!("{err:?}");
    assert!(debug.contains("42"), "debug: {debug}");
}

// --- Edge cases ---

#[test]
fn empty_string_variants() {
    let url_err = Error::UrlParse(String::new());
    assert!(url_err.to_string().contains("URL parse error: "));

    let http_err = Error::Http(String::new());
    assert!(http_err.to_string().contains("HTTP protocol error: "));

    let transfer_err = Error::Transfer { code: 0, message: String::new() };
    assert!(transfer_err.to_string().contains("transfer error"));
}

#[test]
fn very_long_error_message() {
    let long_msg = "x".repeat(10_000);
    let err = Error::Http(long_msg.clone());
    let display = err.to_string();
    assert!(display.contains(&long_msg));
}

#[test]
fn transfer_code_boundaries() {
    for code in [0, 1, 255, 65535, u32::MAX] {
        let err = Error::Transfer { code, message: "test".into() };
        let msg = err.to_string();
        assert!(msg.contains(&code.to_string()), "code {code} not in msg: {msg}");
    }
}
