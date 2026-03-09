//! Easy handle configuration completeness tests.
//!
//! Tests setter methods that haven't been covered by other test files:
//! `max_redirects`, `verbose`, `hsts`, `resolve`, `form_field`,
//! `range`, `resume_from`, `fail_on_error`, and `method_is_default`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::Easy;

// --- max_redirects ---

#[test]
fn max_redirects_default_is_50() {
    let easy = Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 50"), "got: {debug}");
}

#[test]
fn max_redirects_can_be_set() {
    let mut easy = Easy::new();
    easy.max_redirects(10);
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 10"), "got: {debug}");
}

#[test]
fn max_redirects_zero() {
    let mut easy = Easy::new();
    easy.max_redirects(0);
    let debug = format!("{easy:?}");
    assert!(debug.contains("max_redirects: 0"), "got: {debug}");
}

// --- verbose ---

#[test]
fn verbose_default_is_false() {
    let easy = Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("verbose: false"), "got: {debug}");
}

#[test]
fn verbose_can_be_enabled() {
    let mut easy = Easy::new();
    easy.verbose(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("verbose: true"), "got: {debug}");
}

// --- hsts ---

#[test]
fn hsts_default_is_none() {
    let easy = Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: None"), "got: {debug}");
}

#[test]
fn hsts_enable_creates_cache() {
    let mut easy = Easy::new();
    easy.hsts(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("HstsCache"), "got: {debug}");
}

#[test]
fn hsts_disable_removes_cache() {
    let mut easy = Easy::new();
    easy.hsts(true);
    easy.hsts(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: None"), "got: {debug}");
}

// --- resolve ---

#[test]
fn resolve_adds_override() {
    let mut easy = Easy::new();
    easy.resolve("example.com", "127.0.0.1");
    let debug = format!("{easy:?}");
    assert!(debug.contains("example.com"), "got: {debug}");
    assert!(debug.contains("127.0.0.1"), "got: {debug}");
}

#[test]
fn resolve_lowercases_host() {
    let mut easy = Easy::new();
    easy.resolve("EXAMPLE.COM", "127.0.0.1");
    let debug = format!("{easy:?}");
    assert!(debug.contains("example.com"), "got: {debug}");
}

// --- form_field ---

#[test]
fn form_field_creates_multipart() {
    let mut easy = Easy::new();
    easy.form_field("name", "value");
    let debug = format!("{easy:?}");
    assert!(debug.contains("MultipartForm"), "got: {debug}");
}

// --- range ---

#[test]
fn range_sets_value() {
    let mut easy = Easy::new();
    easy.range("0-499");
    let debug = format!("{easy:?}");
    assert!(debug.contains("0-499"), "got: {debug}");
}

#[test]
fn resume_from_sets_range() {
    let mut easy = Easy::new();
    easy.resume_from(1000);
    let debug = format!("{easy:?}");
    assert!(debug.contains("1000-"), "got: {debug}");
}

// --- fail_on_error ---

#[test]
fn fail_on_error_default_is_false() {
    let easy = Easy::new();
    let debug = format!("{easy:?}");
    assert!(debug.contains("fail_on_error: false"), "got: {debug}");
}

#[test]
fn fail_on_error_can_be_enabled() {
    let mut easy = Easy::new();
    easy.fail_on_error(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("fail_on_error: true"), "got: {debug}");
}

// --- method_is_default ---

#[test]
fn method_is_default_initially() {
    let easy = Easy::new();
    assert!(easy.method_is_default());
}

#[test]
fn method_is_not_default_after_set() {
    let mut easy = Easy::new();
    easy.method("POST");
    assert!(!easy.method_is_default());
}

// --- clone preserves config ---

#[test]
fn clone_preserves_settings() {
    let mut easy = Easy::new();
    easy.url("http://example.com").unwrap();
    easy.method("PUT");
    easy.max_redirects(5);
    easy.verbose(true);
    easy.fail_on_error(true);
    easy.range("100-200");

    let cloned = easy.clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("PUT"), "method missing: {debug}");
    assert!(debug.contains("max_redirects: 5"), "max_redirects missing: {debug}");
    assert!(debug.contains("verbose: true"), "verbose missing: {debug}");
    assert!(debug.contains("fail_on_error: true"), "fail_on_error missing: {debug}");
    assert!(debug.contains("100-200"), "range missing: {debug}");
}
