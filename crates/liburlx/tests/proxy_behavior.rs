//! Proxy behavior tests.
//!
//! Tests proxy URL validation, noproxy bypass patterns, and proxy
//! configuration on the Easy handle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

// --- Proxy URL validation ---

#[test]
fn proxy_valid_http_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("http://proxy.example.com:3128").is_ok());
}

#[test]
fn proxy_valid_socks5_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("socks5://proxy.example.com:1080").is_ok());
}

#[test]
fn proxy_valid_socks4_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("socks4://proxy:1080").is_ok());
}

#[test]
fn proxy_valid_socks5h_url() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("socks5h://proxy:1080").is_ok());
}

#[test]
fn proxy_invalid_url_rejected() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("not a valid url").is_err());
}

#[test]
fn proxy_empty_url_rejected() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("").is_err());
}

// --- Noproxy configuration ---

#[test]
fn noproxy_set_appears_in_debug() {
    let mut easy = liburlx::Easy::new();
    easy.noproxy("localhost,127.0.0.1,.internal.com");
    let debug = format!("{easy:?}");
    assert!(debug.contains("noproxy: Some"));
}

#[test]
fn noproxy_with_wildcard() {
    let mut easy = liburlx::Easy::new();
    easy.noproxy("*");
    let debug = format!("{easy:?}");
    assert!(debug.contains("noproxy: Some"));
}

// --- Proxy appears in debug ---

#[test]
fn proxy_appears_in_debug() {
    let mut easy = liburlx::Easy::new();
    easy.proxy("http://proxy:8080").unwrap();
    let debug = format!("{easy:?}");
    assert!(debug.contains("proxy"));
}

// --- Proxy with auth in URL ---

#[test]
fn proxy_with_credentials_accepted() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("http://user:pass@proxy:8080").is_ok());
}

#[test]
fn socks5_proxy_with_credentials_accepted() {
    let mut easy = liburlx::Easy::new();
    assert!(easy.proxy("socks5://user:pass@proxy:1080").is_ok());
}

// --- Resolve overrides ---

#[test]
fn resolve_override_set() {
    let mut easy = liburlx::Easy::new();
    easy.resolve("example.com:80", "127.0.0.1:8080");
    let debug = format!("{easy:?}");
    assert!(debug.contains("resolve_overrides"));
}

#[test]
fn multiple_resolve_overrides() {
    let mut easy = liburlx::Easy::new();
    easy.resolve("a.com:80", "127.0.0.1:8001");
    easy.resolve("b.com:80", "127.0.0.1:8002");
    let debug = format!("{easy:?}");
    assert!(debug.contains("resolve_overrides"));
}

// --- HSTS enable/disable via Easy ---

#[test]
fn hsts_enabled_appears_in_debug() {
    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: Some"));
}

#[test]
fn hsts_disabled_appears_in_debug() {
    let mut easy = liburlx::Easy::new();
    easy.hsts(true);
    easy.hsts(false);
    let debug = format!("{easy:?}");
    assert!(debug.contains("hsts_cache: None"));
}

// --- Range/Resume ---

#[test]
fn range_set_appears_in_debug() {
    let mut easy = liburlx::Easy::new();
    easy.range("0-999");
    let debug = format!("{easy:?}");
    assert!(debug.contains("range: Some"));
}

#[test]
fn resume_from_sets_range() {
    let mut easy = liburlx::Easy::new();
    easy.resume_from(500);
    let debug = format!("{easy:?}");
    assert!(debug.contains("range: Some"));
}
