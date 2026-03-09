//! Property-based tests for URL parsing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

proptest! {
    /// Any URL that parses successfully re-parses to the same string.
    #[test]
    fn url_roundtrip(s in "https?://[a-z]{1,20}\\.[a-z]{2,6}/[a-z0-9/]{0,50}") {
        if let Ok(parsed) = liburlx::Url::parse(&s) {
            let reparsed = liburlx::Url::parse(parsed.as_str()).unwrap();
            prop_assert_eq!(parsed.as_str(), reparsed.as_str());
        }
    }

    /// Scheme is always lowercase after parsing.
    #[test]
    fn scheme_always_lowercase(s in "(HTTP|HTTPS|http|https|Http|Https)://example\\.com/") {
        let parsed = liburlx::Url::parse(&s).unwrap();
        let scheme = parsed.scheme();
        prop_assert_eq!(scheme, scheme.to_lowercase());
    }

    /// Host is always lowercase after parsing.
    #[test]
    fn host_always_lowercase(
        host in "[A-Za-z]{1,15}\\.[A-Za-z]{2,6}"
    ) {
        let url_str = format!("http://{host}/");
        if let Ok(parsed) = liburlx::Url::parse(&url_str) {
            if let Some(h) = parsed.host_str() {
                prop_assert_eq!(h, h.to_lowercase());
            }
        }
    }

    /// Port values are in the valid range 0-65535.
    /// Default ports (80 for HTTP, 443 for HTTPS) are normalized to None by the url crate.
    #[test]
    fn port_in_valid_range(port in 0u16..=65535u16) {
        let url_str = format!("http://example.com:{port}/");
        let parsed = liburlx::Url::parse(&url_str).unwrap();
        if port == 80 {
            // Default HTTP port is normalized away
            prop_assert_eq!(parsed.port(), None);
        } else {
            prop_assert_eq!(parsed.port(), Some(port));
        }
        // port_or_default always returns the port
        prop_assert_eq!(parsed.port_or_default(), Some(port));
    }

    /// URLs with query strings preserve the query.
    #[test]
    fn query_preserved(
        path in "/[a-z]{0,10}",
        query in "[a-z]{1,5}=[a-z0-9]{1,10}"
    ) {
        let url_str = format!("http://example.com{path}?{query}");
        let parsed = liburlx::Url::parse(&url_str).unwrap();
        prop_assert_eq!(parsed.query(), Some(query.as_str()));
    }

    /// URLs with fragments preserve the fragment.
    #[test]
    fn fragment_preserved(frag in "[a-z]{1,20}") {
        let url_str = format!("http://example.com/#{frag}");
        let parsed = liburlx::Url::parse(&url_str).unwrap();
        prop_assert_eq!(parsed.fragment(), Some(frag.as_str()));
    }

    /// Empty string always fails to parse.
    #[test]
    fn empty_always_fails(s in "[ \t\n]*") {
        // Pure whitespace should either fail or default to http scheme
        // Empty string specifically must fail
        if s.is_empty() {
            prop_assert!(liburlx::Url::parse(&s).is_err());
        }
    }

    /// No-scheme URLs default to HTTP.
    #[test]
    fn no_scheme_defaults_http(host in "[a-z]{1,10}\\.[a-z]{2,4}") {
        let parsed = liburlx::Url::parse(&host).unwrap();
        prop_assert_eq!(parsed.scheme(), "http");
    }

    /// Credentials in URL are extracted correctly.
    #[test]
    fn credentials_roundtrip(
        user in "[a-z]{1,8}",
        pass in "[a-z0-9]{1,8}"
    ) {
        let url_str = format!("http://{user}:{pass}@example.com/");
        let parsed = liburlx::Url::parse(&url_str).unwrap();
        let (u, p) = parsed.credentials().unwrap();
        prop_assert_eq!(u, user.as_str());
        prop_assert_eq!(p, pass.as_str());
    }

    /// `host_and_port()` always returns the default port for HTTP/HTTPS.
    #[test]
    fn http_default_port_80(host in "[a-z]{1,10}\\.com") {
        let url_str = format!("http://{host}/");
        let parsed = liburlx::Url::parse(&url_str).unwrap();
        let (_h, port) = parsed.host_and_port().unwrap();
        prop_assert_eq!(port, 80);
    }

    /// `request_target()` always starts with `/`.
    #[test]
    fn request_target_starts_with_slash(
        path in "(/[a-z]{0,10}){0,5}"
    ) {
        let url_str = format!("http://example.com{path}");
        if let Ok(parsed) = liburlx::Url::parse(&url_str) {
            let target = parsed.request_target();
            prop_assert!(target.starts_with('/'), "target was: {}", target);
        }
    }
}
