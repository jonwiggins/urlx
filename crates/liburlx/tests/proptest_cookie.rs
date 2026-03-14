//! Property-based tests for the cookie engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

proptest! {
    /// A cookie stored with a valid name/value can be retrieved.
    #[test]
    fn cookie_roundtrip(
        name in "[a-zA-Z][a-zA-Z0-9]{0,15}",
        value in "[a-zA-Z0-9]{1,30}"
    ) {
        let mut jar = liburlx::CookieJar::new();
        let header = format!("{name}={value}");
        jar.store_cookies(&[&header], "example.com", "/", true);
        let cookie = jar.cookie_header("example.com", "/", false);
        prop_assert!(cookie.is_some(), "cookie should be retrievable");
        let cookie = cookie.unwrap();
        prop_assert!(cookie.contains(&format!("{name}={value}")),
            "cookie header '{}' should contain '{name}={value}'", cookie);
    }

    /// Empty cookie names are always rejected.
    #[test]
    fn empty_name_rejected(value in "[a-zA-Z0-9]{1,20}") {
        let mut jar = liburlx::CookieJar::new();
        let header = format!("={value}");
        jar.store_cookies(&[&header], "example.com", "/", true);
        prop_assert!(jar.is_empty(), "empty name should be rejected");
    }

    /// Cookies with no `=` separator are always rejected.
    #[test]
    fn no_equals_rejected(s in "[a-zA-Z]{1,20}") {
        let mut jar = liburlx::CookieJar::new();
        jar.store_cookies(&[s.as_str()], "example.com", "/", true);
        prop_assert!(jar.is_empty(), "no-equals cookie should be rejected");
    }

    /// `Max-Age=0` always results in an expired cookie after cleanup.
    #[test]
    fn max_age_zero_expires(
        name in "[a-zA-Z]{1,10}",
        value in "[a-zA-Z0-9]{1,10}"
    ) {
        let mut jar = liburlx::CookieJar::new();
        let header = format!("{name}={value}; Max-Age=0");
        jar.store_cookies(&[&header], "example.com", "/", true);
        jar.remove_expired();
        prop_assert!(jar.is_empty(), "Max-Age=0 cookie should be expired");
    }

    /// Overwriting a cookie replaces the old value.
    #[test]
    fn overwrite_replaces(
        name in "[a-zA-Z]{1,10}",
        old_value in "[a-z]{1,10}",
        new_value in "[A-Z]{1,10}"
    ) {
        let mut jar = liburlx::CookieJar::new();
        jar.store_cookies(
            &[&format!("{name}={old_value}")],
            "example.com",
            "/",
            true,
        );
        jar.store_cookies(
            &[&format!("{name}={new_value}")],
            "example.com",
            "/",
            true,
        );
        prop_assert_eq!(jar.len(), 1);
        let cookie = jar.cookie_header("example.com", "/", false).unwrap();
        let expected = format!("{name}={new_value}");
        prop_assert_eq!(cookie, expected);
    }

    /// Domain matching is case-insensitive.
    #[test]
    fn domain_case_insensitive(
        name in "[a-zA-Z]{1,10}",
        value in "[a-zA-Z0-9]{1,10}",
        subdomain in "[a-z]{1,8}"
    ) {
        // Use a fixed TLD to ensure the domain is always eTLD+1,
        // not a public suffix (PSL validation would reject it otherwise).
        let domain = format!("{subdomain}.example.com");
        let mut jar = liburlx::CookieJar::new();
        let header = format!("{name}={value}; Domain={domain}");
        jar.store_cookies(&[&header], &domain, "/", true);

        // Uppercase version should still match
        let upper = domain.to_uppercase();
        let cookie = jar.cookie_header(&upper, "/", false);
        prop_assert!(cookie.is_some(), "case-insensitive domain should match");
    }

    /// A cookie set for path `/foo` matches `/foo/bar` but not `/other`.
    #[test]
    fn path_prefix_matching(
        name in "[a-zA-Z]{1,10}",
        value in "[a-zA-Z0-9]{1,10}",
        prefix in "/[a-z]{1,8}",
        suffix in "/[a-z]{1,8}"
    ) {
        let mut jar = liburlx::CookieJar::new();
        let header = format!("{name}={value}; Path={prefix}");
        jar.store_cookies(&[&header], "example.com", "/", true);

        // Should match the prefix + suffix
        let full_path = format!("{prefix}{suffix}");
        let cookie = jar.cookie_header("example.com", &full_path, false);
        prop_assert!(cookie.is_some(), "path prefix should match: {} under {}", full_path, prefix);

        // Should not match a completely different path
        let other = "/zzz_other";
        if !other.starts_with(&prefix) {
            let cookie = jar.cookie_header("example.com", other, false);
            prop_assert!(cookie.is_none(), "unrelated path should not match");
        }
    }

    /// Secure cookies are not sent over non-secure connections.
    #[test]
    fn secure_only_over_https(
        name in "[a-zA-Z]{1,10}",
        value in "[a-zA-Z0-9]{1,10}"
    ) {
        let mut jar = liburlx::CookieJar::new();
        let header = format!("{name}={value}; Secure");
        jar.store_cookies(&[&header], "example.com", "/", true);
        prop_assert!(jar.cookie_header("example.com", "/", false).is_none(),
            "secure cookie should not be sent over HTTP");
        prop_assert!(jar.cookie_header("example.com", "/", true).is_some(),
            "secure cookie should be sent over HTTPS");
    }
}
