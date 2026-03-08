//! Property-based tests for the HSTS cache.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

proptest! {
    /// `max-age=0` always removes the host from the cache.
    #[test]
    fn max_age_zero_removes(host in "[a-z]{1,10}\\.com") {
        let mut cache = liburlx::HstsCache::new();
        cache.store(&host, "max-age=31536000");
        prop_assert!(cache.should_upgrade(&host));
        cache.store(&host, "max-age=0");
        prop_assert!(!cache.should_upgrade(&host));
    }

    /// Host lookup is case-insensitive.
    #[test]
    fn case_insensitive_lookup(host in "[a-z]{1,10}\\.com") {
        let mut cache = liburlx::HstsCache::new();
        cache.store(&host, "max-age=31536000");
        let upper = host.to_uppercase();
        prop_assert!(cache.should_upgrade(&upper),
            "uppercase '{}' should match stored '{}'", upper, host);
    }

    /// `includeSubDomains` makes subdomains upgrade too.
    #[test]
    fn include_subdomains_works(
        parent in "[a-z]{1,8}\\.com",
        sub in "[a-z]{1,8}"
    ) {
        let mut cache = liburlx::HstsCache::new();
        cache.store(&parent, "max-age=31536000; includeSubDomains");

        let subdomain = format!("{sub}.{parent}");
        prop_assert!(cache.should_upgrade(&subdomain),
            "subdomain '{}' should be upgraded for parent '{}'", subdomain, parent);
    }

    /// Without `includeSubDomains`, subdomains are NOT upgraded.
    #[test]
    fn no_include_subdomains_no_upgrade(
        parent in "[a-z]{1,8}\\.com",
        sub in "[a-z]{1,8}"
    ) {
        let mut cache = liburlx::HstsCache::new();
        cache.store(&parent, "max-age=31536000");

        let subdomain = format!("{sub}.{parent}");
        prop_assert!(!cache.should_upgrade(&subdomain),
            "subdomain '{}' should NOT be upgraded without includeSubDomains", subdomain);
    }

    /// A positive max-age always results in `should_upgrade` returning true.
    #[test]
    fn positive_max_age_upgrades(
        host in "[a-z]{1,10}\\.com",
        seconds in 1u64..31_536_000
    ) {
        let mut cache = liburlx::HstsCache::new();
        let header = format!("max-age={seconds}");
        cache.store(&host, &header);
        prop_assert!(cache.should_upgrade(&host));
    }

    /// Unknown hosts never get upgraded.
    #[test]
    fn unknown_hosts_not_upgraded(host in "[a-z]{1,10}\\.com") {
        let cache = liburlx::HstsCache::new();
        prop_assert!(!cache.should_upgrade(&host));
    }

    /// Storing the same host twice updates (not duplicates) the entry.
    #[test]
    fn store_twice_idempotent(host in "[a-z]{1,10}\\.com") {
        let mut cache = liburlx::HstsCache::new();
        cache.store(&host, "max-age=100");
        cache.store(&host, "max-age=200");
        prop_assert!(cache.should_upgrade(&host));
    }
}
