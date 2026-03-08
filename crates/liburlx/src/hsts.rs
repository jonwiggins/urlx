//! HTTP Strict Transport Security (HSTS) enforcement.
//!
//! Parses `Strict-Transport-Security` headers and maintains a cache
//! of HSTS-enabled hosts to auto-upgrade HTTP to HTTPS.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// An HSTS cache that tracks which hosts require HTTPS.
#[derive(Debug, Clone)]
pub struct HstsCache {
    entries: HashMap<String, HstsEntry>,
}

/// A single HSTS entry for a host.
#[derive(Debug, Clone)]
struct HstsEntry {
    /// When this entry expires.
    expires: Instant,
    /// Whether subdomains are also covered.
    include_subdomains: bool,
}

impl HstsCache {
    /// Create a new empty HSTS cache.
    #[must_use]
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Parse and store an HSTS header value for a given host.
    ///
    /// Parses the `Strict-Transport-Security` header directives:
    /// - `max-age=<seconds>` — how long to remember this host
    /// - `includeSubDomains` — also apply to subdomains
    ///
    /// A `max-age=0` removes the host from the cache.
    pub fn store(&mut self, host: &str, header_value: &str) {
        let directives = parse_hsts_header(header_value);

        let max_age = directives.max_age;
        let include_subdomains = directives.include_subdomains;

        if max_age == 0 {
            let _removed = self.entries.remove(host);
            return;
        }

        let _old = self.entries.insert(
            host.to_lowercase(),
            HstsEntry {
                expires: Instant::now() + Duration::from_secs(max_age),
                include_subdomains,
            },
        );
    }

    /// Check if a host should be upgraded to HTTPS.
    #[must_use]
    pub fn should_upgrade(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Direct match
        if let Some(entry) = self.entries.get(&host_lower) {
            if entry.expires > Instant::now() {
                return true;
            }
        }

        // Check parent domains with includeSubDomains
        let mut domain = host_lower.as_str();
        while let Some(dot_pos) = domain.find('.') {
            domain = &domain[dot_pos + 1..];
            if let Some(entry) = self.entries.get(domain) {
                if entry.include_subdomains && entry.expires > Instant::now() {
                    return true;
                }
            }
        }

        false
    }

    /// Remove expired entries from the cache.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires > now);
    }
}

impl Default for HstsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed HSTS directives.
struct HstsDirectives {
    max_age: u64,
    include_subdomains: bool,
}

/// Parse an HSTS header value into directives.
fn parse_hsts_header(value: &str) -> HstsDirectives {
    let mut max_age: u64 = 0;
    let mut include_subdomains = false;

    for part in value.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("max-age=").or_else(|| part.strip_prefix("Max-Age=")) {
            max_age = val.trim().trim_matches('"').parse().unwrap_or(0);
        } else if part.eq_ignore_ascii_case("includeSubDomains") {
            include_subdomains = true;
        }
    }

    HstsDirectives { max_age, include_subdomains }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn store_and_lookup() {
        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=31536000");
        assert!(cache.should_upgrade("example.com"));
        assert!(!cache.should_upgrade("other.com"));
    }

    #[test]
    fn include_subdomains() {
        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=31536000; includeSubDomains");
        assert!(cache.should_upgrade("example.com"));
        assert!(cache.should_upgrade("sub.example.com"));
        assert!(cache.should_upgrade("deep.sub.example.com"));
        assert!(!cache.should_upgrade("notexample.com"));
    }

    #[test]
    fn subdomains_not_included_by_default() {
        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=31536000");
        assert!(cache.should_upgrade("example.com"));
        assert!(!cache.should_upgrade("sub.example.com"));
    }

    #[test]
    fn max_age_zero_removes_entry() {
        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=31536000");
        assert!(cache.should_upgrade("example.com"));
        cache.store("example.com", "max-age=0");
        assert!(!cache.should_upgrade("example.com"));
    }

    #[test]
    fn case_insensitive() {
        let mut cache = HstsCache::new();
        cache.store("Example.COM", "max-age=31536000");
        assert!(cache.should_upgrade("example.com"));
        assert!(cache.should_upgrade("EXAMPLE.COM"));
    }

    #[test]
    fn parse_header_with_quotes() {
        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=\"31536000\"");
        assert!(cache.should_upgrade("example.com"));
    }

    #[test]
    fn parse_header_multiple_directives() {
        let directives = parse_hsts_header("max-age=300; includeSubDomains; preload");
        assert_eq!(directives.max_age, 300);
        assert!(directives.include_subdomains);
    }

    #[test]
    fn empty_cache_returns_false() {
        let cache = HstsCache::new();
        assert!(!cache.should_upgrade("example.com"));
    }

    #[test]
    fn purge_expired_removes_old_entries() {
        let mut cache = HstsCache::new();
        // Insert with max-age=0 to test (it removes immediately)
        // Instead, insert then manually expire
        cache.entries.insert(
            "expired.com".to_string(),
            HstsEntry {
                expires: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
                include_subdomains: false,
            },
        );
        cache.entries.insert(
            "valid.com".to_string(),
            HstsEntry {
                expires: Instant::now() + Duration::from_secs(3600),
                include_subdomains: false,
            },
        );

        assert_eq!(cache.entries.len(), 2);
        cache.purge_expired();
        assert_eq!(cache.entries.len(), 1);
        assert!(!cache.should_upgrade("expired.com"));
        assert!(cache.should_upgrade("valid.com"));
    }
}
