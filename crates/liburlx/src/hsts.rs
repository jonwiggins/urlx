//! HTTP Strict Transport Security (HSTS) enforcement.
//!
//! Parses `Strict-Transport-Security` headers and maintains a cache
//! of HSTS-enabled hosts to auto-upgrade HTTP to HTTPS.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// An HSTS cache that tracks which hosts require HTTPS.
#[derive(Debug, Clone)]
pub struct HstsCache {
    entries: HashMap<String, HstsEntry>,
}

/// A single HSTS entry for a host.
#[derive(Debug, Clone)]
struct HstsEntry {
    /// When this entry expires (monotonic, for runtime checks).
    expires: Instant,
    /// When this entry expires (wall clock, for file persistence).
    expire_timestamp: u64,
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

        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let _old = self.entries.insert(
            host.to_lowercase(),
            HstsEntry {
                expires: Instant::now() + Duration::from_secs(max_age),
                expire_timestamp: now_secs + max_age,
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

    /// Load HSTS entries from a file.
    ///
    /// Each line has the format: `host\ttimestamp\tinclude_subdomains`
    /// where `timestamp` is a Unix epoch second and `include_subdomains` is `0` or `1`.
    /// Lines starting with `#` are comments. Invalid lines are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn load_from_file(path: &Path) -> Result<Self, crate::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Http(format!("failed to read HSTS file: {e}")))?;

        let mut cache = Self::new();
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 2 {
                continue;
            }

            let host = parts[0].to_lowercase();
            let Ok(expire_ts) = parts[1].parse::<u64>() else {
                continue;
            };
            let include_subdomains = parts.get(2).is_some_and(|v| *v == "1");

            // Skip already-expired entries
            if expire_ts <= now_secs {
                continue;
            }

            let remaining_secs = expire_ts - now_secs;
            let _old = cache.entries.insert(
                host,
                HstsEntry {
                    expires: Instant::now() + Duration::from_secs(remaining_secs),
                    expire_timestamp: expire_ts,
                    include_subdomains,
                },
            );
        }

        Ok(cache)
    }

    /// Save HSTS entries to a file.
    ///
    /// Writes one entry per line in the format: `host\ttimestamp\tinclude_subdomains`.
    /// Expired entries are not written.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save_to_file(&self, path: &Path) -> Result<(), crate::Error> {
        use std::fmt::Write;

        let now = Instant::now();
        let mut output =
            String::from("# HSTS cache — urlx\n# host\texpire_timestamp\tinclude_subdomains\n");

        for (host, entry) in &self.entries {
            if entry.expires <= now {
                continue;
            }
            let subdomains = if entry.include_subdomains { "1" } else { "0" };
            let _ = writeln!(output, "{host}\t{}\t{subdomains}", entry.expire_timestamp);
        }

        std::fs::write(path, output)
            .map_err(|e| crate::Error::Http(format!("failed to write HSTS file: {e}")))?;

        Ok(())
    }

    /// Returns the number of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
                expire_timestamp: 0,
                include_subdomains: false,
            },
        );
        cache.entries.insert(
            "valid.com".to_string(),
            HstsEntry {
                expires: Instant::now() + Duration::from_secs(3600),
                expire_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                    + 3600,
                include_subdomains: false,
            },
        );

        assert_eq!(cache.entries.len(), 2);
        cache.purge_expired();
        assert_eq!(cache.entries.len(), 1);
        assert!(!cache.should_upgrade("expired.com"));
        assert!(cache.should_upgrade("valid.com"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hsts.txt");

        let mut cache = HstsCache::new();
        cache.store("example.com", "max-age=31536000");
        cache.store("secure.org", "max-age=86400; includeSubDomains");
        cache.save_to_file(&path).unwrap();

        let loaded = HstsCache::load_from_file(&path).unwrap();
        assert!(loaded.should_upgrade("example.com"));
        assert!(loaded.should_upgrade("secure.org"));
        assert!(loaded.should_upgrade("sub.secure.org"));
        assert!(!loaded.should_upgrade("other.com"));
    }

    #[test]
    fn load_skips_expired_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hsts.txt");

        // Write a file with an expired entry (timestamp 1 = 1970)
        std::fs::write(&path, "expired.com\t1\t0\n").unwrap();

        let cache = HstsCache::load_from_file(&path).unwrap();
        assert!(!cache.should_upgrade("expired.com"));
        assert!(cache.is_empty());
    }

    #[test]
    fn load_skips_comments_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hsts.txt");

        let future_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 86400;
        let content = format!("# comment\n\nexample.com\t{future_ts}\t1\n");
        std::fs::write(&path, content).unwrap();

        let cache = HstsCache::load_from_file(&path).unwrap();
        assert!(cache.should_upgrade("example.com"));
        assert!(cache.should_upgrade("sub.example.com"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = HstsCache::load_from_file(Path::new("/nonexistent/hsts.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn len_and_is_empty() {
        let mut cache = HstsCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.store("example.com", "max-age=3600");
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }
}
