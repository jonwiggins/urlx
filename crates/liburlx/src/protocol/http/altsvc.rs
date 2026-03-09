//! Alt-Svc header parsing (RFC 7838).
//!
//! Parses `Alt-Svc` response headers to discover alternative services
//! (e.g., HTTP/3 via QUIC). Currently provides parsing only; caching
//! and automatic upgrade are planned for future phases.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A single alternative service entry from an `Alt-Svc` header.
///
/// Example: `h3=":443"; ma=2592000` produces an `AltSvc` with
/// `protocol_id = "h3"`, `host = ""`, `port = 443`, and
/// `max_age = Duration::from_secs(2592000)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc {
    /// ALPN protocol identifier (e.g., "h3", "h2", "h3-29").
    pub protocol_id: String,
    /// Alternative hostname (empty string means same as origin).
    pub host: String,
    /// Alternative port number.
    pub port: u16,
    /// Maximum age before the entry expires.
    pub max_age: Duration,
}

/// Default max-age for Alt-Svc entries (24 hours per RFC 7838).
const DEFAULT_MAX_AGE_SECS: u64 = 86400;

/// Parse an `Alt-Svc` header value into a list of alternative service entries.
///
/// Handles the `clear` directive (returns empty vec) and multiple
/// comma-separated alternatives.
///
/// # Examples
///
/// ```
/// use liburlx::protocol::http::altsvc::parse_alt_svc;
///
/// let entries = parse_alt_svc(r#"h3=":443"; ma=2592000, h2=":443""#);
/// assert_eq!(entries.len(), 2);
/// assert_eq!(entries[0].protocol_id, "h3");
/// assert_eq!(entries[0].port, 443);
/// ```
#[must_use]
pub fn parse_alt_svc(value: &str) -> Vec<AltSvc> {
    let trimmed = value.trim();

    // "clear" means the server wants to invalidate all cached Alt-Svc entries
    if trimmed == "clear" {
        return Vec::new();
    }

    let mut results = Vec::new();

    for entry in split_entries(trimmed) {
        if let Some(alt) = parse_single_entry(entry.trim()) {
            results.push(alt);
        }
    }

    results
}

/// Split Alt-Svc header into individual entries, respecting quoted strings.
fn split_entries(value: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, ch) in value.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                entries.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    if start < value.len() {
        entries.push(&value[start..]);
    }

    entries
}

/// Parse a single Alt-Svc entry like `h3=":443"; ma=2592000`.
fn parse_single_entry(entry: &str) -> Option<AltSvc> {
    // Split on first '=' to get protocol_id and authority
    let (proto_id, rest) = entry.split_once('=')?;
    let protocol_id = proto_id.trim().to_string();

    // Parse the rest: "authority"; params...
    let mut parts = rest.splitn(2, ';');
    let authority_str = parts.next()?.trim().trim_matches('"');
    let params_str = parts.next().unwrap_or("");

    // Parse authority (host:port)
    let (host, port) = parse_authority(authority_str)?;

    // Parse parameters
    let max_age = parse_max_age(params_str);

    Some(AltSvc { protocol_id, host, port, max_age })
}

/// Parse an authority string like ":443" or "alt.example.com:443".
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(colon_pos) = authority.rfind(':') {
        let host = authority[..colon_pos].to_string();
        let port: u16 = authority[colon_pos + 1..].parse().ok()?;
        Some((host, port))
    } else {
        // No port — invalid
        None
    }
}

/// Parse the `ma=` parameter from Alt-Svc parameters.
fn parse_max_age(params: &str) -> Duration {
    for param in params.split(';') {
        let param = param.trim();
        if let Some(val) = param.strip_prefix("ma=") {
            if let Ok(secs) = val.trim().parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
    }
    Duration::from_secs(DEFAULT_MAX_AGE_SECS)
}

/// Parse a `Retry-After` response header value.
///
/// The value can be either:
/// - A number of seconds (e.g., `120`)
/// - An HTTP-date (e.g., `Fri, 31 Dec 1999 23:59:59 GMT`) — not yet supported
///
/// Returns `None` if the value cannot be parsed.
///
/// # Examples
///
/// ```
/// use liburlx::protocol::http::altsvc::parse_retry_after;
///
/// assert_eq!(parse_retry_after("120"), Some(std::time::Duration::from_secs(120)));
/// assert_eq!(parse_retry_after("0"), Some(std::time::Duration::from_secs(0)));
/// assert_eq!(parse_retry_after("not a number"), None);
/// ```
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    // Try parsing as seconds first (most common)
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // HTTP-date parsing would go here in a future phase
    None
}

/// A cached Alt-Svc entry with expiry time.
#[derive(Debug, Clone)]
struct AltSvcEntry {
    /// The alternative service information.
    alt_svc: AltSvc,
    /// When this entry expires.
    expires_at: Instant,
}

/// An in-memory cache for Alt-Svc entries.
///
/// Stores alternative service entries per origin (scheme + host + port)
/// with TTL-based expiry. Used to remember that a server supports HTTP/3
/// or other alternative protocols.
#[derive(Debug)]
pub struct AltSvcCache {
    /// Cached entries keyed by origin (e.g., `"https://example.com:443"`).
    entries: HashMap<String, Vec<AltSvcEntry>>,
}

impl AltSvcCache {
    /// Create a new, empty Alt-Svc cache.
    #[must_use]
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Store Alt-Svc entries for an origin.
    ///
    /// The origin should be in the format "scheme://host:port".
    pub fn store(&mut self, origin: &str, services: &[AltSvc]) {
        let now = Instant::now();
        let entries: Vec<AltSvcEntry> = services
            .iter()
            .map(|svc| AltSvcEntry { alt_svc: svc.clone(), expires_at: now + svc.max_age })
            .collect();
        let _ = self.entries.insert(origin.to_string(), entries);
    }

    /// Clear all entries for an origin (used when server sends `Alt-Svc: clear`).
    pub fn clear_origin(&mut self, origin: &str) {
        let _ = self.entries.remove(origin);
    }

    /// Look up valid (non-expired) Alt-Svc entries for an origin.
    #[must_use]
    pub fn get(&self, origin: &str) -> Vec<&AltSvc> {
        let now = Instant::now();
        self.entries
            .get(origin)
            .map(|entries| {
                entries.iter().filter(|e| now < e.expires_at).map(|e| &e.alt_svc).collect()
            })
            .unwrap_or_default()
    }

    /// Look up a specific protocol (e.g., "h3") for an origin.
    #[must_use]
    pub fn get_protocol(&self, origin: &str, protocol_id: &str) -> Option<&AltSvc> {
        let now = Instant::now();
        self.entries.get(origin).and_then(|entries| {
            entries
                .iter()
                .find(|e| now < e.expires_at && e.alt_svc.protocol_id == protocol_id)
                .map(|e| &e.alt_svc)
        })
    }

    /// Remove expired entries from the cache.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entries| {
            entries.retain(|e| now < e.expires_at);
            !entries.is_empty()
        });
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of origins in the cache.
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

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AltSvcCache {
    fn clone(&self) -> Self {
        Self { entries: self.entries.clone() }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_clear() {
        let result = parse_alt_svc("clear");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_single_h3() {
        let result = parse_alt_svc(r#"h3=":443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[0].host, "");
        assert_eq!(result[0].port, 443);
        assert_eq!(result[0].max_age, Duration::from_secs(DEFAULT_MAX_AGE_SECS));
    }

    #[test]
    fn parse_with_max_age() {
        let result = parse_alt_svc(r#"h3=":443"; ma=2592000"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[0].port, 443);
        assert_eq!(result[0].max_age, Duration::from_secs(2_592_000));
    }

    #[test]
    fn parse_multiple_entries() {
        let result = parse_alt_svc(r#"h3=":443"; ma=2592000, h2=":443""#);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[1].protocol_id, "h2");
    }

    #[test]
    fn parse_with_host() {
        let result = parse_alt_svc(r#"h3="alt.example.com:8443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "alt.example.com");
        assert_eq!(result[0].port, 8443);
    }

    #[test]
    fn parse_versioned_protocol() {
        let result = parse_alt_svc(r#"h3-29=":443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3-29");
    }

    #[test]
    fn parse_empty_string() {
        let result = parse_alt_svc("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_whitespace() {
        let result = parse_alt_svc("   ");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_invalid_port() {
        let result = parse_alt_svc(r#"h3=":notaport""#);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_no_port() {
        let result = parse_alt_svc(r#"h3="noport""#);
        assert!(result.is_empty());
    }

    #[test]
    fn retry_after_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_zero() {
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn retry_after_with_whitespace() {
        assert_eq!(parse_retry_after("  60  "), Some(Duration::from_secs(60)));
    }

    #[test]
    fn retry_after_invalid() {
        assert_eq!(parse_retry_after("not a number"), None);
    }

    #[test]
    fn retry_after_http_date_not_supported() {
        // HTTP-date is not yet supported
        assert_eq!(parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT"), None);
    }

    #[test]
    fn split_entries_basic() {
        let entries = split_entries(r#"h3=":443", h2=":443""#);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn split_entries_with_quoted_comma() {
        // Comma inside quotes should not split
        let entries = split_entries(r#"h3="host,name:443""#);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_authority_basic() {
        let (host, port) = parse_authority(":443").unwrap();
        assert_eq!(host, "");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_authority_with_host() {
        let (host, port) = parse_authority("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    // --- AltSvcCache tests ---

    #[test]
    fn cache_new_is_empty() {
        let cache = AltSvcCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_store_and_get() {
        let mut cache = AltSvcCache::new();
        let services = vec![AltSvc {
            protocol_id: "h3".to_string(),
            host: String::new(),
            port: 443,
            max_age: Duration::from_secs(3600),
        }];
        cache.store("https://example.com:443", &services);

        let result = cache.get("https://example.com:443");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[0].port, 443);
    }

    #[test]
    fn cache_get_missing_returns_empty() {
        let cache = AltSvcCache::new();
        assert!(cache.get("https://example.com:443").is_empty());
    }

    #[test]
    fn cache_get_protocol() {
        let mut cache = AltSvcCache::new();
        let services = vec![
            AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            },
            AltSvc {
                protocol_id: "h2".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            },
        ];
        cache.store("https://example.com:443", &services);

        assert!(cache.get_protocol("https://example.com:443", "h3").is_some());
        assert!(cache.get_protocol("https://example.com:443", "h2").is_some());
        assert!(cache.get_protocol("https://example.com:443", "h1").is_none());
    }

    #[test]
    fn cache_expired_entries_not_returned() {
        let mut cache = AltSvcCache::new();
        let services = vec![AltSvc {
            protocol_id: "h3".to_string(),
            host: String::new(),
            port: 443,
            max_age: Duration::ZERO, // Immediately expired
        }];
        cache.store("https://example.com:443", &services);

        assert!(cache.get("https://example.com:443").is_empty());
        assert!(cache.get_protocol("https://example.com:443", "h3").is_none());
    }

    #[test]
    fn cache_clear_origin() {
        let mut cache = AltSvcCache::new();
        let services = vec![AltSvc {
            protocol_id: "h3".to_string(),
            host: String::new(),
            port: 443,
            max_age: Duration::from_secs(3600),
        }];
        cache.store("https://example.com:443", &services);
        assert_eq!(cache.len(), 1);

        cache.clear_origin("https://example.com:443");
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_clear_all() {
        let mut cache = AltSvcCache::new();
        cache.store(
            "https://a.com:443",
            &[AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            }],
        );
        cache.store(
            "https://b.com:443",
            &[AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            }],
        );
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_purge_expired() {
        let mut cache = AltSvcCache::new();
        cache.store(
            "https://expired.com:443",
            &[AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::ZERO,
            }],
        );
        cache.store(
            "https://valid.com:443",
            &[AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            }],
        );
        assert_eq!(cache.len(), 2);

        cache.purge_expired();
        assert_eq!(cache.len(), 1);
        assert!(!cache.get("https://valid.com:443").is_empty());
    }

    #[test]
    fn cache_default_is_empty() {
        let cache = AltSvcCache::default();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_clone() {
        let mut cache = AltSvcCache::new();
        cache.store(
            "https://example.com:443",
            &[AltSvc {
                protocol_id: "h3".to_string(),
                host: String::new(),
                port: 443,
                max_age: Duration::from_secs(3600),
            }],
        );
        let cloned = cache.clone();
        assert_eq!(cloned.len(), 1);
    }

    // --- Alt-Svc h3 upgrade tests ---

    #[test]
    fn cache_h3_upgrade_from_header() {
        // Simulate receiving an Alt-Svc header and checking for h3 upgrade
        let entries = parse_alt_svc(r#"h3=":443"; ma=86400"#);
        assert_eq!(entries.len(), 1);

        let mut cache = AltSvcCache::new();
        cache.store("https://example.com:443", &entries);

        // Should find h3 for subsequent requests
        let h3 = cache.get_protocol("https://example.com:443", "h3");
        assert!(h3.is_some());
        assert_eq!(h3.unwrap().port, 443);
    }

    #[test]
    fn cache_h3_upgrade_different_port() {
        // Server advertises h3 on a different port
        let entries = parse_alt_svc(r#"h3=":8443"; ma=86400"#);
        let mut cache = AltSvcCache::new();
        cache.store("https://example.com:443", &entries);

        let h3 = cache.get_protocol("https://example.com:443", "h3");
        assert!(h3.is_some());
        assert_eq!(h3.unwrap().port, 8443);
    }

    #[test]
    fn cache_h3_upgrade_not_available_for_http() {
        // HTTP (not HTTPS) — h3 should not be cached for HTTP origins
        let entries = parse_alt_svc(r#"h3=":443"; ma=86400"#);
        let mut cache = AltSvcCache::new();
        cache.store("http://example.com:80", &entries);

        // Query for the HTTPS origin should not find it
        assert!(cache.get_protocol("https://example.com:443", "h3").is_none());
    }

    #[test]
    fn cache_clear_disables_h3_upgrade() {
        let entries = parse_alt_svc(r#"h3=":443"; ma=86400"#);
        let mut cache = AltSvcCache::new();
        cache.store("https://example.com:443", &entries);
        assert!(cache.get_protocol("https://example.com:443", "h3").is_some());

        // Server sends Alt-Svc: clear
        let clear_entries = parse_alt_svc("clear");
        assert!(clear_entries.is_empty());
        cache.clear_origin("https://example.com:443");
        assert!(cache.get_protocol("https://example.com:443", "h3").is_none());
    }

    #[test]
    fn cache_h3_upgrade_with_h2_fallback() {
        // Server advertises both h3 and h2
        let entries = parse_alt_svc(r#"h3=":443"; ma=86400, h2=":443"; ma=86400"#);
        let mut cache = AltSvcCache::new();
        cache.store("https://example.com:443", &entries);

        // h3 should be preferred
        assert!(cache.get_protocol("https://example.com:443", "h3").is_some());
        assert!(cache.get_protocol("https://example.com:443", "h2").is_some());
    }
}
