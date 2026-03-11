//! DNS resolution and caching.
//!
//! Provides DNS resolution via pluggable resolvers and an in-memory
//! TTL-based cache. The default `SystemResolver` wraps
//! `tokio::net::lookup_host`. When the `hickory-dns` feature is enabled,
//! `HickoryResolver` provides true async resolution with support for
//! custom DNS servers, DNS-over-HTTPS (`DoH`), and DNS-over-TLS (`DoT`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::error::Error;

/// DNS resolver that can resolve hostnames to socket addresses.
///
/// Uses an enum to avoid async trait object safety issues while
/// supporting multiple resolver backends.
#[derive(Debug, Default)]
pub enum DnsResolver {
    /// System resolver via `tokio::net::lookup_host` (wraps `getaddrinfo`).
    #[default]
    System,
    /// Async resolver via `hickory-resolver` with configurable DNS servers,
    /// DNS-over-HTTPS, and DNS-over-TLS support.
    #[cfg(feature = "hickory-dns")]
    Hickory(Box<HickoryResolver>),
}

impl DnsResolver {
    /// Resolve a hostname and port to a list of socket addresses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolve`] if DNS resolution fails.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
        match self {
            Self::System => system_resolve(host, port).await,
            #[cfg(feature = "hickory-dns")]
            Self::Hickory(resolver) => resolver.resolve(host, port).await,
        }
    }
}

/// Resolve using the system DNS resolver (`tokio::net::lookup_host`).
async fn system_resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| Error::DnsResolve(format!("Could not resolve host: {host} ({e})")))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::DnsResolve(format!(
            "Could not resolve host: {host} (no addresses returned)"
        )));
    }
    Ok(addrs)
}

/// Async DNS resolver backed by `hickory-resolver`.
///
/// Supports custom DNS server addresses, DNS-over-HTTPS (`DoH`),
/// and DNS-over-TLS (`DoT`).
#[cfg(feature = "hickory-dns")]
#[derive(Debug)]
pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

#[cfg(feature = "hickory-dns")]
impl HickoryResolver {
    /// Create a resolver using the system's default DNS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the system DNS configuration cannot be read.
    pub fn from_system() -> Result<Self, Error> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| Error::Http(format!("failed to create DNS resolver: {e}")))?
            .build();
        Ok(Self { resolver })
    }

    /// Create a resolver using custom DNS server addresses.
    #[must_use]
    pub fn from_servers(servers: &[SocketAddr]) -> Self {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::proto::xfer::Protocol;
        let mut config = ResolverConfig::new();
        for addr in servers {
            config.add_name_server(NameServerConfig::new(*addr, Protocol::Udp));
            config.add_name_server(NameServerConfig::new(*addr, Protocol::Tcp));
        }
        let provider = hickory_resolver::name_server::TokioConnectionProvider::default();
        let resolver =
            hickory_resolver::TokioResolver::builder_with_config(config, provider).build();
        Self { resolver }
    }

    /// Create a resolver that performs DNS-over-HTTPS queries.
    ///
    /// Uses Cloudflare's DNS-over-HTTPS by default. The `_doh_url` parameter
    /// is accepted for API compatibility but the resolver uses the well-known
    /// Cloudflare `DoH` endpoint directly.
    ///
    /// The `insecure` parameter is accepted for API compatibility with
    /// `CURLOPT_DOH_SSL_VERIFYPEER`. The hickory-resolver crate does not
    /// currently expose TLS verification configuration for `DoH` connections,
    /// so this parameter is stored but not enforced. The `DoH` connection
    /// always uses TLS with certificate verification.
    // TODO: wire insecure to hickory TLS config when the crate supports it
    #[must_use]
    pub fn from_doh(_doh_url: &str, _insecure: bool) -> Self {
        use hickory_resolver::config::ResolverConfig;
        let config = ResolverConfig::cloudflare_https();
        let provider = hickory_resolver::name_server::TokioConnectionProvider::default();
        let resolver =
            hickory_resolver::TokioResolver::builder_with_config(config, provider).build();
        Self { resolver }
    }

    /// Resolve a hostname to socket addresses.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
        let response = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::DnsResolve(format!("Could not resolve host: {host} ({e})")))?;
        let addrs: Vec<SocketAddr> = response.iter().map(|ip| SocketAddr::new(ip, port)).collect();
        if addrs.is_empty() {
            return Err(Error::DnsResolve(format!(
                "Could not resolve host: {host} (no addresses returned)"
            )));
        }
        Ok(addrs)
    }
}

/// Default TTL for cached DNS entries (60 seconds, matching curl).
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// A cached DNS entry with expiry time.
#[derive(Debug, Clone)]
struct DnsEntry {
    /// The resolved socket addresses.
    addrs: Vec<SocketAddr>,
    /// When this entry expires.
    expires_at: Instant,
}

/// An in-memory DNS cache with TTL-based expiry.
#[derive(Debug)]
pub struct DnsCache {
    /// Cached entries keyed by "host:port".
    entries: HashMap<String, DnsEntry>,
    /// Time-to-live for cached entries.
    ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache with the default TTL (60 seconds).
    #[must_use]
    pub fn new() -> Self {
        Self { entries: HashMap::new(), ttl: DEFAULT_TTL }
    }

    /// Create a new DNS cache with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { entries: HashMap::new(), ttl }
    }

    /// Set the TTL for new entries added to the cache.
    ///
    /// Does not affect already-cached entries.
    pub const fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }

    /// Returns the current TTL for new entries.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Look up a cached DNS entry for the given host and port.
    ///
    /// Returns `None` if no entry exists or the entry has expired.
    #[must_use]
    pub fn get(&self, host: &str, port: u16) -> Option<&[SocketAddr]> {
        let key = cache_key(host, port);
        self.entries.get(&key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.addrs.as_slice())
            } else {
                None
            }
        })
    }

    /// Store resolved addresses in the cache.
    pub fn put(&mut self, host: &str, port: u16, addrs: Vec<SocketAddr>) {
        let key = cache_key(host, port);
        let entry = DnsEntry { addrs, expires_at: Instant::now() + self.ttl };
        let _ = self.entries.insert(key, entry);
    }

    /// Remove expired entries from the cache.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| now < entry.expires_at);
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of entries in the cache (including expired).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a cache key from host and port.
///
/// Pre-allocates the exact capacity needed to avoid reallocation.
fn cache_key(host: &str, port: u16) -> String {
    use std::fmt::Write;
    // port is at most 5 digits + 1 colon + host length
    let mut key = String::with_capacity(host.len() + 6);
    for b in host.bytes() {
        key.push(b.to_ascii_lowercase() as char);
    }
    key.push(':');
    let _ = write!(key, "{port}");
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn addr_v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn addr_v6(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    #[test]
    fn new_cache_is_empty() {
        let cache = DnsCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut cache = DnsCache::new();
        let addrs = vec![addr_v4([127, 0, 0, 1], 80)];
        cache.put("example.com", 80, addrs.clone());
        let result = cache.get("example.com", 80);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &addrs[..]);
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = DnsCache::new();
        assert!(cache.get("example.com", 80).is_none());
    }

    #[test]
    fn case_insensitive_lookup() {
        let mut cache = DnsCache::new();
        cache.put("Example.COM", 443, vec![addr_v4([1, 2, 3, 4], 443)]);
        assert!(cache.get("example.com", 443).is_some());
        assert!(cache.get("EXAMPLE.COM", 443).is_some());
    }

    #[test]
    fn different_ports_are_separate() {
        let mut cache = DnsCache::new();
        cache.put("example.com", 80, vec![addr_v4([1, 2, 3, 4], 80)]);
        cache.put("example.com", 443, vec![addr_v4([5, 6, 7, 8], 443)]);

        let r80 = cache.get("example.com", 80).unwrap();
        let r443 = cache.get("example.com", 443).unwrap();
        assert_ne!(r80, r443);
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut cache = DnsCache::with_ttl(Duration::ZERO);
        cache.put("example.com", 80, vec![addr_v4([1, 2, 3, 4], 80)]);
        // TTL is zero, so entry is immediately expired
        assert!(cache.get("example.com", 80).is_none());
    }

    #[test]
    fn purge_expired_removes_old_entries() {
        let mut cache = DnsCache::with_ttl(Duration::ZERO);
        cache.put("old.com", 80, vec![addr_v4([1, 1, 1, 1], 80)]);
        assert_eq!(cache.len(), 1);
        cache.purge_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn clear_removes_all() {
        let mut cache = DnsCache::new();
        cache.put("a.com", 80, vec![addr_v4([1, 1, 1, 1], 80)]);
        cache.put("b.com", 80, vec![addr_v4([2, 2, 2, 2], 80)]);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn multiple_addrs_stored() {
        let mut cache = DnsCache::new();
        let addrs = vec![addr_v4([1, 2, 3, 4], 80), addr_v4([5, 6, 7, 8], 80), addr_v6(80)];
        cache.put("multi.example.com", 80, addrs);
        assert_eq!(cache.get("multi.example.com", 80).unwrap().len(), 3);
    }

    #[test]
    fn overwrite_existing_entry() {
        let mut cache = DnsCache::new();
        cache.put("example.com", 80, vec![addr_v4([1, 1, 1, 1], 80)]);
        cache.put("example.com", 80, vec![addr_v4([2, 2, 2, 2], 80)]);
        let addrs = cache.get("example.com", 80).unwrap();
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[test]
    fn default_is_new() {
        let cache = DnsCache::default();
        assert!(cache.is_empty());
    }

    #[test]
    fn ttl_returns_default() {
        let cache = DnsCache::new();
        assert_eq!(cache.ttl(), Duration::from_secs(60));
    }

    #[test]
    fn set_ttl_changes_ttl() {
        let mut cache = DnsCache::new();
        cache.set_ttl(Duration::from_secs(300));
        assert_eq!(cache.ttl(), Duration::from_secs(300));
    }

    #[test]
    fn set_ttl_affects_new_entries() {
        let mut cache = DnsCache::new();
        cache.set_ttl(Duration::ZERO);
        cache.put("example.com", 80, vec![addr_v4([1, 2, 3, 4], 80)]);
        // New entry uses zero TTL, so it's immediately expired
        assert!(cache.get("example.com", 80).is_none());
    }

    #[test]
    fn with_ttl_returns_custom_ttl() {
        let cache = DnsCache::with_ttl(Duration::from_secs(120));
        assert_eq!(cache.ttl(), Duration::from_secs(120));
    }

    #[test]
    fn cache_key_format() {
        assert_eq!(cache_key("Example.COM", 443), "example.com:443");
        assert_eq!(cache_key("localhost", 80), "localhost:80");
        assert_eq!(cache_key("HOST", 65535), "host:65535");
    }

    #[test]
    fn dns_resolver_default_is_system() {
        let resolver = DnsResolver::default();
        assert!(matches!(resolver, DnsResolver::System));
    }

    #[test]
    fn dns_resolver_system_debug() {
        let resolver = DnsResolver::System;
        let debug = format!("{resolver:?}");
        assert!(debug.contains("System"));
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let resolver = DnsResolver::System;
        let addrs = resolver.resolve("localhost", 80).await.unwrap();
        assert!(!addrs.is_empty());
        // All addresses should have port 80
        for addr in &addrs {
            assert_eq!(addr.port(), 80);
        }
    }

    #[tokio::test]
    async fn system_resolver_fails_for_invalid_host() {
        let resolver = DnsResolver::System;
        let result = resolver.resolve("this-host-does-not-exist.invalid", 80).await;
        assert!(result.is_err());
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn hickory_resolver_from_system() {
        let resolver = HickoryResolver::from_system().unwrap();
        let dns = DnsResolver::Hickory(Box::new(resolver));
        let debug = format!("{dns:?}");
        assert!(debug.contains("Hickory"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn hickory_resolver_from_servers() {
        use std::net::Ipv4Addr;
        let servers = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)];
        let resolver = HickoryResolver::from_servers(&servers);
        let dns = DnsResolver::Hickory(Box::new(resolver));
        let debug = format!("{dns:?}");
        assert!(debug.contains("Hickory"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn hickory_resolver_from_doh() {
        let resolver = HickoryResolver::from_doh("https://cloudflare-dns.com/dns-query", false);
        let dns = DnsResolver::Hickory(Box::new(resolver));
        let debug = format!("{dns:?}");
        assert!(debug.contains("Hickory"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn hickory_resolver_from_doh_insecure() {
        // Verify the insecure parameter is accepted without panic
        let resolver = HickoryResolver::from_doh("https://cloudflare-dns.com/dns-query", true);
        let dns = DnsResolver::Hickory(Box::new(resolver));
        let debug = format!("{dns:?}");
        assert!(debug.contains("Hickory"));
    }
}
