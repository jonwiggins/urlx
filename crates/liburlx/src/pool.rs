//! Connection pooling for HTTP keep-alive.
//!
//! Stores and retrieves reusable connections keyed by (host, port, TLS).
//! Connections are stored after successful requests and reused for
//! subsequent requests to the same origin.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Default connection pool TTL (curl uses 118 seconds).
const DEFAULT_POOL_TTL: Duration = Duration::from_secs(118);

/// Default max connections per host (curl default is 5).
const DEFAULT_MAX_PER_HOST: usize = 5;

/// Default max total connections in pool (curl default is 25).
const DEFAULT_MAX_TOTAL: usize = 25;

/// A connection that can be stored in the pool.
///
/// Wraps either a plain TCP stream, a TLS stream, or a Unix stream,
/// implementing [`AsyncRead`] and [`AsyncWrite`] so it can be used generically.
#[allow(clippy::large_enum_variant)]
pub enum PooledStream {
    /// Plain TCP connection (HTTP).
    Tcp(TcpStream),
    /// TLS-wrapped connection (HTTPS).
    #[cfg(feature = "rustls")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    /// Unix domain socket connection.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl PooledStream {
    /// Get the local socket address of the underlying connection.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp(s) => s.local_addr().ok(),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => s.get_ref().0.local_addr().ok(),
            #[cfg(unix)]
            Self::Unix(_) => None,
        }
    }

    /// Get the peer socket address of the underlying connection.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp(s) => s.peer_addr().ok(),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => s.get_ref().0.peer_addr().ok(),
            #[cfg(unix)]
            Self::Unix(_) => None,
        }
    }
}

impl AsyncRead for PooledStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PooledStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Key for connection pool lookup.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct PoolKey {
    host: String,
    port: u16,
    is_tls: bool,
}

/// A pooled connection with its insertion timestamp for TTL tracking.
struct PoolEntry {
    stream: PooledStream,
    inserted_at: Instant,
}

/// A pool of reusable connections.
///
/// Connections are keyed by (host, port, `is_tls`) and stored in LIFO order.
/// Only HTTP/1.1 connections that support keep-alive are pooled.
///
/// Supports TTL-based expiry (default 118s, matching curl) and per-host
/// and total connection limits.
pub struct ConnectionPool {
    connections: HashMap<PoolKey, Vec<PoolEntry>>,
    /// Connection time-to-live. Connections older than this are evicted.
    pub(crate) ttl: Duration,
    /// Maximum connections per host.
    pub(crate) max_per_host: usize,
    /// Maximum total connections in pool.
    pub(crate) max_total: usize,
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.connections.values().map(Vec::len).sum();
        f.debug_struct("ConnectionPool")
            .field("pooled_connections", &total)
            .field("ttl_secs", &self.ttl.as_secs())
            .field("max_per_host", &self.max_per_host)
            .field("max_total", &self.max_total)
            .finish()
    }
}

impl ConnectionPool {
    /// Create a new empty connection pool with default settings.
    ///
    /// Default TTL: 118 seconds (matching curl).
    /// Default max per host: 5. Default max total: 25.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            ttl: DEFAULT_POOL_TTL,
            max_per_host: DEFAULT_MAX_PER_HOST,
            max_total: DEFAULT_MAX_TOTAL,
        }
    }

    /// Set the connection TTL (time-to-live).
    ///
    /// Connections older than this duration are evicted on the next `get()` call.
    /// Set to `Duration::ZERO` to disable pooling.
    pub const fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }

    /// Set the maximum number of connections per host.
    #[allow(dead_code)] // Public API for callers configuring pool limits
    pub const fn set_max_per_host(&mut self, max: usize) {
        self.max_per_host = max;
    }

    /// Set the maximum total number of connections in the pool.
    pub const fn set_max_total(&mut self, max: usize) {
        self.max_total = max;
    }

    /// Returns the total number of connections currently in the pool.
    pub fn len(&self) -> usize {
        self.connections.values().map(Vec::len).sum()
    }

    /// Returns `true` if the pool contains no connections.
    #[allow(dead_code)] // Public API complementing len()
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retrieve a pooled connection for the given host/port/tls combination.
    ///
    /// Evicts expired connections before returning. Returns `None` if no
    /// valid connection is available.
    pub fn get(&mut self, host: &str, port: u16, is_tls: bool) -> Option<PooledStream> {
        let key = PoolKey { host: host.to_string(), port, is_tls };
        let entries = self.connections.get_mut(&key)?;
        let now = Instant::now();

        // Evict expired entries from this key's list
        entries.retain(|entry| now.duration_since(entry.inserted_at) < self.ttl);

        // Pop the most recent valid connection (LIFO)
        let entry = entries.pop()?;

        // Clean up empty vecs
        if entries.is_empty() {
            let _ = self.connections.remove(&key);
        }

        Some(entry.stream)
    }

    /// Store a connection for later reuse.
    ///
    /// Enforces per-host and total limits. If the per-host limit is reached,
    /// the oldest connection for that host is evicted. If the total limit is
    /// reached, the globally oldest connection is evicted.
    pub fn put(&mut self, host: &str, port: u16, is_tls: bool, stream: PooledStream) {
        // TTL of zero means connection reuse is disabled
        if self.ttl.is_zero() {
            return;
        }

        let key = PoolKey { host: host.to_string(), port, is_tls };

        // Enforce per-host limit: evict oldest if at capacity
        let entries = self.connections.entry(key).or_default();
        while entries.len() >= self.max_per_host {
            let _ = entries.remove(0); // Remove oldest (front of Vec)
        }

        entries.push(PoolEntry { stream, inserted_at: Instant::now() });

        // Enforce total limit: evict globally oldest if at capacity
        while self.len() > self.max_total {
            self.evict_oldest();
        }
    }

    /// Remove all connections from the pool.
    #[allow(dead_code)] // Public API for callers that need to flush the pool
    pub fn clear(&mut self) {
        self.connections.clear();
    }

    /// Evict all expired connections from the pool.
    ///
    /// This is called automatically by `get()`, but can also be called
    /// manually to proactively clean up stale connections.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.connections.retain(|_, entries| {
            entries.retain(|entry| now.duration_since(entry.inserted_at) < ttl);
            !entries.is_empty()
        });
    }

    /// Evict the single oldest connection across all keys.
    fn evict_oldest(&mut self) {
        let oldest_key = self
            .connections
            .iter()
            .filter(|(_, entries)| !entries.is_empty())
            .min_by_key(|(_, entries)| entries.first().map_or_else(Instant::now, |e| e.inserted_at))
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            if let Some(entries) = self.connections.get_mut(&key) {
                let _ = entries.remove(0);
                if entries.is_empty() {
                    let _ = self.connections.remove(&key);
                }
            }
        }
    }
}

/// Pool for reusable HTTP/2 connections.
///
/// Stores `h2::client::SendRequest` handles keyed by (host, port).
/// The background connection driver task continues running as long as
/// the `SendRequest` handle is alive, so pooled connections remain active.
#[cfg(feature = "http2")]
pub struct H2Pool {
    connections: HashMap<PoolKey, h2::client::SendRequest<bytes::Bytes>>,
}

#[cfg(feature = "http2")]
impl std::fmt::Debug for H2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Pool").field("pooled_connections", &self.connections.len()).finish()
    }
}

#[cfg(feature = "http2")]
impl H2Pool {
    /// Create a new empty HTTP/2 pool.
    pub fn new() -> Self {
        Self { connections: HashMap::new() }
    }

    /// Retrieve a pooled HTTP/2 connection for the given host/port.
    ///
    /// Returns `None` if no connection is available.
    pub fn get(&mut self, host: &str, port: u16) -> Option<h2::client::SendRequest<bytes::Bytes>> {
        let key = PoolKey { host: host.to_string(), port, is_tls: true };
        self.connections.remove(&key)
    }

    /// Store an HTTP/2 connection for later reuse.
    pub fn put(&mut self, host: &str, port: u16, client: h2::client::SendRequest<bytes::Bytes>) {
        let key = PoolKey { host: host.to_string(), port, is_tls: true };
        let _old = self.connections.insert(key, client);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// Helper to create a TCP connection pair for pool testing.
    async fn make_tcp_pair() -> (TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();
        let (client, server): (std::io::Result<TcpStream>, _) =
            tokio::join!(connect_fut, accept_fut);
        let (server, _addr) = server.unwrap();
        (client.unwrap(), server)
    }

    #[test]
    fn pool_new_is_empty() {
        let mut pool = ConnectionPool::new();
        assert!(pool.get("example.com", 80, false).is_none());
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pool_default_settings() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.ttl, Duration::from_secs(118));
        assert_eq!(pool.max_per_host, 5);
        assert_eq!(pool.max_total, 25);
    }

    #[test]
    fn pool_set_ttl() {
        let mut pool = ConnectionPool::new();
        pool.set_ttl(Duration::from_secs(60));
        assert_eq!(pool.ttl, Duration::from_secs(60));
    }

    #[test]
    fn pool_set_max_per_host() {
        let mut pool = ConnectionPool::new();
        pool.set_max_per_host(10);
        assert_eq!(pool.max_per_host, 10);
    }

    #[test]
    fn pool_set_max_total() {
        let mut pool = ConnectionPool::new();
        pool.set_max_total(50);
        assert_eq!(pool.max_total, 50);
    }

    #[tokio::test]
    async fn pool_put_and_get() {
        let (client, _server) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        pool.put("127.0.0.1", 80, false, PooledStream::Tcp(client));

        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());

        // Should get it back
        let conn = pool.get("127.0.0.1", 80, false);
        assert!(conn.is_some());

        // Pool should now be empty
        assert!(pool.get("127.0.0.1", 80, false).is_none());
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn pool_ttl_evicts_expired() {
        let (client, _server) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        // Set a very short TTL
        pool.set_ttl(Duration::from_millis(1));

        pool.put("127.0.0.1", 80, false, PooledStream::Tcp(client));
        assert_eq!(pool.len(), 1);

        // Wait for the TTL to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Connection should be evicted on get
        assert!(pool.get("127.0.0.1", 80, false).is_none());
    }

    #[tokio::test]
    async fn pool_ttl_zero_disables_pooling() {
        let (client, _server) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        pool.set_ttl(Duration::ZERO);

        // put() should be a no-op
        pool.put("127.0.0.1", 80, false, PooledStream::Tcp(client));
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn pool_max_per_host_evicts_oldest() {
        let mut pool = ConnectionPool::new();
        pool.set_max_per_host(2);

        // Put 3 connections for the same host
        let (c1, _s1) = make_tcp_pair().await;
        let (c2, _s2) = make_tcp_pair().await;
        let (c3, _s3) = make_tcp_pair().await;

        pool.put("host.com", 80, false, PooledStream::Tcp(c1));
        pool.put("host.com", 80, false, PooledStream::Tcp(c2));
        pool.put("host.com", 80, false, PooledStream::Tcp(c3));

        // Should only have 2 (oldest evicted)
        assert_eq!(pool.len(), 2);

        // Should be able to get 2 connections
        assert!(pool.get("host.com", 80, false).is_some());
        assert!(pool.get("host.com", 80, false).is_some());
        assert!(pool.get("host.com", 80, false).is_none());
    }

    #[tokio::test]
    async fn pool_max_total_evicts_globally_oldest() {
        let mut pool = ConnectionPool::new();
        pool.set_max_total(2);
        pool.set_max_per_host(5);

        let (c1, _s1) = make_tcp_pair().await;
        let (c2, _s2) = make_tcp_pair().await;
        let (c3, _s3) = make_tcp_pair().await;

        pool.put("host1.com", 80, false, PooledStream::Tcp(c1));
        pool.put("host2.com", 80, false, PooledStream::Tcp(c2));
        // This should evict the oldest (host1)
        pool.put("host3.com", 80, false, PooledStream::Tcp(c3));

        assert_eq!(pool.len(), 2);
        // host1 was evicted (oldest)
        assert!(pool.get("host1.com", 80, false).is_none());
        assert!(pool.get("host2.com", 80, false).is_some());
        assert!(pool.get("host3.com", 80, false).is_some());
    }

    #[tokio::test]
    async fn pool_cleanup_removes_expired() {
        let (c1, _s1) = make_tcp_pair().await;
        let (c2, _s2) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        pool.set_ttl(Duration::from_millis(1));

        pool.put("host1.com", 80, false, PooledStream::Tcp(c1));
        assert_eq!(pool.len(), 1);

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add a fresh connection
        pool.put("host2.com", 80, false, PooledStream::Tcp(c2));
        assert_eq!(pool.len(), 2);

        // Cleanup should remove only the expired one
        pool.cleanup();
        assert_eq!(pool.len(), 1);
        assert!(pool.get("host1.com", 80, false).is_none());
        assert!(pool.get("host2.com", 80, false).is_some());
    }

    #[tokio::test]
    async fn pool_clear() {
        let (c1, _s1) = make_tcp_pair().await;
        let (c2, _s2) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        pool.put("host1.com", 80, false, PooledStream::Tcp(c1));
        pool.put("host2.com", 443, true, PooledStream::Tcp(c2));
        assert_eq!(pool.len(), 2);

        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn pool_debug_includes_settings() {
        let pool = ConnectionPool::new();
        let debug = format!("{pool:?}");
        assert!(debug.contains("ConnectionPool"));
        assert!(debug.contains("ttl_secs"));
        assert!(debug.contains("max_per_host"));
        assert!(debug.contains("max_total"));
    }

    #[cfg(feature = "http2")]
    #[test]
    fn h2_pool_new_is_empty() {
        let mut pool = H2Pool::new();
        assert!(pool.get("example.com", 443).is_none());
    }

    #[cfg(feature = "http2")]
    #[test]
    fn h2_pool_debug() {
        let pool = H2Pool::new();
        let debug = format!("{pool:?}");
        assert!(debug.contains("H2Pool"));
    }

    #[tokio::test]
    async fn pool_keyed_by_host_port_tls() {
        let (client, _server) = make_tcp_pair().await;

        let mut pool = ConnectionPool::new();
        pool.put("127.0.0.1", 80, false, PooledStream::Tcp(client));

        // Different host → miss
        assert!(pool.get("other.com", 80, false).is_none());
        // Different port → miss
        assert!(pool.get("127.0.0.1", 81, false).is_none());
        // Different TLS flag → miss
        assert!(pool.get("127.0.0.1", 80, true).is_none());
        // Correct key → hit
        assert!(pool.get("127.0.0.1", 80, false).is_some());
    }
}
