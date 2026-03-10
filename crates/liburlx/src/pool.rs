//! Connection pooling for HTTP keep-alive.
//!
//! Stores and retrieves reusable connections keyed by (host, port, TLS).
//! Connections are stored after successful requests and reused for
//! subsequent requests to the same origin.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

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

/// A pool of reusable connections.
///
/// Connections are keyed by (host, port, `is_tls`) and stored in LIFO order.
/// Only HTTP/1.1 connections that support keep-alive are pooled.
pub struct ConnectionPool {
    connections: HashMap<PoolKey, Vec<PooledStream>>,
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.connections.values().map(Vec::len).sum();
        f.debug_struct("ConnectionPool").field("pooled_connections", &total).finish()
    }
}

impl ConnectionPool {
    /// Create a new empty connection pool.
    pub fn new() -> Self {
        Self { connections: HashMap::new() }
    }

    /// Retrieve a pooled connection for the given host/port/tls combination.
    ///
    /// Returns `None` if no connection is available.
    pub fn get(&mut self, host: &str, port: u16, is_tls: bool) -> Option<PooledStream> {
        let key = PoolKey { host: host.to_string(), port, is_tls };
        self.connections.get_mut(&key).and_then(Vec::pop)
    }

    /// Store a connection for later reuse.
    pub fn put(&mut self, host: &str, port: u16, is_tls: bool, stream: PooledStream) {
        let key = PoolKey { host: host.to_string(), port, is_tls };
        self.connections.entry(key).or_default().push(stream);
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

    #[test]
    fn pool_new_is_empty() {
        let mut pool = ConnectionPool::new();
        assert!(pool.get("example.com", 80, false).is_none());
    }

    #[tokio::test]
    async fn pool_put_and_get() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create a real TCP connection to put in the pool
        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();

        let (client, _server): (std::io::Result<TcpStream>, _) =
            tokio::join!(connect_fut, accept_fut);
        let client = client.unwrap();

        let mut pool = ConnectionPool::new();
        pool.put("127.0.0.1", addr.port(), false, PooledStream::Tcp(client));

        // Should get it back
        let conn = pool.get("127.0.0.1", addr.port(), false);
        assert!(conn.is_some());

        // Pool should now be empty
        assert!(pool.get("127.0.0.1", addr.port(), false).is_none());
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();
        let (client, _server): (std::io::Result<TcpStream>, _) =
            tokio::join!(connect_fut, accept_fut);
        let client = client.unwrap();

        let mut pool = ConnectionPool::new();
        pool.put("127.0.0.1", addr.port(), false, PooledStream::Tcp(client));

        // Different host → miss
        assert!(pool.get("other.com", addr.port(), false).is_none());
        // Different port → miss
        assert!(pool.get("127.0.0.1", addr.port() + 1, false).is_none());
        // Different TLS flag → miss
        assert!(pool.get("127.0.0.1", addr.port(), true).is_none());
        // Correct key → hit
        assert!(pool.get("127.0.0.1", addr.port(), false).is_some());
    }
}
