//! TLS connector using rustls.
//!
//! Provides TLS connection wrapping for HTTPS transfers.

#[cfg(feature = "rustls")]
mod rustls_impl {
    use std::sync::Arc;

    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    use crate::error::Error;

    /// The negotiated application protocol after TLS handshake.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AlpnProtocol {
        /// HTTP/2 was negotiated.
        H2,
        /// HTTP/1.1 was negotiated (or no ALPN).
        Http11,
    }

    /// A TLS connector backed by rustls.
    pub struct TlsConnector {
        config: Arc<rustls::ClientConfig>,
    }

    impl TlsConnector {
        /// Create a new TLS connector with the default system root certificates.
        ///
        /// Advertises both h2 and http/1.1 via ALPN when the `http2` feature is enabled.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built.
        pub fn new() -> Result<Self, Error> {
            let root_store: rustls::RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            // Advertise ALPN protocols
            #[cfg(feature = "http2")]
            {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            #[cfg(not(feature = "http2"))]
            {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }

            Ok(Self { config: Arc::new(config) })
        }

        /// Wrap a TCP stream with TLS and return the stream and negotiated protocol.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the handshake fails.
        pub async fn connect(
            &self,
            stream: TcpStream,
            server_name: &str,
        ) -> Result<(TlsStream<TcpStream>, AlpnProtocol), Error> {
            let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|e| Error::Tls(Box::new(e)))?;

            let connector = tokio_rustls::TlsConnector::from(self.config.clone());
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::Tls(Box::new(e)))?;

            // Check ALPN result
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .and_then(|p| if p == b"h2" { Some(AlpnProtocol::H2) } else { None })
                .unwrap_or(AlpnProtocol::Http11);

            Ok((tls_stream, alpn))
        }
    }
}

#[cfg(feature = "rustls")]
pub use rustls_impl::{AlpnProtocol, TlsConnector};

#[cfg(test)]
mod tests {
    #[cfg(feature = "rustls")]
    use super::*;

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_creates_successfully() {
        let connector = TlsConnector::new();
        assert!(connector.is_ok());
    }
}
