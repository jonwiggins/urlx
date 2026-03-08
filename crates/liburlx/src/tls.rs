//! TLS connector using rustls.
//!
//! Provides TLS connection wrapping for HTTPS transfers.

#[cfg(feature = "rustls")]
mod rustls_impl {
    use std::sync::Arc;

    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;

    use crate::error::Error;

    /// A TLS connector backed by rustls.
    pub struct TlsConnector {
        config: Arc<rustls::ClientConfig>,
    }

    impl TlsConnector {
        /// Create a new TLS connector with the default system root certificates.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built.
        pub fn new() -> Result<Self, Error> {
            let root_store: rustls::RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ok(Self { config: Arc::new(config) })
        }

        /// Wrap a TCP stream with TLS.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the handshake fails.
        pub async fn connect(
            &self,
            stream: TcpStream,
            server_name: &str,
        ) -> Result<impl AsyncRead + AsyncWrite + Unpin, Error> {
            let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|e| Error::Tls(Box::new(e)))?;

            let connector = tokio_rustls::TlsConnector::from(self.config.clone());
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::Tls(Box::new(e)))?;

            Ok(tls_stream)
        }
    }
}

#[cfg(feature = "rustls")]
pub use rustls_impl::TlsConnector;

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
