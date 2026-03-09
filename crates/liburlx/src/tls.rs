//! TLS connector using rustls.
//!
//! Provides TLS connection wrapping for HTTPS transfers, with configurable
//! certificate verification, custom CA bundles, and client certificates.

use std::path::PathBuf;

/// Configuration for TLS connections.
///
/// Controls certificate verification, custom CA bundles, client certificates,
/// and TLS version negotiation.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether to verify the server's TLS certificate (default: true).
    ///
    /// Setting this to `false` disables all certificate verification,
    /// equivalent to curl's `-k` / `--insecure` flag.
    pub verify_peer: bool,

    /// Whether to verify the server's hostname matches the certificate (default: true).
    ///
    /// When `false`, accepts certificates for any hostname.
    pub verify_host: bool,

    /// Path to a custom CA certificate bundle in PEM format.
    ///
    /// When set, only certificates signed by CAs in this bundle are trusted,
    /// replacing the system default root certificates.
    pub ca_cert: Option<PathBuf>,

    /// Path to a client certificate in PEM format.
    ///
    /// Used for mutual TLS (mTLS) authentication.
    pub client_cert: Option<PathBuf>,

    /// Path to a client private key in PEM format.
    ///
    /// Must correspond to the certificate specified in `client_cert`.
    pub client_key: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_peer: true,
            verify_host: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        }
    }
}

#[cfg(feature = "rustls")]
mod rustls_impl {
    use std::sync::Arc;

    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    use super::TlsConfig;
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
        /// Create a new TLS connector with the given configuration.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built,
        /// or if certificate/key files cannot be read.
        pub fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
            let config = if !tls_config.verify_peer {
                // Insecure mode: accept any certificate
                let mut config = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth();

                Self::configure_alpn(&mut config);
                config
            } else if let Some(ref ca_path) = tls_config.ca_cert {
                // Custom CA bundle
                let root_store = load_ca_certs(ca_path)?;

                let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

                let mut config = if let (Some(ref cert_path), Some(ref key_path)) =
                    (&tls_config.client_cert, &tls_config.client_key)
                {
                    let certs = load_client_certs(cert_path)?;
                    let key = load_client_key(key_path)?;
                    builder
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| Error::Tls(Box::new(e)))?
                } else {
                    builder.with_no_client_auth()
                };

                Self::configure_alpn(&mut config);
                config
            } else {
                // Default: system root certificates
                let root_store: rustls::RootCertStore =
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

                let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

                let mut config = if let (Some(ref cert_path), Some(ref key_path)) =
                    (&tls_config.client_cert, &tls_config.client_key)
                {
                    let certs = load_client_certs(cert_path)?;
                    let key = load_client_key(key_path)?;
                    builder
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| Error::Tls(Box::new(e)))?
                } else {
                    builder.with_no_client_auth()
                };

                Self::configure_alpn(&mut config);
                config
            };

            Ok(Self { config: Arc::new(config) })
        }

        /// Configure ALPN protocols on a `ClientConfig`.
        fn configure_alpn(config: &mut rustls::ClientConfig) {
            #[cfg(feature = "http2")]
            {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            #[cfg(not(feature = "http2"))]
            {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
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

    /// A certificate verifier that accepts any server certificate.
    ///
    /// This is the equivalent of curl's `-k` / `--insecure` flag.
    /// **WARNING: This disables all TLS security. Use only for testing or
    /// when connecting to servers with self-signed certificates.**
    #[derive(Debug)]
    struct NoVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ED448,
            ]
        }
    }

    /// Load CA certificates from a PEM file.
    fn load_ca_certs(path: &std::path::Path) -> Result<rustls::RootCertStore, Error> {
        let file = std::fs::File::open(path).map_err(|e| Error::Tls(Box::new(e)))?;
        let mut reader = std::io::BufReader::new(file);

        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(Box::new(e)))?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(|e| Error::Tls(Box::new(e)))?;
        }

        if root_store.is_empty() {
            return Err(Error::Tls("no valid CA certificates found in file".into()));
        }

        Ok(root_store)
    }

    /// Load client certificates from a PEM file.
    fn load_client_certs(
        path: &std::path::Path,
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Error> {
        let file = std::fs::File::open(path).map_err(|e| Error::Tls(Box::new(e)))?;
        let mut reader = std::io::BufReader::new(file);

        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(Box::new(e)))?;

        if certs.is_empty() {
            return Err(Error::Tls("no valid client certificates found in file".into()));
        }

        Ok(certs)
    }

    /// Load a private key from a PEM file.
    fn load_client_key(
        path: &std::path::Path,
    ) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Error> {
        let file = std::fs::File::open(path).map_err(|e| Error::Tls(Box::new(e)))?;
        let mut reader = std::io::BufReader::new(file);

        // Try loading PKCS#8, RSA, or EC keys
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| Error::Tls(Box::new(e)))?
            .ok_or_else(|| Error::Tls("no valid private key found in file".into()))?;

        Ok(key)
    }
}

#[cfg(feature = "rustls")]
pub use rustls_impl::{AlpnProtocol, TlsConnector};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_default_verifies_peer() {
        let config = TlsConfig::default();
        assert!(config.verify_peer);
        assert!(config.verify_host);
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_creates_with_default_config() {
        let config = TlsConfig::default();
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_creates_with_insecure_config() {
        let config = TlsConfig { verify_peer: false, ..TlsConfig::default() };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_rejects_missing_ca_cert_file() {
        let config = TlsConfig {
            ca_cert: Some(std::path::PathBuf::from("/nonexistent/ca.pem")),
            ..TlsConfig::default()
        };
        let result = TlsConnector::new(&config);
        assert!(result.is_err());
    }
}
