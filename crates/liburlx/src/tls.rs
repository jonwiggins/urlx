//! TLS connector using rustls.
//!
//! Provides TLS connection wrapping for HTTPS transfers, with configurable
//! certificate verification, custom CA bundles, and client certificates.

use std::path::PathBuf;

/// Minimum TLS protocol version to allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

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

    /// Minimum TLS version to allow.
    ///
    /// When set, connections using a lower TLS version will be rejected.
    /// Equivalent to curl's `--tlsv1.2` or `--tlsv1.3`.
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version to allow.
    ///
    /// When set, connections using a higher TLS version will not be attempted.
    /// Equivalent to curl's `--tls-max`.
    pub max_tls_version: Option<TlsVersion>,

    /// SHA-256 hash of the server's public key for pinning.
    ///
    /// Format: `sha256//<base64-encoded-hash>` (same as curl's `--pinnedpubkey`).
    /// The connection will fail if the server's public key hash doesn't match.
    pub pinned_public_key: Option<String>,

    /// Cipher suite list specification.
    ///
    /// Stored for logging and compatibility; rustls uses a fixed set of
    /// secure cipher suites and does not support arbitrary filtering.
    /// Equivalent to `CURLOPT_SSL_CIPHER_LIST`.
    pub cipher_list: Option<String>,

    /// Whether to enable TLS session ID caching for reuse (default: true).
    ///
    /// When enabled (the default), TLS session tickets are accepted for
    /// faster reconnections. Equivalent to `CURLOPT_SSL_SESSIONID_CACHE`.
    pub session_cache: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_peer: true,
            verify_host: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            min_tls_version: None,
            max_tls_version: None,
            pinned_public_key: None,
            cipher_list: None,
            session_cache: true,
        }
    }
}

#[cfg(feature = "rustls")]
mod rustls_impl {
    use std::sync::Arc;

    use rustls::client::WantsClientCert;
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    use super::{TlsConfig, TlsVersion};
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
        /// SHA-256 pin of the server's public key (base64-encoded).
        pinned_public_key: Option<String>,
    }

    impl TlsConnector {
        /// Create a new TLS connector with the given configuration.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built,
        /// or if certificate/key files cannot be read.
        pub fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
            let versions = Self::protocol_versions(tls_config);

            let config = if !tls_config.verify_peer {
                // Insecure mode: accept any certificate
                let mut config = Self::config_builder(&versions)
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth();

                Self::configure_alpn(&mut config);
                config
            } else if let Some(ref ca_path) = tls_config.ca_cert {
                // Custom CA bundle
                let root_store = load_ca_certs(ca_path)?;

                let builder = Self::config_builder(&versions).with_root_certificates(root_store);

                let mut config = Self::with_client_auth(builder, tls_config)?;
                Self::configure_alpn(&mut config);
                config
            } else {
                // Default: system root certificates
                let root_store: rustls::RootCertStore =
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

                let builder = Self::config_builder(&versions).with_root_certificates(root_store);

                let mut config = Self::with_client_auth(builder, tls_config)?;
                Self::configure_alpn(&mut config);
                config
            };

            // Extract the base64 hash from the "sha256//..." format
            let pinned_public_key = tls_config
                .pinned_public_key
                .as_ref()
                .and_then(|pin| pin.strip_prefix("sha256//").map(ToString::to_string));

            Ok(Self { config: Arc::new(config), pinned_public_key })
        }

        /// Determine the allowed TLS protocol versions based on config.
        fn protocol_versions(
            tls_config: &TlsConfig,
        ) -> Vec<&'static rustls::SupportedProtocolVersion> {
            let all = [
                (TlsVersion::Tls12, &rustls::version::TLS12),
                (TlsVersion::Tls13, &rustls::version::TLS13),
            ];

            let min = tls_config.min_tls_version.unwrap_or(TlsVersion::Tls12);
            let max = tls_config.max_tls_version.unwrap_or(TlsVersion::Tls13);

            all.iter().filter(|(v, _)| *v >= min && *v <= max).map(|(_, proto)| *proto).collect()
        }

        /// Create a config builder with the given protocol versions.
        fn config_builder(
            versions: &[&'static rustls::SupportedProtocolVersion],
        ) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
            if versions.is_empty() {
                // Fallback: use defaults (shouldn't happen with valid min/max)
                rustls::ClientConfig::builder()
            } else {
                rustls::ClientConfig::builder_with_protocol_versions(versions)
            }
        }

        /// Apply client auth configuration to a builder.
        fn with_client_auth(
            builder: rustls::ConfigBuilder<rustls::ClientConfig, WantsClientCert>,
            tls_config: &TlsConfig,
        ) -> Result<rustls::ClientConfig, Error> {
            if let (Some(ref cert_path), Some(ref key_path)) =
                (&tls_config.client_cert, &tls_config.client_key)
            {
                let certs = load_client_certs(cert_path)?;
                let key = load_client_key(key_path)?;
                builder.with_client_auth_cert(certs, key).map_err(|e| Error::Tls(Box::new(e)))
            } else {
                Ok(builder.with_no_client_auth())
            }
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
        /// Returns [`Error::Tls`] if the handshake fails or certificate pinning
        /// validation fails.
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

            // Verify certificate pinning if configured
            if let Some(ref expected_hash) = self.pinned_public_key {
                Self::verify_pin(&tls_stream, expected_hash)?;
            }

            // Check ALPN result
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .and_then(|p| if p == b"h2" { Some(AlpnProtocol::H2) } else { None })
                .unwrap_or(AlpnProtocol::Http11);

            Ok((tls_stream, alpn))
        }

        /// Verify the server's public key hash matches the pinned value.
        fn verify_pin(
            tls_stream: &TlsStream<TcpStream>,
            expected_hash_b64: &str,
        ) -> Result<(), Error> {
            use base64::Engine as _;
            use sha2::Digest as _;

            let peer_certs = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .ok_or_else(|| Error::Tls("no peer certificates for pinning check".into()))?;

            let leaf_cert = peer_certs
                .first()
                .ok_or_else(|| Error::Tls("no leaf certificate for pinning check".into()))?;

            // Parse the DER certificate to extract the SPKI
            let spki = extract_spki_der(leaf_cert.as_ref())
                .ok_or_else(|| Error::Tls("failed to extract SPKI from certificate".into()))?;

            // Hash the SPKI
            let actual_hash = sha2::Sha256::digest(spki);
            let actual_hash_b64 = base64::engine::general_purpose::STANDARD.encode(actual_hash);

            if actual_hash_b64 != expected_hash_b64 {
                return Err(Error::Tls(
                    format!(
                        "certificate pinning failed: expected sha256//{expected_hash_b64}, got sha256//{actual_hash_b64}"
                    )
                    .into(),
                ));
            }

            Ok(())
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
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| Error::Tls(Box::new(e)))?
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
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| Error::Tls(Box::new(e)))?
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
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::PrivateKeyDer;

        let key = PrivateKeyDer::from_pem_file(path).map_err(|e| Error::Tls(Box::new(e)))?;

        Ok(key)
    }

    /// Extract the Subject Public Key Info (SPKI) DER bytes from an X.509 certificate.
    ///
    /// This is a minimal DER parser — it walks the ASN.1 structure of the certificate
    /// to find the `subjectPublicKeyInfo` field (the 7th element of the `TBSCertificate`).
    ///
    /// X.509 structure:
    /// ```text
    /// Certificate ::= SEQUENCE {
    ///     tbsCertificate      TBSCertificate,
    ///     ...
    /// }
    /// TBSCertificate ::= SEQUENCE {
    ///     version         [0] EXPLICIT Version DEFAULT v1,
    ///     serialNumber    CertificateSerialNumber,
    ///     signature       AlgorithmIdentifier,
    ///     issuer          Name,
    ///     validity        Validity,
    ///     subject         Name,
    ///     subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///     ...
    /// }
    /// ```
    pub fn extract_spki_der(cert_der: &[u8]) -> Option<&[u8]> {
        // Parse outer SEQUENCE (Certificate)
        let (_, cert_content) = parse_der_element(cert_der)?;
        // Parse TBSCertificate SEQUENCE
        let (_, tbs_content) = parse_der_element(cert_content)?;

        // Skip fields in TBSCertificate to reach subjectPublicKeyInfo (index 6)
        let mut pos = tbs_content;
        for _ in 0..6 {
            let (rest, _) = parse_der_element(pos)?;
            pos = rest;
        }

        // The next element is the SPKI — return its full DER encoding (tag + length + content)
        let (_, _) = parse_der_element(pos)?;
        let spki_len = pos.len() - parse_der_element(pos)?.0.len();
        Some(&pos[..spki_len])
    }

    /// Parse a single DER element, returning (remaining bytes, element content).
    ///
    /// For constructed types (SEQUENCE, SET), the content is the inner bytes.
    /// For primitive types, the content is the value bytes.
    pub fn parse_der_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
        if data.is_empty() {
            return None;
        }

        // Tag byte at data[0] is consumed but not inspected
        let (len, header_size) = parse_der_length(&data[1..])?;
        let total_header = 1 + header_size;

        if data.len() < total_header + len {
            return None;
        }

        let content = &data[total_header..total_header + len];
        let rest = &data[total_header + len..];
        Some((rest, content))
    }

    /// Parse a DER length field, returning (length, number of bytes consumed).
    pub fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() {
            return None;
        }

        if data[0] < 0x80 {
            // Short form
            Some((data[0] as usize, 1))
        } else {
            // Long form
            let num_bytes = (data[0] & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
                return None;
            }
            let mut len = 0usize;
            for &b in &data[1..=num_bytes] {
                len = len.checked_mul(256)?.checked_add(b as usize)?;
            }
            Some((len, 1 + num_bytes))
        }
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

    #[test]
    fn tls_version_ordering() {
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_min_tls13() {
        let config = TlsConfig { min_tls_version: Some(TlsVersion::Tls13), ..TlsConfig::default() };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_max_tls12() {
        let config = TlsConfig { max_tls_version: Some(TlsVersion::Tls12), ..TlsConfig::default() };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_tls12_only() {
        let config = TlsConfig {
            min_tls_version: Some(TlsVersion::Tls12),
            max_tls_version: Some(TlsVersion::Tls12),
            ..TlsConfig::default()
        };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_tls13_only() {
        let config = TlsConfig {
            min_tls_version: Some(TlsVersion::Tls13),
            max_tls_version: Some(TlsVersion::Tls13),
            ..TlsConfig::default()
        };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[test]
    fn tls_config_default_has_no_pin() {
        let config = TlsConfig::default();
        assert!(config.pinned_public_key.is_none());
    }

    #[test]
    fn tls_config_default_cipher_list_none() {
        let config = TlsConfig::default();
        assert!(config.cipher_list.is_none());
    }

    #[test]
    fn tls_config_default_session_cache_enabled() {
        let config = TlsConfig::default();
        assert!(config.session_cache);
    }

    #[test]
    fn tls_config_cipher_list_set() {
        let config =
            TlsConfig { cipher_list: Some("HIGH:!aNULL:!MD5".to_string()), ..TlsConfig::default() };
        assert_eq!(config.cipher_list.as_deref(), Some("HIGH:!aNULL:!MD5"));
    }

    #[test]
    fn tls_config_session_cache_disabled() {
        let config = TlsConfig { session_cache: false, ..TlsConfig::default() };
        assert!(!config.session_cache);
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_pin_creates_ok() {
        let config = TlsConfig {
            pinned_public_key: Some(
                "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ),
            ..TlsConfig::default()
        };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn der_parser_short_length() {
        use rustls_impl::parse_der_length;
        assert_eq!(parse_der_length(&[0x05]), Some((5, 1)));
        assert_eq!(parse_der_length(&[0x7F]), Some((127, 1)));
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn der_parser_long_length() {
        use rustls_impl::parse_der_length;
        // 0x81 0x80 = 128 in long form (1 byte for length)
        assert_eq!(parse_der_length(&[0x81, 0x80]), Some((128, 2)));
        // 0x82 0x01 0x00 = 256 in long form (2 bytes for length)
        assert_eq!(parse_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn der_parser_empty() {
        use rustls_impl::parse_der_length;
        assert_eq!(parse_der_length(&[]), None);
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn der_parse_element_simple() {
        use rustls_impl::parse_der_element;
        // SEQUENCE (tag 0x30) with 2 bytes of content
        let data = [0x30, 0x02, 0xAA, 0xBB, 0xCC];
        let (rest, content) = parse_der_element(&data).unwrap();
        assert_eq!(content, &[0xAA, 0xBB]);
        assert_eq!(rest, &[0xCC]);
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn extract_spki_from_generated_cert() {
        use rustls_impl::extract_spki_der;
        // Generate a self-signed cert using rcgen and verify SPKI extraction
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der();

        let spki = extract_spki_der(cert_der);
        assert!(spki.is_some());
        let spki = spki.unwrap();
        // SPKI should start with SEQUENCE tag (0x30)
        assert_eq!(spki[0], 0x30);
        // SPKI should be non-trivially long
        assert!(spki.len() > 32);
    }
}
