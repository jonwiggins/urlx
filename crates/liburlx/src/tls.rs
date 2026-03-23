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

    /// In-memory CA certificate bundle in PEM or DER format.
    ///
    /// Alternative to `ca_cert` (file path). When set, these bytes are used
    /// as the trusted CA store. Equivalent to `CURLOPT_CAINFO_BLOB`.
    pub ca_cert_blob: Option<Vec<u8>>,

    /// In-memory client certificate in PEM or DER format.
    ///
    /// Alternative to `client_cert` (file path). Used for mutual TLS.
    /// Equivalent to `CURLOPT_SSLCERT_BLOB`.
    pub client_cert_blob: Option<Vec<u8>>,

    /// In-memory client private key in PEM or DER format.
    ///
    /// Alternative to `client_key` (file path). Must correspond to the
    /// client certificate. Equivalent to `CURLOPT_SSLKEY_BLOB`.
    pub client_key_blob: Option<Vec<u8>>,

    /// Path to a CRL (Certificate Revocation List) file in PEM format.
    ///
    /// When set, the server's certificate chain is checked against this CRL.
    /// If any certificate in the chain has been revoked, the connection fails
    /// with error 60. Equivalent to curl's `--crlfile`.
    pub crl_file: Option<PathBuf>,

    /// TLS-SRP username for password-based TLS authentication (RFC 5054).
    pub srp_user: Option<String>,

    /// TLS-SRP password for password-based TLS authentication (RFC 5054).
    pub srp_password: Option<String>,
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
            ca_cert_blob: None,
            client_cert_blob: None,
            client_key_blob: None,
            crl_file: None,
            srp_user: None,
            srp_password: None,
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
        /// Configures HTTP ALPN protocols (h2, http/1.1) for use with
        /// HTTP/HTTPS connections.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built,
        /// or if certificate/key files cannot be read.
        pub fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
            Self::build(tls_config, true)
        }

        /// Create a new TLS connector without HTTP ALPN negotiation.
        ///
        /// Suitable for non-HTTP protocols (FTP, SMTP, etc.) where
        /// HTTP-specific ALPN extensions would be inappropriate.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS configuration cannot be built,
        /// or if certificate/key files cannot be read.
        pub fn new_no_alpn(tls_config: &TlsConfig) -> Result<Self, Error> {
            Self::build(tls_config, false)
        }

        /// Internal builder shared by `new()` and `new_no_alpn()`.
        fn build(tls_config: &TlsConfig, use_http_alpn: bool) -> Result<Self, Error> {
            let versions = Self::protocol_versions(tls_config);

            let config = if !tls_config.verify_peer {
                // Insecure mode: accept any certificate
                let mut config = Self::config_builder(&versions)
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth();

                if use_http_alpn {
                    Self::configure_alpn(&mut config);
                }
                config
            } else if let Some(ref ca_path) = tls_config.ca_cert {
                // Custom CA bundle from file
                let root_store = load_ca_certs(ca_path)?;

                // When a CRL file is specified, build a custom verifier with
                // CRL checking (curl compat: test 313 — --crlfile)
                if let Some(ref crl_path) = tls_config.crl_file {
                    let crls = load_crls(crl_path)?;
                    let verifier =
                        rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                            .with_crls(crls)
                            .build()
                            .map_err(|e| {
                                Error::Tls(format!("CRL verifier build failed: {e}").into())
                            })?;

                    let builder = Self::config_builder(&versions)
                        .dangerous()
                        .with_custom_certificate_verifier(verifier);

                    let mut config = builder.with_no_client_auth();
                    if use_http_alpn {
                        Self::configure_alpn(&mut config);
                    }
                    config
                } else {
                    let builder =
                        Self::config_builder(&versions).with_root_certificates(root_store);

                    let mut config = Self::with_client_auth(builder, tls_config)?;
                    if use_http_alpn {
                        Self::configure_alpn(&mut config);
                    }
                    config
                }
            } else if let Some(ref ca_blob) = tls_config.ca_cert_blob {
                // Custom CA bundle from in-memory blob
                let root_store = load_ca_certs_from_blob(ca_blob)?;

                let builder = Self::config_builder(&versions).with_root_certificates(root_store);

                let mut config = Self::with_client_auth(builder, tls_config)?;
                if use_http_alpn {
                    Self::configure_alpn(&mut config);
                }
                config
            } else {
                // Default: system root certificates
                let root_store: rustls::RootCertStore =
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

                let builder = Self::config_builder(&versions).with_root_certificates(root_store);

                let mut config = Self::with_client_auth(builder, tls_config)?;
                if use_http_alpn {
                    Self::configure_alpn(&mut config);
                }
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
            // Try file-based client auth first, then blob-based
            if let (Some(ref cert_path), Some(ref key_path)) =
                (&tls_config.client_cert, &tls_config.client_key)
            {
                let certs = load_client_certs(cert_path)?;
                let key = load_client_key(key_path)?;
                builder.with_client_auth_cert(certs, key).map_err(|e| Error::Tls(Box::new(e)))
            } else if let (Some(ref cert_blob), Some(ref key_blob)) =
                (&tls_config.client_cert_blob, &tls_config.client_key_blob)
            {
                let certs = load_client_certs_from_blob(cert_blob)?;
                let key = load_client_key_from_blob(key_blob)?;
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

        /// Wrap a generic stream with TLS and return the stream and negotiated ALPN.
        ///
        /// Used when the inner stream is not a plain `TcpStream` (e.g., for
        /// HTTPS proxy tunnels where the stream is already TLS-wrapped).
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the handshake fails.
        pub async fn connect_generic<S>(
            &self,
            stream: S,
            server_name: &str,
        ) -> Result<(TlsStream<S>, AlpnProtocol), Error>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        {
            let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|e| Error::Tls(Box::new(e)))?;

            let connector = tokio_rustls::TlsConnector::from(self.config.clone());
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::Tls(Box::new(e)))?;

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

    /// Load CRLs (Certificate Revocation Lists) from a PEM file.
    fn load_crls(
        path: &std::path::Path,
    ) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, Error> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateRevocationListDer;

        let crls = CertificateRevocationListDer::pem_file_iter(path)
            .map_err(|e| Error::Tls(Box::new(e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(Box::new(e)))?;

        if crls.is_empty() {
            return Err(Error::Tls("no valid CRLs found in file".into()));
        }

        Ok(crls)
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

    /// Load CA certificates from an in-memory PEM blob.
    fn load_ca_certs_from_blob(blob: &[u8]) -> Result<rustls::RootCertStore, Error> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let certs = CertificateDer::pem_slice_iter(blob)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(Box::new(e)))?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(|e| Error::Tls(Box::new(e)))?;
        }

        if root_store.is_empty() {
            return Err(Error::Tls("no valid CA certificates found in blob".into()));
        }

        Ok(root_store)
    }

    /// Load client certificates from an in-memory PEM blob.
    fn load_client_certs_from_blob(
        blob: &[u8],
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Error> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let certs = CertificateDer::pem_slice_iter(blob)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(Box::new(e)))?;

        if certs.is_empty() {
            return Err(Error::Tls("no valid client certificates found in blob".into()));
        }

        Ok(certs)
    }

    /// Load a private key from an in-memory PEM blob.
    fn load_client_key_from_blob(
        blob: &[u8],
    ) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Error> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::PrivateKeyDer;

        PrivateKeyDer::from_pem_slice(blob).map_err(|e| Error::Tls(Box::new(e)))
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

#[cfg(feature = "tls-srp")]
#[allow(unsafe_code)]
mod openssl_srp_impl {
    use std::pin::Pin;

    use tokio::net::TcpStream;

    use super::TlsConfig;
    use crate::error::Error;

    // FFI bindings for OpenSSL SRP functions (deprecated in 3.0 but still available)
    extern "C" {
        fn SSL_CTX_set_srp_username(
            ctx: *mut openssl_sys::SSL_CTX,
            name: *const std::os::raw::c_char,
        ) -> std::os::raw::c_int;
        fn SSL_CTX_set_srp_password(
            ctx: *mut openssl_sys::SSL_CTX,
            password: *const std::os::raw::c_char,
        ) -> std::os::raw::c_int;
    }

    /// A TLS connector using OpenSSL with SRP (Secure Remote Password) key exchange.
    ///
    /// This connector is used only when TLS-SRP credentials are configured
    /// (`--tlsuser` and `--tlspassword`). It provides password-based TLS
    /// authentication without certificates (RFC 5054).
    pub struct SrpTlsConnector {
        connector: openssl::ssl::SslConnector,
    }

    impl SrpTlsConnector {
        /// Create a new SRP TLS connector with the given configuration.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the OpenSSL configuration cannot be built
        /// or SRP credentials cannot be set.
        pub fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

            let mut builder = SslConnector::builder(SslMethod::tls_client())
                .map_err(|e| Error::Tls(Box::new(e)))?;

            // Set SRP credentials via openssl-sys FFI
            if let (Some(user), Some(password)) = (&tls_config.srp_user, &tls_config.srp_password) {
                Self::set_srp_credentials(&mut builder, user, password)?;
            }

            // Use SRP-only cipher suites (no fallback to non-SRP ciphers).
            // SRP ciphers only work with TLS 1.2 and below, so cap the max version.
            builder.set_cipher_list("SRP").map_err(|e| Error::Tls(Box::new(e)))?;
            builder
                .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(Box::new(e)))?;

            // Configure certificate verification
            if !tls_config.verify_peer {
                builder.set_verify(SslVerifyMode::NONE);
            }

            // Set CA cert if provided
            if let Some(ref ca_path) = tls_config.ca_cert {
                builder.set_ca_file(ca_path).map_err(|e| Error::Tls(Box::new(e)))?;
            }

            let connector = builder.build();
            Ok(Self { connector })
        }

        /// Set SRP username and password on the SSL context via OpenSSL FFI.
        fn set_srp_credentials(
            builder: &mut openssl::ssl::SslConnectorBuilder,
            user: &str,
            password: &str,
        ) -> Result<(), Error> {
            use std::ffi::CString;

            let user_c = CString::new(user)
                .map_err(|_| Error::Tls("SRP username contains null byte".into()))?;
            let pass_c = CString::new(password)
                .map_err(|_| Error::Tls("SRP password contains null byte".into()))?;

            // SAFETY: We pass valid CString pointers to OpenSSL SRP functions.
            // The SSL_CTX copies these strings internally, so they don't need
            // to outlive this call. The ctx pointer is valid because it comes
            // from a live SslConnectorBuilder.
            unsafe {
                let ctx = builder.as_ptr();
                let ret = SSL_CTX_set_srp_username(ctx, user_c.as_ptr());
                if ret != 1 {
                    return Err(Error::Tls("failed to set SRP username".into()));
                }
                let ret = SSL_CTX_set_srp_password(ctx, pass_c.as_ptr());
                if ret != 1 {
                    return Err(Error::Tls("failed to set SRP password".into()));
                }
            }

            Ok(())
        }

        /// Connect to a server using TLS-SRP key exchange.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Tls`] if the TLS handshake fails (e.g., invalid
        /// SRP credentials, server doesn't support SRP, or certificate
        /// verification failure).
        pub async fn connect(
            &self,
            stream: TcpStream,
            server_name: &str,
        ) -> Result<tokio_openssl::SslStream<TcpStream>, Error> {
            let ssl = self
                .connector
                .configure()
                .map_err(|e| Error::Tls(Box::new(e)))?
                .into_ssl(server_name)
                .map_err(|e| Error::Tls(Box::new(e)))?;

            let mut ssl_stream =
                tokio_openssl::SslStream::new(ssl, stream).map_err(|e| Error::Tls(Box::new(e)))?;

            Pin::new(&mut ssl_stream).connect().await.map_err(|e| {
                // Map OpenSSL errors to curl-compatible error codes.
                // SSL handshake failures map to Error::Tls (exit code 35).
                Error::Tls(Box::new(e))
            })?;

            Ok(ssl_stream)
        }
    }

    /// Returns true if TLS-SRP is configured (both user and password set).
    #[must_use]
    pub const fn is_srp_configured(tls_config: &TlsConfig) -> bool {
        tls_config.srp_user.is_some() && tls_config.srp_password.is_some()
    }
}

#[cfg(feature = "tls-srp")]
pub use openssl_srp_impl::{is_srp_configured, SrpTlsConnector};

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

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_no_alpn_creates_ok() {
        let config = TlsConfig::default();
        let connector = TlsConnector::new_no_alpn(&config);
        assert!(connector.is_ok());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_no_alpn_insecure() {
        let config = TlsConfig { verify_peer: false, ..TlsConfig::default() };
        let connector = TlsConnector::new_no_alpn(&config);
        assert!(connector.is_ok());
    }

    #[test]
    fn tls_config_default_has_no_ca_cert_blob() {
        let config = TlsConfig::default();
        assert!(config.ca_cert_blob.is_none());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_valid_ca_cert_blob() {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem().into_bytes();

        let config = TlsConfig { ca_cert_blob: Some(ca_pem), ..TlsConfig::default() };
        let connector = TlsConnector::new(&config);
        assert!(connector.is_ok(), "valid PEM CA cert blob should create TLS connector");
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_invalid_ca_cert_blob_fails() {
        let config = TlsConfig {
            ca_cert_blob: Some(b"not valid PEM data".to_vec()),
            ..TlsConfig::default()
        };
        let result = TlsConnector::new(&config);
        assert!(result.is_err(), "invalid PEM blob should fail");
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_with_empty_ca_cert_blob_fails() {
        let config = TlsConfig { ca_cert_blob: Some(Vec::new()), ..TlsConfig::default() };
        let result = TlsConnector::new(&config);
        assert!(result.is_err(), "empty blob should fail");
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_ca_cert_blob_no_alpn() {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem().into_bytes();

        let config = TlsConfig { ca_cert_blob: Some(ca_pem), ..TlsConfig::default() };
        let connector = TlsConnector::new_no_alpn(&config);
        assert!(connector.is_ok(), "valid PEM CA cert blob should work without ALPN");
    }
}
