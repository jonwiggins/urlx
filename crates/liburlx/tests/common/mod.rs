//! Shared test infrastructure for liburlx integration tests.
//!
//! Provides a reusable `TestServer` backed by hyper that can be configured
//! with custom handlers for HTTP integration testing.

#![allow(dead_code, unused_results, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A simple HTTP test server that runs on a random local port.
///
/// The server shuts down when dropped.
pub struct TestServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    /// Start a test server with a handler function.
    ///
    /// The handler is called for each incoming request and must return
    /// a hyper `Response<Full<Bytes>>`.
    pub async fn start<F>(handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>>
            + Send
            + Sync
            + 'static
            + Clone,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let (tx, mut rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            let handler = handler.clone();
                            let io = TokioIo::new(stream);
                            tokio::spawn(async move {
                                let _ = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| {
                                            let handler = handler.clone();
                                            async move {
                                                Ok::<_, Infallible>(handler(req))
                                            }
                                        }),
                                    )
                                    .await;
                            });
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });

        Self { addr, shutdown: Some(tx) }
    }

    /// Get the URL for a given path on this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }

    /// Get the server's socket address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Test certificate authority and server certificates generated at test time.
pub struct TestCerts {
    /// CA certificate in PEM format.
    pub ca_cert_pem: Vec<u8>,
    /// Server certificate in PEM format.
    pub server_cert_pem: Vec<u8>,
    /// Server private key in PEM format.
    pub server_key_pem: Vec<u8>,
    /// Client certificate in PEM format (for mTLS tests).
    pub client_cert_pem: Vec<u8>,
    /// Client private key in PEM format (for mTLS tests).
    pub client_key_pem: Vec<u8>,
    /// rustls server config (ready to use).
    pub server_config: Arc<rustls::ServerConfig>,
    /// rustls server config requiring client certificates (mTLS).
    pub mtls_server_config: Arc<rustls::ServerConfig>,
}

impl TestCerts {
    /// Generate a fresh CA + server cert + client cert for testing.
    pub fn generate() -> Self {
        // Generate CA
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate server cert signed by CA
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        server_params.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // Generate client cert signed by CA
        let mut client_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.distinguished_name.push(rcgen::DnType::CommonName, "Test Client");
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        let ca_cert_pem = ca_cert.pem().into_bytes();
        let server_cert_pem = server_cert.pem().into_bytes();
        let server_key_pem = server_key.serialize_pem().into_bytes();
        let client_cert_pem = client_cert.pem().into_bytes();
        let client_key_pem = client_key.serialize_pem().into_bytes();

        // Build rustls server config
        let server_cert_der = rustls::pki_types::CertificateDer::from(server_cert.der().to_vec());
        let server_key_der =
            rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert_der.clone()], server_key_der.clone_key())
            .unwrap();

        // Build mTLS server config (requires client cert)
        let mut ca_root_store = rustls::RootCertStore::empty();
        let ca_cert_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());
        ca_root_store.add(ca_cert_der).unwrap();
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_root_store)).build().unwrap();

        let mtls_server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert_der], server_key_der.clone_key())
            .unwrap();

        Self {
            ca_cert_pem,
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
            server_config: Arc::new(server_config),
            mtls_server_config: Arc::new(mtls_server_config),
        }
    }

    /// Write CA cert to a temporary file and return the path.
    pub fn write_ca_cert(&self) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &self.ca_cert_pem).unwrap();
        f
    }

    /// Write client cert to a temporary file and return the path.
    pub fn write_client_cert(&self) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &self.client_cert_pem).unwrap();
        f
    }

    /// Write client key to a temporary file and return the path.
    pub fn write_client_key(&self) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &self.client_key_pem).unwrap();
        f
    }
}

/// An HTTPS test server that uses self-signed certificates.
///
/// The server shuts down when dropped.
pub struct HttpsTestServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl HttpsTestServer {
    /// Start an HTTPS test server with a handler function and TLS config.
    pub async fn start<F>(server_config: Arc<rustls::ServerConfig>, handler: F) -> Self
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>>
            + Send
            + Sync
            + 'static
            + Clone,
    {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let (tx, mut rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            let handler = handler.clone();
                            let acceptor = tls_acceptor.clone();
                            tokio::spawn(async move {
                                let Ok(tls_stream) = acceptor.accept(stream).await else {
                                    return;
                                };
                                let io = TokioIo::new(tls_stream);
                                let _ = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| {
                                            let handler = handler.clone();
                                            async move {
                                                Ok::<_, Infallible>(handler(req))
                                            }
                                        }),
                                    )
                                    .await;
                            });
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });

        Self { addr, shutdown: Some(tx) }
    }

    /// Get the HTTPS URL for a given path on this server.
    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.addr.port())
    }

    /// Get the server's socket address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for HttpsTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}
