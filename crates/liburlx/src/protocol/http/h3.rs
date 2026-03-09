//! HTTP/3 request/response codec.
//!
//! Uses the `h3` and `h3-quinn` crates for HTTP/3 over QUIC transport.
//! HTTP/3 connections are established via QUIC (RFC 9000) and use
//! the HTTP/3 framing protocol (RFC 9114).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Buf;

use crate::error::Error;
use crate::protocol::http::response::Response;
use crate::throttle::{RateLimiter, SpeedLimits, THROTTLE_CHUNK_SIZE};

/// Create a QUIC client configuration using rustls.
///
/// Uses the same TLS settings as HTTP/2 connections but with QUIC-specific
/// ALPN protocol identifiers (h3).
fn make_quic_client_config(verify_peer: bool) -> Result<quinn::ClientConfig, Error> {
    let mut tls_config = if verify_peer {
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| Error::Http(format!("QUIC TLS config error: {e}")))?;

    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Certificate verifier that accepts all certificates (for `-k` / insecure mode).
#[derive(Debug)]
struct InsecureServerVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerVerifier {
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
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Send an HTTP/3 request over QUIC and read the response.
///
/// Establishes a new QUIC connection to the given address, performs an
/// HTTP/3 request, and returns the response.
///
/// # Errors
///
/// Returns errors for QUIC connection failures, TLS errors, or HTTP/3 protocol errors.
#[allow(clippy::too_many_arguments)]
pub async fn request(
    addr: SocketAddr,
    server_name: &str,
    method: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
    speed_limits: &SpeedLimits,
    verify_peer: bool,
) -> Result<Response, Error> {
    // Create QUIC client configuration
    let client_config = make_quic_client_config(verify_peer)?;

    // Create QUIC endpoint (bind to any local address)
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| Error::Http(format!("failed to parse bind address: {e}")))?,
    )
    .map_err(|e| Error::Http(format!("failed to create QUIC endpoint: {e}")))?;

    endpoint.set_default_client_config(client_config);

    // Connect to the server — try 0-RTT first, fall back to full handshake
    let connecting = endpoint
        .connect(addr, server_name)
        .map_err(|e| Error::Http(format!("QUIC connect error: {e}")))?;

    let connection = match connecting.into_0rtt() {
        Ok((conn, _zero_rtt_accepted)) => {
            // 0-RTT connection established (session resumption available)
            // _zero_rtt_accepted is a future that resolves when server confirms 0-RTT
            conn
        }
        Err(connecting) => {
            // No 0-RTT data available, perform full handshake
            connecting.await.map_err(|e| {
                Error::Connect(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                ))
            })?
        }
    };

    // Create h3 connection over QUIC
    let quinn_conn = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn)
        .await
        .map_err(|e| Error::Http(format!("h3 handshake failed: {e}")))?;

    // Spawn the h3 connection driver in the background
    let _driver_handle = tokio::spawn(async move {
        let _r = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Build the request
    let uri: http::Uri = format!("https://{server_name}{request_target}")
        .parse()
        .map_err(|e: http::uri::InvalidUri| Error::Http(format!("invalid URI: {e}")))?;

    let method: http::Method = method
        .parse()
        .map_err(|e: http::method::InvalidMethod| Error::Http(format!("invalid method: {e}")))?;

    let is_head = method == http::Method::HEAD;

    let mut builder = http::Request::builder().method(method).uri(uri);

    builder = builder.header("host", server_name);

    let has_user_agent = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    if !has_user_agent {
        builder = builder.header("user-agent", "urlx/0.1.0");
    }

    let has_accept = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept"));
    if !has_accept {
        builder = builder.header("accept", "*/*");
    }

    for (name, value) in custom_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    let req =
        builder.body(()).map_err(|e| Error::Http(format!("failed to build h3 request: {e}")))?;

    // Send the request
    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| Error::Http(format!("h3 send failed: {e}")))?;

    // Send body if present
    if let Some(body_data) = body {
        let mut send_limiter = RateLimiter::for_send(speed_limits);
        if send_limiter.is_active() {
            let mut offset = 0;
            while offset < body_data.len() {
                let end = (offset + THROTTLE_CHUNK_SIZE).min(body_data.len());
                let chunk = &body_data[offset..end];
                let chunk_len = chunk.len();
                stream
                    .send_data(bytes::Bytes::copy_from_slice(chunk))
                    .await
                    .map_err(|e| Error::Http(format!("h3 body send failed: {e}")))?;
                send_limiter.record(chunk_len).await?;
                offset = end;
            }
        } else {
            stream
                .send_data(bytes::Bytes::copy_from_slice(body_data))
                .await
                .map_err(|e| Error::Http(format!("h3 body send failed: {e}")))?;
        }
    }

    // Signal end of request
    stream.finish().await.map_err(|e| Error::Http(format!("h3 finish failed: {e}")))?;

    // Receive response
    let h3_response =
        stream.recv_response().await.map_err(|e| Error::Http(format!("h3 response error: {e}")))?;

    let status = h3_response.status().as_u16();

    // Convert headers
    let mut headers = HashMap::new();
    for (name, value) in h3_response.headers() {
        let name = name.as_str().to_lowercase();
        let value = String::from_utf8_lossy(value.as_bytes()).to_string();
        let _old = headers.insert(name, value);
    }

    // HEAD responses have no body
    if is_head {
        return Ok(Response::new(status, headers, Vec::new(), url.to_string()));
    }

    // Read body with optional rate limiting
    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
    let mut body_bytes = Vec::new();
    while let Some(chunk) =
        stream.recv_data().await.map_err(|e| Error::Http(format!("h3 body read error: {e}")))?
    {
        let chunk_len = chunk.remaining();
        body_bytes.extend_from_slice(chunk.chunk());
        if recv_limiter.is_active() {
            recv_limiter.record(chunk_len).await?;
        }
    }

    Ok(Response::new(status, headers, body_bytes, url.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn quic_client_config_secure() {
        let config = super::make_quic_client_config(true);
        assert!(config.is_ok());
    }

    #[test]
    fn quic_client_config_insecure() {
        let config = super::make_quic_client_config(false);
        assert!(config.is_ok());
    }
}
