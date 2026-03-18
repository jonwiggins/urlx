//! HTTP authentication mechanisms.
//!
//! Supports Basic, Bearer, Digest (RFC 7616), NTLM, SCRAM-SHA-256, and AWS `SigV4` authentication.

pub mod aws_sigv4;
pub mod cram_md5;
pub mod digest;
pub mod ntlm;
pub mod scram;

/// The HTTP authentication method to use.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// HTTP Basic authentication (RFC 7617).
    ///
    /// Sends credentials as base64-encoded `user:password` on every request.
    Basic,
    /// HTTP Bearer token authentication (RFC 6750).
    Bearer,
    /// HTTP Digest authentication (RFC 7616).
    ///
    /// Performs challenge-response: first request gets 401, then retries
    /// with a computed hash response.
    Digest,
    /// NTLM authentication (NT LAN Manager).
    ///
    /// Multi-step challenge-response: Type 1 negotiate, Type 2 challenge,
    /// Type 3 authenticate.
    Ntlm,
    /// Automatic authentication method selection.
    ///
    /// Sends the first request without auth, then examines the
    /// `WWW-Authenticate` header to pick the strongest supported method
    /// (Digest > NTLM > Basic).
    AnyAuth,
}

/// Credentials for HTTP authentication.
#[derive(Debug, Clone)]
pub struct AuthCredentials {
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// The authentication method to use.
    pub method: AuthMethod,
    /// Optional NTLM domain (e.g., from `DOMAIN\user` format).
    pub domain: Option<String>,
}

/// Proxy authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyAuthMethod {
    /// HTTP Basic authentication.
    Basic,
    /// HTTP Digest authentication.
    Digest,
    /// NTLM authentication.
    Ntlm,
    /// Automatic authentication method selection.
    ///
    /// Sends the first request without auth, then examines the
    /// `Proxy-Authenticate` header to pick the strongest supported method
    /// (NTLM > Digest > Basic).
    Any,
}

/// Proxy authentication credentials.
#[derive(Debug, Clone)]
pub struct ProxyAuthCredentials {
    /// Username for proxy authentication.
    pub username: String,
    /// Password for proxy authentication.
    pub password: String,
    /// The authentication method to use.
    pub method: ProxyAuthMethod,
    /// Optional NTLM domain (e.g., "DOMAIN\\user").
    pub domain: Option<String>,
}
