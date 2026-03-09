//! HTTP authentication mechanisms.
//!
//! Supports Basic, Bearer, and Digest (RFC 7616) authentication.

pub mod digest;

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
}
