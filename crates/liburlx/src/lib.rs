//! # liburlx
//!
//! A memory-safe URL transfer library — a from-scratch Rust reimplementation of libcurl.
//!
//! `liburlx` provides both blocking ([`Easy`]) and concurrent ([`Multi`]) APIs for
//! transferring data over URLs. It supports HTTP/1.0-1.1, HTTP/2, HTTP/3 (QUIC), FTP/FTPS,
//! SFTP/SCP, WebSocket, SMTP, IMAP, POP3, MQTT, DICT, TFTP, Gopher, RTSP, and `file://`.
//!
//! Zero `unsafe` code — all unsafe is confined to the separate `liburlx-ffi` crate.
//! TLS is provided by [rustls](https://github.com/rustls/rustls) with no OpenSSL dependency.
//!
//! ## Quick start
//!
//! ```no_run
//! # fn main() -> Result<(), liburlx::Error> {
//! // Simple GET request
//! let mut easy = liburlx::Easy::new();
//! easy.url("https://httpbin.org/get")?;
//! let response = easy.perform()?;
//!
//! println!("Status: {}", response.status());          // 200
//! println!("Body: {}", response.body_str()?);          // {"origin": ...}
//! println!("Content-Type: {:?}", response.content_type()); // Some("application/json")
//! # Ok(())
//! # }
//! ```
//!
//! ## POST with headers and authentication
//!
//! ```no_run
//! # fn main() -> Result<(), liburlx::Error> {
//! let mut easy = liburlx::Easy::new();
//! easy.url("https://api.example.com/data")?;
//! easy.method("POST");
//! easy.header("Content-Type", "application/json");
//! easy.body(br#"{"key": "value"}"#);
//! easy.basic_auth("user", "password");
//! easy.follow_redirects(true);
//!
//! let response = easy.perform()?;
//! assert_eq!(response.status(), 200);
//! # Ok(())
//! # }
//! ```
//!
//! ## Concurrent transfers
//!
//! [`Multi`] runs multiple transfers concurrently using tokio under the hood:
//!
//! ```no_run
//! # fn main() -> Result<(), liburlx::Error> {
//! let mut multi = liburlx::Multi::new();
//!
//! let mut a = liburlx::Easy::new();
//! a.url("https://httpbin.org/get")?;
//! multi.add(a);
//!
//! let mut b = liburlx::Easy::new();
//! b.url("https://httpbin.org/ip")?;
//! multi.add(b);
//!
//! let results = multi.perform_blocking()?;
//! for result in &results {
//!     match result {
//!         Ok(resp) => println!("{}: {}", resp.effective_url(), resp.status()),
//!         Err(e) => eprintln!("Transfer failed: {e}"),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## TLS configuration
//!
//! ```no_run
//! # fn main() -> Result<(), liburlx::Error> {
//! use std::path::Path;
//!
//! let mut easy = liburlx::Easy::new();
//! easy.url("https://internal.corp.example.com/api")?;
//! easy.ssl_ca_cert(Path::new("/etc/ssl/custom-ca.pem"));
//! easy.ssl_client_cert(Path::new("client.pem"));
//! easy.ssl_client_key(Path::new("client-key.pem"));
//! easy.ssl_pinned_public_key("sha256//YhKJG3phE6xw3TXJdrKg0MF2SHqP2D7jOZ+Buvnb5dA=");
//!
//! let response = easy.perform()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## FTP upload
//!
//! ```no_run
//! # fn main() -> Result<(), liburlx::Error> {
//! let mut easy = liburlx::Easy::new();
//! easy.url("ftp://ftp.example.com/upload/data.csv")?;
//! easy.basic_auth("ftpuser", "ftppass");
//! easy.upload_file(std::path::Path::new("data.csv"))?;
//!
//! let response = easy.perform()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `http` | Yes | HTTP/1.x protocol |
//! | `http2` | Yes | HTTP/2 via the `h2` crate |
//! | `http3` | No | HTTP/3 via `quinn` (QUIC) |
//! | `rustls` | Yes | TLS via rustls (no OpenSSL) |
//! | `tls-srp` | No | TLS-SRP via OpenSSL |
//! | `ssh` | No | SFTP/SCP via `russh` |
//! | `decompression` | Yes | gzip, deflate, brotli, zstd |
//! | `hickory-dns` | No | Async DNS with DoH/DoT via `hickory-resolver` |
//!
//! ## Architecture
//!
//! - **[`Easy`]** — Single-transfer blocking API. Wraps a tokio runtime internally.
//!   Configure the request, call [`Easy::perform`], get a [`Response`].
//! - **[`Multi`]** — Concurrent transfers. Add multiple [`Easy`] handles, execute
//!   them all with [`Multi::perform_blocking`].
//! - **[`Response`]** — Status, headers, body, and detailed transfer info (timing,
//!   connection metadata, TLS certificates).
//! - **[`Error`]** — Non-exhaustive error enum with variants for each failure mode
//!   (DNS, TLS, timeout, auth, protocol-specific errors).
//! - **[`CookieJar`]** / **[`HstsCache`]** / **[`DnsCache`]** — Shared state that
//!   can be attached to transfers or shared across handles via [`Share`].

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod cookie;
pub mod dns;
pub mod easy;
pub mod error;
pub mod glob;
pub mod hsts;
pub mod idn;
pub mod multi;
pub mod netrc;
pub(crate) mod pool;
pub mod progress;
pub mod protocol;
pub mod proxy;
pub mod share;
pub mod throttle;
pub mod tls;
pub mod url;

pub use auth::{AuthCredentials, AuthMethod, ProxyAuthCredentials, ProxyAuthMethod};
pub use cookie::CookieJar;
#[cfg(feature = "hickory-dns")]
pub use dns::HickoryResolver;
pub use dns::{DnsCache, DnsResolver};
pub use easy::{Easy, HttpVersion};
pub use error::Error;
pub use hsts::HstsCache;
pub use multi::{Multi, PipeliningMode};
pub use progress::{make_progress_callback, ProgressCallback, ProgressInfo};
pub use protocol::http::multipart::{
    guess_content_type as guess_form_content_type, FilenameEscapeMode, MultipartForm,
};
pub use protocol::http::response::{PushedResponse, Response, ResponseHttpVersion, TransferInfo};
pub use share::{Share, ShareType};
pub use throttle::SpeedLimits;
pub use tls::{TlsConfig, TlsVersion};
pub use url::Url;

pub use protocol::ftp::{FtpConfig, FtpMethod, FtpSslMode, UseSsl};
#[cfg(feature = "ssh")]
pub use protocol::ssh::{SshAuthMethod, SshHostKeyPolicy};

/// Convenience result type for liburlx operations.
pub type Result<T> = std::result::Result<T, Error>;
