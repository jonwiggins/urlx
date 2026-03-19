//! `liburlx` — A memory-safe URL transfer library.
//!
//! This is an idiomatic Rust reimplementation of libcurl, providing both
//! blocking (`Easy`) and async (`Multi`) APIs for URL transfers.
//!
//! # Quick Start
//!
//! The library is currently in early development. The `Easy` API for
//! simple transfers is coming in Phase 1.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod cookie;
pub mod dns;
pub mod easy;
pub mod error;
pub mod glob;
pub mod hsts;
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
