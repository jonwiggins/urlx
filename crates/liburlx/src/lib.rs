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

pub mod cookie;
pub mod easy;
pub mod error;
pub mod hsts;
pub mod multi;
pub(crate) mod pool;
pub mod protocol;
pub mod proxy;
pub mod tls;
pub mod url;

pub use cookie::CookieJar;
pub use easy::Easy;
pub use error::Error;
pub use multi::Multi;
pub use protocol::http::multipart::MultipartForm;
pub use protocol::http::response::{Response, TransferInfo};

/// Convenience result type for liburlx operations.
pub type Result<T> = std::result::Result<T, Error>;
