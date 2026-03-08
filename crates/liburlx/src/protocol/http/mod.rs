//! HTTP/1.1 protocol implementation.
//!
//! Handles request construction, response parsing, and body reading
//! for HTTP and HTTPS transfers.

pub mod decompress;
pub mod h1;
#[cfg(feature = "http2")]
pub mod h2;
pub mod response;
