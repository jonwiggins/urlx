//! HTTP protocol implementation.
//!
//! Handles request construction, response parsing, and body reading
//! for HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 transfers.

pub mod altsvc;
pub mod decompress;
pub mod h1;
#[cfg(feature = "http2")]
pub mod h2;
#[cfg(feature = "http3")]
pub mod h3;
pub mod multipart;
pub mod response;
