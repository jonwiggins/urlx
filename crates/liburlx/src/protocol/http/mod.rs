//! HTTP protocol implementation.
//!
//! Handles request construction, response parsing, and body reading
//! for HTTP/1.0, HTTP/1.1, and HTTP/2 transfers.

pub mod altsvc;
pub mod decompress;
pub mod h1;
#[cfg(feature = "http2")]
pub mod h2;
pub mod multipart;
pub mod response;
