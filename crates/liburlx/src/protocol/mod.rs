//! Protocol handler definitions.
//!
//! Each protocol (HTTP, FTP, etc.) implements the transfer logic
//! for its scheme.

pub mod file;
pub mod http;
pub mod ws;
