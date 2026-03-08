//! Protocol handler definitions.
//!
//! Each protocol (HTTP, FTP, etc.) implements the transfer logic
//! for its scheme.

pub mod dict;
pub mod file;
pub mod ftp;
pub mod http;
pub mod imap;
pub mod mqtt;
pub mod pop3;
pub mod smtp;
pub mod tftp;
pub mod ws;
