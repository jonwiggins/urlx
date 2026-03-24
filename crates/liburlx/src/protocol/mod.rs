//! Protocol handler definitions.
//!
//! Each protocol (HTTP, FTP, etc.) implements the transfer logic
//! for its scheme.

pub mod dict;
pub mod file;
pub mod ftp;
pub mod gopher;
pub mod http;
pub mod imap;
pub mod ldap;
pub mod mqtt;
pub mod pop3;
pub mod rtsp;
#[cfg(feature = "smb")]
pub mod smb;
pub mod smtp;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod tftp;
pub mod ws;
