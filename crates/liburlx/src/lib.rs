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

pub mod error;

pub use error::Error;

/// Convenience result type for liburlx operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn library_loads() {
        // Smoke test: the library compiles and loads
        assert_eq!(2 + 2, 4);
    }
}
