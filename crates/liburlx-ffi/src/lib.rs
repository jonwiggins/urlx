//! `liburlx-ffi` — C ABI compatibility layer for liburlx.
//!
//! This crate provides a libcurl-compatible C API, allowing `liburlx` to serve
//! as a drop-in replacement for `libcurl` at the binary level.
//!
//! All `unsafe` code in the urlx project is confined to this crate.

#![warn(missing_docs)]

/// Placeholder: returns the version of the urlx library.
///
/// # Safety
///
/// This function is safe to call from C code. The returned pointer is valid
/// for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn is not stable on MSRV 1.75
pub extern "C" fn urlx_version() -> *const std::ffi::c_char {
    // SAFETY: This is a static string literal, valid for the entire program lifetime.
    c"liburlx/0.1.0".as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_non_null() {
        let ptr = urlx_version();
        assert!(!ptr.is_null());
    }
}
