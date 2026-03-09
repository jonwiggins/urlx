//! `liburlx-ffi` — C ABI compatibility layer for liburlx.
//!
//! This crate provides a libcurl-compatible C API, allowing `liburlx` to serve
//! as a drop-in replacement for `libcurl` at the binary level.
//!
//! All `unsafe` code in the urlx project is confined to this crate.

#![warn(missing_docs)]

use std::ffi::{c_char, c_long, c_void, CStr};
use std::ptr;

/// `CURLcode` — result codes for easy handle operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLcode {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1,
    CURLE_FAILED_INIT = 2,
    CURLE_URL_MALFORMAT = 3,
    CURLE_COULDNT_RESOLVE_HOST = 6,
    CURLE_COULDNT_CONNECT = 7,
    CURLE_OPERATION_TIMEDOUT = 28,
    CURLE_SSL_CONNECT_ERROR = 35,
    CURLE_GOT_NOTHING = 52,
    CURLE_SEND_ERROR = 55,
    CURLE_RECV_ERROR = 56,
    CURLE_UNKNOWN_OPTION = 48,
}

/// `CURLOPT` — option codes for `curl_easy_setopt`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLoption {
    CURLOPT_URL = 10002,
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_WRITEDATA = 10001,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_POST = 47,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_POSTFIELDSIZE = 60,
    CURLOPT_FOLLOWLOCATION = 52,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_TIMEOUT = 13,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_VERBOSE = 41,
    CURLOPT_PROXY = 10004,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_NOBODY = 44,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_HEADERDATA = 10029,
}

/// `CURLINFO` — info codes for `curl_easy_getinfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLINFO {
    CURLINFO_RESPONSE_CODE = 0x0020_0002,
    CURLINFO_CONTENT_TYPE = 0x0010_0012,
    CURLINFO_EFFECTIVE_URL = 0x0010_0001,
    CURLINFO_TOTAL_TIME = 0x0030_0003,
    CURLINFO_SIZE_DOWNLOAD = 0x0030_0008,
    CURLINFO_REDIRECT_COUNT = 0x0020_0014,
}

/// Write callback type matching libcurl's `CURLOPT_WRITEFUNCTION`.
type WriteCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Header callback type matching libcurl's `CURLOPT_HEADERFUNCTION`.
type HeaderCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Internal state for an easy handle.
struct EasyHandle {
    easy: liburlx::Easy,
    last_response: Option<liburlx::Response>,
    write_callback: Option<WriteCallback>,
    write_data: *mut c_void,
    header_callback: Option<HeaderCallback>,
    header_data: *mut c_void,
    postfields: Option<Vec<u8>>,
    error_buf: [u8; 256],
}

// SAFETY: The raw pointers in EasyHandle (write_data, header_data) are
// provided by the C caller and are only dereferenced inside callback
// invocations during perform, which is single-threaded from the
// caller's perspective (matching libcurl's thread-safety model).
unsafe impl Send for EasyHandle {}

/// `curl_easy_init` — create a new easy handle.
///
/// # Safety
///
/// Returns a new handle that must be freed with `curl_easy_cleanup`.
#[no_mangle]
pub extern "C" fn curl_easy_init() -> *mut c_void {
    let handle = Box::new(EasyHandle {
        easy: liburlx::Easy::new(),
        last_response: None,
        write_callback: None,
        write_data: ptr::null_mut(),
        header_callback: None,
        header_data: ptr::null_mut(),
        postfields: None,
        error_buf: [0u8; 256],
    });
    Box::into_raw(handle).cast::<c_void>()
}

/// `curl_easy_cleanup` — free an easy handle.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by `curl_easy_init`, or null.
/// After this call, `handle` must not be used.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: Caller guarantees handle is from curl_easy_init
        let _ = unsafe { Box::from_raw(handle.cast::<EasyHandle>()) };
    }
}

/// `curl_easy_setopt` — set options on an easy handle.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
/// Variadic arguments must match the expected type for each option.
#[no_mangle]
#[allow(clippy::too_many_lines)]
pub unsafe extern "C" fn curl_easy_setopt(
    handle: *mut c_void,
    option: c_long,
    value: *const c_void,
) -> CURLcode {
    if handle.is_null() {
        return CURLcode::CURLE_FAILED_INIT;
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &mut *handle.cast::<EasyHandle>() };

    match option {
        // CURLOPT_URL
        10002 => {
            if value.is_null() {
                return CURLcode::CURLE_URL_MALFORMAT;
            }
            // SAFETY: Caller guarantees value is a null-terminated C string
            let url_str = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
            match url_str.to_str() {
                Ok(s) => match h.easy.url(s) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(_) => CURLcode::CURLE_URL_MALFORMAT,
                },
                Err(_) => CURLcode::CURLE_URL_MALFORMAT,
            }
        }

        // CURLOPT_WRITEFUNCTION
        20011 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.write_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, WriteCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_WRITEDATA
        10001 => {
            h.write_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_HEADERFUNCTION
        20079 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.header_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, HeaderCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_HEADERDATA
        10029 => {
            h.header_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_USERAGENT
        10018 => {
            if value.is_null() {
                return CURLcode::CURLE_OK;
            }
            // SAFETY: Caller guarantees value is a null-terminated C string
            let agent = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
            if let Ok(s) = agent.to_str() {
                h.easy.header("User-Agent", s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_POST
        47 => {
            if value as c_long != 0 {
                h.easy.method("POST");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_POSTFIELDS
        10015 => {
            if value.is_null() {
                h.postfields = None;
            } else {
                // SAFETY: Caller guarantees value is a null-terminated C string
                let data = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
                h.postfields = Some(data.to_bytes().to_vec());
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_FOLLOWLOCATION
        52 => {
            h.easy.follow_redirects(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXREDIRS
        68 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.max_redirects(value as u32);
            CURLcode::CURLE_OK
        }

        // CURLOPT_TIMEOUT
        13 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            if secs > 0 {
                h.easy.timeout(std::time::Duration::from_secs(secs));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CONNECTTIMEOUT
        78 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            if secs > 0 {
                h.easy.connect_timeout(std::time::Duration::from_secs(secs));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_VERBOSE
        41 => {
            h.easy.verbose(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY
        10004 => {
            if value.is_null() {
                return CURLcode::CURLE_OK;
            }
            // SAFETY: Caller guarantees value is a null-terminated C string
            let proxy = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
            if let Ok(s) = proxy.to_str() {
                match h.easy.proxy(s) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(_) => CURLcode::CURLE_URL_MALFORMAT,
                }
            } else {
                CURLcode::CURLE_URL_MALFORMAT
            }
        }

        // CURLOPT_NOPROXY
        10177 => {
            if value.is_null() {
                return CURLcode::CURLE_OK;
            }
            // SAFETY: Caller guarantees value is a null-terminated C string
            let np = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
            if let Ok(s) = np.to_str() {
                h.easy.noproxy(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CUSTOMREQUEST
        10036 => {
            if value.is_null() {
                return CURLcode::CURLE_OK;
            }
            // SAFETY: Caller guarantees value is a null-terminated C string
            let method = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
            if let Ok(s) = method.to_str() {
                h.easy.method(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_NOBODY (HEAD request)
        44 => {
            if value as c_long != 0 {
                h.easy.method("HEAD");
            }
            CURLcode::CURLE_OK
        }

        _ => CURLcode::CURLE_UNKNOWN_OPTION,
    }
}

/// `curl_easy_perform` — perform the transfer.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_perform(handle: *mut c_void) -> CURLcode {
    if handle.is_null() {
        return CURLcode::CURLE_FAILED_INIT;
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &mut *handle.cast::<EasyHandle>() };

    // Set POST body if configured
    if let Some(ref body) = h.postfields {
        h.easy.body(body);
    }

    // Perform the transfer, catching any panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.easy.perform()));

    match result {
        Ok(Ok(response)) => {
            // Call write callback if set
            if let Some(cb) = h.write_callback {
                let body = response.body();
                if !body.is_empty() {
                    // SAFETY: Caller set up the callback and data pointer correctly
                    let written = unsafe {
                        cb(body.as_ptr().cast_mut().cast::<c_char>(), 1, body.len(), h.write_data)
                    };
                    if written != body.len() {
                        return CURLcode::CURLE_SEND_ERROR;
                    }
                }
            }

            // Call header callback if set
            if let Some(cb) = h.header_callback {
                for (name, value) in response.headers() {
                    let header_line = format!("{name}: {value}\r\n");
                    let bytes = header_line.as_bytes();
                    // SAFETY: Caller set up the callback and data pointer correctly
                    let _written = unsafe {
                        cb(
                            bytes.as_ptr().cast_mut().cast::<c_char>(),
                            1,
                            bytes.len(),
                            h.header_data,
                        )
                    };
                }
            }

            h.last_response = Some(response);
            CURLcode::CURLE_OK
        }
        Ok(Err(e)) => {
            // Store error message
            let msg = e.to_string();
            let bytes = msg.as_bytes();
            let len = bytes.len().min(h.error_buf.len() - 1);
            h.error_buf[..len].copy_from_slice(&bytes[..len]);
            h.error_buf[len] = 0;

            error_to_curlcode(&e)
        }
        Err(_) => {
            // Panic in perform — should not happen but handle gracefully
            CURLcode::CURLE_FAILED_INIT
        }
    }
}

/// `curl_easy_getinfo` — get info about the last transfer.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
/// `out` must be a valid pointer to the appropriate type for the info code.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_getinfo(
    handle: *mut c_void,
    info: c_long,
    out: *mut c_void,
) -> CURLcode {
    if handle.is_null() || out.is_null() {
        return CURLcode::CURLE_FAILED_INIT;
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &*handle.cast::<EasyHandle>() };

    let Some(ref response) = h.last_response else {
        return CURLcode::CURLE_GOT_NOTHING;
    };

    match info {
        // CURLINFO_RESPONSE_CODE
        0x20_0002 => {
            // SAFETY: Caller guarantees out points to a c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            *out = c_long::from(response.status());
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONTENT_TYPE
        0x10_0012 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.content_type().map_or(ptr::null(), |ct| ct.as_ptr().cast::<c_char>());
            CURLcode::CURLE_OK
        }

        // CURLINFO_EFFECTIVE_URL
        0x10_0001 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.effective_url().as_ptr().cast::<c_char>();
            CURLcode::CURLE_OK
        }

        // CURLINFO_TOTAL_TIME
        0x30_0003 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_total.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_SIZE_DOWNLOAD
        0x30_0008 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            #[allow(clippy::cast_precision_loss)]
            {
                *out = response.size_download() as f64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_REDIRECT_COUNT
        0x20_0014 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            #[allow(clippy::cast_possible_wrap, clippy::cast_lossless)]
            {
                *out = response.transfer_info().num_redirects as c_long;
            }
            CURLcode::CURLE_OK
        }

        _ => CURLcode::CURLE_UNKNOWN_OPTION,
    }
}

/// `curl_easy_strerror` — return a human-readable error message.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable on MSRV 1.75
pub extern "C" fn curl_easy_strerror(code: CURLcode) -> *const c_char {
    let msg = match code {
        CURLcode::CURLE_OK => c"No error",
        CURLcode::CURLE_UNSUPPORTED_PROTOCOL => c"Unsupported protocol",
        CURLcode::CURLE_FAILED_INIT => c"Failed initialization",
        CURLcode::CURLE_URL_MALFORMAT => c"URL using bad/illegal format or missing URL",
        CURLcode::CURLE_COULDNT_RESOLVE_HOST => c"Couldn't resolve host name",
        CURLcode::CURLE_COULDNT_CONNECT => c"Failed to connect to host or proxy",
        CURLcode::CURLE_OPERATION_TIMEDOUT => c"Operation timed out",
        CURLcode::CURLE_SSL_CONNECT_ERROR => c"SSL connect error",
        CURLcode::CURLE_GOT_NOTHING => c"Server returned nothing (no headers, no data)",
        CURLcode::CURLE_SEND_ERROR => c"Failed sending data to the peer",
        CURLcode::CURLE_RECV_ERROR => c"Failure when receiving data from the peer",
        CURLcode::CURLE_UNKNOWN_OPTION => c"An unknown option was passed to libcurl",
    };
    msg.as_ptr()
}

/// `urlx_version` — returns the version string.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn urlx_version() -> *const c_char {
    // SAFETY: This is a static string literal, valid for the entire program lifetime.
    c"liburlx/0.1.0".as_ptr()
}

/// Convert a liburlx error to a `CURLcode`.
fn error_to_curlcode(err: &liburlx::Error) -> CURLcode {
    match err {
        liburlx::Error::UrlParse(_) => CURLcode::CURLE_URL_MALFORMAT,
        liburlx::Error::Connect(_) => CURLcode::CURLE_COULDNT_CONNECT,
        liburlx::Error::Tls(_) => CURLcode::CURLE_SSL_CONNECT_ERROR,
        liburlx::Error::Http(msg) => {
            if msg.contains("unsupported scheme") {
                CURLcode::CURLE_UNSUPPORTED_PROTOCOL
            } else if msg.contains("resolve") || msg.contains("DNS") {
                CURLcode::CURLE_COULDNT_RESOLVE_HOST
            } else {
                CURLcode::CURLE_RECV_ERROR
            }
        }
        liburlx::Error::Timeout(_) => CURLcode::CURLE_OPERATION_TIMEDOUT,
        _ => CURLcode::CURLE_RECV_ERROR,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_non_null() {
        let ptr = urlx_version();
        assert!(!ptr.is_null());
    }

    #[test]
    fn easy_init_cleanup() {
        let handle = curl_easy_init();
        assert!(!handle.is_null());
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_cleanup_null_is_safe() {
        unsafe { curl_easy_cleanup(ptr::null_mut()) };
    }

    #[test]
    fn easy_setopt_url() {
        let handle = curl_easy_init();
        let url = c"http://example.com";
        let code = unsafe { curl_easy_setopt(handle, 10002, url.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_invalid_url() {
        let handle = curl_easy_init();
        let url = c"";
        let code = unsafe { curl_easy_setopt(handle, 10002, url.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_URL_MALFORMAT);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_null_url() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 10002, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_URL_MALFORMAT);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_verbose() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 41, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_follow_redirects() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 52, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_timeout() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 13, 30 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_unknown_option() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 99999, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_UNKNOWN_OPTION);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_null_handle() {
        let code = unsafe { curl_easy_setopt(ptr::null_mut(), 10002, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_FAILED_INIT);
    }

    #[test]
    fn easy_perform_without_url() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_perform(handle) };
        assert_ne!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_perform_null_handle() {
        let code = unsafe { curl_easy_perform(ptr::null_mut()) };
        assert_eq!(code, CURLcode::CURLE_FAILED_INIT);
    }

    #[test]
    fn easy_getinfo_null_handle() {
        let mut code: c_long = 0;
        let out_ptr = ptr::from_mut(&mut code).cast::<c_void>();
        let result = unsafe { curl_easy_getinfo(ptr::null_mut(), 0x20_0002, out_ptr) };
        assert_eq!(result, CURLcode::CURLE_FAILED_INIT);
    }

    #[test]
    fn easy_getinfo_no_response() {
        let handle = curl_easy_init();
        let url = c"http://example.com";
        let _code = unsafe { curl_easy_setopt(handle, 10002, url.as_ptr().cast::<c_void>()) };

        let mut code: c_long = 0;
        let out_ptr = ptr::from_mut(&mut code).cast::<c_void>();
        let result = unsafe { curl_easy_getinfo(handle, 0x20_0002, out_ptr) };
        assert_eq!(result, CURLcode::CURLE_GOT_NOTHING);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_strerror_ok() {
        let msg = curl_easy_strerror(CURLcode::CURLE_OK);
        assert!(!msg.is_null());
        let s = unsafe { CStr::from_ptr(msg) };
        assert_eq!(s.to_str().unwrap(), "No error");
    }

    #[test]
    fn easy_strerror_timeout() {
        let msg = curl_easy_strerror(CURLcode::CURLE_OPERATION_TIMEDOUT);
        let s = unsafe { CStr::from_ptr(msg) };
        assert_eq!(s.to_str().unwrap(), "Operation timed out");
    }

    #[test]
    fn easy_setopt_custom_request() {
        let handle = curl_easy_init();
        let method = c"DELETE";
        let code = unsafe { curl_easy_setopt(handle, 10036, method.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_nobody() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 44, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_postfields() {
        let handle = curl_easy_init();
        let data = c"key=value";
        let code = unsafe { curl_easy_setopt(handle, 10015, data.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy() {
        let handle = curl_easy_init();
        let proxy = c"http://proxy:8080";
        let code = unsafe { curl_easy_setopt(handle, 10004, proxy.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn error_code_mapping() {
        assert_eq!(
            error_to_curlcode(&liburlx::Error::UrlParse("bad".to_string())),
            CURLcode::CURLE_URL_MALFORMAT
        );
        assert_eq!(
            error_to_curlcode(&liburlx::Error::Timeout(std::time::Duration::from_secs(1))),
            CURLcode::CURLE_OPERATION_TIMEDOUT
        );
    }
}
