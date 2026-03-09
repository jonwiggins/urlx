//! `liburlx-ffi` — C ABI compatibility layer for liburlx.
//!
//! This crate provides a libcurl-compatible C API, allowing `liburlx` to serve
//! as a drop-in replacement for `libcurl` at the binary level.
//!
//! All `unsafe` code in the urlx project is confined to this crate.

#![warn(missing_docs)]

use std::ffi::{c_char, c_long, c_void, CStr};
use std::ptr;

// ───────────────────────── CURLcode ─────────────────────────

/// `CURLcode` — result codes for easy handle operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLcode {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1,
    CURLE_FAILED_INIT = 2,
    CURLE_URL_MALFORMAT = 3,
    CURLE_COULDNT_RESOLVE_PROXY = 5,
    CURLE_COULDNT_RESOLVE_HOST = 6,
    CURLE_COULDNT_CONNECT = 7,
    CURLE_FTP_WEIRD_SERVER_REPLY = 8,
    CURLE_REMOTE_ACCESS_DENIED = 9,
    CURLE_HTTP2 = 16,
    CURLE_HTTP_RETURNED_ERROR = 22,
    CURLE_WRITE_ERROR = 23,
    CURLE_READ_ERROR = 26,
    CURLE_OUT_OF_MEMORY = 27,
    CURLE_OPERATION_TIMEDOUT = 28,
    CURLE_SSL_CONNECT_ERROR = 35,
    CURLE_ABORTED_BY_CALLBACK = 42,
    CURLE_BAD_FUNCTION_ARGUMENT = 43,
    CURLE_UNKNOWN_OPTION = 48,
    CURLE_GOT_NOTHING = 52,
    CURLE_SEND_ERROR = 55,
    CURLE_RECV_ERROR = 56,
    CURLE_SSL_CERTPROBLEM = 58,
    CURLE_PEER_FAILED_VERIFICATION = 60,
    CURLE_LOGIN_DENIED = 67,
}

// ───────────────────────── CURLoption ─────────────────────────

/// `CURLOPT` — option codes for `curl_easy_setopt`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLoption {
    // String options (CURLOPTTYPE_STRINGPOINT = 10000)
    CURLOPT_WRITEDATA = 10001,
    CURLOPT_URL = 10002,
    CURLOPT_PROXY = 10004,
    CURLOPT_USERPWD = 10005,
    CURLOPT_RANGE = 10007,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_COOKIE = 10022,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_SSLCERT = 10025,
    CURLOPT_HEADERDATA = 10029,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_CAINFO = 10065,
    CURLOPT_SSLKEY = 10087,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_RESOLVE = 10203,
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    CURLOPT_PINNEDPUBLICKEY = 10230,
    CURLOPT_INTERFACE = 10062,

    // Long options (CURLOPTTYPE_LONG = 0)
    CURLOPT_TIMEOUT = 13,
    CURLOPT_LOW_SPEED_LIMIT = 19,
    CURLOPT_LOW_SPEED_TIME = 20,
    CURLOPT_SSLVERSION = 32,
    CURLOPT_VERBOSE = 41,
    CURLOPT_NOBODY = 44,
    CURLOPT_FAILONERROR = 45,
    CURLOPT_UPLOAD = 46,
    CURLOPT_POST = 47,
    CURLOPT_FOLLOWLOCATION = 52,
    CURLOPT_PUT = 54,
    CURLOPT_POSTFIELDSIZE = 60,
    CURLOPT_SSL_VERIFYPEER = 64,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_HTTPGET = 80,
    CURLOPT_SSL_VERIFYHOST = 81,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_LOCALPORT = 139,
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    CURLOPT_TCP_KEEPALIVE = 213,

    // Off_t options (CURLOPTTYPE_OFF_T = 30000)
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,

    // Function options (CURLOPTTYPE_FUNCTIONPOINT = 20000)
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_HEADERFUNCTION = 20079,
}

// ───────────────────────── CURLINFO ─────────────────────────

/// `CURLINFO` — info codes for `curl_easy_getinfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLINFO {
    CURLINFO_EFFECTIVE_URL = 0x0010_0001,
    CURLINFO_RESPONSE_CODE = 0x0020_0002,
    CURLINFO_TOTAL_TIME = 0x0030_0003,
    CURLINFO_NAMELOOKUP_TIME = 0x0030_0004,
    CURLINFO_CONNECT_TIME = 0x0030_0005,
    CURLINFO_SIZE_UPLOAD = 0x0030_0007,
    CURLINFO_SIZE_DOWNLOAD = 0x0030_0008,
    CURLINFO_SPEED_DOWNLOAD = 0x0030_0009,
    CURLINFO_SPEED_UPLOAD = 0x0030_000A,
    CURLINFO_HEADER_SIZE = 0x0020_000B,
    CURLINFO_PRETRANSFER_TIME = 0x0030_000E,
    CURLINFO_STARTTRANSFER_TIME = 0x0030_0011,
    CURLINFO_CONTENT_TYPE = 0x0010_0012,
    CURLINFO_REDIRECT_COUNT = 0x0020_0014,
    CURLINFO_APPCONNECT_TIME = 0x0030_0033,
}

// ───────────────────────── CURLMcode ─────────────────────────

/// `CURLMcode` — result codes for multi handle operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLMcode {
    CURLM_OK = 0,
    CURLM_BAD_HANDLE = -1,
    CURLM_BAD_EASY_HANDLE = -2,
    CURLM_OUT_OF_MEMORY = -3,
    CURLM_INTERNAL_ERROR = -4,
    CURLM_UNKNOWN_OPTION = -6,
}

// ───────────────────────── Callback types ─────────────────────────

/// Write callback type matching libcurl's `CURLOPT_WRITEFUNCTION`.
type WriteCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Header callback type matching libcurl's `CURLOPT_HEADERFUNCTION`.
type HeaderCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

// ───────────────────────── curl_slist ─────────────────────────

/// Linked list node for string data (e.g., HTTP headers).
///
/// Equivalent to libcurl's `struct curl_slist`.
#[repr(C)]
pub struct curl_slist {
    /// The string data for this node.
    pub data: *mut c_char,
    /// Pointer to the next node, or null.
    pub next: *mut Self,
}

/// `curl_slist_append` — append a string to a linked list.
///
/// # Safety
///
/// `data` must be a valid null-terminated C string.
/// `list` can be null (creates a new list) or a valid `curl_slist` pointer.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    if data.is_null() {
        return list;
    }

    // SAFETY: Caller guarantees data is a null-terminated C string
    let s = unsafe { CStr::from_ptr(data) };
    let owned = s.to_bytes().to_vec();
    let mut buf = owned;
    buf.push(0); // null terminator

    let node =
        Box::new(curl_slist { data: buf.as_mut_ptr().cast::<c_char>(), next: ptr::null_mut() });
    std::mem::forget(buf); // data is now owned by the node

    let node_ptr = Box::into_raw(node);

    if list.is_null() {
        node_ptr
    } else {
        // Walk to end of list
        let mut current = list;
        // SAFETY: Caller guarantees list is a valid curl_slist chain
        while unsafe { !(*current).next.is_null() } {
            current = unsafe { (*current).next };
        }
        // SAFETY: current is a valid node
        unsafe {
            (*current).next = node_ptr;
        }
        list
    }
}

/// `curl_slist_free_all` — free an entire linked list.
///
/// # Safety
///
/// `list` must be a valid `curl_slist` pointer from `curl_slist_append`, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    let mut current = list;
    while !current.is_null() {
        // SAFETY: current is a valid node from curl_slist_append
        let node = unsafe { Box::from_raw(current) };
        let next = node.next;

        // Free the string data
        if !node.data.is_null() {
            // SAFETY: data was allocated via Vec + mem::forget
            let s = unsafe { CStr::from_ptr(node.data) };
            let len = s.to_bytes_with_nul().len();
            let _ = unsafe { Vec::from_raw_parts(node.data.cast::<u8>(), len, len) };
        }

        current = next;
    }
}

// ───────────────────────── Easy handle ─────────────────────────

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

/// `curl_easy_duphandle` — clone an easy handle.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
/// The returned handle must be freed with `curl_easy_cleanup`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_duphandle(handle: *mut c_void) -> *mut c_void {
    if handle.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &*handle.cast::<EasyHandle>() };
    let dup = Box::new(EasyHandle {
        easy: h.easy.clone(),
        last_response: None,
        write_callback: h.write_callback,
        write_data: h.write_data,
        header_callback: h.header_callback,
        header_data: h.header_data,
        postfields: h.postfields.clone(),
        error_buf: [0u8; 256],
    });
    Box::into_raw(dup).cast::<c_void>()
}

/// `curl_easy_reset` — reset an easy handle to initial state.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_reset(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &mut *handle.cast::<EasyHandle>() };
    h.easy = liburlx::Easy::new();
    h.last_response = None;
    h.write_callback = None;
    h.write_data = ptr::null_mut();
    h.header_callback = None;
    h.header_data = ptr::null_mut();
    h.postfields = None;
    h.error_buf = [0u8; 256];
}

/// Helper to read a C string from a `*const c_void`.
///
/// # Safety
///
/// `value` must point to a null-terminated C string.
unsafe fn read_cstr(value: *const c_void) -> Option<&'static str> {
    if value.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees value is a null-terminated C string
    let cstr = unsafe { CStr::from_ptr(value.cast::<c_char>()) };
    cstr.to_str().ok()
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
        // ─── String options ───

        // CURLOPT_URL = 10002
        10002 => {
            // SAFETY: value must be a null-terminated C string
            match unsafe { read_cstr(value) } {
                Some(s) => match h.easy.url(s) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(_) => CURLcode::CURLE_URL_MALFORMAT,
                },
                None => CURLcode::CURLE_URL_MALFORMAT,
            }
        }

        // CURLOPT_WRITEFUNCTION = 20011
        20011 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.write_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, WriteCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_WRITEDATA = 10001
        10001 => {
            h.write_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_HEADERFUNCTION = 20079
        20079 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.header_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, HeaderCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_HEADERDATA = 10029
        10029 => {
            h.header_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_USERAGENT = 10018
        10018 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.header("User-Agent", s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_POSTFIELDS = 10015
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

        // CURLOPT_PROXY = 10004
        10004 => {
            // SAFETY: value must be a null-terminated C string
            match unsafe { read_cstr(value) } {
                Some(s) => match h.easy.proxy(s) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(_) => CURLcode::CURLE_URL_MALFORMAT,
                },
                None => CURLcode::CURLE_OK,
            }
        }

        // CURLOPT_NOPROXY = 10177
        10177 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.noproxy(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CUSTOMREQUEST = 10036
        10036 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.method(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_USERPWD = 10005
        10005 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                if let Some((user, pass)) = s.split_once(':') {
                    h.easy.basic_auth(user, pass);
                } else {
                    h.easy.basic_auth(s, "");
                }
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_RANGE = 10007
        10007 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.range(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_COOKIE = 10022
        10022 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.header("Cookie", s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSLCERT = 10025
        10025 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssl_client_cert(std::path::Path::new(s));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSLKEY = 10087
        10087 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssl_client_key(std::path::Path::new(s));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CAINFO = 10065
        10065 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssl_ca_cert(std::path::Path::new(s));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_ACCEPT_ENCODING = 10102
        10102 => {
            h.easy.accept_encoding(!value.is_null());
            CURLcode::CURLE_OK
        }

        // CURLOPT_UNIX_SOCKET_PATH = 10231
        10231 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.unix_socket(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PINNEDPUBLICKEY = 10230
        10230 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssl_pinned_public_key(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_INTERFACE = 10062
        10062 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.interface(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_RESOLVE = 10203
        10203 => {
            // This expects a curl_slist of "host:port:address" entries
            if !value.is_null() {
                let mut current = value.cast::<curl_slist>().cast_mut();
                while !current.is_null() {
                    // SAFETY: current is a valid curl_slist node
                    let node = unsafe { &*current };
                    if !node.data.is_null() {
                        // SAFETY: node.data is a null-terminated string
                        if let Ok(s) = unsafe { CStr::from_ptr(node.data) }.to_str() {
                            // Parse "host:port:address"
                            let parts: Vec<&str> = s.splitn(3, ':').collect();
                            if parts.len() == 3 {
                                let host_port = format!("{}:{}", parts[0], parts[1]);
                                h.easy.resolve(&host_port, parts[2]);
                            }
                        }
                    }
                    current = node.next;
                }
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTPHEADER = 10023
        10023 => {
            // This expects a curl_slist of "Name: Value" headers
            if !value.is_null() {
                let mut current = value.cast::<curl_slist>().cast_mut();
                while !current.is_null() {
                    // SAFETY: current is a valid curl_slist node
                    let node = unsafe { &*current };
                    if !node.data.is_null() {
                        // SAFETY: node.data is a null-terminated string
                        if let Ok(s) = unsafe { CStr::from_ptr(node.data) }.to_str() {
                            if let Some((name, val)) = s.split_once(':') {
                                h.easy.header(name.trim(), val.trim());
                            }
                        }
                    }
                    current = node.next;
                }
            }
            CURLcode::CURLE_OK
        }

        // ─── Long options ───

        // CURLOPT_POST = 47
        47 => {
            if value as c_long != 0 {
                h.easy.method("POST");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_NOBODY = 44 (HEAD request)
        44 => {
            if value as c_long != 0 {
                h.easy.method("HEAD");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_FAILONERROR = 45
        45 => {
            h.easy.fail_on_error(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_UPLOAD = 46, CURLOPT_PUT = 54
        46 | 54 => {
            if value as c_long != 0 {
                h.easy.method("PUT");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_FOLLOWLOCATION = 52
        52 => {
            h.easy.follow_redirects(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_POSTFIELDSIZE = 60
        60 => {
            // Store size but actual data comes via POSTFIELDS
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSL_VERIFYPEER = 64
        64 => {
            h.easy.ssl_verify_peer(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXREDIRS = 68
        68 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.max_redirects(value as u32);
            CURLcode::CURLE_OK
        }

        // CURLOPT_CONNECTTIMEOUT = 78
        78 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            if secs > 0 {
                h.easy.connect_timeout(std::time::Duration::from_secs(secs));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTPGET = 80
        80 => {
            if value as c_long != 0 {
                h.easy.method("GET");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSL_VERIFYHOST = 81
        81 => {
            // libcurl: 0 = don't verify, 2 = verify (1 is deprecated = 2)
            h.easy.ssl_verify_host(value as c_long >= 2);
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTPAUTH = 107
        107 => {
            // libcurl auth bitmask: 1=Basic, 2=Digest, 4=Negotiate, 8=NTLM
            // We accept the value but currently only Basic/Digest work
            CURLcode::CURLE_OK
        }

        // CURLOPT_TCP_NODELAY = 121
        121 => {
            h.easy.tcp_nodelay(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_LOCALPORT = 139
        139 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.local_port(value as u16);
            CURLcode::CURLE_OK
        }

        // CURLOPT_TCP_KEEPALIVE = 213
        213 => {
            if value as c_long != 0 {
                h.easy.tcp_keepalive(std::time::Duration::from_secs(60));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_TIMEOUT = 13
        13 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            if secs > 0 {
                h.easy.timeout(std::time::Duration::from_secs(secs));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_VERBOSE = 41
        41 => {
            h.easy.verbose(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSLVERSION = 32
        32 => {
            // libcurl: 0=default, 6=TLSv1.2, 7=TLSv1.3
            let version = value as c_long;
            if version == 6 {
                h.easy.ssl_min_version(liburlx::TlsVersion::Tls12);
            } else if version == 7 {
                h.easy.ssl_min_version(liburlx::TlsVersion::Tls13);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_LOW_SPEED_LIMIT = 19
        19 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.low_speed_limit(value as u32);
            CURLcode::CURLE_OK
        }

        // CURLOPT_LOW_SPEED_TIME = 20
        20 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            h.easy.low_speed_time(std::time::Duration::from_secs(secs));
            CURLcode::CURLE_OK
        }

        // CURLOPT_FRESH_CONNECT = 74
        74 => {
            h.easy.fresh_connect(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FORBID_REUSE = 75
        75 => {
            h.easy.forbid_reuse(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_TIMEOUT_MS = 155
        155 => {
            #[allow(clippy::cast_sign_loss)]
            let ms = value as u64;
            if ms > 0 {
                h.easy.timeout(std::time::Duration::from_millis(ms));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CONNECTTIMEOUT_MS = 156
        156 => {
            #[allow(clippy::cast_sign_loss)]
            let ms = value as u64;
            if ms > 0 {
                h.easy.connect_timeout(std::time::Duration::from_millis(ms));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAX_SEND_SPEED_LARGE = 30145
        30145 => {
            #[allow(clippy::cast_sign_loss)]
            let speed = value as u64;
            if speed > 0 {
                h.easy.max_send_speed(speed);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAX_RECV_SPEED_LARGE = 30146
        30146 => {
            #[allow(clippy::cast_sign_loss)]
            let speed = value as u64;
            if speed > 0 {
                h.easy.max_recv_speed(speed);
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
                        return CURLcode::CURLE_WRITE_ERROR;
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
#[allow(clippy::too_many_lines)]
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
        // CURLINFO_EFFECTIVE_URL = 0x100001
        0x10_0001 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.effective_url().as_ptr().cast::<c_char>();
            CURLcode::CURLE_OK
        }

        // CURLINFO_RESPONSE_CODE = 0x200002
        0x20_0002 => {
            // SAFETY: Caller guarantees out points to a c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            *out = c_long::from(response.status());
            CURLcode::CURLE_OK
        }

        // CURLINFO_TOTAL_TIME = 0x300003
        0x30_0003 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_total.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_NAMELOOKUP_TIME = 0x300004
        0x30_0004 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_namelookup.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONNECT_TIME = 0x300005
        0x30_0005 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_connect.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_SIZE_DOWNLOAD = 0x300008
        0x30_0008 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            #[allow(clippy::cast_precision_loss)]
            {
                *out = response.size_download() as f64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_SPEED_DOWNLOAD = 0x300009
        0x30_0009 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            let total = response.transfer_info().time_total.as_secs_f64();
            #[allow(clippy::cast_precision_loss)]
            if total > 0.0 {
                *out = response.size_download() as f64 / total;
            } else {
                *out = 0.0;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_HEADER_SIZE = 0x20000B
        0x20_000B => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // Estimate header size from response headers
            let header_size: usize = response
                .headers()
                .iter()
                .map(|(k, v)| k.len() + v.len() + 4) // "key: value\r\n"
                .sum();
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            {
                *out = header_size as c_long;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_STARTTRANSFER_TIME = 0x300011
        0x30_0011 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_starttransfer.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONTENT_TYPE = 0x100012
        0x10_0012 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.content_type().map_or(ptr::null(), |ct| ct.as_ptr().cast::<c_char>());
            CURLcode::CURLE_OK
        }

        // CURLINFO_REDIRECT_COUNT = 0x200014
        0x20_0014 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            #[allow(clippy::cast_possible_wrap, clippy::cast_lossless)]
            {
                *out = response.transfer_info().num_redirects as c_long;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_APPCONNECT_TIME = 0x300033
        0x30_0033 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_appconnect.as_secs_f64();
            CURLcode::CURLE_OK
        }

        // CURLINFO_SIZE_UPLOAD = 0x300007
        0x30_0007 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            #[allow(clippy::cast_precision_loss)]
            {
                *out = response.transfer_info().size_upload as f64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_SPEED_UPLOAD = 0x30000A
        0x30_000A => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().speed_upload;
            CURLcode::CURLE_OK
        }

        // CURLINFO_PRETRANSFER_TIME = 0x30000E
        0x30_000E => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            *out = response.transfer_info().time_pretransfer.as_secs_f64();
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
        CURLcode::CURLE_COULDNT_RESOLVE_PROXY => c"Couldn't resolve proxy name",
        CURLcode::CURLE_COULDNT_RESOLVE_HOST => c"Couldn't resolve host name",
        CURLcode::CURLE_COULDNT_CONNECT => c"Failed to connect to host or proxy",
        CURLcode::CURLE_FTP_WEIRD_SERVER_REPLY => c"Weird server reply",
        CURLcode::CURLE_REMOTE_ACCESS_DENIED => c"Access denied",
        CURLcode::CURLE_HTTP2 => c"Error in the HTTP2 framing layer",
        CURLcode::CURLE_HTTP_RETURNED_ERROR => c"HTTP response code said error",
        CURLcode::CURLE_WRITE_ERROR => c"Failed writing received data to disk/application",
        CURLcode::CURLE_READ_ERROR => c"Failed to read data",
        CURLcode::CURLE_OUT_OF_MEMORY => c"Out of memory",
        CURLcode::CURLE_OPERATION_TIMEDOUT => c"Operation timed out",
        CURLcode::CURLE_SSL_CONNECT_ERROR => c"SSL connect error",
        CURLcode::CURLE_ABORTED_BY_CALLBACK => c"Aborted by callback",
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT => c"A libcurl function was given a bad argument",
        CURLcode::CURLE_UNKNOWN_OPTION => c"An unknown option was passed to libcurl",
        CURLcode::CURLE_GOT_NOTHING => c"Server returned nothing (no headers, no data)",
        CURLcode::CURLE_SEND_ERROR => c"Failed sending data to the peer",
        CURLcode::CURLE_RECV_ERROR => c"Failure when receiving data from the peer",
        CURLcode::CURLE_SSL_CERTPROBLEM => c"Problem with the local SSL certificate",
        CURLcode::CURLE_PEER_FAILED_VERIFICATION => {
            c"SSL peer certificate or SSH remote key was not OK"
        }
        CURLcode::CURLE_LOGIN_DENIED => c"Login denied",
    };
    msg.as_ptr()
}

// ───────────────────────── Multi handle ─────────────────────────

/// Internal state for a multi handle.
struct MultiHandle {
    multi: liburlx::Multi,
    easy_handles: Vec<*mut c_void>,
}

// SAFETY: Easy handles are only accessed from the perform thread
unsafe impl Send for MultiHandle {}

/// `curl_multi_init` — create a new multi handle.
///
/// # Safety
///
/// Returns a new handle that must be freed with `curl_multi_cleanup`.
#[no_mangle]
pub extern "C" fn curl_multi_init() -> *mut c_void {
    let handle = Box::new(MultiHandle { multi: liburlx::Multi::new(), easy_handles: Vec::new() });
    Box::into_raw(handle).cast::<c_void>()
}

/// `curl_multi_cleanup` — free a multi handle.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_multi_init`, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(handle: *mut c_void) -> CURLMcode {
    if handle.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    // SAFETY: Caller guarantees handle is from curl_multi_init
    let _ = unsafe { Box::from_raw(handle.cast::<MultiHandle>()) };
    CURLMcode::CURLM_OK
}

/// `curl_multi_add_handle` — add an easy handle to a multi handle.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`, `easy` from `curl_easy_init`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_add_handle(multi: *mut c_void, easy: *mut c_void) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    if easy.is_null() {
        return CURLMcode::CURLM_BAD_EASY_HANDLE;
    }

    // SAFETY: Caller guarantees handles are valid
    let m = unsafe { &mut *multi.cast::<MultiHandle>() };
    let e = unsafe { &*easy.cast::<EasyHandle>() };

    m.multi.add(e.easy.clone());
    m.easy_handles.push(easy);

    CURLMcode::CURLM_OK
}

/// `curl_multi_remove_handle` — remove an easy handle from a multi handle.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`, `easy` from `curl_easy_init`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_remove_handle(
    multi: *mut c_void,
    easy: *mut c_void,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    if easy.is_null() {
        return CURLMcode::CURLM_BAD_EASY_HANDLE;
    }

    // SAFETY: Caller guarantees handles are valid
    let m = unsafe { &mut *multi.cast::<MultiHandle>() };

    if let Some(pos) = m.easy_handles.iter().position(|&h| h == easy) {
        let _ = m.easy_handles.remove(pos);
        let _ = m.multi.remove(pos);
        CURLMcode::CURLM_OK
    } else {
        CURLMcode::CURLM_BAD_EASY_HANDLE
    }
}

/// `curl_multi_perform` — perform all queued transfers.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `running_handles` must be a valid pointer to an int, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    multi: *mut c_void,
    running_handles: *mut c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    // SAFETY: Caller guarantees multi is from curl_multi_init
    let m = unsafe { &mut *multi.cast::<MultiHandle>() };

    let result = m.multi.perform_blocking();

    match result {
        Ok(results) => {
            // Store results back into easy handles
            for (i, result) in results.into_iter().enumerate() {
                if i < m.easy_handles.len() {
                    // SAFETY: easy_handles[i] is from curl_easy_init
                    let eh = unsafe { &mut *m.easy_handles[i].cast::<EasyHandle>() };
                    match result {
                        Ok(response) => {
                            eh.last_response = Some(response);
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            let bytes = msg.as_bytes();
                            let len = bytes.len().min(eh.error_buf.len() - 1);
                            eh.error_buf[..len].copy_from_slice(&bytes[..len]);
                            eh.error_buf[len] = 0;
                        }
                    }
                }
            }

            if !running_handles.is_null() {
                // SAFETY: Caller guarantees running_handles is valid
                unsafe {
                    *running_handles = 0;
                } // All done after blocking perform
            }

            CURLMcode::CURLM_OK
        }
        Err(_) => CURLMcode::CURLM_INTERNAL_ERROR,
    }
}

// ───────────────────────── Version ─────────────────────────

/// `curl_version` — returns the version string (libcurl compatibility).
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn curl_version() -> *const c_char {
    c"liburlx/0.1.0".as_ptr()
}

/// `urlx_version` — returns the version string.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn urlx_version() -> *const c_char {
    c"liburlx/0.1.0".as_ptr()
}

// ───────────────────────── Error mapping ─────────────────────────

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
            } else if msg.contains("HTTP error") && msg.contains("fail_on_error") {
                CURLcode::CURLE_HTTP_RETURNED_ERROR
            } else if msg.contains("aborted by") || msg.contains("callback") {
                CURLcode::CURLE_ABORTED_BY_CALLBACK
            } else if msg.contains("FTP") {
                CURLcode::CURLE_FTP_WEIRD_SERVER_REPLY
            } else {
                CURLcode::CURLE_RECV_ERROR
            }
        }
        liburlx::Error::Timeout(_) => CURLcode::CURLE_OPERATION_TIMEDOUT,
        _ => CURLcode::CURLE_RECV_ERROR,
    }
}

// ───────────────────────── Tests ─────────────────────────

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
    fn curl_version_returns_non_null() {
        let ptr = curl_version();
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
    fn easy_strerror_all_codes() {
        // Ensure every error code has a message
        let codes = [
            CURLcode::CURLE_OK,
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL,
            CURLcode::CURLE_FAILED_INIT,
            CURLcode::CURLE_URL_MALFORMAT,
            CURLcode::CURLE_COULDNT_RESOLVE_PROXY,
            CURLcode::CURLE_COULDNT_RESOLVE_HOST,
            CURLcode::CURLE_COULDNT_CONNECT,
            CURLcode::CURLE_FTP_WEIRD_SERVER_REPLY,
            CURLcode::CURLE_REMOTE_ACCESS_DENIED,
            CURLcode::CURLE_HTTP2,
            CURLcode::CURLE_HTTP_RETURNED_ERROR,
            CURLcode::CURLE_WRITE_ERROR,
            CURLcode::CURLE_READ_ERROR,
            CURLcode::CURLE_OUT_OF_MEMORY,
            CURLcode::CURLE_OPERATION_TIMEDOUT,
            CURLcode::CURLE_SSL_CONNECT_ERROR,
            CURLcode::CURLE_ABORTED_BY_CALLBACK,
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
            CURLcode::CURLE_UNKNOWN_OPTION,
            CURLcode::CURLE_GOT_NOTHING,
            CURLcode::CURLE_SEND_ERROR,
            CURLcode::CURLE_RECV_ERROR,
            CURLcode::CURLE_SSL_CERTPROBLEM,
            CURLcode::CURLE_PEER_FAILED_VERIFICATION,
            CURLcode::CURLE_LOGIN_DENIED,
        ];
        for code in codes {
            let msg = curl_easy_strerror(code);
            assert!(!msg.is_null(), "strerror returned null for {code:?}");
        }
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
    fn easy_setopt_userpwd() {
        let handle = curl_easy_init();
        let up = c"user:pass";
        let code = unsafe { curl_easy_setopt(handle, 10005, up.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssl_verify() {
        let handle = curl_easy_init();
        // SSL_VERIFYPEER = 64
        let code = unsafe { curl_easy_setopt(handle, 64, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        // SSL_VERIFYHOST = 81
        let code = unsafe { curl_easy_setopt(handle, 81, 2 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_tcp_options() {
        let handle = curl_easy_init();
        // TCP_NODELAY = 121
        let code = unsafe { curl_easy_setopt(handle, 121, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        // TCP_KEEPALIVE = 213
        let code = unsafe { curl_easy_setopt(handle, 213, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_fail_on_error() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 45, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_accept_encoding() {
        let handle = curl_easy_init();
        let enc = c"gzip, deflate";
        let code = unsafe { curl_easy_setopt(handle, 10102, enc.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_range() {
        let handle = curl_easy_init();
        let range = c"0-99";
        let code = unsafe { curl_easy_setopt(handle, 10007, range.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_httpget() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 80, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_upload() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 46, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_sslversion() {
        let handle = curl_easy_init();
        // TLSv1.2 = 6
        let code = unsafe { curl_easy_setopt(handle, 32, 6 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_duphandle() {
        let handle = curl_easy_init();
        let url = c"http://example.com";
        let _ = unsafe { curl_easy_setopt(handle, 10002, url.as_ptr().cast::<c_void>()) };

        let dup = unsafe { curl_easy_duphandle(handle) };
        assert!(!dup.is_null());
        assert_ne!(dup, handle);

        unsafe {
            curl_easy_cleanup(dup);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn easy_duphandle_null() {
        let dup = unsafe { curl_easy_duphandle(ptr::null_mut()) };
        assert!(dup.is_null());
    }

    #[test]
    fn easy_reset() {
        let handle = curl_easy_init();
        let url = c"http://example.com";
        let _ = unsafe { curl_easy_setopt(handle, 10002, url.as_ptr().cast::<c_void>()) };
        unsafe { curl_easy_reset(handle) };
        // After reset, perform should fail (no URL)
        let code = unsafe { curl_easy_perform(handle) };
        assert_ne!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn slist_append_and_free() {
        let list = unsafe { curl_slist_append(ptr::null_mut(), c"Header1: value1".as_ptr()) };
        assert!(!list.is_null());

        let list = unsafe { curl_slist_append(list, c"Header2: value2".as_ptr()) };
        assert!(!list.is_null());

        // Verify first node
        let first = unsafe { CStr::from_ptr((*list).data) };
        assert_eq!(first.to_str().unwrap(), "Header1: value1");

        // Verify second node
        let second = unsafe { CStr::from_ptr((*(*list).next).data) };
        assert_eq!(second.to_str().unwrap(), "Header2: value2");

        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn slist_free_null_is_safe() {
        unsafe { curl_slist_free_all(ptr::null_mut()) };
    }

    #[test]
    fn slist_append_null_data() {
        let list = unsafe { curl_slist_append(ptr::null_mut(), ptr::null()) };
        assert!(list.is_null());
    }

    #[test]
    fn multi_init_cleanup() {
        let handle = curl_multi_init();
        assert!(!handle.is_null());
        let code = unsafe { curl_multi_cleanup(handle) };
        assert_eq!(code, CURLMcode::CURLM_OK);
    }

    #[test]
    fn multi_cleanup_null() {
        let code = unsafe { curl_multi_cleanup(ptr::null_mut()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_add_remove_handle() {
        let multi = curl_multi_init();
        let easy = curl_easy_init();

        let code = unsafe { curl_multi_add_handle(multi, easy) };
        assert_eq!(code, CURLMcode::CURLM_OK);

        let code = unsafe { curl_multi_remove_handle(multi, easy) };
        assert_eq!(code, CURLMcode::CURLM_OK);

        unsafe {
            curl_easy_cleanup(easy);
            let _ = curl_multi_cleanup(multi);
        }
    }

    #[test]
    fn multi_add_null_handles() {
        let multi = curl_multi_init();
        assert_eq!(
            unsafe { curl_multi_add_handle(ptr::null_mut(), ptr::null_mut()) },
            CURLMcode::CURLM_BAD_HANDLE
        );
        assert_eq!(
            unsafe { curl_multi_add_handle(multi, ptr::null_mut()) },
            CURLMcode::CURLM_BAD_EASY_HANDLE
        );
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_remove_nonexistent() {
        let multi = curl_multi_init();
        let easy = curl_easy_init();

        let code = unsafe { curl_multi_remove_handle(multi, easy) };
        assert_eq!(code, CURLMcode::CURLM_BAD_EASY_HANDLE);

        unsafe {
            curl_easy_cleanup(easy);
            let _ = curl_multi_cleanup(multi);
        }
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

    #[test]
    fn error_code_http_returned_error() {
        assert_eq!(
            error_to_curlcode(&liburlx::Error::Http(
                "HTTP error 404 (fail_on_error enabled)".to_string()
            )),
            CURLcode::CURLE_HTTP_RETURNED_ERROR
        );
    }

    #[test]
    fn error_code_aborted_by_callback() {
        assert_eq!(
            error_to_curlcode(&liburlx::Error::Http(
                "transfer aborted by progress callback".to_string()
            )),
            CURLcode::CURLE_ABORTED_BY_CALLBACK
        );
    }

    #[test]
    fn error_code_ftp() {
        assert_eq!(
            error_to_curlcode(&liburlx::Error::Http("FTP protocol error".to_string())),
            CURLcode::CURLE_FTP_WEIRD_SERVER_REPLY
        );
    }

    #[test]
    fn easy_setopt_httpheader_with_slist() {
        let handle = curl_easy_init();
        let list = unsafe { curl_slist_append(ptr::null_mut(), c"X-Custom: test".as_ptr()) };
        let code = unsafe { curl_easy_setopt(handle, 10023, list.cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe {
            curl_slist_free_all(list);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn easy_setopt_timeout_ms() {
        let handle = curl_easy_init();
        // CURLOPT_TIMEOUT_MS = 155
        let code = unsafe { curl_easy_setopt(handle, 155, 5000_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_connecttimeout_ms() {
        let handle = curl_easy_init();
        // CURLOPT_CONNECTTIMEOUT_MS = 156
        let code = unsafe { curl_easy_setopt(handle, 156, 3000_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_fresh_connect() {
        let handle = curl_easy_init();
        // CURLOPT_FRESH_CONNECT = 74
        let code = unsafe { curl_easy_setopt(handle, 74, 1_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_forbid_reuse() {
        let handle = curl_easy_init();
        // CURLOPT_FORBID_REUSE = 75
        let code = unsafe { curl_easy_setopt(handle, 75, 1_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_low_speed_limit() {
        let handle = curl_easy_init();
        // CURLOPT_LOW_SPEED_LIMIT = 19
        let code = unsafe { curl_easy_setopt(handle, 19, 1000_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_low_speed_time() {
        let handle = curl_easy_init();
        // CURLOPT_LOW_SPEED_TIME = 20
        let code = unsafe { curl_easy_setopt(handle, 20, 30_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_max_send_speed() {
        let handle = curl_easy_init();
        // CURLOPT_MAX_SEND_SPEED_LARGE = 30145
        let code = unsafe { curl_easy_setopt(handle, 30145, 1024_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_max_recv_speed() {
        let handle = curl_easy_init();
        // CURLOPT_MAX_RECV_SPEED_LARGE = 30146
        let code = unsafe { curl_easy_setopt(handle, 30146, 2048_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }
}
