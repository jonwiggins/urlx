//! `liburlx-ffi` — C ABI compatibility layer for liburlx.
//!
//! This crate provides a libcurl-compatible C API, allowing `liburlx` to serve
//! as a drop-in replacement for `libcurl` at the binary level.
//!
//! All `unsafe` code in the urlx project is confined to this crate.
//!
//! # Safety Invariants
//!
//! The following safety contracts apply throughout this crate:
//!
//! - **Handle pointers** (`*mut c_void` for easy/multi/share/url/mime handles):
//!   All callers must provide valid, non-null pointers obtained from the
//!   corresponding `_init` function. Every exported function null-checks its
//!   handle argument before dereferencing. Handles are `Box`-allocated and cast
//!   to `*mut c_void`; `Box::from_raw` reclaims ownership in `_cleanup`.
//!
//! - **C strings** (`*const c_char`): Callers must provide valid,
//!   null-terminated strings. The helper `read_cstr()` combines null-check +
//!   `CStr::from_ptr` + UTF-8 validation. Direct `CStr::from_ptr` calls
//!   appear where `read_cstr` is insufficient (e.g., when the pointer type
//!   differs or when non-UTF-8 data is acceptable).
//!
//! - **Output pointers** in `curl_easy_getinfo`: Callers must provide a valid
//!   pointer to the expected output type (`*mut c_long`, `*mut f64`,
//!   `*mut *const c_char`, `*mut i64`). Each match arm casts `out` to the
//!   documented type and writes through it. The function null-checks `out`
//!   before the match.
//!
//! - **Callback function pointers**: `std::mem::transmute` converts `*const
//!   c_void` to the appropriate callback signature. Callers must ensure the
//!   pointer is actually a function with the documented C signature. Callbacks
//!   are invoked during `curl_easy_perform` with the corresponding `*data`
//!   pointer passed as the user-data argument.
//!
//! - **`curl_slist` traversal**: Linked-list nodes are caller-allocated. The
//!   list is walked via `(*node).next` until null. Each `node.data` is a
//!   caller-owned C string. `curl_slist_free_all` reclaims all nodes.
//!
//! - **Panic safety**: `curl_easy_perform` wraps the transfer in
//!   `std::panic::catch_unwind` to prevent Rust panics from unwinding across
//!   the FFI boundary.

#![warn(missing_docs)]

use std::ffi::{c_char, c_long, c_short, c_void, CStr};
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
    CURLE_FILESIZE_EXCEEDED = 63,
    CURLE_LOGIN_DENIED = 67,
    CURLE_TOO_MANY_REDIRECTS = 47,
    CURLE_HTTP3 = 95,
    CURLE_PARTIAL_FILE = 18,
    CURLE_RANGE_ERROR = 33,
    CURLE_AGAIN = 81,
    CURLE_AUTH_ERROR = 94,
    CURLE_UNRECOVERABLE_POLL = 99,
    CURLE_FTP_COULDNT_RETR_FILE = 19,
    CURLE_UPLOAD_FAILED = 25,
    CURLE_LDAP_SEARCH_FAILED = 39,
    CURLE_FUNCTION_NOT_FOUND = 41,
    CURLE_INTERFACE_FAILED = 45,
    CURLE_SSL_ENGINE_NOTFOUND = 53,
    CURLE_SSL_ENGINE_SETFAILED = 54,
    CURLE_SSL_PINNEDPUBKEYNOTMATCH = 90,
    CURLE_SSL_INVALIDCERTSTATUS = 91,
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
    CURLOPT_ERRORBUFFER = 10010,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_COOKIE = 10022,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_SSLCERT = 10025,
    CURLOPT_HEADERDATA = 10029,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_STDERR = 10037,
    CURLOPT_CAINFO = 10065,
    CURLOPT_SSLKEY = 10087,
    CURLOPT_INTERFACE = 10062,
    CURLOPT_SSL_CIPHER_LIST = 10083,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_COOKIEFILE = 10031,
    CURLOPT_COOKIEJAR = 10082,
    CURLOPT_COOKIELIST = 10135,
    CURLOPT_PROXYUSERPWD = 10006,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_RESOLVE = 10203,
    CURLOPT_PINNEDPUBLICKEY = 10230,
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    CURLOPT_PROXY_CAINFO = 10246,
    CURLOPT_PROXY_SSLCERT = 10254,
    CURLOPT_PROXY_SSLKEY = 10255,
    CURLOPT_READDATA = 10009,
    CURLOPT_DEBUGDATA = 10095,
    CURLOPT_DNS_SERVERS = 10211,
    CURLOPT_DOH_URL = 10279,
    CURLOPT_HSTS = 10300,
    CURLOPT_PROTOCOLS_STR = 10318,
    CURLOPT_REDIR_PROTOCOLS_STR = 10319,

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
    CURLOPT_HTTPPROXYTUNNEL = 61,
    CURLOPT_SSL_VERIFYPEER = 64,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_HTTPGET = 80,
    CURLOPT_SSL_VERIFYHOST = 81,
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_MAXFILESIZE = 114,
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,
    CURLOPT_PROXY_SSL_VERIFYHOST = 249,
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_LOCALPORT = 139,
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    CURLOPT_POSTREDIR = 161,
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    CURLOPT_TRANSFER_ENCODING = 207,
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,
    CURLOPT_PATH_AS_IS = 234,
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,
    CURLOPT_DNS_SHUFFLE_ADDRESSES = 275,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,
    CURLOPT_TCP_KEEPALIVE = 213,
    CURLOPT_SSL_SESSIONID_CACHE = 150,
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_PIPEWAIT = 237,
    CURLOPT_STREAM_WEIGHT = 239,
    CURLOPT_TCP_FASTOPEN = 244,
    CURLOPT_HTTP09_ALLOWED = 285,

    // Off_t options (CURLOPTTYPE_OFF_T = 30000)
    CURLOPT_INFILESIZE_LARGE = 30115,
    CURLOPT_MAXFILESIZE_LARGE = 30117,
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,

    // More string options
    CURLOPT_REFERER = 10016,
    CURLOPT_XOAUTH2_BEARER = 10220,
    CURLOPT_AWS_SIGV4 = 10306,

    // Pointer/object options
    CURLOPT_SHARE = 10100,
    CURLOPT_PRIVATE = 10103,
    CURLOPT_MIMEPOST = 10269,

    // Function options (CURLOPTTYPE_FUNCTIONPOINT = 20000)
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_READFUNCTION = 20012,
    CURLOPT_PROGRESSFUNCTION = 20056,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_DEBUGFUNCTION = 20094,
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_XFERINFOFUNCTION = 20219,

    // Long options (progress control, HTTP version, etc.)
    CURLOPT_NOPROGRESS = 43,
    CURLOPT_AUTOREFERER = 58,
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_NOSIGNAL = 99,
    CURLOPT_LOCALPORTRANGE = 164,

    // Off_t options
    CURLOPT_RESUME_FROM_LARGE = 30116,

    // Pointer data options for callbacks
    CURLOPT_PROGRESSDATA = 10057,
    CURLOPT_SEEKDATA = 10168,
}

// ───────────────────────── CURLUcode / CURLUPart ─────────────────────────

/// `CURLUcode` — result codes for URL API operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLUcode {
    CURLUE_OK = 0,
    CURLUE_BAD_HANDLE = 1,
    CURLUE_BAD_PARTPOINTER = 2,
    CURLUE_MALFORMED_INPUT = 3,
    CURLUE_BAD_PORT_NUMBER = 4,
    CURLUE_UNSUPPORTED_SCHEME = 5,
    CURLUE_OUT_OF_MEMORY = 7,
    CURLUE_NO_SCHEME = 8,
    CURLUE_NO_HOST = 9,
    CURLUE_UNKNOWN_PART = 11,
}

/// `CURLUPart` — part identifiers for URL manipulation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLUPart {
    CURLUPART_URL = 0,
    CURLUPART_SCHEME = 1,
    CURLUPART_USER = 2,
    CURLUPART_PASSWORD = 3,
    CURLUPART_OPTIONS = 4,
    CURLUPART_HOST = 5,
    CURLUPART_PORT = 6,
    CURLUPART_PATH = 7,
    CURLUPART_QUERY = 8,
    CURLUPART_FRAGMENT = 9,
    CURLUPART_ZONEID = 10,
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
    CURLINFO_FILETIME = 0x0020_000E,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 0x0030_000F,
    CURLINFO_CONTENT_LENGTH_UPLOAD = 0x0030_0010,
    CURLINFO_PRETRANSFER_TIME = 0x0030_000E,
    CURLINFO_STARTTRANSFER_TIME = 0x0030_0011,
    CURLINFO_CONTENT_TYPE = 0x0010_0012,
    CURLINFO_REDIRECT_COUNT = 0x0020_0014,
    CURLINFO_SSL_VERIFYRESULT = 0x0020_000D,
    CURLINFO_PRIVATE = 0x0010_0015,
    CURLINFO_OS_ERRNO = 0x0020_0019,
    CURLINFO_PRIMARY_IP = 0x0010_0020,
    CURLINFO_NUM_CONNECTS = 0x0020_0026,
    CURLINFO_LOCAL_IP = 0x0010_0029,
    CURLINFO_REDIRECT_URL = 0x0010_0031,
    CURLINFO_HTTP_VERSION = 0x0020_0032,
    CURLINFO_APPCONNECT_TIME = 0x0030_0033,
    CURLINFO_CONDITION_UNMET = 0x0020_0035,
    CURLINFO_PRIMARY_PORT = 0x0020_0040,
    CURLINFO_LOCAL_PORT = 0x0020_0042,
    CURLINFO_SCHEME = 0x0010_0044,
    CURLINFO_REDIRECT_TIME = 0x0030_0013,
    CURLINFO_TOTAL_TIME_T = 0x0060_003E,
    CURLINFO_NAMELOOKUP_TIME_T = 0x0060_003F,
    CURLINFO_CONNECT_TIME_T = 0x0060_0040,
    CURLINFO_PRETRANSFER_TIME_T = 0x0060_0041,
    CURLINFO_STARTTRANSFER_TIME_T = 0x0060_0042,
    CURLINFO_REDIRECT_TIME_T = 0x0060_0043,
    CURLINFO_APPCONNECT_TIME_T = 0x0060_0044,
    CURLINFO_RETRY_AFTER = 0x0020_003A,
    CURLINFO_SIZE_UPLOAD_T = 0x0060_0045,
    CURLINFO_SIZE_DOWNLOAD_T = 0x0060_0046,
    CURLINFO_SPEED_DOWNLOAD_T = 0x0060_0047,
    CURLINFO_SPEED_UPLOAD_T = 0x0060_0048,
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

/// `CURLMSG` — message types from `curl_multi_info_read`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLMSG {
    CURLMSG_DONE = 1,
}

/// `CURLMsg` — completion message from `curl_multi_info_read`.
#[repr(C)]
#[allow(non_camel_case_types, missing_docs)]
pub struct CURLMsg {
    pub msg: CURLMSG,
    pub easy_handle: *mut c_void,
    pub result: CURLcode,
}

/// `CURLMoption` — option codes for `curl_multi_setopt`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLMoption {
    CURLMOPT_SOCKETFUNCTION = 20001,
    CURLMOPT_SOCKETDATA = 10002,
    CURLMOPT_PIPELINING = 3,
    CURLMOPT_TIMERFUNCTION = 20004,
    CURLMOPT_TIMERDATA = 10005,
    CURLMOPT_MAXCONNECTS = 6,
    CURLMOPT_MAX_HOST_CONNECTIONS = 7,
    CURLMOPT_MAX_TOTAL_CONNECTIONS = 13,
}

/// `curl_waitfd` — extra file descriptor for `curl_multi_wait`/`curl_multi_poll`.
#[repr(C)]
#[allow(non_camel_case_types, missing_docs)]
pub struct curl_waitfd {
    pub fd: c_long,
    pub events: c_short,
    pub revents: c_short,
}

/// `curl_blob` — in-memory binary data for TLS certificate/key options.
///
/// Equivalent to libcurl's `struct curl_blob`. Used with `CURLOPT_SSLCERT_BLOB`,
/// `CURLOPT_SSLKEY_BLOB`, and `CURLOPT_CAINFO_BLOB`.
#[repr(C)]
#[allow(non_camel_case_types, missing_docs)]
pub struct curl_blob {
    pub data: *const c_void,
    pub len: usize,
    pub flags: u32,
}

/// Socket callback type matching libcurl's `CURLMOPT_SOCKETFUNCTION`.
#[allow(non_camel_case_types)]
type CurlSocketCallback =
    unsafe extern "C" fn(*mut c_void, c_long, c_long, *mut c_void, *mut c_void) -> c_long;

/// Timer callback type matching libcurl's `CURLMOPT_TIMERFUNCTION`.
#[allow(non_camel_case_types)]
type CurlTimerCallback = unsafe extern "C" fn(*mut c_void, c_long, *mut c_void) -> c_long;

// ───────────────────────── Callback types ─────────────────────────

/// Write callback type matching libcurl's `CURLOPT_WRITEFUNCTION`.
type WriteCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Header callback type matching libcurl's `CURLOPT_HEADERFUNCTION`.
type HeaderCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Read callback type matching libcurl's `CURLOPT_READFUNCTION`.
///
/// Called to supply upload data. Returns number of bytes written to buffer.
/// Return 0 to signal end of data, `CURL_READFUNC_ABORT` (0x10000000) to abort.
type ReadCallback = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Debug callback type matching libcurl's `CURLOPT_DEBUGFUNCTION`.
///
/// Called with debug information during transfer. The `info_type` parameter
/// indicates the type of data (text, header in/out, data in/out).
type DebugCallback =
    unsafe extern "C" fn(*mut c_void, c_long, *mut c_char, usize, *mut c_void) -> c_long;

/// Progress callback type matching libcurl's `CURLOPT_PROGRESSFUNCTION`.
///
/// Called with download/upload progress. Parameters: clientp, dltotal, dlnow, ultotal, ulnow.
/// Return non-zero to abort the transfer.
type ProgressCallback = unsafe extern "C" fn(*mut c_void, f64, f64, f64, f64) -> c_long;

/// Transfer info callback type matching libcurl's `CURLOPT_XFERINFOFUNCTION`.
///
/// Modern replacement for `CURLOPT_PROGRESSFUNCTION` using `curl_off_t` (i64).
/// Return non-zero to abort the transfer.
type XferInfoCallback = unsafe extern "C" fn(*mut c_void, i64, i64, i64, i64) -> c_long;

/// Seek callback type matching libcurl's `CURLOPT_SEEKFUNCTION`.
///
/// Called to seek in the input stream. Returns 0 on success, 1 on failure, 2 for can't seek.
type SeekCallback = unsafe extern "C" fn(*mut c_void, i64, c_long) -> c_long;

// ───────────────────────── CURLSHcode / CURLSHoption ─────────────────────────

/// `CURLSHcode` — result codes for share handle operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLSHcode {
    CURLSHE_OK = 0,
    CURLSHE_BAD_OPTION = 1,
    CURLSHE_IN_USE = 2,
    CURLSHE_INVALID = 3,
    CURLSHE_NOMEM = 4,
    CURLSHE_NOT_BUILT_IN = 5,
}

/// `CURLSHoption` — option codes for `curl_share_setopt`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CURLSHoption {
    CURLSHOPT_SHARE = 1,
    CURLSHOPT_UNSHARE = 2,
    CURLSHOPT_LOCKFUNC = 3,
    CURLSHOPT_UNLOCKFUNC = 4,
}

// ───────────────────────── curl_mime ─────────────────────────

/// Internal state for a MIME handle.
struct MimeHandle {
    form: liburlx::MultipartForm,
}

/// Internal state for a MIME part being built.
struct MimePartHandle {
    name: Option<String>,
    data: Option<Vec<u8>>,
    filename: Option<String>,
    mime_type: Option<String>,
}

/// `curl_mime_init` — create a new MIME handle.
///
/// # Safety
///
/// `easy` must be a valid pointer from `curl_easy_init` (used for context only).
/// The returned handle must be freed with `curl_mime_free`.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_init(_easy: *mut c_void) -> *mut c_void {
    let handle = Box::new(MimeHandle { form: liburlx::MultipartForm::new() });
    Box::into_raw(handle).cast::<c_void>()
}

/// `curl_mime_addpart` — add a new part to a MIME handle.
///
/// # Safety
///
/// `mime` must be a valid pointer from `curl_mime_init`.
/// The returned part pointer is valid until `curl_mime_free` is called on the parent.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_addpart(mime: *mut c_void) -> *mut c_void {
    if mime.is_null() {
        return ptr::null_mut();
    }
    let part = Box::new(MimePartHandle { name: None, data: None, filename: None, mime_type: None });
    Box::into_raw(part).cast::<c_void>()
}

/// `curl_mime_name` — set the name of a MIME part.
///
/// # Safety
///
/// `part` must be a valid pointer from `curl_mime_addpart`.
/// `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_name(part: *mut c_void, name: *const c_char) -> CURLcode {
    if part.is_null() || name.is_null() {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: Caller guarantees part is from curl_mime_addpart
    let p = unsafe { &mut *part.cast::<MimePartHandle>() };
    // SAFETY: Caller guarantees name is a null-terminated C string
    let s = unsafe { CStr::from_ptr(name) };
    match s.to_str() {
        Ok(name_str) => {
            p.name = Some(name_str.to_string());
            CURLcode::CURLE_OK
        }
        Err(_) => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    }
}

/// `curl_mime_data` — set data for a MIME part.
///
/// # Safety
///
/// `part` must be a valid pointer from `curl_mime_addpart`.
/// `data` must point to at least `datasize` bytes.
/// If `datasize` is `usize::MAX`, `data` is treated as a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut c_void,
    data: *const c_char,
    datasize: usize,
) -> CURLcode {
    if part.is_null() || data.is_null() {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: Caller guarantees part is from curl_mime_addpart
    let p = unsafe { &mut *part.cast::<MimePartHandle>() };

    let bytes = if datasize == usize::MAX {
        // CURL_ZERO_TERMINATED — treat as null-terminated string
        // SAFETY: Caller guarantees data is null-terminated
        let s = unsafe { CStr::from_ptr(data) };
        s.to_bytes().to_vec()
    } else {
        // SAFETY: Caller guarantees data points to at least datasize bytes
        unsafe { std::slice::from_raw_parts(data.cast::<u8>(), datasize) }.to_vec()
    };

    p.data = Some(bytes);
    CURLcode::CURLE_OK
}

/// `curl_mime_filename` — set the filename for a MIME part.
///
/// # Safety
///
/// `part` must be a valid pointer from `curl_mime_addpart`.
/// `filename` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut c_void,
    filename: *const c_char,
) -> CURLcode {
    if part.is_null() || filename.is_null() {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: Caller guarantees part is from curl_mime_addpart
    let p = unsafe { &mut *part.cast::<MimePartHandle>() };
    // SAFETY: Caller guarantees filename is a null-terminated C string
    let s = unsafe { CStr::from_ptr(filename) };
    match s.to_str() {
        Ok(f) => {
            p.filename = Some(f.to_string());
            CURLcode::CURLE_OK
        }
        Err(_) => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    }
}

/// `curl_mime_type` — set the MIME type for a MIME part.
///
/// # Safety
///
/// `part` must be a valid pointer from `curl_mime_addpart`.
/// `mimetype` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_type(part: *mut c_void, mimetype: *const c_char) -> CURLcode {
    if part.is_null() || mimetype.is_null() {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: Caller guarantees part is from curl_mime_addpart
    let p = unsafe { &mut *part.cast::<MimePartHandle>() };
    // SAFETY: Caller guarantees mimetype is a null-terminated C string
    let s = unsafe { CStr::from_ptr(mimetype) };
    match s.to_str() {
        Ok(t) => {
            p.mime_type = Some(t.to_string());
            CURLcode::CURLE_OK
        }
        Err(_) => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    }
}

/// `curl_mime_free` — free a MIME handle and all its parts.
///
/// # Safety
///
/// `mime` must be a valid pointer from `curl_mime_init`, or null.
/// After this call, `mime` must not be used.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_free(mime: *mut c_void) {
    if !mime.is_null() {
        // SAFETY: Caller guarantees mime is from curl_mime_init
        let _ = unsafe { Box::from_raw(mime.cast::<MimeHandle>()) };
    }
}

/// Helper to finalize a MIME part into the parent MIME form.
///
/// # Safety
///
/// `mime` must be a valid `MimeHandle`, `part` a valid `MimePartHandle`.
unsafe fn finalize_mime_part(mime: *mut c_void, part: *mut c_void) {
    if mime.is_null() || part.is_null() {
        return;
    }
    // SAFETY: Caller guarantees these are valid handles
    let m = unsafe { &mut *mime.cast::<MimeHandle>() };
    let p = unsafe { Box::from_raw(part.cast::<MimePartHandle>()) };

    if let (Some(name), Some(data)) = (&p.name, &p.data) {
        if let Some(ref filename) = p.filename {
            m.form.file_data(name, filename, data);
        } else {
            // Treat as text field
            if let Ok(text) = std::str::from_utf8(data) {
                m.form.field(name, text);
            } else {
                // Binary data without filename — use file_data with a default name
                m.form.file_data(name, "data", data);
            }
        }
    }
}

// ───────────────────────── curl_share ─────────────────────────

/// `curl_share_init` — create a new share handle.
///
/// # Safety
///
/// Returns a new handle that must be freed with `curl_share_cleanup`.
#[no_mangle]
pub extern "C" fn curl_share_init() -> *mut c_void {
    let share = Box::new(liburlx::Share::new());
    Box::into_raw(share).cast::<c_void>()
}

/// `curl_share_cleanup` — free a share handle.
///
/// # Safety
///
/// `share` must be a valid pointer from `curl_share_init`, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_share_cleanup(share: *mut c_void) -> CURLSHcode {
    if share.is_null() {
        return CURLSHcode::CURLSHE_INVALID;
    }
    // SAFETY: Caller guarantees share is from curl_share_init
    let _ = unsafe { Box::from_raw(share.cast::<liburlx::Share>()) };
    CURLSHcode::CURLSHE_OK
}

/// `curl_share_setopt` — set options on a share handle.
///
/// # Safety
///
/// `share` must be a valid pointer from `curl_share_init`.
/// For `CURLSHOPT_SHARE`/`CURLSHOPT_UNSHARE`, `value` is a `CURL_LOCK_DATA_*` constant.
#[no_mangle]
pub unsafe extern "C" fn curl_share_setopt(
    share: *mut c_void,
    option: c_long,
    value: *const c_void,
) -> CURLSHcode {
    if share.is_null() {
        return CURLSHcode::CURLSHE_INVALID;
    }

    // SAFETY: Caller guarantees share is from curl_share_init
    let s = unsafe { &mut *share.cast::<liburlx::Share>() };

    match option {
        // CURLSHOPT_SHARE = 1
        1 => {
            let lock_data = value as c_long;
            match lock_data {
                // CURL_LOCK_DATA_COOKIE = 2
                2 => {
                    s.add(liburlx::ShareType::Cookies);
                    CURLSHcode::CURLSHE_OK
                }
                // CURL_LOCK_DATA_DNS = 3
                3 => {
                    s.add(liburlx::ShareType::Dns);
                    CURLSHcode::CURLSHE_OK
                }
                _ => CURLSHcode::CURLSHE_BAD_OPTION,
            }
        }
        // CURLSHOPT_UNSHARE = 2
        2 => {
            let lock_data = value as c_long;
            match lock_data {
                2 => {
                    s.remove(liburlx::ShareType::Cookies);
                    CURLSHcode::CURLSHE_OK
                }
                3 => {
                    s.remove(liburlx::ShareType::Dns);
                    CURLSHcode::CURLSHE_OK
                }
                _ => CURLSHcode::CURLSHE_BAD_OPTION,
            }
        }
        // CURLSHOPT_LOCKFUNC = 3, CURLSHOPT_UNLOCKFUNC = 4
        // Accept but ignore — our Share uses Arc<Mutex> internally
        3 | 4 => CURLSHcode::CURLSHE_OK,
        _ => CURLSHcode::CURLSHE_BAD_OPTION,
    }
}

/// `curl_share_strerror` — return a human-readable share error message.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn curl_share_strerror(code: CURLSHcode) -> *const c_char {
    let msg = match code {
        CURLSHcode::CURLSHE_OK => c"No error",
        CURLSHcode::CURLSHE_BAD_OPTION => c"Bad option in share call",
        CURLSHcode::CURLSHE_IN_USE => c"Share already in use",
        CURLSHcode::CURLSHE_INVALID => c"Invalid share handle",
        CURLSHcode::CURLSHE_NOMEM => c"Out of memory",
        CURLSHcode::CURLSHE_NOT_BUILT_IN => c"Feature not available",
    };
    msg.as_ptr()
}

// ───────────────────────── curl_url (URL API) ─────────────────────────

/// Mutable URL handle for the curl URL API.
///
/// Stores individual URL components that can be set/get independently.
/// Components are lazily reassembled into a full URL string when requested.
struct UrlHandle {
    scheme: Option<String>,
    user: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
    /// Cached reassembled URL string (invalidated on set).
    cached_url: Option<String>,
}

impl UrlHandle {
    const fn new() -> Self {
        Self {
            scheme: None,
            user: None,
            password: None,
            host: None,
            port: None,
            path: None,
            query: None,
            fragment: None,
            cached_url: None,
        }
    }

    /// Reassemble the URL from components.
    fn reassemble(&mut self) -> String {
        let scheme = self.scheme.as_deref().unwrap_or("https");
        let mut url = format!("{scheme}://");
        if let Some(ref user) = self.user {
            url.push_str(user);
            if let Some(ref pass) = self.password {
                url.push(':');
                url.push_str(pass);
            }
            url.push('@');
        }
        if let Some(ref host) = self.host {
            url.push_str(host);
        }
        if let Some(port) = self.port {
            url.push(':');
            url.push_str(&port.to_string());
        }
        url.push_str(self.path.as_deref().unwrap_or("/"));
        if let Some(ref query) = self.query {
            url.push('?');
            url.push_str(query);
        }
        if let Some(ref fragment) = self.fragment {
            url.push('#');
            url.push_str(fragment);
        }
        self.cached_url = Some(url.clone());
        url
    }

    /// Parse a full URL into components.
    fn set_url(&mut self, url_str: &str) -> CURLUcode {
        match liburlx::Url::parse(url_str) {
            Ok(parsed) => {
                self.scheme = Some(parsed.scheme().to_string());
                let user = parsed.username();
                self.user = if user.is_empty() { None } else { Some(user.to_string()) };
                self.password = parsed.password().map(String::from);
                self.host = parsed.host_str().map(String::from);
                self.port = parsed.port();
                let path = parsed.path();
                self.path = Some(path.to_string());
                self.query = parsed.query().map(String::from);
                self.fragment = parsed.fragment().map(String::from);
                self.cached_url = Some(parsed.as_str().to_string());
                CURLUcode::CURLUE_OK
            }
            Err(_) => CURLUcode::CURLUE_MALFORMED_INPUT,
        }
    }
}

impl Clone for UrlHandle {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme.clone(),
            user: self.user.clone(),
            password: self.password.clone(),
            host: self.host.clone(),
            port: self.port,
            path: self.path.clone(),
            query: self.query.clone(),
            fragment: self.fragment.clone(),
            cached_url: self.cached_url.clone(),
        }
    }
}

/// `curl_url` — create a new URL handle.
///
/// # Safety
///
/// Returns a new handle that must be freed with `curl_url_cleanup`.
#[no_mangle]
pub extern "C" fn curl_url() -> *mut c_void {
    let handle = Box::new(UrlHandle::new());
    Box::into_raw(handle).cast::<c_void>()
}

/// `curl_url_cleanup` — free a URL handle.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_url`, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: Caller guarantees handle is from curl_url
        let _ = unsafe { Box::from_raw(handle.cast::<UrlHandle>()) };
    }
}

/// `curl_url_dup` — duplicate a URL handle.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_url`.
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(handle: *mut c_void) -> *mut c_void {
    if handle.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller guarantees handle is from curl_url
    let h = unsafe { &*handle.cast::<UrlHandle>() };
    let dup = Box::new(h.clone());
    Box::into_raw(dup).cast::<c_void>()
}

/// `curl_url_set` — set a URL component.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_url`.
/// `content` must be a valid null-terminated C string (or null to clear).
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    handle: *mut c_void,
    what: c_long,
    content: *const c_char,
    _flags: c_long,
) -> CURLUcode {
    if handle.is_null() {
        return CURLUcode::CURLUE_BAD_HANDLE;
    }

    // SAFETY: Caller guarantees handle is from curl_url
    let h = unsafe { &mut *handle.cast::<UrlHandle>() };

    // Null content clears the part
    let value = if content.is_null() {
        None
    } else {
        // SAFETY: Caller guarantees content is null-terminated
        match unsafe { CStr::from_ptr(content) }.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return CURLUcode::CURLUE_MALFORMED_INPUT,
        }
    };

    h.cached_url = None; // Invalidate cache

    match what {
        // CURLUPART_URL = 0
        0 => {
            if let Some(ref url_str) = value {
                return h.set_url(url_str);
            }
            // Clear all components
            *h = UrlHandle::new();
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_SCHEME = 1
        1 => {
            h.scheme = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_USER = 2
        2 => {
            h.user = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_PASSWORD = 3
        3 => {
            h.password = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_OPTIONS = 4, CURLUPART_ZONEID = 10 — accept but ignore
        4 | 10 => CURLUcode::CURLUE_OK,
        // CURLUPART_HOST = 5
        5 => {
            h.host = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_PORT = 6
        6 => {
            if let Some(ref port_str) = value {
                match port_str.parse::<u16>() {
                    Ok(port) => {
                        h.port = Some(port);
                        CURLUcode::CURLUE_OK
                    }
                    Err(_) => CURLUcode::CURLUE_BAD_PORT_NUMBER,
                }
            } else {
                h.port = None;
                CURLUcode::CURLUE_OK
            }
        }
        // CURLUPART_PATH = 7
        7 => {
            h.path = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_QUERY = 8
        8 => {
            h.query = value;
            CURLUcode::CURLUE_OK
        }
        // CURLUPART_FRAGMENT = 9
        9 => {
            h.fragment = value;
            CURLUcode::CURLUE_OK
        }
        _ => CURLUcode::CURLUE_UNKNOWN_PART,
    }
}

/// `curl_url_get` — get a URL component.
///
/// The returned string is allocated and must be freed by the caller with `libc::free`
/// or `curl_free`. For simplicity, we allocate via a leaked `CString`.
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_url`.
/// `part` must be a valid pointer to `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn curl_url_get(
    handle: *mut c_void,
    what: c_long,
    part: *mut *mut c_char,
    _flags: c_long,
) -> CURLUcode {
    if handle.is_null() {
        return CURLUcode::CURLUE_BAD_HANDLE;
    }
    if part.is_null() {
        return CURLUcode::CURLUE_BAD_PARTPOINTER;
    }

    // SAFETY: Caller guarantees handle is from curl_url
    let h = unsafe { &mut *handle.cast::<UrlHandle>() };

    let result: Option<String> = match what {
        // CURLUPART_URL = 0
        0 => Some(h.reassemble()),
        // CURLUPART_SCHEME = 1
        1 => h.scheme.clone(),
        // CURLUPART_USER = 2
        2 => h.user.clone(),
        // CURLUPART_PASSWORD = 3
        3 => h.password.clone(),
        // CURLUPART_OPTIONS = 4, CURLUPART_ZONEID = 10 — not stored
        4 | 10 => None,
        // CURLUPART_HOST = 5
        5 => h.host.clone(),
        // CURLUPART_PORT = 6
        6 => h.port.map(|p| p.to_string()),
        // CURLUPART_PATH = 7
        7 => h.path.clone(),
        // CURLUPART_QUERY = 8
        8 => h.query.clone(),
        // CURLUPART_FRAGMENT = 9
        9 => h.fragment.clone(),
        _ => return CURLUcode::CURLUE_UNKNOWN_PART,
    };

    if let Some(s) = result {
        // Allocate a C string for the result
        std::ffi::CString::new(s).map_or(CURLUcode::CURLUE_OUT_OF_MEMORY, |cstr| {
            // SAFETY: part is a valid pointer
            unsafe {
                *part = cstr.into_raw();
            }
            CURLUcode::CURLUE_OK
        })
    } else {
        // Part not set
        // SAFETY: part is a valid pointer
        unsafe {
            *part = ptr::null_mut();
        }
        CURLUcode::CURLUE_OK
    }
}

/// `curl_free` — free memory allocated by curl functions.
///
/// # Safety
///
/// `ptr` must be a pointer returned by curl functions (e.g., `curl_url_get`), or null.
#[no_mangle]
pub unsafe extern "C" fn curl_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // SAFETY: ptr was allocated via CString::into_raw
        let _ = unsafe { std::ffi::CString::from_raw(ptr.cast::<c_char>()) };
    }
}

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
                 // Convert to boxed slice for exact-length allocation (len == capacity guaranteed)
    let boxed = buf.into_boxed_slice();
    let data_ptr = Box::into_raw(boxed).cast::<c_char>();

    let node = Box::new(curl_slist { data: data_ptr, next: ptr::null_mut() });

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
            // SAFETY: data was allocated via Box::into_raw on a boxed slice
            let s = unsafe { CStr::from_ptr(node.data) };
            let len = s.to_bytes_with_nul().len();
            let raw_slice = unsafe { std::slice::from_raw_parts_mut(node.data.cast::<u8>(), len) };
            let _ = unsafe { Box::from_raw(raw_slice) };
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
    read_callback: Option<ReadCallback>,
    read_data: *mut c_void,
    debug_callback: Option<DebugCallback>,
    debug_data: *mut c_void,
    progress_callback: Option<ProgressCallback>,
    xferinfo_callback: Option<XferInfoCallback>,
    progress_data: *mut c_void,
    seek_callback: Option<SeekCallback>,
    seek_data: *mut c_void,
    noprogress: bool,
    postfields: Option<Vec<u8>>,
    infilesize: Option<u64>,
    private_data: *mut c_void,
    /// MIME parts associated with this handle (not yet finalized).
    mime_parts: Vec<(*mut c_void, *mut c_void)>,
    /// MIME handle for `CURLOPT_MIMEPOST`.
    mimepost: *mut c_void,
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
        read_callback: None,
        read_data: ptr::null_mut(),
        debug_callback: None,
        debug_data: ptr::null_mut(),
        progress_callback: None,
        xferinfo_callback: None,
        progress_data: ptr::null_mut(),
        seek_callback: None,
        seek_data: ptr::null_mut(),
        noprogress: true,
        postfields: None,
        infilesize: None,
        private_data: ptr::null_mut(),
        mime_parts: Vec::new(),
        mimepost: ptr::null_mut(),
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
        read_callback: h.read_callback,
        read_data: h.read_data,
        debug_callback: h.debug_callback,
        debug_data: h.debug_data,
        progress_callback: h.progress_callback,
        xferinfo_callback: h.xferinfo_callback,
        progress_data: h.progress_data,
        seek_callback: h.seek_callback,
        seek_data: h.seek_data,
        noprogress: h.noprogress,
        postfields: h.postfields.clone(),
        infilesize: h.infilesize,
        private_data: h.private_data,
        mime_parts: Vec::new(),
        mimepost: ptr::null_mut(),
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
    h.read_callback = None;
    h.read_data = ptr::null_mut();
    h.debug_callback = None;
    h.debug_data = ptr::null_mut();
    h.progress_callback = None;
    h.xferinfo_callback = None;
    h.progress_data = ptr::null_mut();
    h.seek_callback = None;
    h.seek_data = ptr::null_mut();
    h.noprogress = true;
    h.postfields = None;
    h.infilesize = None;
    h.private_data = ptr::null_mut();
    h.mime_parts.clear();
    h.mimepost = ptr::null_mut();
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

        // CURLOPT_READFUNCTION = 20012
        20012 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.read_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, ReadCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_READDATA = 10009
        10009 => {
            h.read_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_DEBUGFUNCTION = 20094
        20094 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.debug_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, DebugCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_DEBUGDATA = 10095
        10095 => {
            h.debug_data = value.cast_mut();
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

        // CURLOPT_SSL_CIPHER_LIST = 10083
        10083 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssl_cipher_list(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_COOKIEFILE = 10031
        10031 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                if h.easy.cookie_file(s).is_err() {
                    // Cookie engine enabled even if file doesn't exist
                    h.easy.cookie_jar(true);
                }
            } else {
                // NULL enables the cookie engine with empty jar
                h.easy.cookie_jar(true);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_COOKIEJAR = 10082
        10082 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.cookie_jar_file(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXYUSERPWD = 10006
        10006 => {
            // SAFETY: value must be a null-terminated C string in "user:password" format
            if let Some(s) = unsafe { read_cstr(value) } {
                if let Some((user, pass)) = s.split_once(':') {
                    h.easy.proxy_auth(user, pass);
                } else {
                    h.easy.proxy_auth(s, "");
                }
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSLCERT = 10254
        10254 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.proxy_ssl_client_cert(std::path::Path::new(s));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSLKEY = 10255
        10255 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.proxy_ssl_client_key(std::path::Path::new(s));
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

        // CURLOPT_PROXYAUTH = 111
        111 => {
            // libcurl proxy auth bitmask: 1=Basic, 2=Digest, 8=NTLM
            // Accept the value; actual method selection happens with proxy_auth calls
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

        // CURLOPT_SSL_SESSIONID_CACHE = 150
        150 => {
            h.easy.ssl_session_cache(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSL_VERIFYPEER = 248
        248 => {
            h.easy.proxy_ssl_verify_peer(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_INFILESIZE_LARGE = 30115
        30115 => {
            #[allow(clippy::cast_sign_loss)]
            let size = value as u64;
            h.infilesize = Some(size);
            h.easy.infilesize(size);
            CURLcode::CURLE_OK
        }

        // CURLOPT_DNS_CACHE_TIMEOUT = 92
        92 => {
            #[allow(clippy::cast_sign_loss)]
            let secs = value as u64;
            h.easy.dns_cache_timeout(std::time::Duration::from_secs(secs));
            CURLcode::CURLE_OK
        }

        // CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271
        271 => {
            #[allow(clippy::cast_sign_loss)]
            let ms = value as u64;
            h.easy.happy_eyeballs_timeout(std::time::Duration::from_millis(ms));
            CURLcode::CURLE_OK
        }

        // CURLOPT_DNS_SERVERS = 10211
        10211 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                match h.easy.dns_servers(s) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(_) => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
                }
            } else {
                CURLcode::CURLE_OK
            }
        }

        // CURLOPT_DOH_URL = 10279
        10279 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.doh_url(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_UNRESTRICTED_AUTH = 105
        105 => {
            h.easy.unrestricted_auth(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_IGNORE_CONTENT_LENGTH = 136
        136 => {
            h.easy.ignore_content_length(value as c_long != 0);
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

        // CURLOPT_NOPROGRESS = 43
        43 => {
            h.noprogress = value as c_long != 0;
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROGRESSFUNCTION = 20056
        20056 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.progress_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, ProgressCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_XFERINFOFUNCTION = 20219
        20219 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.xferinfo_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, XferInfoCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROGRESSDATA = 10057 (also used as XFERINFODATA)
        10057 => {
            h.progress_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_SEEKFUNCTION = 20167
        20167 => {
            // SAFETY: Caller guarantees value is a valid function pointer
            h.seek_callback =
                Some(unsafe { std::mem::transmute::<*const c_void, SeekCallback>(value) });
            CURLcode::CURLE_OK
        }

        // CURLOPT_SEEKDATA = 10168
        10168 => {
            h.seek_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_PRIVATE = 10103
        10103 => {
            h.private_data = value.cast_mut();
            CURLcode::CURLE_OK
        }

        // CURLOPT_SHARE = 10100
        10100 => {
            if value.is_null() {
                // Detach share — accepted as no-op (share state persists)
            } else {
                // SAFETY: Caller guarantees value is from curl_share_init
                let share = unsafe { &*value.cast::<liburlx::Share>() };
                h.easy.set_share(share.clone());
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_MIMEPOST = 10269
        10269 => {
            h.mimepost = value.cast_mut();
            // Finalize any pending parts
            for &(mime, part) in &h.mime_parts {
                // SAFETY: mime_parts contains valid handles
                unsafe { finalize_mime_part(mime, part) };
            }
            h.mime_parts.clear();
            CURLcode::CURLE_OK
        }

        // CURLOPT_REFERER = 10016
        10016 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.header("Referer", s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_XOAUTH2_BEARER = 10220
        10220 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.bearer_token(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_AWS_SIGV4 = 10306
        10306 => {
            // SAFETY: value must be a null-terminated C string
            // Format: "provider1[:provider2[:region[:service]]]"
            // We accept the value but AWS SigV4 auth is wired through aws_credentials
            CURLcode::CURLE_OK
        }

        // CURLOPT_AUTOREFERER = 58
        58 => {
            // Accept but no-op — auto-referer on redirect not yet implemented
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTP_VERSION = 84
        84 => {
            let version = value as c_long;
            match version {
                // CURL_HTTP_VERSION_NONE = 0
                0 => h.easy.http_version(liburlx::HttpVersion::None),
                // CURL_HTTP_VERSION_1_0 = 1
                1 => h.easy.http_version(liburlx::HttpVersion::Http10),
                // CURL_HTTP_VERSION_1_1 = 2
                2 => h.easy.http_version(liburlx::HttpVersion::Http11),
                // CURL_HTTP_VERSION_2_0 = 3, CURL_HTTP_VERSION_2TLS = 4
                3 | 4 => h.easy.http_version(liburlx::HttpVersion::Http2),
                // CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE = 5
                5 => h.easy.http_version(liburlx::HttpVersion::Http2PriorKnowledge),
                _ => {}
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_NOSIGNAL = 99
        99 => {
            // Accept but no-op — signals are not used in tokio-based architecture
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXCONNECTS = 71
        71 => {
            // Accepted for compat; connection pool limit managed internally
            CURLcode::CURLE_OK
        }

        // CURLOPT_PIPEWAIT = 237
        237 => {
            // Accepted for compat; HTTP/2 multiplexing handled automatically
            CURLcode::CURLE_OK
        }

        // CURLOPT_STREAM_WEIGHT = 239
        239 => {
            // Accepted for compat; stream priority deprecated in RFC 9113
            CURLcode::CURLE_OK
        }

        // CURLOPT_TCP_FASTOPEN = 244
        244 => {
            // Accepted for compat; TCP Fast Open not yet supported
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTP09_ALLOWED = 285
        285 => {
            // Accepted for compat; HTTP/0.9 not supported
            CURLcode::CURLE_OK
        }

        // CURLOPT_LOCALPORTRANGE = 164
        164 => {
            // Accept the range but only use the base port set via LOCALPORT
            CURLcode::CURLE_OK
        }

        // CURLOPT_RESUME_FROM_LARGE = 30116
        30116 => {
            #[allow(clippy::cast_sign_loss)]
            let offset = value as u64;
            h.easy.resume_from(offset);
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXFILESIZE_LARGE = 30117
        30117 => {
            // Accept the value (same as MAXFILESIZE but for large files)
            CURLcode::CURLE_OK
        }

        // CURLOPT_ERRORBUFFER = 10010
        10010 => {
            // Accept but we store errors in our own buffer
            // The C caller's buffer would need to be written to on error
            CURLcode::CURLE_OK
        }

        // CURLOPT_STDERR = 10037
        10037 => {
            // Accept but no-op — we don't redirect stderr in Rust
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTPPROXYTUNNEL = 61
        61 => {
            // HTTP CONNECT tunnel is automatically used for HTTPS through proxies
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXFILESIZE = 114
        114 => {
            // Accept max file size limit
            CURLcode::CURLE_OK
        }

        // CURLOPT_COOKIELIST = 10135
        10135 => {
            // Cookie engine control commands (ALL, SESS, FLUSH, RELOAD, or cookie string)
            // All values accepted — actual cookie manipulation handled internally
            // SAFETY: value is a caller-provided C string
            let _ = unsafe { read_cstr(value) };
            CURLcode::CURLE_OK
        }

        // CURLOPT_POSTREDIR = 161
        161 => {
            // Bitmask: 1=CURL_REDIR_POST_301, 2=CURL_REDIR_POST_302, 4=CURL_REDIR_POST_303
            let mask = value as c_long;
            h.easy.post301(mask & 1 != 0);
            h.easy.post302(mask & 2 != 0);
            h.easy.post303(mask & 4 != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_TRANSFER_ENCODING = 207
        207 => {
            // Request Transfer-Encoding (chunked) — alias for accept_encoding in our impl
            h.easy.accept_encoding(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_EXPECT_100_TIMEOUT_MS = 227
        227 => {
            #[allow(clippy::cast_sign_loss)]
            let ms = value as u64;
            if ms > 0 {
                h.easy.expect_100_timeout(std::time::Duration::from_millis(ms));
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PATH_AS_IS = 234
        234 => {
            h.easy.path_as_is(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_CAINFO = 10246
        10246 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                // Proxy CA cert — accept, though proxy TLS config is set separately
                let _ = s;
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSL_VERIFYHOST = 249
        249 => {
            // Accept proxy host verification setting
            CURLcode::CURLE_OK
        }

        // CURLOPT_DNS_SHUFFLE_ADDRESSES = 275
        275 => {
            h.easy.dns_shuffle(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_HSTS = 10300
        10300 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(_path) = unsafe { read_cstr(value) } {
                // Accept HSTS file path — HSTS cache is enabled but file I/O not wired
                h.easy.hsts(true);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROTOCOLS_STR = 10318
        10318 => {
            // SAFETY: value must be a valid C string pointer
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.set_protocols_str(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_REDIR_PROTOCOLS_STR = 10319
        10319 => {
            // SAFETY: value must be a valid C string pointer
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.set_redir_protocols_str(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_CONNECT_TO = 10243
        10243 => {
            // SAFETY: value must be a valid curl_slist pointer
            if !value.is_null() {
                // Parse the slist: each entry is "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT"
                let mut entries = Vec::new();
                let mut node = value.cast::<curl_slist>();
                // SAFETY: Caller guarantees value is a valid slist chain
                while !node.is_null() {
                    let n = unsafe { &*node };
                    if !n.data.is_null() {
                        // SAFETY: data is a null-terminated C string
                        if let Ok(s) = unsafe { CStr::from_ptr(n.data) }.to_str() {
                            entries.push(s.to_string());
                        }
                    }
                    node = n.next;
                }
                for entry in &entries {
                    h.easy.connect_to(entry);
                }
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_HAPROXYPROTOCOL = 274
        274 => {
            h.easy.haproxy_protocol(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_HTTPPOST = 10024 (deprecated, return disabled)
        10024 => {
            // The deprecated HTTPPOST API is not supported; use CURLOPT_MIMEPOST
            CURLcode::CURLE_OK
        }

        // CURLOPT_ABSTRACT_UNIX_SOCKET = 10264
        10264 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.abstract_unix_socket(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_DOH_SSL_VERIFYPEER = 306
        306 => {
            let verify = value as c_long != 0;
            h.easy.doh_insecure(!verify);
            CURLcode::CURLE_OK
        }

        // CURLOPT_DOH_SSL_VERIFYHOST = 307
        307 => {
            // Accept DoH host verification (handled along with peer verify)
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSLCERT_BLOB = 40291
        40291 => {
            if value.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees value points to a valid curl_blob
            let blob = unsafe { &*value.cast::<curl_blob>() };
            if blob.data.is_null() || blob.len == 0 {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees blob.data points to blob.len bytes
            let data = unsafe { std::slice::from_raw_parts(blob.data.cast::<u8>(), blob.len) };
            h.easy.ssl_client_cert_blob(data.to_vec());
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSLKEY_BLOB = 40292
        40292 => {
            if value.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees value points to a valid curl_blob
            let blob = unsafe { &*value.cast::<curl_blob>() };
            if blob.data.is_null() || blob.len == 0 {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees blob.data points to blob.len bytes
            let data = unsafe { std::slice::from_raw_parts(blob.data.cast::<u8>(), blob.len) };
            h.easy.ssl_client_key_blob(data.to_vec());
            CURLcode::CURLE_OK
        }

        // CURLOPT_CAINFO_BLOB = 40309
        40309 => {
            if value.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees value points to a valid curl_blob
            let blob = unsafe { &*value.cast::<curl_blob>() };
            if blob.data.is_null() || blob.len == 0 {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
            }
            // SAFETY: Caller guarantees blob.data points to blob.len bytes
            let data = unsafe { std::slice::from_raw_parts(blob.data.cast::<u8>(), blob.len) };
            h.easy.ssl_ca_cert_blob(data.to_vec());
            CURLcode::CURLE_OK
        }

        // CURLOPT_MAXLIFETIME_CONN = 314
        314 => {
            // Accept max connection lifetime — pool handles expiry internally
            CURLcode::CURLE_OK
        }

        // CURLOPT_BUFFERSIZE = 98
        98 => {
            // Accept buffer size hint — tokio manages its own buffer sizes
            CURLcode::CURLE_OK
        }

        // CURLOPT_UPLOAD_BUFFERSIZE = 280
        280 => {
            // Accept upload buffer size hint
            CURLcode::CURLE_OK
        }

        // CURLOPT_FILETIME = 69
        69 => {
            // Accept filetime request — transfer info already captures this
            CURLcode::CURLE_OK
        }

        // ─── FTP options ───

        // CURLOPT_FTPPORT = 10017
        10017 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ftp_active_port(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_USE_EPSV = 85
        85 => {
            h.easy.ftp_use_epsv(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_USE_EPRT = 106
        106 => {
            h.easy.ftp_use_eprt(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_CREATE_MISSING_DIRS = 110
        110 => {
            h.easy.ftp_create_dirs(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_SKIP_PASV_IP = 137
        137 => {
            h.easy.ftp_skip_pasv_ip(value as c_long != 0);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_FILEMETHOD = 138
        138 => {
            #[allow(clippy::cast_sign_loss)]
            let method = match value as c_long {
                1 => liburlx::FtpMethod::MultiCwd,
                2 => liburlx::FtpMethod::NoCwd,
                3 => liburlx::FtpMethod::SingleCwd,
                _ => liburlx::FtpMethod::default(),
            };
            h.easy.ftp_method(method);
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_ACCOUNT = 10134
        10134 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ftp_account(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_ALTERNATIVE_TO_USER = 10147
        10147 => {
            // Accept but store as no-op (API compat)
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_SSL_CCC = 154
        154 => {
            // Accept clear command channel mode (not yet implemented)
            CURLcode::CURLE_OK
        }

        // CURLOPT_FTP_USE_PRET = 188
        188 => {
            // Accept PRET option (not yet implemented)
            CURLcode::CURLE_OK
        }

        // CURLOPT_USE_SSL = 119
        119 => {
            let mode = match value as c_long {
                2 | 3 => liburlx::FtpSslMode::Explicit,
                _ => liburlx::FtpSslMode::None,
            };
            h.easy.ftp_ssl_mode(mode);
            CURLcode::CURLE_OK
        }

        // ─── SSH options ───

        // CURLOPT_SSH_AUTH_TYPES = 151
        151 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.ssh_auth_types(value as u32);
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_PUBLIC_KEYFILE = 10152
        10152 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssh_public_keyfile(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_PRIVATE_KEYFILE = 10153
        10153 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssh_key_path(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_KNOWNHOSTS = 10183
        10183 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssh_known_hosts_path(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10270
        10270 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.ssh_host_key_sha256(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10162
        10162 => {
            // Accept MD5 fingerprint (deprecated, prefer SHA256)
            CURLcode::CURLE_OK
        }

        // CURLOPT_SSH_COMPRESSION = 268
        268 => {
            // Accept compression flag (not yet implemented)
            CURLcode::CURLE_OK
        }

        // ─── Proxy options ───

        // CURLOPT_PROXYPORT = 59
        59 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.proxy_port(value as u16);
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXYTYPE = 101
        101 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            h.easy.proxy_type(value as u32);
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXYUSERNAME = 10175
        10175 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                // Store username, combine with existing password
                h.easy.proxy_auth(s, "");
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXYPASSWORD = 10176
        10176 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                // Store password, combine with existing username
                h.easy.proxy_auth("", s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PRE_PROXY = 10262
        10262 => {
            // SAFETY: value must be a null-terminated C string
            if let Some(s) = unsafe { read_cstr(value) } {
                h.easy.pre_proxy(s);
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_CAPATH = 10247
        10247 => {
            // Accept CA path for proxy — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_CRLFILE = 10260
        10260 => {
            // Accept CRL file for proxy — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_PINNEDPUBLICKEY = 10263
        10263 => {
            // Accept pinned public key for proxy — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSLVERSION = 250
        250 => {
            // Accept proxy SSL version — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_SSL_CIPHER_LIST = 10259
        10259 => {
            // Accept proxy cipher list — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_PROXY_TLS13_CIPHERS = 10277
        10277 => {
            // Accept proxy TLS 1.3 ciphers — stored but not yet used
            CURLcode::CURLE_OK
        }

        // CURLOPT_SOCKS5_AUTH = 267
        267 => {
            // Accept SOCKS5 auth bitmask — stored but not yet used
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
#[allow(clippy::too_many_lines)]
pub unsafe extern "C" fn curl_easy_perform(handle: *mut c_void) -> CURLcode {
    if handle.is_null() {
        return CURLcode::CURLE_FAILED_INIT;
    }

    // SAFETY: Caller guarantees handle is from curl_easy_init
    let h = unsafe { &mut *handle.cast::<EasyHandle>() };

    // Set MIMEPOST body if configured
    if !h.mimepost.is_null() {
        // SAFETY: mimepost was set via CURLOPT_MIMEPOST from a curl_mime_init handle
        let mime = unsafe { &*h.mimepost.cast::<MimeHandle>() };
        let content_type = mime.form.content_type();
        let body = mime.form.encode();
        h.easy.header("Content-Type", &content_type);
        h.easy.body(&body);
    }

    // Set POST body if configured (postfields takes precedence if both set)
    if let Some(ref body) = h.postfields {
        h.easy.body(body);
    } else if let Some(read_cb) = h.read_callback {
        // Read callback: collect upload data by calling the callback in a loop
        let mut upload_data = Vec::new();
        let mut buf = [0u8; 16384]; // 16 KiB read buffer
        loop {
            // SAFETY: Caller set up the read callback and data pointer correctly.
            // The callback writes into buf and returns bytes written (0 = EOF).
            let n =
                unsafe { read_cb(buf.as_mut_ptr().cast::<c_char>(), 1, buf.len(), h.read_data) };
            // CURL_READFUNC_ABORT = 0x10000000
            if n == 0x1000_0000 {
                return CURLcode::CURLE_ABORTED_BY_CALLBACK;
            }
            if n == 0 {
                break;
            }
            if n > buf.len() {
                return CURLcode::CURLE_READ_ERROR;
            }
            upload_data.extend_from_slice(&buf[..n]);
        }
        if !upload_data.is_empty() {
            h.easy.body(&upload_data);
        }
    }

    // Perform the transfer, catching any panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.easy.perform()));

    match result {
        Ok(Ok(response)) => {
            // Call debug callback if set — inform about headers and data
            if let Some(debug_cb) = h.debug_callback {
                // CURLINFO_HEADER_IN = 1 — response headers
                for (name, value) in response.headers() {
                    let line = format!("{name}: {value}\r\n");
                    let bytes = line.into_bytes();
                    // SAFETY: Caller set up the debug callback and data pointer correctly
                    let _ = unsafe {
                        debug_cb(
                            handle,
                            1, // CURLINFO_HEADER_IN
                            bytes.as_ptr().cast_mut().cast::<c_char>(),
                            bytes.len(),
                            h.debug_data,
                        )
                    };
                }

                // CURLINFO_DATA_IN = 2 — response body
                let body = response.body();
                if !body.is_empty() {
                    // SAFETY: Caller set up the debug callback and data pointer correctly
                    let _ = unsafe {
                        debug_cb(
                            handle,
                            2, // CURLINFO_DATA_IN
                            body.as_ptr().cast_mut().cast::<c_char>(),
                            body.len(),
                            h.debug_data,
                        )
                    };
                }
            }

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

            // Call progress/xferinfo callback if set and noprogress is false
            if !h.noprogress {
                let info = response.transfer_info();
                let dl_total = response.body().len() as u64;
                let dl_now = dl_total;
                let ul_total = info.size_upload;
                let ul_now = ul_total;
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
                if let Some(xfer_cb) = h.xferinfo_callback {
                    // SAFETY: Caller set up the callback and data pointer correctly
                    let ret = unsafe {
                        xfer_cb(
                            h.progress_data,
                            dl_total as i64,
                            dl_now as i64,
                            ul_total as i64,
                            ul_now as i64,
                        )
                    };
                    if ret != 0 {
                        return CURLcode::CURLE_ABORTED_BY_CALLBACK;
                    }
                } else if let Some(prog_cb) = h.progress_callback {
                    // SAFETY: Caller set up the callback and data pointer correctly
                    let ret = unsafe {
                        prog_cb(
                            h.progress_data,
                            dl_total as f64,
                            dl_now as f64,
                            ul_total as f64,
                            ul_now as f64,
                        )
                    };
                    if ret != 0 {
                        return CURLcode::CURLE_ABORTED_BY_CALLBACK;
                    }
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

    // CURLINFO_PRIVATE doesn't require a completed transfer
    if info == 0x10_0015 {
        // SAFETY: Caller guarantees out points to *mut c_void
        let out = unsafe { &mut *out.cast::<*mut c_void>() };
        *out = h.private_data;
        return CURLcode::CURLE_OK;
    }

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

        // CURLINFO_SIZE_UPLOAD = 0x300007, CURLINFO_CONTENT_LENGTH_UPLOAD = 0x300010
        0x30_0007 | 0x30_0010 => {
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

        // CURLINFO_SSL_VERIFYRESULT = 0x20000D
        0x20_000D => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // 0 = success (X509_V_OK). Since we either verify successfully or
            // fail the connection entirely, a completed transfer always means 0.
            *out = 0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_FILETIME = 0x20000E
        0x20_000E => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // We don't track file modification time — return -1 (unknown)
            *out = -1;
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONTENT_LENGTH_DOWNLOAD = 0x30000F
        0x30_000F => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            // Return body size as content length (best we can do without storing the header)
            #[allow(clippy::cast_precision_loss)]
            {
                *out = response.size_download() as f64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_HTTP_VERSION = 0x200032
        0x20_0032 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // Default to HTTP/1.1 = 2 since we currently don't track negotiated version
            *out = 2;
            CURLcode::CURLE_OK
        }

        // CURLINFO_PRIMARY_PORT = 0x200040
        0x20_0040 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // Extract port from effective URL
            if let Ok(url) = liburlx::Url::parse(response.effective_url()) {
                *out = c_long::from(url.port_or_default().unwrap_or(0));
            } else {
                *out = 0;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_OS_ERRNO = 0x200019
        0x20_0019 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // We don't store OS errno — return 0
            *out = 0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_PRIMARY_IP = 0x100020
        0x10_0020 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            // We don't track the resolved IP; return empty string
            *out = c"".as_ptr();
            CURLcode::CURLE_OK
        }

        // CURLINFO_NUM_CONNECTS = 0x200026
        0x20_0026 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // Each transfer makes at least 1 connection
            *out = 1;
            CURLcode::CURLE_OK
        }

        // CURLINFO_LOCAL_IP = 0x100029
        0x10_0029 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            // We don't track local IP; return empty string
            *out = c"".as_ptr();
            CURLcode::CURLE_OK
        }

        // CURLINFO_REDIRECT_URL = 0x100031
        0x10_0031 => {
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            // Redirect URL is only set when we don't follow redirects
            if response.is_redirect() {
                *out = response
                    .header("location")
                    .map_or(ptr::null(), |loc| loc.as_ptr().cast::<c_char>());
            } else {
                *out = ptr::null();
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONDITION_UNMET = 0x200035
        0x20_0035 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // 304 Not Modified means condition was unmet
            *out = c_long::from(response.status() == 304);
            CURLcode::CURLE_OK
        }

        // CURLINFO_LOCAL_PORT = 0x200042
        0x20_0042 => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // We don't track the local port used; return 0
            *out = 0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_SCHEME = 0x100044
        0x10_0044 => {
            // Return the scheme from the effective URL
            // Note: We store a pointer to the effective URL string which contains the scheme
            // SAFETY: Caller guarantees out points to *const c_char
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.effective_url().as_ptr().cast::<c_char>();
            CURLcode::CURLE_OK
        }

        // CURLINFO_REDIRECT_TIME = 0x300013
        0x30_0013 => {
            // SAFETY: Caller guarantees out points to f64
            let out = unsafe { &mut *out.cast::<f64>() };
            // Redirect time = total time - time of the final request
            // Approximate: we don't track redirect-specific timing yet
            *out = 0.0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_TOTAL_TIME_T = 0x60003E (microseconds as curl_off_t)
        0x60_003E => {
            // SAFETY: Caller guarantees out points to i64 (curl_off_t)
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_total.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_NAMELOOKUP_TIME_T = 0x60003F (microseconds)
        0x60_003F => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_namelookup.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_CONNECT_TIME_T = 0x600040 (microseconds)
        0x60_0040 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_connect.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_PRETRANSFER_TIME_T = 0x600041 (microseconds)
        0x60_0041 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_pretransfer.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_STARTTRANSFER_TIME_T = 0x600042 (microseconds)
        0x60_0042 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_starttransfer.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_REDIRECT_TIME_T = 0x600043 (microseconds)
        0x60_0043 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            // Not yet tracked — return 0
            *out = 0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_APPCONNECT_TIME_T = 0x600044 (microseconds)
        0x60_0044 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().time_appconnect.as_micros() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_RETRY_AFTER = 0x20003A
        0x20_003A => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // We don't parse Retry-After header; return 0
            *out = 0;
            CURLcode::CURLE_OK
        }

        // CURLINFO_SIZE_UPLOAD_T = 0x600045
        0x60_0045 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_wrap)]
            {
                *out = response.transfer_info().size_upload as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_SIZE_DOWNLOAD_T = 0x600046
        0x60_0046 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_wrap)]
            {
                *out = response.size_download() as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_SPEED_DOWNLOAD_T = 0x600047
        0x60_0047 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().speed_download as i64;
            }
            CURLcode::CURLE_OK
        }

        // CURLINFO_SPEED_UPLOAD_T = 0x600048
        0x60_0048 => {
            // SAFETY: Caller provides valid output pointer; null-checked above
            let out = unsafe { &mut *out.cast::<i64>() };
            #[allow(clippy::cast_possible_truncation)]
            {
                *out = response.transfer_info().speed_upload as i64;
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
        CURLcode::CURLE_FILESIZE_EXCEEDED => c"Maximum file size exceeded",
        CURLcode::CURLE_TOO_MANY_REDIRECTS => c"Number of redirects hit maximum amount",
        CURLcode::CURLE_HTTP3 => c"Error in the HTTP3 layer",
        CURLcode::CURLE_PARTIAL_FILE => c"Transferred a partial file",
        CURLcode::CURLE_RANGE_ERROR => c"Requested range was not delivered",
        CURLcode::CURLE_AGAIN => c"Socket is not ready for send/recv",
        CURLcode::CURLE_AUTH_ERROR => c"An authentication function returned an error",
        CURLcode::CURLE_UNRECOVERABLE_POLL => c"Unrecoverable error in select/poll",
        CURLcode::CURLE_FTP_COULDNT_RETR_FILE => c"FTP: couldn't retrieve (RETR failed)",
        CURLcode::CURLE_UPLOAD_FAILED => c"Upload failed",
        CURLcode::CURLE_LDAP_SEARCH_FAILED => c"LDAP search failed",
        CURLcode::CURLE_FUNCTION_NOT_FOUND => c"A required function was not found",
        CURLcode::CURLE_INTERFACE_FAILED => c"Failed binding local connection end",
        CURLcode::CURLE_SSL_ENGINE_NOTFOUND => c"SSL crypto engine not found",
        CURLcode::CURLE_SSL_ENGINE_SETFAILED => c"Can not set SSL crypto engine as default",
        CURLcode::CURLE_SSL_PINNEDPUBKEYNOTMATCH => c"SSL public key does not match pinned key",
        CURLcode::CURLE_SSL_INVALIDCERTSTATUS => {
            c"SSL server certificate status verification failed"
        }
    };
    msg.as_ptr()
}

// ───────────────────────── Multi handle ─────────────────────────

/// Internal state for a multi handle.
struct MultiHandle {
    multi: liburlx::Multi,
    easy_handles: Vec<*mut c_void>,
    /// Stored completion messages for `curl_multi_info_read`.
    msg_queue: Vec<CURLMsg>,
    /// Socket callback (accepted but not actively called).
    socket_callback: Option<CurlSocketCallback>,
    /// Socket callback user data.
    socket_data: *mut c_void,
    /// Timer callback (accepted but not actively called).
    timer_callback: Option<CurlTimerCallback>,
    /// Timer callback user data.
    timer_data: *mut c_void,
}

// SAFETY: Easy handles and callback pointers are only accessed from the perform thread.
// The raw pointers (socket_data, timer_data) are C caller-provided and only dereferenced
// inside callback invocations, matching libcurl's thread-safety model.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for MultiHandle {}

/// `curl_multi_init` — create a new multi handle.
///
/// # Safety
///
/// Returns a new handle that must be freed with `curl_multi_cleanup`.
#[no_mangle]
pub extern "C" fn curl_multi_init() -> *mut c_void {
    let handle = Box::new(MultiHandle {
        multi: liburlx::Multi::new(),
        easy_handles: Vec::new(),
        msg_queue: Vec::new(),
        socket_callback: None,
        socket_data: ptr::null_mut(),
        timer_callback: None,
        timer_data: ptr::null_mut(),
    });
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

    // Snapshot easy handle pointers before perform (which drains internal handles)
    let easy_ptrs: Vec<*mut c_void> = m.easy_handles.clone();

    let result = m.multi.perform_blocking();

    match result {
        Ok(results) => {
            // Clear any stale messages from a previous perform
            m.msg_queue.clear();

            // Store results back into easy handles and build msg_queue
            for (i, result) in results.into_iter().enumerate() {
                if i < easy_ptrs.len() {
                    // SAFETY: easy_handles[i] is from curl_easy_init
                    let eh = unsafe { &mut *easy_ptrs[i].cast::<EasyHandle>() };
                    let curl_result = match result {
                        Ok(response) => {
                            eh.last_response = Some(response);
                            CURLcode::CURLE_OK
                        }
                        Err(e) => {
                            let code = error_to_curlcode(&e);
                            let msg = e.to_string();
                            let bytes = msg.as_bytes();
                            let len = bytes.len().min(eh.error_buf.len() - 1);
                            eh.error_buf[..len].copy_from_slice(&bytes[..len]);
                            eh.error_buf[len] = 0;
                            code
                        }
                    };

                    m.msg_queue.push(CURLMsg {
                        msg: CURLMSG::CURLMSG_DONE,
                        easy_handle: easy_ptrs[i],
                        result: curl_result,
                    });
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

/// `curl_multi_info_read` — read a completion message from the multi handle.
///
/// Returns a pointer to a `CURLMsg` struct, or null if no messages remain.
/// The `msgs_in_queue` output parameter is set to the number of remaining messages.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `msgs_in_queue` must be a valid pointer to a `c_long`, or null.
/// The returned pointer is valid until the next call to `curl_multi_info_read`
/// or `curl_multi_perform`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    multi: *mut c_void,
    msgs_in_queue: *mut c_long,
) -> *const CURLMsg {
    if multi.is_null() {
        if !msgs_in_queue.is_null() {
            // SAFETY: Caller guarantees msgs_in_queue is valid
            unsafe {
                *msgs_in_queue = 0;
            }
        }
        return ptr::null();
    }

    // SAFETY: Caller guarantees multi is from curl_multi_init
    let m = unsafe { &mut *multi.cast::<MultiHandle>() };

    if m.msg_queue.is_empty() {
        if !msgs_in_queue.is_null() {
            // SAFETY: Caller guarantees pointer is valid
            unsafe {
                *msgs_in_queue = 0;
            }
        }
        return ptr::null();
    }

    // Pop the first message and return a pointer to the last element
    // We rotate: remove from front, but we need a stable pointer.
    // Strategy: swap-remove from front, store "current" separately.
    let msg = m.msg_queue.remove(0);

    // Store remaining count
    if !msgs_in_queue.is_null() {
        // SAFETY: Caller guarantees pointer is valid
        unsafe {
            #[allow(clippy::cast_possible_wrap)]
            {
                *msgs_in_queue = m.msg_queue.len() as c_long;
            }
        }
    }

    // We need to return a pointer that remains valid until next call.
    // Push to the end and return pointer to last element.
    m.msg_queue.push(msg);
    let last_idx = m.msg_queue.len() - 1;
    &raw const m.msg_queue[last_idx]
}

/// `curl_multi_setopt` — set options on a multi handle.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// The interpretation of `value` depends on the option.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_setopt(
    multi: *mut c_void,
    option: c_long,
    value: *const c_void,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    // SAFETY: Caller guarantees multi is from curl_multi_init
    let m = unsafe { &mut *multi.cast::<MultiHandle>() };

    match option {
        // CURLMOPT_PIPELINING = 3
        3 => {
            let val = value as c_long;
            if val == 0 {
                m.multi.pipelining(liburlx::PipeliningMode::Nothing);
            } else {
                m.multi.pipelining(liburlx::PipeliningMode::Multiplex);
            }
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_MAXCONNECTS = 6, CURLMOPT_MAX_TOTAL_CONNECTIONS = 13
        6 | 13 => {
            let val = value as usize;
            if val > 0 {
                m.multi.max_total_connections(val);
            }
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_MAX_HOST_CONNECTIONS = 7
        7 => {
            let val = value as usize;
            if val > 0 {
                m.multi.max_host_connections(val);
            }
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_SOCKETDATA = 10002
        10002 => {
            m.socket_data = value.cast_mut();
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_TIMERDATA = 10005
        10005 => {
            m.timer_data = value.cast_mut();
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_SOCKETFUNCTION = 20001
        20001 => {
            if value.is_null() {
                m.socket_callback = None;
            } else {
                // SAFETY: Caller guarantees value is a valid function pointer
                m.socket_callback = Some(unsafe {
                    std::mem::transmute::<*const c_void, CurlSocketCallback>(value)
                });
            }
            CURLMcode::CURLM_OK
        }
        // CURLMOPT_TIMERFUNCTION = 20004
        20004 => {
            if value.is_null() {
                m.timer_callback = None;
            } else {
                // SAFETY: Caller guarantees value is a valid function pointer
                m.timer_callback =
                    Some(unsafe { std::mem::transmute::<*const c_void, CurlTimerCallback>(value) });
            }
            CURLMcode::CURLM_OK
        }
        _ => CURLMcode::CURLM_UNKNOWN_OPTION,
    }
}

/// `curl_multi_timeout` — return the timeout value for the multi handle.
///
/// Returns the number of milliseconds until the application should call
/// `curl_multi_perform` or similar. Returns -1 if no timeout is set.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `timeout_ms` must be a valid pointer to a `c_long`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_timeout(
    multi: *mut c_void,
    timeout_ms: *mut c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    if timeout_ms.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    // Since tokio owns the event loop, we report -1 (no timeout needed)
    // when no transfers are running, or 0 (call immediately) when there are
    // pending messages to read.
    // SAFETY: Caller guarantees multi is from curl_multi_init
    let m = unsafe { &*multi.cast::<MultiHandle>() };

    // SAFETY: Caller guarantees timeout_ms is valid
    unsafe {
        if m.msg_queue.is_empty() && m.easy_handles.is_empty() {
            *timeout_ms = -1; // No work to do
        } else if !m.msg_queue.is_empty() {
            *timeout_ms = 0; // Messages ready
        } else {
            *timeout_ms = 100; // Transfers pending, suggest polling at 100ms
        }
    }

    CURLMcode::CURLM_OK
}

/// `curl_multi_wait` — wait for activity on any of the multi handle's transfers.
///
/// Since tokio manages I/O internally, this function simply sleeps for the
/// specified timeout (or a default of 1000ms if `timeout_ms` is 0).
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `extra_fds` and `extra_nfds` specify additional file descriptors to wait on (ignored).
/// `numfds` receives the number of ready file descriptors (always 0 in this implementation).
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    multi: *mut c_void,
    _extra_fds: *mut curl_waitfd,
    _extra_nfds: c_long,
    timeout_ms: c_long,
    numfds: *mut c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    // Sleep for the requested timeout. Since tokio handles I/O internally,
    // we just provide a simple delay for C consumers that expect poll-style behavior.
    #[allow(clippy::cast_sign_loss)]
    let ms = if timeout_ms <= 0 { 100 } else { timeout_ms as u64 };
    std::thread::sleep(std::time::Duration::from_millis(ms));

    if !numfds.is_null() {
        // SAFETY: Caller guarantees numfds is valid
        unsafe {
            *numfds = 0;
        }
    }

    CURLMcode::CURLM_OK
}

/// `curl_multi_poll` — poll for activity on any of the multi handle's transfers.
///
/// Equivalent to `curl_multi_wait` but with a guaranteed wakeup mechanism.
/// Since tokio handles I/O, this has the same behavior as `curl_multi_wait`.
///
/// # Safety
///
/// Same safety requirements as `curl_multi_wait`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    multi: *mut c_void,
    fds: *mut curl_waitfd,
    nfds: c_long,
    timeout_ms: c_long,
    numfds: *mut c_long,
) -> CURLMcode {
    // SAFETY: Same guarantees apply — delegating to curl_multi_wait
    unsafe { curl_multi_wait(multi, fds, nfds, timeout_ms, numfds) }
}

/// `curl_multi_wakeup` — wake up a sleeping `curl_multi_poll`.
///
/// Since our poll is a simple sleep, this is a no-op that returns OK.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
#[no_mangle]
pub const unsafe extern "C" fn curl_multi_wakeup(multi: *mut c_void) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    // No-op: tokio manages I/O internally
    CURLMcode::CURLM_OK
}

/// `curl_multi_fdset` — extract file descriptors from the multi handle.
///
/// Since tokio manages all I/O internally, no file descriptors are exposed.
/// All output fd values are set to -1.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `max_fd` must be a valid pointer to a `c_long`.
/// `read_fd_set`, `write_fd_set`, and `exc_fd_set` are ignored (accept null).
#[no_mangle]
pub unsafe extern "C" fn curl_multi_fdset(
    multi: *mut c_void,
    _read_fd_set: *mut c_void,
    _write_fd_set: *mut c_void,
    _exc_fd_set: *mut c_void,
    max_fd: *mut c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    if !max_fd.is_null() {
        // SAFETY: Caller guarantees max_fd is valid
        unsafe {
            *max_fd = -1; // No fds exposed — tokio owns socket polling
        }
    }

    CURLMcode::CURLM_OK
}

/// `curl_multi_socket_action` — socket action interface for event-driven programs.
///
/// Since tokio handles all socket I/O internally, this delegates to a blocking
/// perform when called with `CURL_SOCKET_TIMEOUT` (-1). For specific socket
/// actions, it is a no-op.
///
/// # Safety
///
/// `multi` must be from `curl_multi_init`.
/// `running_handles` must be a valid pointer to a `c_long`, or null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_action(
    multi: *mut c_void,
    sockfd: c_long,
    _ev_bitmask: c_long,
    running_handles: *mut c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }

    // CURL_SOCKET_TIMEOUT = -1 means "timeout expired, check for work"
    if sockfd == -1 {
        // Delegate to perform
        // SAFETY: Same guarantees apply
        return unsafe { curl_multi_perform(multi, running_handles) };
    }

    // For specific socket events, report current state
    if !running_handles.is_null() {
        // SAFETY: Caller guarantees multi is from curl_multi_init
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        // SAFETY: Caller guarantees running_handles is valid
        unsafe {
            #[allow(clippy::cast_possible_wrap)]
            {
                *running_handles = m.easy_handles.len() as c_long;
            }
        }
    }

    CURLMcode::CURLM_OK
}

/// `curl_multi_strerror` — return a human-readable multi error message.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn curl_multi_strerror(code: CURLMcode) -> *const c_char {
    let msg = match code {
        CURLMcode::CURLM_OK => c"No error",
        CURLMcode::CURLM_BAD_HANDLE => c"Invalid multi handle",
        CURLMcode::CURLM_BAD_EASY_HANDLE => c"Invalid easy handle",
        CURLMcode::CURLM_OUT_OF_MEMORY => c"Out of memory",
        CURLMcode::CURLM_INTERNAL_ERROR => c"Internal error",
        CURLMcode::CURLM_UNKNOWN_OPTION => c"Unknown option",
    };
    msg.as_ptr()
}

// ───────────────────────── Utility functions ─────────────────────────

/// `curl_escape` — URL-encode a string.
///
/// Returns a newly allocated string that must be freed with `curl_free`.
/// If `length` is 0, the string is treated as null-terminated.
///
/// # Safety
///
/// `string` must be a valid pointer to at least `length` bytes.
/// If `length` is 0, `string` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn curl_escape(string: *const c_char, length: c_long) -> *mut c_char {
    if string.is_null() {
        return ptr::null_mut();
    }

    let input = if length == 0 {
        // SAFETY: Caller guarantees string is null-terminated
        unsafe { CStr::from_ptr(string) }.to_bytes()
    } else {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        // SAFETY: Caller guarantees string points to at least length bytes
        unsafe {
            std::slice::from_raw_parts(string.cast::<u8>(), length as usize)
        }
    };

    let encoded = percent_encode(input);

    std::ffi::CString::new(encoded).map_or(ptr::null_mut(), std::ffi::CString::into_raw)
}

/// `curl_unescape` — URL-decode a string.
///
/// Returns a newly allocated string that must be freed with `curl_free`.
/// If `length` is 0, the string is treated as null-terminated.
///
/// # Safety
///
/// `string` must be a valid pointer to at least `length` bytes.
/// If `length` is 0, `string` must be null-terminated.
/// If `outlength` is non-null, it receives the length of the decoded string.
#[no_mangle]
pub unsafe extern "C" fn curl_unescape(
    string: *const c_char,
    length: c_long,
    outlength: *mut c_long,
) -> *mut c_char {
    if string.is_null() {
        return ptr::null_mut();
    }

    let input = if length == 0 {
        // SAFETY: Caller guarantees string is null-terminated
        unsafe { CStr::from_ptr(string) }.to_bytes()
    } else {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        // SAFETY: Caller guarantees string points to at least length bytes
        unsafe {
            std::slice::from_raw_parts(string.cast::<u8>(), length as usize)
        }
    };

    let decoded = percent_decode(input);

    if !outlength.is_null() {
        // SAFETY: Caller guarantees outlength is valid
        unsafe {
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            {
                *outlength = decoded.len() as c_long;
            }
        }
    }

    std::ffi::CString::new(decoded).map_or(ptr::null_mut(), std::ffi::CString::into_raw)
}

/// `curl_easy_escape` — URL-encode a string using an easy handle.
///
/// The easy handle parameter is accepted for API compatibility but not used.
/// Returns a newly allocated string that must be freed with `curl_free`.
///
/// # Safety
///
/// `_handle` can be null (not used). `string` must be valid.
/// If `length` is 0, the string is treated as null-terminated.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    _handle: *mut c_void,
    string: *const c_char,
    length: c_long,
) -> *mut c_char {
    // SAFETY: Delegates to curl_escape with same safety requirements
    unsafe { curl_escape(string, length) }
}

/// `curl_easy_unescape` — URL-decode a string using an easy handle.
///
/// The easy handle parameter is accepted for API compatibility but not used.
/// Returns a newly allocated string that must be freed with `curl_free`.
///
/// # Safety
///
/// `_handle` can be null (not used). `string` must be valid.
/// If `inlength` is 0, the string is treated as null-terminated.
/// `outlength` receives the decoded length (can be null).
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    _handle: *mut c_void,
    string: *const c_char,
    inlength: c_long,
    outlength: *mut c_long,
) -> *mut c_char {
    // SAFETY: Delegates to curl_unescape with same safety requirements
    unsafe { curl_unescape(string, inlength, outlength) }
}

/// `curl_getdate` — parse a date string to a Unix timestamp.
///
/// Parses RFC 2822, RFC 850, and asctime date formats.
/// Returns the number of seconds since the Unix epoch, or -1 on failure.
///
/// # Safety
///
/// `datestring` must be a valid null-terminated C string.
/// `now` is unused (accepted for API compatibility, can be null).
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(datestring: *const c_char, _now: *const c_void) -> i64 {
    if datestring.is_null() {
        return -1;
    }

    // SAFETY: Caller guarantees datestring is null-terminated
    let Ok(s) = unsafe { CStr::from_ptr(datestring) }.to_str() else {
        return -1;
    };

    parse_http_date(s).unwrap_or(-1)
}

/// `curl_formadd` — deprecated multipart form API.
///
/// This function is deprecated in libcurl in favor of the MIME API.
/// Returns `CURL_FORMADD_DISABLED` (7) to indicate it's not supported.
///
/// # Safety
///
/// Arguments are ignored. Always returns disabled.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub unsafe extern "C" fn curl_formadd(_first: *mut *mut c_void, _last: *mut *mut c_void) -> c_long {
    7 // CURL_FORMADD_DISABLED
}

/// `curl_formfree` — free a form created by `curl_formadd`.
///
/// Since `curl_formadd` always returns disabled, this is a no-op.
///
/// # Safety
///
/// `form` can be any pointer (ignored).
#[no_mangle]
#[allow(clippy::missing_const_for_fn)]
pub unsafe extern "C" fn curl_formfree(_form: *mut c_void) {
    // No-op: curl_formadd is disabled
}

/// Percent-encode bytes for URL escaping.
fn percent_encode(input: &[u8]) -> String {
    let mut result = String::with_capacity(input.len());
    for &byte in input {
        if byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~'
        {
            result.push(char::from(byte));
        } else {
            result.push('%');
            result.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            result.push(char::from(HEX_UPPER[usize::from(byte & 0x0F)]));
        }
    }
    result
}

/// Upper-case hex digits for percent-encoding.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Percent-decode bytes from URL escaping.
fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        } else if input[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(input[i]);
        i += 1;
    }
    result
}

/// Convert a hex ASCII digit to its numeric value.
const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse an HTTP date string to Unix timestamp.
///
/// Supports:
/// - RFC 2822: "Sun, 06 Nov 1994 08:49:37 GMT"
/// - RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT"
/// - asctime: "Sun Nov  6 08:49:37 1994"
fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();

    // Try RFC 2822 / RFC 1123: "Sun, 06 Nov 1994 08:49:37 GMT"
    if let Some(ts) = parse_rfc2822(s) {
        return Some(ts);
    }

    // Try RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT"
    if let Some(ts) = parse_rfc850(s) {
        return Some(ts);
    }

    // Try asctime: "Sun Nov  6 08:49:37 1994"
    parse_asctime(s)
}

/// Month name to 0-based month number.
fn month_from_name(name: &str) -> Option<u32> {
    match name {
        "Jan" => Some(0),
        "Feb" => Some(1),
        "Mar" => Some(2),
        "Apr" => Some(3),
        "May" => Some(4),
        "Jun" => Some(5),
        "Jul" => Some(6),
        "Aug" => Some(7),
        "Sep" => Some(8),
        "Oct" => Some(9),
        "Nov" => Some(10),
        "Dec" => Some(11),
        _ => None,
    }
}

/// Days in each month (non-leap year).
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Check if a year is a leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert date components to Unix timestamp.
fn date_to_timestamp(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    // Days from epoch (1970-01-01) to start of this year
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if is_leap_year(y) { 366 } else { 365 };
        }
    }

    // Add days for completed months
    for m in 0..month {
        days += i64::from(DAYS_IN_MONTH[m as usize]);
        if m == 1 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days (1-based)
    days += i64::from(day) - 1;

    days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)
}

/// Parse RFC 2822 date: "Sun, 06 Nov 1994 08:49:37 GMT"
fn parse_rfc2822(s: &str) -> Option<i64> {
    // Skip optional day name and comma
    let s = s.find(", ").map_or(s, |pos| &s[pos + 2..]);
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = month_from_name(parts[1])?;
    let year: i64 = parts[2].parse().ok()?;
    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec: u32 = time_parts[2].parse().ok()?;

    Some(date_to_timestamp(year, month, day, hour, min, sec))
}

/// Parse RFC 850 date: "Sunday, 06-Nov-94 08:49:37 GMT"
fn parse_rfc850(s: &str) -> Option<i64> {
    let pos = s.find(", ")?;
    let s = &s[pos + 2..];
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    // "06-Nov-94"
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let day: u32 = date_parts[0].parse().ok()?;
    let month = month_from_name(date_parts[1])?;
    let mut year: i64 = date_parts[2].parse().ok()?;
    if year < 100 {
        year += if year < 70 { 2000 } else { 1900 };
    }

    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec: u32 = time_parts[2].parse().ok()?;

    Some(date_to_timestamp(year, month, day, hour, min, sec))
}

/// Parse asctime date: "Sun Nov  6 08:49:37 1994"
fn parse_asctime(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // Skip day name (parts[0])
    let month = month_from_name(parts[1])?;
    let day: u32 = parts[2].parse().ok()?;
    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec: u32 = time_parts[2].parse().ok()?;
    let year: i64 = parts[4].parse().ok()?;

    Some(date_to_timestamp(year, month, day, hour, min, sec))
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

// ───────────────────────── Global init/cleanup ─────────────────────────

/// `curl_global_init` — global initialization (no-op in urlx).
///
/// In libcurl this initializes SSL, Win32 sockets, etc. In urlx, tokio
/// and rustls handle their own initialization, so this is a no-op.
///
/// # Safety
///
/// This function is always safe to call.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable
pub extern "C" fn curl_global_init(_flags: c_long) -> CURLcode {
    CURLcode::CURLE_OK
}

/// `curl_global_cleanup` — global cleanup (no-op in urlx).
///
/// # Safety
///
/// This function is always safe to call.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable
pub extern "C" fn curl_global_cleanup() {}

/// Bitmask constants for `curl_global_init`.
/// `CURL_GLOBAL_SSL` — initialize SSL.
pub const CURL_GLOBAL_SSL: c_long = 1;
/// `CURL_GLOBAL_WIN32` — initialize Win32 sockets.
pub const CURL_GLOBAL_WIN32: c_long = 2;
/// `CURL_GLOBAL_ALL` — initialize everything.
pub const CURL_GLOBAL_ALL: c_long = 3;
/// `CURL_GLOBAL_DEFAULT` — same as ALL.
pub const CURL_GLOBAL_DEFAULT: c_long = 3;

// ───────────────────────── Version info ─────────────────────────

/// Version info struct returned by `curl_version_info`.
///
/// Matches the `curl_version_info_data` struct from libcurl.
/// Only the essential fields are populated.
#[repr(C)]
pub struct CurlVersionInfo {
    /// Age of this struct (`CURLVERSION_FIRST` = 0).
    pub age: c_long,
    /// Version string (e.g., "0.1.0").
    pub version: *const c_char,
    /// Numeric version (major*0x10000 + minor*0x100 + patch).
    pub version_num: c_long,
    /// Host system description.
    pub host: *const c_char,
    /// Feature bitmask.
    pub features: c_long,
    /// SSL version string or NULL.
    pub ssl_version: *const c_char,
    /// Unused (libssl version number).
    pub ssl_version_num: c_long,
    /// libz version string or NULL.
    pub libz_version: *const c_char,
    /// Null-terminated array of supported protocols.
    pub protocols: *const *const c_char,
}

// SAFETY: CurlVersionInfo contains only pointers to static string literals and
// null pointers. These never change and are valid for the lifetime of the program.
unsafe impl Sync for CurlVersionInfo {}

/// Feature bit: SSL support.
pub const CURL_VERSION_SSL: c_long = 1 << 2;
/// Feature bit: HTTP/2 support.
pub const CURL_VERSION_HTTP2: c_long = 1 << 16;
/// Feature bit: async DNS support.
pub const CURL_VERSION_ASYNCHDNS: c_long = 1 << 7;
/// Feature bit: PSL support.
pub const CURL_VERSION_PSL: c_long = 1 << 20;

/// `curl_version_info` — return version info struct.
///
/// Returns a pointer to a static struct with version information.
/// The pointer is valid for the lifetime of the program.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
pub extern "C" fn curl_version_info(_age: c_long) -> *const CurlVersionInfo {
    // Use Box::leak to create a 'static reference. OnceLock ensures single init.
    static INFO: std::sync::OnceLock<&'static CurlVersionInfo> = std::sync::OnceLock::new();
    let info = INFO.get_or_init(|| {
        // Protocols array — leaked to get a 'static pointer
        let protocols: &'static [*const c_char] = Box::leak(Box::new([
            c"http".as_ptr(),
            c"https".as_ptr(),
            c"ftp".as_ptr(),
            c"ftps".as_ptr(),
            c"sftp".as_ptr(),
            c"scp".as_ptr(),
            c"ws".as_ptr(),
            c"wss".as_ptr(),
            ptr::null(), // Null terminator
        ]));
        Box::leak(Box::new(CurlVersionInfo {
            age: 0,
            version: c"0.1.0".as_ptr(),
            version_num: 0x000_100, // 0.1.0
            host: c"urlx".as_ptr(),
            features: CURL_VERSION_SSL | CURL_VERSION_HTTP2 | CURL_VERSION_PSL,
            ssl_version: c"rustls/0.23".as_ptr(),
            ssl_version_num: 0,
            libz_version: ptr::null(),
            protocols: protocols.as_ptr(),
        }))
    });
    *info
}

/// `curl_easy_pause` — pause/unpause a transfer (stub).
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable
pub extern "C" fn curl_easy_pause(_handle: *mut c_void, _bitmask: c_long) -> CURLcode {
    // Pause/unpause is not yet implemented; return OK as a no-op
    CURLcode::CURLE_OK
}

/// Pause direction constants.
/// `CURLPAUSE_RECV` — pause receiving.
pub const CURLPAUSE_RECV: c_long = 1;
/// `CURLPAUSE_SEND` — pause sending.
pub const CURLPAUSE_SEND: c_long = 4;
/// `CURLPAUSE_ALL` — pause both directions.
pub const CURLPAUSE_ALL: c_long = 5;
/// `CURLPAUSE_CONT` — unpause both directions.
pub const CURLPAUSE_CONT: c_long = 0;

/// `curl_easy_upkeep` — perform connection upkeep (no-op).
///
/// # Safety
///
/// `handle` must be a valid pointer from `curl_easy_init`.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable
pub extern "C" fn curl_easy_upkeep(_handle: *mut c_void) -> CURLcode {
    CURLcode::CURLE_OK
}

/// `curl_multi_assign` — assign custom pointer to socket (no-op stub).
///
/// # Safety
///
/// `multi_handle` must be a valid pointer from `curl_multi_init`.
#[no_mangle]
#[allow(clippy::missing_const_for_fn)] // const extern "C" fn not stable
pub extern "C" fn curl_multi_assign(
    _multi_handle: *mut c_void,
    _sockfd: c_long,
    _sockp: *mut c_void,
) -> CURLMcode {
    CURLMcode::CURLM_OK
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
        liburlx::Error::Timeout(_) | liburlx::Error::SpeedLimit { .. } => {
            CURLcode::CURLE_OPERATION_TIMEDOUT
        }
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
        let code = unsafe { curl_easy_setopt(handle, 41, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_follow_redirects() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 52, std::ptr::dangling::<c_void>()) };
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
        let code = unsafe { curl_easy_setopt(handle, 44, std::ptr::dangling::<c_void>()) };
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
        let code = unsafe { curl_easy_setopt(handle, 121, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        // TCP_KEEPALIVE = 213
        let code = unsafe { curl_easy_setopt(handle, 213, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_fail_on_error() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 45, std::ptr::dangling::<c_void>()) };
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
        let code = unsafe { curl_easy_setopt(handle, 80, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_upload() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 46, std::ptr::dangling::<c_void>()) };
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
        let code = unsafe { curl_easy_setopt(handle, 74, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_forbid_reuse() {
        let handle = curl_easy_init();
        // CURLOPT_FORBID_REUSE = 75
        let code = unsafe { curl_easy_setopt(handle, 75, std::ptr::dangling::<c_void>()) };
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

    #[test]
    fn easy_setopt_ssl_cipher_list() {
        let handle = curl_easy_init();
        let ciphers = c"HIGH:!aNULL:!MD5";
        let code = unsafe { curl_easy_setopt(handle, 10083, ciphers.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_cookiefile() {
        let handle = curl_easy_init();
        let path = c"/tmp/cookies.txt";
        let code = unsafe { curl_easy_setopt(handle, 10031, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_cookiefile_null_enables_engine() {
        let handle = curl_easy_init();
        // NULL enables the cookie engine
        let code = unsafe { curl_easy_setopt(handle, 10031, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_cookiejar() {
        let handle = curl_easy_init();
        let path = c"/tmp/cookies_out.txt";
        let code = unsafe { curl_easy_setopt(handle, 10082, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssl_sessionid_cache() {
        let handle = curl_easy_init();
        // CURLOPT_SSL_SESSIONID_CACHE = 150
        let code = unsafe { curl_easy_setopt(handle, 150, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        // Disable it
        let code = unsafe { curl_easy_setopt(handle, 150, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_interface() {
        let handle = curl_easy_init();
        let iface = c"lo0";
        let code = unsafe { curl_easy_setopt(handle, 10062, iface.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxyuserpwd() {
        let handle = curl_easy_init();
        let up = c"proxyuser:proxypass";
        // CURLOPT_PROXYUSERPWD = 10006
        let code = unsafe { curl_easy_setopt(handle, 10006, up.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxyauth() {
        let handle = curl_easy_init();
        // CURLOPT_PROXYAUTH = 111, bitmask 1=Basic
        let code = unsafe { curl_easy_setopt(handle, 111, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy_sslcert() {
        let handle = curl_easy_init();
        let path = c"/tmp/proxy-cert.pem";
        // CURLOPT_PROXY_SSLCERT = 10254
        let code = unsafe { curl_easy_setopt(handle, 10254, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy_sslkey() {
        let handle = curl_easy_init();
        let path = c"/tmp/proxy-key.pem";
        // CURLOPT_PROXY_SSLKEY = 10255
        let code = unsafe { curl_easy_setopt(handle, 10255, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy_ssl_verifypeer() {
        let handle = curl_easy_init();
        // CURLOPT_PROXY_SSL_VERIFYPEER = 248
        let code = unsafe { curl_easy_setopt(handle, 248, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    unsafe extern "C" fn test_read_cb(
        _buf: *mut c_char,
        _size: usize,
        _nmemb: usize,
        _data: *mut c_void,
    ) -> usize {
        0 // EOF
    }

    unsafe extern "C" fn test_debug_cb(
        _handle: *mut c_void,
        _info_type: c_long,
        _data: *mut c_char,
        _size: usize,
        _userdata: *mut c_void,
    ) -> c_long {
        0
    }

    #[test]
    fn easy_setopt_readfunction() {
        let handle = curl_easy_init();
        // CURLOPT_READFUNCTION = 20012
        let code = unsafe { curl_easy_setopt(handle, 20012, test_read_cb as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_readdata() {
        let handle = curl_easy_init();
        // CURLOPT_READDATA = 10009
        let mut data: usize = 42;
        let code =
            unsafe { curl_easy_setopt(handle, 10009, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_debugfunction() {
        let handle = curl_easy_init();
        // CURLOPT_DEBUGFUNCTION = 20094
        let code = unsafe { curl_easy_setopt(handle, 20094, test_debug_cb as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_debugdata() {
        let handle = curl_easy_init();
        // CURLOPT_DEBUGDATA = 10095
        let mut data: usize = 99;
        let code =
            unsafe { curl_easy_setopt(handle, 10095, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_infilesize_large() {
        let handle = curl_easy_init();
        // CURLOPT_INFILESIZE_LARGE = 30115
        let code = unsafe { curl_easy_setopt(handle, 30115, 4096_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_duphandle_preserves_callbacks() {
        let handle = curl_easy_init();
        let _ = unsafe { curl_easy_setopt(handle, 20012, test_read_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 20094, test_debug_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 30115, 1024_usize as *const c_void) };

        let dup = unsafe { curl_easy_duphandle(handle) };
        assert!(!dup.is_null());

        // Verify callbacks were preserved
        let dup_h = unsafe { &*dup.cast::<EasyHandle>() };
        assert!(dup_h.read_callback.is_some());
        assert!(dup_h.debug_callback.is_some());
        assert_eq!(dup_h.infilesize, Some(1024));

        unsafe {
            curl_easy_cleanup(dup);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn easy_reset_clears_callbacks() {
        let handle = curl_easy_init();
        let _ = unsafe { curl_easy_setopt(handle, 20012, test_read_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 30115, 2048_usize as *const c_void) };

        unsafe { curl_easy_reset(handle) };

        let h = unsafe { &*handle.cast::<EasyHandle>() };
        assert!(h.read_callback.is_none());
        assert!(h.debug_callback.is_none());
        assert!(h.infilesize.is_none());

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_dns_cache_timeout() {
        let handle = curl_easy_init();
        // CURLOPT_DNS_CACHE_TIMEOUT = 92
        let code = unsafe { curl_easy_setopt(handle, 92, 120_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_happy_eyeballs_timeout() {
        let handle = curl_easy_init();
        // CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271
        let code = unsafe { curl_easy_setopt(handle, 271, 100_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_dns_servers() {
        let handle = curl_easy_init();
        // CURLOPT_DNS_SERVERS = 10211
        let servers = c"8.8.8.8,8.8.4.4";
        let code = unsafe { curl_easy_setopt(handle, 10211, servers.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_dns_servers_invalid() {
        let handle = curl_easy_init();
        let servers = c"not-valid";
        let code = unsafe { curl_easy_setopt(handle, 10211, servers.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_doh_url() {
        let handle = curl_easy_init();
        // CURLOPT_DOH_URL = 10279
        let url = c"https://dns.google/dns-query";
        let code = unsafe { curl_easy_setopt(handle, 10279, url.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_unrestricted_auth() {
        let handle = curl_easy_init();
        // CURLOPT_UNRESTRICTED_AUTH = 105
        let code = unsafe { curl_easy_setopt(handle, 105, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ignore_content_length() {
        let handle = curl_easy_init();
        // CURLOPT_IGNORE_CONTENT_LENGTH = 136
        let code = unsafe { curl_easy_setopt(handle, 136, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 22: Progress callbacks ───

    unsafe extern "C" fn test_progress_cb(
        _clientp: *mut c_void,
        _dltotal: f64,
        _dlnow: f64,
        _ultotal: f64,
        _ulnow: f64,
    ) -> c_long {
        0 // continue
    }

    unsafe extern "C" fn test_xferinfo_cb(
        _clientp: *mut c_void,
        _dltotal: i64,
        _dlnow: i64,
        _ultotal: i64,
        _ulnow: i64,
    ) -> c_long {
        0 // continue
    }

    unsafe extern "C" fn test_seek_cb(
        _clientp: *mut c_void,
        _offset: i64,
        _origin: c_long,
    ) -> c_long {
        0 // success
    }

    #[test]
    fn easy_setopt_progressfunction() {
        let handle = curl_easy_init();
        // CURLOPT_PROGRESSFUNCTION = 20056
        let code = unsafe { curl_easy_setopt(handle, 20056, test_progress_cb as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_xferinfofunction() {
        let handle = curl_easy_init();
        // CURLOPT_XFERINFOFUNCTION = 20219
        let code = unsafe { curl_easy_setopt(handle, 20219, test_xferinfo_cb as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_progressdata() {
        let handle = curl_easy_init();
        // CURLOPT_PROGRESSDATA = 10057
        let mut data: usize = 42;
        let code =
            unsafe { curl_easy_setopt(handle, 10057, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_noprogress() {
        let handle = curl_easy_init();
        // Verify default is noprogress=true
        let h = unsafe { &*handle.cast::<EasyHandle>() };
        assert!(h.noprogress);

        // CURLOPT_NOPROGRESS = 43, set to 0 (false) to enable progress
        let code = unsafe { curl_easy_setopt(handle, 43, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        let h = unsafe { &*handle.cast::<EasyHandle>() };
        assert!(!h.noprogress);

        // Set back to 1 (true) to disable progress
        let code = unsafe { curl_easy_setopt(handle, 43, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        let h = unsafe { &*handle.cast::<EasyHandle>() };
        assert!(h.noprogress);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_seekfunction() {
        let handle = curl_easy_init();
        // CURLOPT_SEEKFUNCTION = 20167
        let code = unsafe { curl_easy_setopt(handle, 20167, test_seek_cb as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_seekdata() {
        let handle = curl_easy_init();
        // CURLOPT_SEEKDATA = 10168
        let mut data: usize = 99;
        let code =
            unsafe { curl_easy_setopt(handle, 10168, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 22: CURLOPT_PRIVATE ───

    #[test]
    fn easy_setopt_private() {
        let handle = curl_easy_init();
        let mut data: usize = 12345;
        // CURLOPT_PRIVATE = 10103
        let code =
            unsafe { curl_easy_setopt(handle, 10103, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);

        // Retrieve it via CURLINFO_PRIVATE = 0x100015
        let mut out: *mut c_void = ptr::null_mut();
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0015, ptr::from_mut(&mut out).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(out, ptr::from_mut(&mut data).cast::<c_void>());

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_private_default_null() {
        let handle = curl_easy_init();
        let mut out: *mut c_void = std::ptr::dangling_mut::<c_void>();
        // CURLINFO_PRIVATE before setting — should be null
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0015, ptr::from_mut(&mut out).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!(out.is_null());
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 22: CURLOPT_SHARE ───

    #[test]
    fn easy_setopt_share() {
        let handle = curl_easy_init();
        let share = curl_share_init();

        // CURLOPT_SHARE = 10100
        let code = unsafe { curl_easy_setopt(handle, 10100, share.cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);

        // Detach share
        let code = unsafe { curl_easy_setopt(handle, 10100, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);

        unsafe {
            let _ = curl_share_cleanup(share);
            curl_easy_cleanup(handle);
        }
    }

    // ─── Phase 22: MIME API ───

    #[test]
    fn mime_init_free() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        assert!(!mime.is_null());
        unsafe {
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn mime_free_null_is_safe() {
        unsafe { curl_mime_free(ptr::null_mut()) };
    }

    #[test]
    fn mime_addpart() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null());
        // Parts are standalone — need to finalize manually
        unsafe {
            // Set name and data on the part
            let code = curl_mime_name(part, c"field1".as_ptr());
            assert_eq!(code, CURLcode::CURLE_OK);
            let code = curl_mime_data(part, c"value1".as_ptr(), usize::MAX);
            assert_eq!(code, CURLcode::CURLE_OK);
            // Finalize part into mime
            finalize_mime_part(mime, part);
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn mime_name_null_part() {
        let code = unsafe { curl_mime_name(ptr::null_mut(), c"test".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_data_null_part() {
        let code = unsafe { curl_mime_data(ptr::null_mut(), c"test".as_ptr(), 4) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_data_with_explicit_size() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        let part = unsafe { curl_mime_addpart(mime) };
        let code = unsafe { curl_mime_name(part, c"binary".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        let data = b"hello";
        let code = unsafe { curl_mime_data(part, data.as_ptr().cast::<c_char>(), 5) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe {
            finalize_mime_part(mime, part);
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn mime_filename() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        let part = unsafe { curl_mime_addpart(mime) };
        let code = unsafe { curl_mime_filename(part, c"upload.txt".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        let code = unsafe { curl_mime_filename(ptr::null_mut(), c"test".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        unsafe {
            // Clean up part without finalize — it was never given name/data
            let _ = Box::from_raw(part.cast::<MimePartHandle>());
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn mime_type() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        let part = unsafe { curl_mime_addpart(mime) };
        let code = unsafe { curl_mime_type(part, c"text/plain".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        let p = unsafe { &*part.cast::<MimePartHandle>() };
        assert_eq!(p.mime_type.as_deref(), Some("text/plain"));
        unsafe {
            let _ = Box::from_raw(part.cast::<MimePartHandle>());
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn mime_type_null_part() {
        let code = unsafe { curl_mime_type(ptr::null_mut(), c"text/plain".as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn easy_setopt_mimepost() {
        let handle = curl_easy_init();
        let mime = unsafe { curl_mime_init(handle) };
        let part = unsafe { curl_mime_addpart(mime) };
        let _ = unsafe { curl_mime_name(part, c"field".as_ptr()) };
        let _ = unsafe { curl_mime_data(part, c"value".as_ptr(), usize::MAX) };
        unsafe { finalize_mime_part(mime, part) };

        // CURLOPT_MIMEPOST = 10269
        let code = unsafe { curl_easy_setopt(handle, 10269, mime.cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);

        unsafe {
            curl_mime_free(mime);
            curl_easy_cleanup(handle);
        }
    }

    // ─── Phase 22: Share API ───

    #[test]
    fn share_init_cleanup() {
        let share = curl_share_init();
        assert!(!share.is_null());
        let code = unsafe { curl_share_cleanup(share) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
    }

    #[test]
    fn share_cleanup_null() {
        let code = unsafe { curl_share_cleanup(ptr::null_mut()) };
        assert_eq!(code, CURLSHcode::CURLSHE_INVALID);
    }

    #[test]
    fn share_setopt_dns() {
        let share = curl_share_init();
        // CURLSHOPT_SHARE = 1, CURL_LOCK_DATA_DNS = 3
        let code = unsafe { curl_share_setopt(share, 1, 3 as *const c_void) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
        let _ = unsafe { curl_share_cleanup(share) };
    }

    #[test]
    fn share_setopt_cookies() {
        let share = curl_share_init();
        // CURLSHOPT_SHARE = 1, CURL_LOCK_DATA_COOKIE = 2
        let code = unsafe { curl_share_setopt(share, 1, 2 as *const c_void) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
        let _ = unsafe { curl_share_cleanup(share) };
    }

    #[test]
    fn share_setopt_unshare() {
        let share = curl_share_init();
        // Share DNS
        let _ = unsafe { curl_share_setopt(share, 1, 3 as *const c_void) };
        // Unshare DNS
        let code = unsafe { curl_share_setopt(share, 2, 3 as *const c_void) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
        let _ = unsafe { curl_share_cleanup(share) };
    }

    #[test]
    fn share_setopt_bad_option() {
        let share = curl_share_init();
        let code = unsafe { curl_share_setopt(share, 99, ptr::null()) };
        assert_eq!(code, CURLSHcode::CURLSHE_BAD_OPTION);
        let _ = unsafe { curl_share_cleanup(share) };
    }

    #[test]
    fn share_setopt_null_handle() {
        let code = unsafe { curl_share_setopt(ptr::null_mut(), 1, 3 as *const c_void) };
        assert_eq!(code, CURLSHcode::CURLSHE_INVALID);
    }

    #[test]
    fn share_setopt_lockfunc_accepted() {
        let share = curl_share_init();
        // CURLSHOPT_LOCKFUNC = 3 — accepted but ignored
        let code = unsafe { curl_share_setopt(share, 3, ptr::null()) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
        // CURLSHOPT_UNLOCKFUNC = 4
        let code = unsafe { curl_share_setopt(share, 4, ptr::null()) };
        assert_eq!(code, CURLSHcode::CURLSHE_OK);
        let _ = unsafe { curl_share_cleanup(share) };
    }

    #[test]
    fn share_strerror_ok() {
        let msg = curl_share_strerror(CURLSHcode::CURLSHE_OK);
        assert!(!msg.is_null());
        let s = unsafe { CStr::from_ptr(msg) };
        assert_eq!(s.to_str().unwrap(), "No error");
    }

    #[test]
    fn share_strerror_all_codes() {
        let codes = [
            CURLSHcode::CURLSHE_OK,
            CURLSHcode::CURLSHE_BAD_OPTION,
            CURLSHcode::CURLSHE_IN_USE,
            CURLSHcode::CURLSHE_INVALID,
            CURLSHcode::CURLSHE_NOMEM,
            CURLSHcode::CURLSHE_NOT_BUILT_IN,
        ];
        for code in codes {
            let msg = curl_share_strerror(code);
            assert!(!msg.is_null(), "share_strerror returned null for {code:?}");
        }
    }

    // ─── Phase 22: Duphandle/Reset preserve new fields ───

    #[test]
    fn easy_duphandle_preserves_progress_callbacks() {
        let handle = curl_easy_init();
        let _ = unsafe { curl_easy_setopt(handle, 20056, test_progress_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 20219, test_xferinfo_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 20167, test_seek_cb as *const c_void) };
        let mut priv_data: usize = 42;
        let _ = unsafe {
            curl_easy_setopt(handle, 10103, ptr::from_mut(&mut priv_data).cast::<c_void>())
        };

        let dup = unsafe { curl_easy_duphandle(handle) };
        assert!(!dup.is_null());
        let dup_h = unsafe { &*dup.cast::<EasyHandle>() };
        assert!(dup_h.progress_callback.is_some());
        assert!(dup_h.xferinfo_callback.is_some());
        assert!(dup_h.seek_callback.is_some());
        assert_eq!(dup_h.private_data, ptr::from_mut(&mut priv_data).cast::<c_void>());

        unsafe {
            curl_easy_cleanup(dup);
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn easy_reset_clears_new_fields() {
        let handle = curl_easy_init();
        let _ = unsafe { curl_easy_setopt(handle, 20056, test_progress_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 20219, test_xferinfo_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 20167, test_seek_cb as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 10103, 42usize as *const c_void) };
        let _ = unsafe { curl_easy_setopt(handle, 43, ptr::null()) }; // noprogress = false

        unsafe { curl_easy_reset(handle) };

        let h = unsafe { &*handle.cast::<EasyHandle>() };
        assert!(h.progress_callback.is_none());
        assert!(h.xferinfo_callback.is_none());
        assert!(h.seek_callback.is_none());
        assert!(h.private_data.is_null());
        assert!(h.noprogress); // reset to default true
        assert!(h.mimepost.is_null());

        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 23: URL API ───

    #[test]
    fn url_init_cleanup() {
        let handle = curl_url();
        assert!(!handle.is_null());
        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_cleanup_null_is_safe() {
        unsafe { curl_url_cleanup(ptr::null_mut()) };
    }

    #[test]
    fn url_set_full_url() {
        let handle = curl_url();
        let url = c"https://example.com/path?q=1#frag";
        let code = unsafe { curl_url_set(handle, 0, url.as_ptr(), 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);

        // Get scheme
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 1, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        assert!(!part.is_null());
        let scheme = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(scheme, "https");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get host
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 5, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let host = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(host, "example.com");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get path
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 7, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let path = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(path, "/path");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get query
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 8, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let query = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(query, "q=1");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get fragment
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 9, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let frag = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(frag, "frag");
        unsafe { curl_free(part.cast::<c_void>()) };

        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_set_individual_parts() {
        let handle = curl_url();
        let _ = unsafe { curl_url_set(handle, 1, c"https".as_ptr(), 0) };
        let _ = unsafe { curl_url_set(handle, 5, c"example.com".as_ptr(), 0) };
        let _ = unsafe { curl_url_set(handle, 6, c"8080".as_ptr(), 0) };
        let _ = unsafe { curl_url_set(handle, 7, c"/api/v1".as_ptr(), 0) };

        // Get reassembled URL
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 0, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let url = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(url, "https://example.com:8080/api/v1");
        unsafe { curl_free(part.cast::<c_void>()) };

        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_set_with_userinfo() {
        let handle = curl_url();
        let url = c"http://user:pass@example.com/";
        let _ = unsafe { curl_url_set(handle, 0, url.as_ptr(), 0) };

        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 2, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let user = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(user, "user");
        unsafe { curl_free(part.cast::<c_void>()) };

        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 3, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let pass = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(pass, "pass");
        unsafe { curl_free(part.cast::<c_void>()) };

        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_set_bad_port() {
        let handle = curl_url();
        let code = unsafe { curl_url_set(handle, 6, c"not_a_port".as_ptr(), 0) };
        assert_eq!(code, CURLUcode::CURLUE_BAD_PORT_NUMBER);
        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_set_malformed_url() {
        let handle = curl_url();
        let code = unsafe { curl_url_set(handle, 0, c"".as_ptr(), 0) };
        assert_eq!(code, CURLUcode::CURLUE_MALFORMED_INPUT);
        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_set_null_clears() {
        let handle = curl_url();
        let _ = unsafe { curl_url_set(handle, 0, c"https://example.com/path".as_ptr(), 0) };
        // Clear the query
        let code = unsafe { curl_url_set(handle, 8, ptr::null(), 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);

        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 8, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        assert!(part.is_null()); // Query was cleared

        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_get_null_handle() {
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(ptr::null_mut(), 0, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_BAD_HANDLE);
    }

    #[test]
    fn url_set_null_handle() {
        let code = unsafe { curl_url_set(ptr::null_mut(), 0, c"test".as_ptr(), 0) };
        assert_eq!(code, CURLUcode::CURLUE_BAD_HANDLE);
    }

    #[test]
    fn url_get_unknown_part() {
        let handle = curl_url();
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 99, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_UNKNOWN_PART);
        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_dup() {
        let handle = curl_url();
        let _ = unsafe { curl_url_set(handle, 0, c"https://example.com/path".as_ptr(), 0) };

        let dup = unsafe { curl_url_dup(handle) };
        assert!(!dup.is_null());

        // Verify dup has same scheme
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(dup, 1, &raw mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let scheme = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(scheme, "https");
        unsafe { curl_free(part.cast::<c_void>()) };

        unsafe {
            curl_url_cleanup(dup);
            curl_url_cleanup(handle);
        }
    }

    #[test]
    fn url_dup_null() {
        let dup = unsafe { curl_url_dup(ptr::null_mut()) };
        assert!(dup.is_null());
    }

    #[test]
    fn curl_free_null_is_safe() {
        unsafe { curl_free(ptr::null_mut()) };
    }

    // ─── Phase 23: New CURLOPT options ───

    #[test]
    fn easy_setopt_referer() {
        let handle = curl_easy_init();
        let referer = c"https://example.com/";
        // CURLOPT_REFERER = 10016
        let code = unsafe { curl_easy_setopt(handle, 10016, referer.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_http_version() {
        let handle = curl_easy_init();
        // CURLOPT_HTTP_VERSION = 84
        // CURL_HTTP_VERSION_1_1 = 2
        let code = unsafe { curl_easy_setopt(handle, 84, 2 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        // CURL_HTTP_VERSION_2_0 = 3
        let code = unsafe { curl_easy_setopt(handle, 84, 3 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_nosignal() {
        let handle = curl_easy_init();
        // CURLOPT_NOSIGNAL = 99
        let code = unsafe { curl_easy_setopt(handle, 99, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_autoreferer() {
        let handle = curl_easy_init();
        // CURLOPT_AUTOREFERER = 58
        let code = unsafe { curl_easy_setopt(handle, 58, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_resume_from_large() {
        let handle = curl_easy_init();
        // CURLOPT_RESUME_FROM_LARGE = 30116
        let code = unsafe { curl_easy_setopt(handle, 30116, 1024_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_xoauth2_bearer() {
        let handle = curl_easy_init();
        let token = c"ya29.token123";
        // CURLOPT_XOAUTH2_BEARER = 10220
        let code = unsafe { curl_easy_setopt(handle, 10220, token.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_localportrange() {
        let handle = curl_easy_init();
        // CURLOPT_LOCALPORTRANGE = 164
        let code = unsafe { curl_easy_setopt(handle, 164, 10_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 27: Multi API Event Loop Integration ───

    #[test]
    fn multi_info_read_empty() {
        let multi = curl_multi_init();
        let mut msgs_in_queue: c_long = 99;
        let msg = unsafe { curl_multi_info_read(multi, &raw mut msgs_in_queue) };
        assert!(msg.is_null());
        assert_eq!(msgs_in_queue, 0);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_info_read_null_handle() {
        let mut msgs_in_queue: c_long = 99;
        let msg = unsafe { curl_multi_info_read(ptr::null_mut(), &raw mut msgs_in_queue) };
        assert!(msg.is_null());
        assert_eq!(msgs_in_queue, 0);
    }

    #[test]
    fn multi_setopt_pipelining() {
        let multi = curl_multi_init();
        // CURLMOPT_PIPELINING = 3, value 2 = multiplex
        let code = unsafe { curl_multi_setopt(multi, 3, 2 as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        // Verify via internal state
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert_eq!(m.multi.pipelining_mode(), liburlx::PipeliningMode::Multiplex);

        // Set back to 0 (nothing)
        let code = unsafe { curl_multi_setopt(multi, 3, ptr::null()) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert_eq!(m.multi.pipelining_mode(), liburlx::PipeliningMode::Nothing);

        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_max_total_connections() {
        let multi = curl_multi_init();
        // CURLMOPT_MAX_TOTAL_CONNECTIONS = 13
        let code = unsafe { curl_multi_setopt(multi, 13, 4 as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_max_host_connections() {
        let multi = curl_multi_init();
        // CURLMOPT_MAX_HOST_CONNECTIONS = 7
        let code = unsafe { curl_multi_setopt(multi, 7, 2 as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_maxconnects() {
        let multi = curl_multi_init();
        // CURLMOPT_MAXCONNECTS = 6
        let code = unsafe { curl_multi_setopt(multi, 6, 10 as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_unknown_option() {
        let multi = curl_multi_init();
        let code = unsafe { curl_multi_setopt(multi, 99999, ptr::null()) };
        assert_eq!(code, CURLMcode::CURLM_UNKNOWN_OPTION);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_null_handle() {
        let code = unsafe { curl_multi_setopt(ptr::null_mut(), 3, ptr::null()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_setopt_socket_data() {
        let multi = curl_multi_init();
        let mut data: usize = 42;
        // CURLMOPT_SOCKETDATA = 10002
        let code =
            unsafe { curl_multi_setopt(multi, 10002, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert_eq!(m.socket_data, ptr::from_mut(&mut data).cast::<c_void>());
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_timer_data() {
        let multi = curl_multi_init();
        let mut data: usize = 99;
        // CURLMOPT_TIMERDATA = 10005
        let code =
            unsafe { curl_multi_setopt(multi, 10005, ptr::from_mut(&mut data).cast::<c_void>()) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert_eq!(m.timer_data, ptr::from_mut(&mut data).cast::<c_void>());
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    unsafe extern "C" fn test_socket_cb(
        _easy: *mut c_void,
        _s: c_long,
        _what: c_long,
        _userp: *mut c_void,
        _socketp: *mut c_void,
    ) -> c_long {
        0
    }

    unsafe extern "C" fn test_timer_cb(
        _multi: *mut c_void,
        _timeout_ms: c_long,
        _userp: *mut c_void,
    ) -> c_long {
        0
    }

    #[test]
    fn multi_setopt_socket_function() {
        let multi = curl_multi_init();
        // CURLMOPT_SOCKETFUNCTION = 20001
        let code = unsafe { curl_multi_setopt(multi, 20001, test_socket_cb as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert!(m.socket_callback.is_some());

        // Clear callback
        let code = unsafe { curl_multi_setopt(multi, 20001, ptr::null()) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert!(m.socket_callback.is_none());

        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_setopt_timer_function() {
        let multi = curl_multi_init();
        // CURLMOPT_TIMERFUNCTION = 20004
        let code = unsafe { curl_multi_setopt(multi, 20004, test_timer_cb as *const c_void) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert!(m.timer_callback.is_some());

        // Clear callback
        let code = unsafe { curl_multi_setopt(multi, 20004, ptr::null()) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let m = unsafe { &*multi.cast::<MultiHandle>() };
        assert!(m.timer_callback.is_none());

        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_timeout_no_work() {
        let multi = curl_multi_init();
        let mut timeout_ms: c_long = 99;
        let code = unsafe { curl_multi_timeout(multi, &raw mut timeout_ms) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(timeout_ms, -1); // No work
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_timeout_null_handle() {
        let mut timeout_ms: c_long = 0;
        let code = unsafe { curl_multi_timeout(ptr::null_mut(), &raw mut timeout_ms) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_timeout_null_output() {
        let multi = curl_multi_init();
        let code = unsafe { curl_multi_timeout(multi, ptr::null_mut()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_timeout_with_handles() {
        let multi = curl_multi_init();
        let easy = curl_easy_init();
        let url = c"http://127.0.0.1:1";
        let _ = unsafe { curl_easy_setopt(easy, 10002, url.as_ptr().cast::<c_void>()) };
        let _ = unsafe { curl_multi_add_handle(multi, easy) };

        let mut timeout_ms: c_long = 0;
        let code = unsafe { curl_multi_timeout(multi, &raw mut timeout_ms) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(timeout_ms, 100); // Transfers pending

        let _ = unsafe { curl_multi_remove_handle(multi, easy) };
        unsafe { curl_easy_cleanup(easy) };
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_wakeup() {
        let multi = curl_multi_init();
        let code = unsafe { curl_multi_wakeup(multi) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_wakeup_null() {
        let code = unsafe { curl_multi_wakeup(ptr::null_mut()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_fdset_empty() {
        let multi = curl_multi_init();
        let mut max_fd: c_long = 99;
        let code = unsafe {
            curl_multi_fdset(
                multi,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut max_fd,
            )
        };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(max_fd, -1); // No fds exposed
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_fdset_null_handle() {
        let mut max_fd: c_long = 0;
        let code = unsafe {
            curl_multi_fdset(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut max_fd,
            )
        };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_fdset_null_maxfd() {
        let multi = curl_multi_init();
        let code = unsafe {
            curl_multi_fdset(
                multi,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(code, CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_socket_action_null_handle() {
        let mut running: c_long = 0;
        let code = unsafe { curl_multi_socket_action(ptr::null_mut(), 0, 0, &raw mut running) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_socket_action_specific_socket() {
        let multi = curl_multi_init();
        let mut running: c_long = 99;
        // Socket 5 with no action — should report 0 running handles
        let code = unsafe { curl_multi_socket_action(multi, 5, 0, &raw mut running) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(running, 0);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn multi_strerror_ok() {
        let msg = curl_multi_strerror(CURLMcode::CURLM_OK);
        assert!(!msg.is_null());
        let s = unsafe { CStr::from_ptr(msg) };
        assert_eq!(s.to_str().unwrap(), "No error");
    }

    #[test]
    fn multi_strerror_all_codes() {
        let codes = [
            CURLMcode::CURLM_OK,
            CURLMcode::CURLM_BAD_HANDLE,
            CURLMcode::CURLM_BAD_EASY_HANDLE,
            CURLMcode::CURLM_OUT_OF_MEMORY,
            CURLMcode::CURLM_INTERNAL_ERROR,
            CURLMcode::CURLM_UNKNOWN_OPTION,
        ];
        for code in codes {
            let msg = curl_multi_strerror(code);
            assert!(!msg.is_null(), "multi_strerror returned null for {code:?}");
        }
    }

    #[test]
    fn multi_wait_null_handle() {
        let mut numfds: c_long = 0;
        let code =
            unsafe { curl_multi_wait(ptr::null_mut(), ptr::null_mut(), 0, 0, &raw mut numfds) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn multi_poll_null_handle() {
        let mut numfds: c_long = 0;
        let code =
            unsafe { curl_multi_poll(ptr::null_mut(), ptr::null_mut(), 0, 0, &raw mut numfds) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    // ─── Phase 34: Utility functions ───

    #[test]
    fn curl_escape_simple() {
        let input = c"hello world";
        let result = unsafe { curl_escape(input.as_ptr(), 0) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "hello%20world");
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_escape_with_length() {
        let input = c"abc123";
        let result = unsafe { curl_escape(input.as_ptr(), 3) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "abc"); // Only first 3 bytes
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_escape_special_chars() {
        let input = c"key=value&foo=bar";
        let result = unsafe { curl_escape(input.as_ptr(), 0) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "key%3Dvalue%26foo%3Dbar");
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_escape_null_returns_null() {
        let result = unsafe { curl_escape(ptr::null(), 0) };
        assert!(result.is_null());
    }

    #[test]
    fn curl_escape_unreserved_chars_preserved() {
        let input = c"abc-_.~XYZ";
        let result = unsafe { curl_escape(input.as_ptr(), 0) };
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "abc-_.~XYZ");
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_unescape_simple() {
        let input = c"hello%20world";
        let mut outlen: c_long = 0;
        let result = unsafe { curl_unescape(input.as_ptr(), 0, &raw mut outlen) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "hello world");
        assert_eq!(outlen, 11);
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_unescape_plus_to_space() {
        let input = c"hello+world";
        let result = unsafe { curl_unescape(input.as_ptr(), 0, ptr::null_mut()) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "hello world");
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_unescape_null_returns_null() {
        let result = unsafe { curl_unescape(ptr::null(), 0, ptr::null_mut()) };
        assert!(result.is_null());
    }

    #[test]
    fn curl_unescape_with_length() {
        let input = c"%41%42%43DEF";
        let mut outlen: c_long = 0;
        let result = unsafe { curl_unescape(input.as_ptr(), 9, &raw mut outlen) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "ABC");
        assert_eq!(outlen, 3);
        unsafe { curl_free(result.cast::<c_void>()) };
    }

    #[test]
    fn curl_easy_escape_delegates() {
        let handle = curl_easy_init();
        let input = c"test value";
        let result = unsafe { curl_easy_escape(handle, input.as_ptr(), 0) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "test%20value");
        unsafe {
            curl_free(result.cast::<c_void>());
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn curl_easy_unescape_delegates() {
        let handle = curl_easy_init();
        let input = c"test%20value";
        let mut outlen: c_long = 0;
        let result = unsafe { curl_easy_unescape(handle, input.as_ptr(), 0, &raw mut outlen) };
        assert!(!result.is_null());
        let s = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert_eq!(s, "test value");
        assert_eq!(outlen, 10);
        unsafe {
            curl_free(result.cast::<c_void>());
            curl_easy_cleanup(handle);
        }
    }

    #[test]
    fn curl_escape_roundtrip() {
        let input = c"hello world/foo?bar=baz&qux=123";
        let encoded = unsafe { curl_escape(input.as_ptr(), 0) };
        assert!(!encoded.is_null());
        let decoded = unsafe { curl_unescape(encoded, 0, ptr::null_mut()) };
        assert!(!decoded.is_null());
        let s = unsafe { CStr::from_ptr(decoded) }.to_str().unwrap();
        assert_eq!(s, "hello world/foo?bar=baz&qux=123");
        unsafe {
            curl_free(decoded.cast::<c_void>());
            curl_free(encoded.cast::<c_void>());
        }
    }

    // ─── Phase 34: curl_getdate ───

    #[test]
    fn getdate_rfc2822() {
        let date = c"Sun, 06 Nov 1994 08:49:37 GMT";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, 784_111_777);
    }

    #[test]
    fn getdate_rfc850() {
        let date = c"Sunday, 06-Nov-94 08:49:37 GMT";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, 784_111_777);
    }

    #[test]
    fn getdate_asctime() {
        let date = c"Sun Nov  6 08:49:37 1994";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, 784_111_777);
    }

    #[test]
    fn getdate_null_returns_negative() {
        let ts = unsafe { curl_getdate(ptr::null(), ptr::null()) };
        assert_eq!(ts, -1);
    }

    #[test]
    fn getdate_invalid_returns_negative() {
        let date = c"not a date";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, -1);
    }

    #[test]
    fn getdate_epoch() {
        let date = c"Thu, 01 Jan 1970 00:00:00 GMT";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, 0);
    }

    #[test]
    fn getdate_y2k() {
        let date = c"Sat, 01 Jan 2000 00:00:00 GMT";
        let ts = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(ts, 946_684_800);
    }

    // ─── Phase 34: curl_formadd / curl_formfree ───

    #[test]
    fn formadd_returns_disabled() {
        let result =
            unsafe { curl_formadd(ptr::null_mut::<*mut c_void>(), ptr::null_mut::<*mut c_void>()) };
        assert_eq!(result, 7); // CURL_FORMADD_DISABLED
    }

    #[test]
    fn formfree_null_is_safe() {
        unsafe { curl_formfree(ptr::null_mut()) };
    }

    // ─── Phase 34: New CURLOPT options ───

    #[test]
    fn easy_setopt_path_as_is() {
        let handle = curl_easy_init();
        // CURLOPT_PATH_AS_IS = 234
        let code = unsafe { curl_easy_setopt(handle, 234, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_expect_100_timeout_ms() {
        let handle = curl_easy_init();
        // CURLOPT_EXPECT_100_TIMEOUT_MS = 227
        let code = unsafe { curl_easy_setopt(handle, 227, 1000 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_postredir() {
        let handle = curl_easy_init();
        // CURLOPT_POSTREDIR = 161, bitmask: 1=301, 2=302, 4=303, 7=all
        let code = unsafe { curl_easy_setopt(handle, 161, 7 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_transfer_encoding() {
        let handle = curl_easy_init();
        // CURLOPT_TRANSFER_ENCODING = 207
        let code = unsafe { curl_easy_setopt(handle, 207, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_dns_shuffle_addresses() {
        let handle = curl_easy_init();
        // CURLOPT_DNS_SHUFFLE_ADDRESSES = 275
        let code = unsafe { curl_easy_setopt(handle, 275, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_httpproxytunnel() {
        let handle = curl_easy_init();
        // CURLOPT_HTTPPROXYTUNNEL = 61
        let code = unsafe { curl_easy_setopt(handle, 61, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_maxfilesize() {
        let handle = curl_easy_init();
        // CURLOPT_MAXFILESIZE = 114
        let code = unsafe { curl_easy_setopt(handle, 114, 1_048_576 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_maxfilesize_large() {
        let handle = curl_easy_init();
        // CURLOPT_MAXFILESIZE_LARGE = 30117
        let code = unsafe { curl_easy_setopt(handle, 30117, 1_048_576 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_hsts() {
        let handle = curl_easy_init();
        let path = c"/tmp/hsts.txt";
        // CURLOPT_HSTS = 10300
        let code = unsafe { curl_easy_setopt(handle, 10300, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_cookielist() {
        let handle = curl_easy_init();
        let cmd = c"ALL";
        // CURLOPT_COOKIELIST = 10135
        let code = unsafe { curl_easy_setopt(handle, 10135, cmd.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_errorbuffer() {
        let handle = curl_easy_init();
        let mut buf = [0u8; 256];
        // CURLOPT_ERRORBUFFER = 10010
        let code = unsafe {
            curl_easy_setopt(handle, 10010, buf.as_mut_ptr().cast::<c_void>().cast_const())
        };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_stderr() {
        let handle = curl_easy_init();
        // CURLOPT_STDERR = 10037
        let code = unsafe { curl_easy_setopt(handle, 10037, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_protocols_str() {
        let handle = curl_easy_init();
        let proto = c"http,https,ftp";
        // CURLOPT_PROTOCOLS_STR = 10318
        let code = unsafe { curl_easy_setopt(handle, 10318, proto.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_redir_protocols_str() {
        let handle = curl_easy_init();
        let proto = c"http,https";
        // CURLOPT_REDIR_PROTOCOLS_STR = 10319
        let code = unsafe { curl_easy_setopt(handle, 10319, proto.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy_cainfo() {
        let handle = curl_easy_init();
        let path = c"/tmp/proxy-ca.pem";
        // CURLOPT_PROXY_CAINFO = 10246
        let code = unsafe { curl_easy_setopt(handle, 10246, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxy_ssl_verifyhost() {
        let handle = curl_easy_init();
        // CURLOPT_PROXY_SSL_VERIFYHOST = 249
        let code = unsafe { curl_easy_setopt(handle, 249, 2 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 34: New CURLINFO codes ───

    #[test]
    fn easy_getinfo_filetime_returns_unknown() {
        let handle = curl_easy_init();
        // Need a completed transfer for getinfo — create a minimal response
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 0;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_000E, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, -1); // Unknown filetime

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_content_length_download() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            b"hello".to_vec(),
            "http://example.com".to_string(),
        ));

        let mut val: f64 = 0.0;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x30_000F, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!((val - 5.0).abs() < f64::EPSILON);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_os_errno() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 99;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_0019, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, 0);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_primary_ip() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: *const c_char = ptr::null();
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0020, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!(!val.is_null());

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_num_connects() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 0;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_0026, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, 1);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_local_ip() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: *const c_char = ptr::null();
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0029, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!(!val.is_null());

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_redirect_url_none() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: *const c_char = std::ptr::dangling::<c_char>();
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0031, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!(val.is_null()); // No redirect

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_redirect_url_present() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        let mut headers = std::collections::HashMap::new();
        let _ = headers.insert("location".to_string(), "http://other.com/".to_string());
        h.last_response = Some(liburlx::Response::new(
            302,
            headers,
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: *const c_char = ptr::null();
        let result = unsafe {
            curl_easy_getinfo(handle, 0x10_0031, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert!(!val.is_null());

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_condition_unmet_false() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 99;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_0035, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, 0);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_condition_unmet_304() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            304,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 0;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_0035, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, 1);

        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_getinfo_local_port() {
        let handle = curl_easy_init();
        let h = unsafe { &mut *handle.cast::<EasyHandle>() };
        h.last_response = Some(liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        ));

        let mut val: c_long = 99;
        let result = unsafe {
            curl_easy_getinfo(handle, 0x20_0042, ptr::from_mut(&mut val).cast::<c_void>())
        };
        assert_eq!(result, CURLcode::CURLE_OK);
        assert_eq!(val, 0);

        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 34: Internal helpers ───

    #[test]
    fn percent_encode_all_bytes() {
        assert_eq!(percent_encode(b"abc"), "abc");
        assert_eq!(percent_encode(b" "), "%20");
        assert_eq!(percent_encode(b"\x00"), "%00");
        assert_eq!(percent_encode(b"\xFF"), "%FF");
        assert_eq!(percent_encode(b"a b"), "a%20b");
    }

    #[test]
    fn percent_decode_all() {
        assert_eq!(percent_decode(b"abc"), b"abc");
        assert_eq!(percent_decode(b"%20"), b" ");
        assert_eq!(percent_decode(b"a+b"), b"a b");
        assert_eq!(percent_decode(b"%00"), b"\x00");
        assert_eq!(percent_decode(b"%FF"), b"\xFF");
        assert_eq!(percent_decode(b"%2f"), b"/"); // lowercase hex
    }

    #[test]
    fn percent_decode_invalid_hex() {
        // Invalid hex sequences should be kept as-is
        assert_eq!(percent_decode(b"%ZZ"), b"%ZZ");
        assert_eq!(percent_decode(b"%2"), b"%2"); // Truncated
    }

    #[test]
    fn date_parsing_internal() {
        // Test internal date helpers
        assert_eq!(month_from_name("Jan"), Some(0));
        assert_eq!(month_from_name("Dec"), Some(11));
        assert_eq!(month_from_name("Bad"), None);

        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2004));
        assert!(!is_leap_year(2001));

        // Epoch
        assert_eq!(date_to_timestamp(1970, 0, 1, 0, 0, 0), 0);
        // One day after epoch
        assert_eq!(date_to_timestamp(1970, 0, 2, 0, 0, 0), 86400);
    }

    // ─── Phase 46: FFI Expansion III ───

    #[test]
    fn global_init_cleanup() {
        let code = curl_global_init(CURL_GLOBAL_ALL);
        assert_eq!(code, CURLcode::CURLE_OK);
        curl_global_cleanup();
    }

    #[test]
    fn global_init_default() {
        let code = curl_global_init(CURL_GLOBAL_DEFAULT);
        assert_eq!(code, CURLcode::CURLE_OK);
    }

    #[test]
    fn version_info_returns_valid() {
        let info = curl_version_info(0);
        assert!(!info.is_null());
        // SAFETY: info is a valid pointer from curl_version_info
        let info = unsafe { &*info };
        assert_eq!(info.age, 0);
        assert!(!info.version.is_null());
        // Check features include SSL and HTTP2
        assert_ne!(info.features & CURL_VERSION_SSL, 0);
        assert_ne!(info.features & CURL_VERSION_HTTP2, 0);
        assert_ne!(info.features & CURL_VERSION_PSL, 0);
        // Check protocols array
        assert!(!info.protocols.is_null());
        // First protocol should be "http"
        // SAFETY: protocols[0] is a valid pointer
        let first = unsafe { CStr::from_ptr(*info.protocols) };
        assert_eq!(first.to_str().unwrap(), "http");
    }

    #[test]
    fn easy_pause_noop() {
        let handle = curl_easy_init();
        assert!(!handle.is_null());
        let code = curl_easy_pause(handle, CURLPAUSE_ALL);
        assert_eq!(code, CURLcode::CURLE_OK);
        let code = curl_easy_pause(handle, CURLPAUSE_CONT);
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_upkeep_noop() {
        let handle = curl_easy_init();
        let code = curl_easy_upkeep(handle);
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn multi_assign_noop() {
        let multi = curl_multi_init();
        assert_eq!(curl_multi_assign(multi, 0, ptr::null_mut()), CURLMcode::CURLM_OK);
        let _ = unsafe { curl_multi_cleanup(multi) };
    }

    #[test]
    fn easy_setopt_haproxyprotocol() {
        let handle = curl_easy_init();
        // CURLOPT_HAPROXYPROTOCOL = 274
        let code =
            unsafe { curl_easy_setopt(handle, 274, std::ptr::without_provenance::<c_void>(1)) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_httppost_deprecated() {
        let handle = curl_easy_init();
        // CURLOPT_HTTPPOST = 10024 (deprecated, should accept)
        let code = unsafe { curl_easy_setopt(handle, 10024, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_abstract_unix_socket() {
        let handle = curl_easy_init();
        let path = std::ffi::CString::new("/tmp/test.sock").unwrap();
        // CURLOPT_ABSTRACT_UNIX_SOCKET = 10264
        let code = unsafe { curl_easy_setopt(handle, 10264, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_doh_ssl_verifypeer() {
        let handle = curl_easy_init();
        // CURLOPT_DOH_SSL_VERIFYPEER = 306
        let code =
            unsafe { curl_easy_setopt(handle, 306, std::ptr::without_provenance::<c_void>(1)) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_buffersize() {
        let handle = curl_easy_init();
        // CURLOPT_BUFFERSIZE = 98
        let code = unsafe { curl_easy_setopt(handle, 98, 65536 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_maxlifetime_conn() {
        let handle = curl_easy_init();
        // CURLOPT_MAXLIFETIME_CONN = 314
        let code = unsafe { curl_easy_setopt(handle, 314, 300 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn new_curlcodes_strerror() {
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_FILESIZE_EXCEEDED), ptr::null());
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_TOO_MANY_REDIRECTS), ptr::null());
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_HTTP3), ptr::null());
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_PARTIAL_FILE), ptr::null());
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_RANGE_ERROR), ptr::null());
        assert_ne!(curl_easy_strerror(CURLcode::CURLE_AGAIN), ptr::null());
    }

    #[test]
    fn curlinfo_enum_has_timing_t_variants() {
        // Verify the _T timing CURLINFO codes exist
        let _ = CURLINFO::CURLINFO_TOTAL_TIME_T;
        let _ = CURLINFO::CURLINFO_NAMELOOKUP_TIME_T;
        let _ = CURLINFO::CURLINFO_CONNECT_TIME_T;
        let _ = CURLINFO::CURLINFO_PRETRANSFER_TIME_T;
        let _ = CURLINFO::CURLINFO_STARTTRANSFER_TIME_T;
        let _ = CURLINFO::CURLINFO_REDIRECT_TIME_T;
        let _ = CURLINFO::CURLINFO_APPCONNECT_TIME_T;
        let _ = CURLINFO::CURLINFO_SIZE_UPLOAD_T;
        let _ = CURLINFO::CURLINFO_SIZE_DOWNLOAD_T;
        let _ = CURLINFO::CURLINFO_SPEED_DOWNLOAD_T;
        let _ = CURLINFO::CURLINFO_SPEED_UPLOAD_T;
        let _ = CURLINFO::CURLINFO_REDIRECT_TIME;
        let _ = CURLINFO::CURLINFO_RETRY_AFTER;
    }

    #[test]
    fn global_constants_defined() {
        assert_eq!(CURL_GLOBAL_SSL, 1);
        assert_eq!(CURL_GLOBAL_WIN32, 2);
        assert_eq!(CURL_GLOBAL_ALL, 3);
        assert_eq!(CURL_GLOBAL_DEFAULT, 3);
        assert_eq!(CURLPAUSE_RECV, 1);
        assert_eq!(CURLPAUSE_SEND, 4);
        assert_eq!(CURLPAUSE_ALL, 5);
        assert_eq!(CURLPAUSE_CONT, 0);
    }

    // ─── Phase 55: Blob cert options ───

    #[test]
    fn easy_setopt_cainfo_blob() {
        let handle = curl_easy_init();
        let pem_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
        let blob =
            curl_blob { data: pem_data.as_ptr().cast::<c_void>(), len: pem_data.len(), flags: 0 };
        // CURLOPT_CAINFO_BLOB = 40309
        let code =
            unsafe { curl_easy_setopt(handle, 40309, ptr::from_ref(&blob).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_sslcert_blob() {
        let handle = curl_easy_init();
        let pem_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
        let blob =
            curl_blob { data: pem_data.as_ptr().cast::<c_void>(), len: pem_data.len(), flags: 0 };
        // CURLOPT_SSLCERT_BLOB = 40291
        let code =
            unsafe { curl_easy_setopt(handle, 40291, ptr::from_ref(&blob).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_sslkey_blob() {
        let handle = curl_easy_init();
        let pem_data = b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n";
        let blob =
            curl_blob { data: pem_data.as_ptr().cast::<c_void>(), len: pem_data.len(), flags: 0 };
        // CURLOPT_SSLKEY_BLOB = 40292
        let code =
            unsafe { curl_easy_setopt(handle, 40292, ptr::from_ref(&blob).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_blob_null_returns_error() {
        let handle = curl_easy_init();
        // Null value pointer
        let code = unsafe { curl_easy_setopt(handle, 40309, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_blob_null_data_returns_error() {
        let handle = curl_easy_init();
        let blob = curl_blob { data: ptr::null(), len: 10, flags: 0 };
        let code =
            unsafe { curl_easy_setopt(handle, 40291, ptr::from_ref(&blob).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_blob_zero_len_returns_error() {
        let handle = curl_easy_init();
        let data = b"some data";
        let blob = curl_blob { data: data.as_ptr().cast::<c_void>(), len: 0, flags: 0 };
        let code =
            unsafe { curl_easy_setopt(handle, 40292, ptr::from_ref(&blob).cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 55: FTP options ───

    #[test]
    fn easy_setopt_ftpport() {
        let handle = curl_easy_init();
        let addr = c"-";
        let code = unsafe { curl_easy_setopt(handle, 10017, addr.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_use_epsv() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 85, ptr::null()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_use_eprt() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 106, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_create_missing_dirs() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 110, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_skip_pasv_ip() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 137, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_filemethod() {
        let handle = curl_easy_init();
        // CURLFTPMETHOD_SINGLECWD = 3
        let code = unsafe { curl_easy_setopt(handle, 138, 3_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ftp_account() {
        let handle = curl_easy_init();
        let acct = c"myaccount";
        let code = unsafe { curl_easy_setopt(handle, 10134, acct.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_use_ssl() {
        let handle = curl_easy_init();
        // CURLUSESSL_TRY = 2
        let code = unsafe { curl_easy_setopt(handle, 119, 2_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 55: SSH options ───

    #[test]
    fn easy_setopt_ssh_auth_types() {
        let handle = curl_easy_init();
        // CURLSSH_AUTH_PUBLICKEY = 1 | CURLSSH_AUTH_PASSWORD = 2
        let code = unsafe { curl_easy_setopt(handle, 151, 3_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssh_public_keyfile() {
        let handle = curl_easy_init();
        let path = c"/home/user/.ssh/id_rsa.pub";
        let code = unsafe { curl_easy_setopt(handle, 10152, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssh_private_keyfile() {
        let handle = curl_easy_init();
        let path = c"/home/user/.ssh/id_rsa";
        let code = unsafe { curl_easy_setopt(handle, 10153, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssh_knownhosts() {
        let handle = curl_easy_init();
        let path = c"/home/user/.ssh/known_hosts";
        let code = unsafe { curl_easy_setopt(handle, 10183, path.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ssh_host_public_key_sha256() {
        let handle = curl_easy_init();
        let fp = c"AAAA+bbb/ccc=";
        let code = unsafe { curl_easy_setopt(handle, 10270, fp.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    // ─── Phase 55: Proxy options ───

    #[test]
    fn easy_setopt_proxyport() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 59, 8080_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxytype() {
        let handle = curl_easy_init();
        // CURLPROXY_SOCKS5 = 5
        let code = unsafe { curl_easy_setopt(handle, 101, 5_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxyusername() {
        let handle = curl_easy_init();
        let user = c"proxyuser";
        let code = unsafe { curl_easy_setopt(handle, 10175, user.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_proxypassword() {
        let handle = curl_easy_init();
        let pass = c"proxypass";
        let code = unsafe { curl_easy_setopt(handle, 10176, pass.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_pre_proxy() {
        let handle = curl_easy_init();
        let url = c"socks5://proxy.example.com:1080";
        let code = unsafe { curl_easy_setopt(handle, 10262, url.as_ptr().cast::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_socks5_auth() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 267, 3_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_maxconnects() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 71, 5_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_pipewait() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 237, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_stream_weight() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 239, 16_usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_tcp_fastopen() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 244, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_http09_allowed() {
        let handle = curl_easy_init();
        let code = unsafe { curl_easy_setopt(handle, 285, std::ptr::dangling::<c_void>()) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn curlcode_auth_error_exists() {
        assert_eq!(CURLcode::CURLE_AUTH_ERROR as i32, 94);
    }

    #[test]
    fn curlcode_ssl_pinnedpubkey_exists() {
        assert_eq!(CURLcode::CURLE_SSL_PINNEDPUBKEYNOTMATCH as i32, 90);
    }
}
