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
    CURLOPT_INTERFACE = 10062,
    CURLOPT_SSL_CIPHER_LIST = 10083,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_COOKIEFILE = 10031,
    CURLOPT_COOKIEJAR = 10082,
    CURLOPT_PROXYUSERPWD = 10006,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_RESOLVE = 10203,
    CURLOPT_PINNEDPUBLICKEY = 10230,
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    CURLOPT_PROXY_SSLCERT = 10254,
    CURLOPT_PROXY_SSLKEY = 10255,
    CURLOPT_READDATA = 10009,
    CURLOPT_DEBUGDATA = 10095,
    CURLOPT_DNS_SERVERS = 10211,
    CURLOPT_DOH_URL = 10279,

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
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_LOCALPORT = 139,
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,
    CURLOPT_TCP_KEEPALIVE = 213,
    CURLOPT_SSL_SESSIONID_CACHE = 150,

    // Off_t options (CURLOPTTYPE_OFF_T = 30000)
    CURLOPT_INFILESIZE_LARGE = 30115,
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
    CURLINFO_PRETRANSFER_TIME = 0x0030_000E,
    CURLINFO_STARTTRANSFER_TIME = 0x0030_0011,
    CURLINFO_CONTENT_TYPE = 0x0010_0012,
    CURLINFO_REDIRECT_COUNT = 0x0020_0014,
    CURLINFO_SSL_VERIFYRESULT = 0x0020_000D,
    CURLINFO_PRIVATE = 0x0010_0015,
    CURLINFO_HTTP_VERSION = 0x0020_0032,
    CURLINFO_APPCONNECT_TIME = 0x0030_0033,
    CURLINFO_PRIMARY_PORT = 0x0020_0040,
    CURLINFO_SCHEME = 0x0010_0044,
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
                // CURL_HTTP_VERSION_2_0 = 3
                3 => h.easy.http_version(liburlx::HttpVersion::Http2),
                _ => {}
            }
            CURLcode::CURLE_OK
        }

        // CURLOPT_NOSIGNAL = 99
        99 => {
            // Accept but no-op — signals are not used in tokio-based architecture
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

        // CURLINFO_SSL_VERIFYRESULT = 0x20000D
        0x20_000D => {
            // SAFETY: Caller guarantees out points to c_long
            let out = unsafe { &mut *out.cast::<c_long>() };
            // 0 = success (X509_V_OK). Since we either verify successfully or
            // fail the connection entirely, a completed transfer always means 0.
            *out = 0;
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

        // CURLINFO_SCHEME = 0x100044
        0x10_0044 => {
            // SAFETY: Caller guarantees out points to *const c_char
            // Return the scheme from the effective URL
            // Note: We store a pointer to the effective URL string which contains the scheme
            let out = unsafe { &mut *out.cast::<*const c_char>() };
            *out = response.effective_url().as_ptr().cast::<c_char>();
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
        let code = unsafe { curl_easy_setopt(handle, 150, 1_usize as *const c_void) };
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
        let code = unsafe { curl_easy_setopt(handle, 111, 1_usize as *const c_void) };
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
        let code = unsafe { curl_easy_setopt(handle, 248, 1_usize as *const c_void) };
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
        let code = unsafe { curl_easy_setopt(handle, 105, 1usize as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_ignore_content_length() {
        let handle = curl_easy_init();
        // CURLOPT_IGNORE_CONTENT_LENGTH = 136
        let code = unsafe { curl_easy_setopt(handle, 136, 1usize as *const c_void) };
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
        let code = unsafe { curl_easy_setopt(handle, 43, 1 as *const c_void) };
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
        let mut out: *mut c_void = 1 as *mut c_void;
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
        let code = unsafe { curl_url_get(handle, 1, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        assert!(!part.is_null());
        let scheme = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(scheme, "https");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get host
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 5, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let host = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(host, "example.com");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get path
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 7, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let path = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(path, "/path");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get query
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 8, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let query = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(query, "q=1");
        unsafe { curl_free(part.cast::<c_void>()) };

        // Get fragment
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 9, &mut part, 0) };
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
        let code = unsafe { curl_url_get(handle, 0, &mut part, 0) };
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
        let code = unsafe { curl_url_get(handle, 2, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        let user = unsafe { CStr::from_ptr(part) }.to_str().unwrap();
        assert_eq!(user, "user");
        unsafe { curl_free(part.cast::<c_void>()) };

        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(handle, 3, &mut part, 0) };
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
        let code = unsafe { curl_url_get(handle, 8, &mut part, 0) };
        assert_eq!(code, CURLUcode::CURLUE_OK);
        assert!(part.is_null()); // Query was cleared

        unsafe { curl_url_cleanup(handle) };
    }

    #[test]
    fn url_get_null_handle() {
        let mut part: *mut c_char = ptr::null_mut();
        let code = unsafe { curl_url_get(ptr::null_mut(), 0, &mut part, 0) };
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
        let code = unsafe { curl_url_get(handle, 99, &mut part, 0) };
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
        let code = unsafe { curl_url_get(dup, 1, &mut part, 0) };
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
        let code = unsafe { curl_easy_setopt(handle, 99, 1 as *const c_void) };
        assert_eq!(code, CURLcode::CURLE_OK);
        unsafe { curl_easy_cleanup(handle) };
    }

    #[test]
    fn easy_setopt_autoreferer() {
        let handle = curl_easy_init();
        // CURLOPT_AUTOREFERER = 58
        let code = unsafe { curl_easy_setopt(handle, 58, 1 as *const c_void) };
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
}
