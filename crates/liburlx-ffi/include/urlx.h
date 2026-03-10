/* urlx — libcurl-compatible C API */

#ifndef URLX_H
#define URLX_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef void CURL;

/**
 * Bitmask constants for `curl_global_init`.
 * `CURL_GLOBAL_SSL` — initialize SSL.
 */
#define CURL_GLOBAL_SSL 1

/**
 * `CURL_GLOBAL_WIN32` — initialize Win32 sockets.
 */
#define CURL_GLOBAL_WIN32 2

/**
 * `CURL_GLOBAL_ALL` — initialize everything.
 */
#define CURL_GLOBAL_ALL 3

/**
 * `CURL_GLOBAL_DEFAULT` — same as ALL.
 */
#define CURL_GLOBAL_DEFAULT 3

/**
 * Feature bit: SSL support.
 */
#define CURL_VERSION_SSL (1 << 2)

/**
 * Feature bit: HTTP/2 support.
 */
#define CURL_VERSION_HTTP2 (1 << 16)

/**
 * Feature bit: async DNS support.
 */
#define CURL_VERSION_ASYNCHDNS (1 << 7)

/**
 * Feature bit: PSL support.
 */
#define CURL_VERSION_PSL (1 << 20)

/**
 * Pause direction constants.
 * `CURLPAUSE_RECV` — pause receiving.
 */
#define CURLPAUSE_RECV 1

/**
 * `CURLPAUSE_SEND` — pause sending.
 */
#define CURLPAUSE_SEND 4

/**
 * `CURLPAUSE_ALL` — pause both directions.
 */
#define CURLPAUSE_ALL 5

/**
 * `CURLPAUSE_CONT` — unpause both directions.
 */
#define CURLPAUSE_CONT 0

/**
 * `CURLINFO` — info codes for `curl_easy_getinfo`.
 */
typedef enum CURLINFO {
    CURLINFO_EFFECTIVE_URL = 1048577,
    CURLINFO_RESPONSE_CODE = 2097154,
    CURLINFO_TOTAL_TIME = 3145731,
    CURLINFO_NAMELOOKUP_TIME = 3145732,
    CURLINFO_CONNECT_TIME = 3145733,
    CURLINFO_SIZE_UPLOAD = 3145735,
    CURLINFO_SIZE_DOWNLOAD = 3145736,
    CURLINFO_SPEED_DOWNLOAD = 3145737,
    CURLINFO_SPEED_UPLOAD = 3145738,
    CURLINFO_HEADER_SIZE = 2097163,
    CURLINFO_FILETIME = 2097166,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 3145743,
    CURLINFO_CONTENT_LENGTH_UPLOAD = 3145744,
    CURLINFO_PRETRANSFER_TIME = 3145742,
    CURLINFO_STARTTRANSFER_TIME = 3145745,
    CURLINFO_CONTENT_TYPE = 1048594,
    CURLINFO_REDIRECT_COUNT = 2097172,
    CURLINFO_SSL_VERIFYRESULT = 2097165,
    CURLINFO_PRIVATE = 1048597,
    CURLINFO_OS_ERRNO = 2097177,
    CURLINFO_PRIMARY_IP = 1048608,
    CURLINFO_NUM_CONNECTS = 2097190,
    CURLINFO_LOCAL_IP = 1048617,
    CURLINFO_REDIRECT_URL = 1048625,
    CURLINFO_HTTP_VERSION = 2097202,
    CURLINFO_APPCONNECT_TIME = 3145779,
    CURLINFO_CONDITION_UNMET = 2097205,
    CURLINFO_PRIMARY_PORT = 2097216,
    CURLINFO_LOCAL_PORT = 2097218,
    CURLINFO_SCHEME = 1048644,
    CURLINFO_REDIRECT_TIME = 3145747,
    CURLINFO_TOTAL_TIME_T = 6291518,
    CURLINFO_NAMELOOKUP_TIME_T = 6291519,
    CURLINFO_CONNECT_TIME_T = 6291520,
    CURLINFO_PRETRANSFER_TIME_T = 6291521,
    CURLINFO_STARTTRANSFER_TIME_T = 6291522,
    CURLINFO_REDIRECT_TIME_T = 6291523,
    CURLINFO_APPCONNECT_TIME_T = 6291524,
    CURLINFO_RETRY_AFTER = 2097210,
    CURLINFO_SIZE_UPLOAD_T = 6291525,
    CURLINFO_SIZE_DOWNLOAD_T = 6291526,
    CURLINFO_SPEED_DOWNLOAD_T = 6291527,
    CURLINFO_SPEED_UPLOAD_T = 6291528,
    CURLINFO_REQUEST_SIZE = 2097164,
    CURLINFO_HTTP_CONNECTCODE = 2097174,
    CURLINFO_HTTPAUTH_AVAIL = 2097175,
    CURLINFO_PROXYAUTH_AVAIL = 2097176,
} CURLINFO;

/**
 * `CURLMSG` — message types from `curl_multi_info_read`.
 */
typedef enum CURLMSG {
    CURLMSG_DONE = 1,
} CURLMSG;

/**
 * `CURLMcode` — result codes for multi handle operations.
 */
typedef enum CURLMcode {
    CURLM_OK = 0,
    CURLM_BAD_HANDLE = -1,
    CURLM_BAD_EASY_HANDLE = -2,
    CURLM_OUT_OF_MEMORY = -3,
    CURLM_INTERNAL_ERROR = -4,
    CURLM_UNKNOWN_OPTION = -6,
} CURLMcode;

/**
 * `CURLSHcode` — result codes for share handle operations.
 */
typedef enum CURLSHcode {
    CURLSHE_OK = 0,
    CURLSHE_BAD_OPTION = 1,
    CURLSHE_IN_USE = 2,
    CURLSHE_INVALID = 3,
    CURLSHE_NOMEM = 4,
    CURLSHE_NOT_BUILT_IN = 5,
} CURLSHcode;

/**
 * `CURLUcode` — result codes for URL API operations.
 */
typedef enum CURLUcode {
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
} CURLUcode;

/**
 * `CURLcode` — result codes for easy handle operations.
 */
typedef enum CURLcode {
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
} CURLcode;

/**
 * `CURLOPT` — option codes for `curl_easy_setopt`.
 */
typedef enum CURLoption {
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
    CURLOPT_PORT = 3,
    CURLOPT_INFILESIZE = 14,
    CURLOPT_RESUME_FROM = 21,
    CURLOPT_PROXYPORT = 59,
    CURLOPT_FILETIME = 69,
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_BUFFERSIZE = 98,
    CURLOPT_PROXYTYPE = 101,
    CURLOPT_IPRESOLVE = 113,
    CURLOPT_FTP_FILEMETHOD = 138,
    CURLOPT_PIPEWAIT = 237,
    CURLOPT_STREAM_WEIGHT = 239,
    CURLOPT_TCP_FASTOPEN = 244,
    CURLOPT_SOCKS5_AUTH = 267,
    CURLOPT_HTTP09_ALLOWED = 285,
    CURLOPT_POSTFIELDSIZE_LARGE = 30120,
    CURLOPT_INFILESIZE_LARGE = 30115,
    CURLOPT_MAXFILESIZE_LARGE = 30117,
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,
    CURLOPT_CAPATH = 10097,
    CURLOPT_REFERER = 10016,
    CURLOPT_XOAUTH2_BEARER = 10220,
    CURLOPT_AWS_SIGV4 = 10306,
    CURLOPT_SHARE = 10100,
    CURLOPT_PRIVATE = 10103,
    CURLOPT_MIMEPOST = 10269,
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_READFUNCTION = 20012,
    CURLOPT_PROGRESSFUNCTION = 20056,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_DEBUGFUNCTION = 20094,
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_XFERINFOFUNCTION = 20219,
    CURLOPT_NOPROGRESS = 43,
    CURLOPT_AUTOREFERER = 58,
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_NOSIGNAL = 99,
    CURLOPT_LOCALPORTRANGE = 164,
    CURLOPT_RESUME_FROM_LARGE = 30116,
    CURLOPT_PROGRESSDATA = 10057,
    CURLOPT_SEEKDATA = 10168,
} CURLoption;

/**
 * Linked list node for string data (e.g., HTTP headers).
 *
 * Equivalent to libcurl's `struct curl_slist`.
 */
typedef struct curl_slist {
    /**
     * The string data for this node.
     */
    char *data;
    /**
     * Pointer to the next node, or null.
     */
    struct curl_slist *next;
} curl_slist;

/**
 * `CURLMsg` — completion message from `curl_multi_info_read`.
 */
typedef struct CURLMsg {
    enum CURLMSG msg;
    void *easy_handle;
    enum CURLcode result;
} CURLMsg;

/**
 * `curl_waitfd` — extra file descriptor for `curl_multi_wait`/`curl_multi_poll`.
 */
typedef struct curl_waitfd {
    long fd;
    short events;
    short revents;
} curl_waitfd;

/**
 * Version info struct returned by `curl_version_info`.
 *
 * Matches the `curl_version_info_data` struct from libcurl.
 * Only the essential fields are populated.
 */
typedef struct CurlVersionInfo {
    /**
     * Age of this struct (`CURLVERSION_FIRST` = 0).
     */
    long age;
    /**
     * Version string (e.g., "0.1.0").
     */
    const char *version;
    /**
     * Numeric version (major*0x10000 + minor*0x100 + patch).
     */
    long version_num;
    /**
     * Host system description.
     */
    const char *host;
    /**
     * Feature bitmask.
     */
    long features;
    /**
     * SSL version string or NULL.
     */
    const char *ssl_version;
    /**
     * Unused (libssl version number).
     */
    long ssl_version_num;
    /**
     * libz version string or NULL.
     */
    const char *libz_version;
    /**
     * Null-terminated array of supported protocols.
     */
    const char *const *protocols;
} CurlVersionInfo;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * `curl_mime_init` — create a new MIME handle.
 *
 * # Safety
 *
 * `easy` must be a valid pointer from `curl_easy_init` (used for context only).
 * The returned handle must be freed with `curl_mime_free`.
 */
 void *curl_mime_init(void *_easy) ;

/**
 * `curl_mime_addpart` — add a new part to a MIME handle.
 *
 * # Safety
 *
 * `mime` must be a valid pointer from `curl_mime_init`.
 * The returned part pointer is valid until `curl_mime_free` is called on the parent.
 */
 void *curl_mime_addpart(void *mime) ;

/**
 * `curl_mime_name` — set the name of a MIME part.
 *
 * # Safety
 *
 * `part` must be a valid pointer from `curl_mime_addpart`.
 * `name` must be a valid null-terminated C string.
 */
 enum CURLcode curl_mime_name(void *part, const char *name) ;

/**
 * `curl_mime_data` — set data for a MIME part.
 *
 * # Safety
 *
 * `part` must be a valid pointer from `curl_mime_addpart`.
 * `data` must point to at least `datasize` bytes.
 * If `datasize` is `usize::MAX`, `data` is treated as a null-terminated string.
 */
 enum CURLcode curl_mime_data(void *part, const char *data, uintptr_t datasize) ;

/**
 * `curl_mime_filename` — set the filename for a MIME part.
 *
 * # Safety
 *
 * `part` must be a valid pointer from `curl_mime_addpart`.
 * `filename` must be a valid null-terminated C string.
 */
 enum CURLcode curl_mime_filename(void *part, const char *filename) ;

/**
 * `curl_mime_type` — set the MIME type for a MIME part.
 *
 * # Safety
 *
 * `part` must be a valid pointer from `curl_mime_addpart`.
 * `mimetype` must be a valid null-terminated C string.
 */
 enum CURLcode curl_mime_type(void *part, const char *mimetype) ;

/**
 * `curl_mime_free` — free a MIME handle and all its parts.
 *
 * # Safety
 *
 * `mime` must be a valid pointer from `curl_mime_init`, or null.
 * After this call, `mime` must not be used.
 */
 void curl_mime_free(void *mime) ;

/**
 * `curl_share_init` — create a new share handle.
 *
 * # Safety
 *
 * Returns a new handle that must be freed with `curl_share_cleanup`.
 */
 void *curl_share_init(void) ;

/**
 * `curl_share_cleanup` — free a share handle.
 *
 * # Safety
 *
 * `share` must be a valid pointer from `curl_share_init`, or null.
 */
 enum CURLSHcode curl_share_cleanup(void *share) ;

/**
 * `curl_share_setopt` — set options on a share handle.
 *
 * # Safety
 *
 * `share` must be a valid pointer from `curl_share_init`.
 * For `CURLSHOPT_SHARE`/`CURLSHOPT_UNSHARE`, `value` is a `CURL_LOCK_DATA_*` constant.
 */
 enum CURLSHcode curl_share_setopt(void *share, long option, const void *value) ;

/**
 * `curl_share_strerror` — return a human-readable share error message.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *curl_share_strerror(enum CURLSHcode code) ;

/**
 * `curl_url` — create a new URL handle.
 *
 * # Safety
 *
 * Returns a new handle that must be freed with `curl_url_cleanup`.
 */
 void *curl_url(void) ;

/**
 * `curl_url_cleanup` — free a URL handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_url`, or null.
 */
 void curl_url_cleanup(void *handle) ;

/**
 * `curl_url_dup` — duplicate a URL handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_url`.
 */
 void *curl_url_dup(void *handle) ;

/**
 * `curl_url_set` — set a URL component.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_url`.
 * `content` must be a valid null-terminated C string (or null to clear).
 */
 enum CURLUcode curl_url_set(void *handle, long what, const char *content, long _flags) ;

/**
 * `curl_url_get` — get a URL component.
 *
 * The returned string is allocated and must be freed by the caller with `libc::free`
 * or `curl_free`. For simplicity, we allocate via a leaked `CString`.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_url`.
 * `part` must be a valid pointer to `*mut c_char`.
 */
 enum CURLUcode curl_url_get(void *handle, long what, char **part, long _flags) ;

/**
 * `curl_free` — free memory allocated by curl functions.
 *
 * # Safety
 *
 * `ptr` must be a pointer returned by curl functions (e.g., `curl_url_get`), or null.
 */
 void curl_free(void *ptr) ;

/**
 * `curl_slist_append` — append a string to a linked list.
 *
 * # Safety
 *
 * `data` must be a valid null-terminated C string.
 * `list` can be null (creates a new list) or a valid `curl_slist` pointer.
 */
 struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data) ;

/**
 * `curl_slist_free_all` — free an entire linked list.
 *
 * # Safety
 *
 * `list` must be a valid `curl_slist` pointer from `curl_slist_append`, or null.
 */
 void curl_slist_free_all(struct curl_slist *list) ;

/**
 * `curl_easy_init` — create a new easy handle.
 *
 * # Safety
 *
 * Returns a new handle that must be freed with `curl_easy_cleanup`.
 */
 void *curl_easy_init(void) ;

/**
 * `curl_easy_cleanup` — free an easy handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by `curl_easy_init`, or null.
 * After this call, `handle` must not be used.
 */
 void curl_easy_cleanup(void *handle) ;

/**
 * `curl_easy_duphandle` — clone an easy handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 * The returned handle must be freed with `curl_easy_cleanup`.
 */
 void *curl_easy_duphandle(void *handle) ;

/**
 * `curl_easy_reset` — reset an easy handle to initial state.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 */
 void curl_easy_reset(void *handle) ;

/**
 * `curl_easy_setopt` — set options on an easy handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 * Variadic arguments must match the expected type for each option.
 */
 enum CURLcode curl_easy_setopt(void *handle, long option, const void *value) ;

/**
 * `curl_easy_perform` — perform the transfer.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 */
 enum CURLcode curl_easy_perform(void *handle) ;

/**
 * `curl_easy_getinfo` — get info about the last transfer.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 * `out` must be a valid pointer to the appropriate type for the info code.
 */
 enum CURLcode curl_easy_getinfo(void *handle, long info, void *out) ;

/**
 * `curl_easy_strerror` — return a human-readable error message.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *curl_easy_strerror(enum CURLcode code) ;

/**
 * `curl_multi_init` — create a new multi handle.
 *
 * # Safety
 *
 * Returns a new handle that must be freed with `curl_multi_cleanup`.
 */
 void *curl_multi_init(void) ;

/**
 * `curl_multi_cleanup` — free a multi handle.
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_multi_init`, or null.
 */
 enum CURLMcode curl_multi_cleanup(void *handle) ;

/**
 * `curl_multi_add_handle` — add an easy handle to a multi handle.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`, `easy` from `curl_easy_init`.
 */
 enum CURLMcode curl_multi_add_handle(void *multi, void *easy) ;

/**
 * `curl_multi_remove_handle` — remove an easy handle from a multi handle.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`, `easy` from `curl_easy_init`.
 */
 enum CURLMcode curl_multi_remove_handle(void *multi, void *easy) ;

/**
 * `curl_multi_perform` — perform all queued transfers.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `running_handles` must be a valid pointer to an int, or null.
 */
 enum CURLMcode curl_multi_perform(void *multi, long *running_handles) ;

/**
 * `curl_multi_info_read` — read a completion message from the multi handle.
 *
 * Returns a pointer to a `CURLMsg` struct, or null if no messages remain.
 * The `msgs_in_queue` output parameter is set to the number of remaining messages.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `msgs_in_queue` must be a valid pointer to a `c_long`, or null.
 * The returned pointer is valid until the next call to `curl_multi_info_read`
 * or `curl_multi_perform`.
 */
 const struct CURLMsg *curl_multi_info_read(void *multi, long *msgs_in_queue) ;

/**
 * `curl_multi_setopt` — set options on a multi handle.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * The interpretation of `value` depends on the option.
 */
 enum CURLMcode curl_multi_setopt(void *multi, long option, const void *value) ;

/**
 * `curl_multi_timeout` — return the timeout value for the multi handle.
 *
 * Returns the number of milliseconds until the application should call
 * `curl_multi_perform` or similar. Returns -1 if no timeout is set.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `timeout_ms` must be a valid pointer to a `c_long`.
 */
 enum CURLMcode curl_multi_timeout(void *multi, long *timeout_ms) ;

/**
 * `curl_multi_wait` — wait for activity on any of the multi handle's transfers.
 *
 * Since tokio manages I/O internally, this function simply sleeps for the
 * specified timeout (or a default of 1000ms if `timeout_ms` is 0).
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `extra_fds` and `extra_nfds` specify additional file descriptors to wait on (ignored).
 * `numfds` receives the number of ready file descriptors (always 0 in this implementation).
 */

enum CURLMcode curl_multi_wait(void *multi,
                               struct curl_waitfd *_extra_fds,
                               long _extra_nfds,
                               long timeout_ms,
                               long *numfds)
;

/**
 * `curl_multi_poll` — poll for activity on any of the multi handle's transfers.
 *
 * Equivalent to `curl_multi_wait` but with a guaranteed wakeup mechanism.
 * Since tokio handles I/O, this has the same behavior as `curl_multi_wait`.
 *
 * # Safety
 *
 * Same safety requirements as `curl_multi_wait`.
 */

enum CURLMcode curl_multi_poll(void *multi,
                               struct curl_waitfd *fds,
                               long nfds,
                               long timeout_ms,
                               long *numfds)
;

/**
 * `curl_multi_wakeup` — wake up a sleeping `curl_multi_poll`.
 *
 * Since our poll is a simple sleep, this is a no-op that returns OK.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 */
 enum CURLMcode curl_multi_wakeup(void *multi) ;

/**
 * `curl_multi_fdset` — extract file descriptors from the multi handle.
 *
 * Since tokio manages all I/O internally, no file descriptors are exposed.
 * All output fd values are set to -1.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `max_fd` must be a valid pointer to a `c_long`.
 * `read_fd_set`, `write_fd_set`, and `exc_fd_set` are ignored (accept null).
 */

enum CURLMcode curl_multi_fdset(void *multi,
                                void *_read_fd_set,
                                void *_write_fd_set,
                                void *_exc_fd_set,
                                long *max_fd)
;

/**
 * `curl_multi_socket_action` — socket action interface for event-driven programs.
 *
 * Since tokio handles all socket I/O internally, this delegates to a blocking
 * perform when called with `CURL_SOCKET_TIMEOUT` (-1). For specific socket
 * actions, it is a no-op.
 *
 * # Safety
 *
 * `multi` must be from `curl_multi_init`.
 * `running_handles` must be a valid pointer to a `c_long`, or null.
 */

enum CURLMcode curl_multi_socket_action(void *multi,
                                        long sockfd,
                                        long _ev_bitmask,
                                        long *running_handles)
;

/**
 * `curl_multi_strerror` — return a human-readable multi error message.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *curl_multi_strerror(enum CURLMcode code) ;

/**
 * `curl_escape` — URL-encode a string.
 *
 * Returns a newly allocated string that must be freed with `curl_free`.
 * If `length` is 0, the string is treated as null-terminated.
 *
 * # Safety
 *
 * `string` must be a valid pointer to at least `length` bytes.
 * If `length` is 0, `string` must be null-terminated.
 */
 char *curl_escape(const char *string, long length) ;

/**
 * `curl_unescape` — URL-decode a string.
 *
 * Returns a newly allocated string that must be freed with `curl_free`.
 * If `length` is 0, the string is treated as null-terminated.
 *
 * # Safety
 *
 * `string` must be a valid pointer to at least `length` bytes.
 * If `length` is 0, `string` must be null-terminated.
 * If `outlength` is non-null, it receives the length of the decoded string.
 */
 char *curl_unescape(const char *string, long length, long *outlength) ;

/**
 * `curl_easy_escape` — URL-encode a string using an easy handle.
 *
 * The easy handle parameter is accepted for API compatibility but not used.
 * Returns a newly allocated string that must be freed with `curl_free`.
 *
 * # Safety
 *
 * `_handle` can be null (not used). `string` must be valid.
 * If `length` is 0, the string is treated as null-terminated.
 */
 char *curl_easy_escape(void *_handle, const char *string, long length) ;

/**
 * `curl_easy_unescape` — URL-decode a string using an easy handle.
 *
 * The easy handle parameter is accepted for API compatibility but not used.
 * Returns a newly allocated string that must be freed with `curl_free`.
 *
 * # Safety
 *
 * `_handle` can be null (not used). `string` must be valid.
 * If `inlength` is 0, the string is treated as null-terminated.
 * `outlength` receives the decoded length (can be null).
 */
 char *curl_easy_unescape(void *_handle, const char *string, long inlength, long *outlength) ;

/**
 * `curl_getdate` — parse a date string to a Unix timestamp.
 *
 * Parses RFC 2822, RFC 850, and asctime date formats.
 * Returns the number of seconds since the Unix epoch, or -1 on failure.
 *
 * # Safety
 *
 * `datestring` must be a valid null-terminated C string.
 * `now` is unused (accepted for API compatibility, can be null).
 */
 int64_t curl_getdate(const char *datestring, const void *_now) ;

/**
 * `curl_formadd` — deprecated multipart form API.
 *
 * This function is deprecated in libcurl in favor of the MIME API.
 * Returns `CURL_FORMADD_DISABLED` (7) to indicate it's not supported.
 *
 * # Safety
 *
 * Arguments are ignored. Always returns disabled.
 */
 long curl_formadd(void **_first, void **_last) ;

/**
 * `curl_formfree` — free a form created by `curl_formadd`.
 *
 * Since `curl_formadd` always returns disabled, this is a no-op.
 *
 * # Safety
 *
 * `form` can be any pointer (ignored).
 */
 void curl_formfree(void *_form) ;

/**
 * `curl_version` — returns the version string (libcurl compatibility).
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *curl_version(void) ;

/**
 * `urlx_version` — returns the version string.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *urlx_version(void) ;

/**
 * `curl_global_init` — global initialization (no-op in urlx).
 *
 * In libcurl this initializes SSL, Win32 sockets, etc. In urlx, tokio
 * and rustls handle their own initialization, so this is a no-op.
 *
 * # Safety
 *
 * This function is always safe to call.
 */
 enum CURLcode curl_global_init(long _flags) ;

/**
 * `curl_global_cleanup` — global cleanup (no-op in urlx).
 *
 * # Safety
 *
 * This function is always safe to call.
 */
 void curl_global_cleanup(void) ;

/**
 * `curl_version_info` — return version info struct.
 *
 * Returns a pointer to a static struct with version information.
 * The pointer is valid for the lifetime of the program.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const struct CurlVersionInfo *curl_version_info(long _age) ;

/**
 * `curl_easy_pause` — pause/unpause a transfer (stub).
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 */
 enum CURLcode curl_easy_pause(void *_handle, long _bitmask) ;

/**
 * `curl_easy_upkeep` — perform connection upkeep (no-op).
 *
 * # Safety
 *
 * `handle` must be a valid pointer from `curl_easy_init`.
 */
 enum CURLcode curl_easy_upkeep(void *_handle) ;

/**
 * `curl_multi_assign` — assign custom pointer to socket (no-op stub).
 *
 * # Safety
 *
 * `multi_handle` must be a valid pointer from `curl_multi_init`.
 */
 enum CURLMcode curl_multi_assign(void *_multi_handle, long _sockfd, void *_sockp) ;

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* URLX_H */


