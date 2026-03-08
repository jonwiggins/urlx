/* urlx — libcurl-compatible C API */

#ifndef URLX_H
#define URLX_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef void CURL;

/**
 * `CURLcode` — result codes for easy handle operations.
 */
typedef enum CURLcode {
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
} CURLcode;

/**
 * `CURLOPT` — option codes for `curl_easy_setopt`.
 */
typedef enum CURLoption {
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
} CURLoption;

/**
 * `CURLINFO` — info codes for `curl_easy_getinfo`.
 */
typedef enum CURLINFO {
    CURLINFO_RESPONSE_CODE = 2097154,
    CURLINFO_CONTENT_TYPE = 1048594,
    CURLINFO_EFFECTIVE_URL = 1048577,
    CURLINFO_TOTAL_TIME = 3145731,
    CURLINFO_SIZE_DOWNLOAD = 3145736,
    CURLINFO_REDIRECT_COUNT = 2097172,
} CURLINFO;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

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
 * `urlx_version` — returns the version string.
 *
 * # Safety
 *
 * The returned pointer is valid for the lifetime of the program.
 */
 const char *urlx_version(void) ;

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* URLX_H */


