/*
 * Basic C test harness for liburlx-ffi.
 *
 * Exercises core FFI functions: init, setopt, getinfo, cleanup,
 * version, strerror, slist, URL API, pause.
 *
 * Compile:
 *   cc -o test_basic test_basic.c -L../../target/release -lurlx_ffi -lpthread -ldl -lm
 * Run:
 *   LD_LIBRARY_PATH=../../target/release ./test_basic
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal declarations matching urlx.h */

typedef void CURL;
typedef void CURLM;

/* CURLcode */
#define CURLE_OK 0
#define CURLE_UNSUPPORTED_PROTOCOL 1
#define CURLE_COULDNT_RESOLVE_HOST 6
#define CURLE_UNKNOWN_OPTION 48

/* CURLoption */
#define CURLOPT_URL 10002
#define CURLOPT_USERAGENT 10018
#define CURLOPT_VERBOSE 41
#define CURLOPT_NOBODY 44
#define CURLOPT_FOLLOWLOCATION 52
#define CURLOPT_TIMEOUT 13
#define CURLOPT_HTTPHEADER 10023
#define CURLOPT_WRITEFUNCTION 20011
#define CURLOPT_WRITEDATA 10001
#define CURLOPT_PRIVATE 10103
#define CURLOPT_PORT 3
#define CURLOPT_IPRESOLVE 113
#define CURLOPT_CAPATH 10097

/* CURLINFO */
#define CURLINFO_RESPONSE_CODE 0x200002
#define CURLINFO_EFFECTIVE_URL 0x100001
#define CURLINFO_CONTENT_TYPE 0x100012
#define CURLINFO_SCHEME 0x100044
#define CURLINFO_REQUEST_SIZE 0x20000C
#define CURLINFO_HTTPAUTH_AVAIL 0x200017

/* CURLUcode */
#define CURLUE_OK 0

/* CURLUPart */
#define CURLUPART_URL 0
#define CURLUPART_SCHEME 1
#define CURLUPART_HOST 5

/* Pause constants */
#define CURLPAUSE_RECV 1
#define CURLPAUSE_SEND 4
#define CURLPAUSE_ALL (CURLPAUSE_RECV | CURLPAUSE_SEND)
#define CURLPAUSE_CONT 0

/* Function declarations.
 * Note: urlx's curl_easy_setopt/getinfo are non-variadic (they take a
 * void* value), unlike real libcurl which uses varargs. We declare them
 * with explicit (void *) to match the Rust ABI. */
extern CURL *curl_easy_init(void);
extern void curl_easy_cleanup(CURL *handle);
extern int curl_easy_setopt(CURL *handle, long option, const void *value);
extern int curl_easy_getinfo(CURL *handle, long info, void *out);
extern int curl_easy_perform(CURL *handle);
extern CURL *curl_easy_duphandle(CURL *handle);
extern void curl_easy_reset(CURL *handle);
extern int curl_easy_pause(CURL *handle, long bitmask);
extern const char *curl_easy_strerror(int code);
extern const char *curl_version(void);

struct curl_slist {
    char *data;
    struct curl_slist *next;
};
extern struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data);
extern void curl_slist_free_all(struct curl_slist *list);

extern void *curl_url(void);
extern void curl_url_cleanup(void *handle);
extern void *curl_url_dup(void *handle);
extern int curl_url_set(void *handle, int part, const char *content, unsigned int flags);
extern int curl_url_get(void *handle, int part, char **content, unsigned int flags);

extern void curl_free(void *ptr);

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %s... ", #name); \
    fflush(stdout); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("ok\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAILED: %s\n", msg); \
} while(0)

/* ── Tests ── */

void test_easy_init_cleanup(void) {
    TEST(easy_init_cleanup);
    CURL *h = curl_easy_init();
    assert(h != NULL);
    curl_easy_cleanup(h);
    PASS();
}

void test_easy_setopt_url(void) {
    TEST(easy_setopt_url);
    CURL *h = curl_easy_init();
    int rc = curl_easy_setopt(h, CURLOPT_URL, "http://example.com");
    assert(rc == CURLE_OK);
    curl_easy_cleanup(h);
    PASS();
}

void test_easy_setopt_various(void) {
    TEST(easy_setopt_various);
    CURL *h = curl_easy_init();
    assert(curl_easy_setopt(h, CURLOPT_VERBOSE, (void *)1L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_NOBODY, (void *)1L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, (void *)1L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_TIMEOUT, (void *)30L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_USERAGENT, "test/1.0") == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_PORT, (void *)8080L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_IPRESOLVE, (void *)1L) == CURLE_OK);
    assert(curl_easy_setopt(h, CURLOPT_CAPATH, "/etc/ssl/certs") == CURLE_OK);
    curl_easy_cleanup(h);
    PASS();
}

void test_easy_duphandle(void) {
    TEST(easy_duphandle);
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, "http://example.com");
    CURL *dup = curl_easy_duphandle(h);
    assert(dup != NULL);
    assert(dup != h);
    curl_easy_cleanup(dup);
    curl_easy_cleanup(h);
    PASS();
}

void test_easy_reset(void) {
    TEST(easy_reset);
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, "http://example.com");
    curl_easy_reset(h);
    /* After reset, handle should still be valid */
    int rc = curl_easy_setopt(h, CURLOPT_URL, "http://other.com");
    assert(rc == CURLE_OK);
    curl_easy_cleanup(h);
    PASS();
}

void test_easy_strerror(void) {
    TEST(easy_strerror);
    const char *msg = curl_easy_strerror(CURLE_OK);
    assert(msg != NULL);
    assert(strcmp(msg, "No error") == 0);

    msg = curl_easy_strerror(CURLE_UNSUPPORTED_PROTOCOL);
    assert(msg != NULL);
    assert(strlen(msg) > 0);
    PASS();
}

void test_version(void) {
    TEST(version);
    const char *v = curl_version();
    assert(v != NULL);
    assert(strlen(v) > 0);
    /* Should contain "urlx" or version number */
    printf("(version: %s) ", v);
    PASS();
}

void test_easy_pause(void) {
    TEST(easy_pause);
    CURL *h = curl_easy_init();
    int rc = curl_easy_pause(h, CURLPAUSE_ALL);
    assert(rc == CURLE_OK);
    rc = curl_easy_pause(h, CURLPAUSE_CONT);
    assert(rc == CURLE_OK);
    curl_easy_cleanup(h);
    PASS();
}

void test_slist(void) {
    TEST(slist);
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, "Content-Type: application/json");
    assert(list != NULL);
    assert(list->data != NULL);
    assert(strcmp(list->data, "Content-Type: application/json") == 0);

    list = curl_slist_append(list, "Accept: */*");
    assert(list != NULL);

    /* Count items */
    int count = 0;
    struct curl_slist *p = list;
    while (p) { count++; p = p->next; }
    assert(count == 2);

    curl_slist_free_all(list);
    /* Also test NULL free is safe */
    curl_slist_free_all(NULL);
    PASS();
}

void test_url_api(void) {
    TEST(url_api);
    void *u = curl_url();
    assert(u != NULL);

    int rc = curl_url_set(u, CURLUPART_URL, "https://example.com/path?q=1", 0);
    assert(rc == CURLUE_OK);

    char *scheme = NULL;
    rc = curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
    assert(rc == CURLUE_OK);
    assert(scheme != NULL);
    assert(strcmp(scheme, "https") == 0);
    curl_free(scheme);

    char *host = NULL;
    rc = curl_url_get(u, CURLUPART_HOST, &host, 0);
    assert(rc == CURLUE_OK);
    assert(host != NULL);
    assert(strcmp(host, "example.com") == 0);
    curl_free(host);

    /* Test dup */
    void *u2 = curl_url_dup(u);
    assert(u2 != NULL);
    assert(u2 != u);

    curl_url_cleanup(u2);
    curl_url_cleanup(u);
    /* NULL cleanup is safe */
    curl_url_cleanup(NULL);
    PASS();
}

void test_easy_getinfo_no_perform(void) {
    TEST(easy_getinfo_no_perform);
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, "http://example.com");

    /* Perform not called — getinfo returns GOT_NOTHING (no response yet) */
    long code = -1;
    int rc = curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
    /* urlx returns CURLE_GOT_NOTHING (52) when no transfer has been done */
    assert(rc != CURLE_OK);

    curl_easy_cleanup(h);
    PASS();
}

int main(void) {
    printf("liburlx-ffi C test harness\n");
    printf("==========================\n\n");

    test_easy_init_cleanup();
    test_easy_setopt_url();
    test_easy_setopt_various();
    test_easy_duphandle();
    test_easy_reset();
    test_easy_strerror();
    test_version();
    test_easy_pause();
    test_slist();
    test_url_api();
    test_easy_getinfo_no_perform();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
