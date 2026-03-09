# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 2 — TLS Hardening + Authentication
**Last completed:** Phase 1 (initial implementation) — 2026-03-08
**Total tests:** 1124
**In progress:** Planning Phase 2
**Blockers:** None
**Next up:** TLS configuration API, client certificates, SSL verification options, Digest/NTLM auth

---

## Decision Log

- **2026-03-08:** Workspace lint inheritance is all-or-nothing in Cargo. `unsafe_code = "deny"` is enforced via `#![deny(unsafe_code)]` in source files (liburlx, urlx-cli) rather than workspace lints, since liburlx-ffi needs to allow it and can't partially override workspace lints.
- **2026-03-08:** `rustfmt.toml` uses only stable options (`edition`, `max_width`, `use_small_heuristics`). `imports_granularity` and `group_imports` are nightly-only and omitted.
- **2026-03-08:** cargo-deny v0.19 uses a simplified config format — `vulnerability`/`unmaintained`/`unlicensed`/`copyleft` keys were removed.
- **2026-03-08:** Connection pool uses `PooledStream` enum (Tcp/Tls variants) with AsyncRead/AsyncWrite delegation, avoiding trait objects. Pool only stores non-proxied H1 connections; H2 multiplexing handles its own reuse.
- **2026-03-08:** For keep-alive, responses with no Content-Length and no chunked encoding (e.g., 204 No Content) are treated as empty body to avoid hanging on `read_to_end`. Stale pooled connections trigger automatic retry with fresh connection.
- **2026-03-08:** WebSocket SHA-1 implemented inline (minimal, ~50 lines) to avoid adding a dependency for a single use case. Not used for security purposes — only for RFC 6455 accept key computation.
- **2026-03-08:** Found and fixed WebSocket accept key GUID typo (`5AB5DC85B11B` → `C5AB0DC85B11`). The existing unit test was written against the buggy implementation. Discovered via RFC 6455 example test in integration tests.

---

## Guiding Principles

1. **Test-driven development is non-negotiable.** Every feature begins with a failing test. No code is merged without tests. Integration tests run against real protocol servers.
2. **Zero `unsafe` outside of `liburlx-ffi`.** The core library and CLI must be 100% safe Rust. All `unsafe` is confined to the FFI boundary in `liburlx-ffi` and must have `// SAFETY:` comments.
3. **Correctness over performance.** Get the behavior right first. Optimize later with benchmarks proving the need.
4. **Behavioral compatibility with curl.** When in doubt about how something should work, match curl's behavior. curl's test suite is the specification.
5. **Feature flags for optional functionality.** Each protocol, TLS backend, and optional feature is behind a Cargo feature flag. The default feature set covers HTTP/HTTPS. Minimal builds must be possible.
6. **Conventional commits.** Every commit message must follow the Conventional Commits specification. This is enforced by CI.
7. **This file is a living document.** CLAUDE.md is the project's source of truth. As work is completed, remove finished sections and add new plans for upcoming work. The file should always reflect the current state and next steps — never stale.

---

## Repository Structure

```
urlx/
├── CLAUDE.md                  # THIS FILE — project directives
├── Cargo.toml                 # Workspace root
├── deny.toml                  # cargo-deny configuration
├── clippy.toml                # Clippy configuration
├── rustfmt.toml               # Formatting configuration
├── .github/
│   └── workflows/
│       ├── ci.yml             # Main CI pipeline
│       └── release.yml        # Release pipeline
├── .pre-commit-config.yaml    # Pre-commit hooks
│
├── crates/
│   ├── liburlx/               # Core library (pure Rust, idiomatic API)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── easy.rs        # Single-transfer blocking API
│   │       ├── multi.rs       # Concurrent transfer API (async-native)
│   │       ├── error.rs       # Error types (maps to CURLcode)
│   │       ├── options.rs     # Typed transfer options
│   │       ├── info.rs        # Transfer info/stats queries
│   │       ├── url.rs         # URL parsing (wraps `url` crate with curl quirks)
│   │       ├── transfer.rs    # Transfer state machine
│   │       ├── pool.rs        # Connection pooling and reuse
│   │       ├── filter.rs      # Connection filter chain framework
│   │       ├── cookie.rs      # Cookie jar engine
│   │       ├── protocol/
│   │       │   ├── mod.rs     # Protocol trait definition
│   │       │   ├── http/
│   │       │   │   ├── mod.rs
│   │       │   │   ├── h1.rs  # HTTP/1.0 and HTTP/1.1
│   │       │   │   ├── h2.rs  # HTTP/2
│   │       │   │   ├── h3.rs  # HTTP/3 (feature-gated)
│   │       │   │   ├── headers.rs
│   │       │   │   ├── chunked.rs
│   │       │   │   └── body.rs
│   │       │   ├── ftp.rs
│   │       │   ├── ws.rs      # WebSocket
│   │       │   ├── mqtt.rs
│   │       │   ├── smtp.rs
│   │       │   ├── imap.rs
│   │       │   ├── pop3.rs
│   │       │   ├── file.rs    # file:// protocol
│   │       │   └── ...
│   │       ├── tls/
│   │       │   ├── mod.rs     # TlsConnector trait
│   │       │   ├── rustls.rs  # Default backend
│   │       │   └── native.rs  # Platform-native (Schannel/SecureTransport)
│   │       ├── dns/
│   │       │   ├── mod.rs     # Resolver trait
│   │       │   ├── system.rs  # System resolver
│   │       │   └── hickory.rs # Async resolver (hickory-dns)
│   │       ├── proxy/
│   │       │   ├── mod.rs
│   │       │   ├── http.rs    # HTTP CONNECT
│   │       │   └── socks.rs   # SOCKS4/SOCKS5
│   │       └── auth/
│   │           ├── mod.rs
│   │           ├── basic.rs
│   │           ├── digest.rs
│   │           ├── bearer.rs
│   │           └── negotiate.rs
│   │
│   ├── liburlx-ffi/           # C ABI compatibility layer
│   │   ├── Cargo.toml
│   │   ├── cbindgen.toml      # C header generation config
│   │   ├── include/
│   │   │   └── urlx.h         # Generated C header (libcurl-compatible)
│   │   └── src/
│   │       ├── lib.rs         # #[no_mangle] extern "C" exports
│   │       ├── easy.rs        # curl_easy_* function implementations
│   │       ├── multi.rs       # curl_multi_* function implementations
│   │       ├── options.rs     # CURLOPT_* integer → typed option mapping
│   │       ├── info.rs        # CURLINFO_* mapping
│   │       └── error.rs       # CURLcode enum and conversion
│   │
│   └── urlx-cli/              # Command-line tool
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── args.rs        # Argument parsing (clap, mirrors curl's CLI)
│           ├── config.rs      # .curlrc / config file parsing
│           ├── output.rs      # --write-out formatting
│           └── progress.rs    # Progress bar/meter display
│
├── tests/                     # Integration test suite
│   ├── fixtures/              # Static test fixtures (certs, data files)
│   │   ├── certs/            # TLS test certificates (generated by setup)
│   │   └── data/             # Test response bodies
│   ├── servers/               # Test server implementations
│   │   ├── mod.rs
│   │   ├── http.rs           # HTTP/1.1 + HTTP/2 test server
│   │   ├── https.rs          # HTTPS test server
│   │   ├── proxy.rs          # HTTP/SOCKS proxy test server
│   │   ├── ftp.rs            # FTP test server
│   │   └── echo.rs           # Generic echo/mirror server
│   ├── common/                # Shared test utilities
│   │   ├── mod.rs
│   │   └── assertions.rs     # Custom assertion helpers
│   ├── http_basic.rs          # HTTP GET/POST/PUT/DELETE/HEAD
│   ├── http_headers.rs        # Header handling, encoding
│   ├── http_redirect.rs       # Redirect following (3xx)
│   ├── http_auth.rs           # Authentication mechanisms
│   ├── http_proxy.rs          # Proxy tunneling
│   ├── http_cookies.rs        # Cookie engine
│   ├── http_tls.rs            # TLS/HTTPS behavior
│   ├── http_upload.rs         # POST bodies, multipart, PUT
│   ├── http_download.rs       # Large transfers, resume, range
│   ├── http_h2.rs             # HTTP/2 specific
│   ├── http_encoding.rs       # Content-Encoding (gzip, br, zstd)
│   ├── connection_pool.rs     # Connection reuse
│   ├── dns.rs                 # DNS resolution behavior
│   ├── url_parsing.rs         # URL handling edge cases
│   ├── error_handling.rs      # Error code correctness
│   ├── ffi_compat.rs          # libcurl C ABI compatibility
│   └── curl_test_compat/      # Ported curl test cases
│       ├── mod.rs
│       └── ...                # Translated from curl's test data
│
└── benches/                   # Benchmarks
    ├── throughput.rs           # Transfer throughput
    ├── latency.rs             # Connection setup latency
    └── concurrency.rs         # Multi-transfer performance
```

---

## Test-Driven Development Protocol

### The TDD Cycle for Every Feature

1. **Write the test first.** The test must fail (or not compile) before any implementation.
2. **Write the minimum code to pass.** No speculative features.
3. **Refactor.** Clean up while all tests still pass.
4. **Verify guardrails.** `cargo clippy`, `cargo fmt`, `cargo doc` must all pass.

### Test Categories

#### Unit Tests (in-crate `#[cfg(test)]` modules)

Every public function, every struct method, every non-trivial private function. Located alongside the code in each crate. Run with `cargo test --lib`.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parse_simple_https() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn url_parse_rejects_empty() {
        assert!(Url::parse("").is_err());
    }
}
```

#### Integration Tests (`tests/` directory)

Test the library through its public API against real servers. Each test file focuses on one behavioral area. Run with `cargo test --test '*'`.

The integration test framework must include:

- **Test servers** written in Rust (using `hyper`, `tokio`) that can be spun up per-test or per-suite. These run on random ports to avoid conflicts.
- **Assertion helpers** that verify response status, headers, body, timing, and error codes.
- **Fixtures** for TLS certificates, test data files, cookie files.

```rust
// tests/http_basic.rs
use liburlx::Easy;
use crate::servers::HttpServer;

#[tokio::test]
async fn get_returns_200_with_body() {
    let server = HttpServer::start(|req| {
        assert_eq!(req.method(), "GET");
        Response::ok("hello world")
    }).await;

    let mut easy = Easy::new();
    easy.url(&server.url("/")).unwrap();
    let response = easy.perform().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body_str(), "hello world");
}

#[tokio::test]
async fn get_follows_redirect() {
    let server = HttpServer::start(|req| match req.path() {
        "/start" => Response::redirect(302, "/end"),
        "/end" => Response::ok("final"),
        _ => Response::not_found(),
    }).await;

    let mut easy = Easy::new();
    easy.url(&server.url("/start")).unwrap();
    easy.follow_redirects(true).unwrap();
    let response = easy.perform().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body_str(), "final");
    assert_eq!(response.effective_url(), server.url("/end"));
}
```

#### Curl Compatibility Tests

These are the most important tests for the FFI layer. The strategy:

1. **Port curl's Python HTTP tests.** curl's `tests/http/test_*.py` suite uses pytest and speaks to real servers. We adapt this framework to test urlx. These tests are authoritative for behavioral compatibility.

2. **Port curl's XML test data.** The 1,918 XML test cases in `tests/data/` define exact request/response pairs. Write a test runner that:
   - Parses curl's XML test format
   - Starts the appropriate test server
   - Runs the equivalent urlx operation
   - Verifies the wire protocol matches curl's expected output

3. **Differential testing.** For any test that passes with urlx, also run it with the real curl binary and compare outputs. Differences are bugs until proven otherwise.

```rust
// tests/curl_test_compat/mod.rs

/// Runs a curl XML test case against liburlx.
/// Returns Ok(()) if behavior matches curl, Err with diff if not.
fn run_curl_test(test_id: u32) -> Result<(), TestDifference> {
    let test_case = CurlTestCase::load(test_id)?;
    let server = test_case.start_server()?;
    let result = test_case.run_with_urlx(&server)?;
    test_case.verify(result)
}
```

#### Property-Based Tests

Use `proptest` for parser correctness:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn url_roundtrip(s in "https?://[a-z]{1,20}\\.[a-z]{2,4}/[a-z0-9/]{0,50}") {
        if let Ok(parsed) = Url::parse(&s) {
            let reparsed = Url::parse(parsed.as_str()).unwrap();
            assert_eq!(parsed, reparsed);
        }
    }
}
```

#### FFI Tests

The `liburlx-ffi` crate must have C-language test programs that link against the library and exercise the libcurl-compatible API:

```c
// tests/ffi/test_easy_get.c
#include "urlx.h"  // libcurl-compatible header

int main(void) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/get");
    CURLcode res = curl_easy_perform(curl);
    assert(res == CURLE_OK);

    long code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    assert(code == 200);

    curl_easy_cleanup(curl);
    return 0;
}
```

These are compiled and run by a build script or test harness to verify ABI compatibility.

### Coverage Requirements

- **Unit test coverage target: 80%+** for all crates. Measured by `cargo-tarpaulin`.
- **Integration test coverage: every public API function** must be exercised.
- **Every bug fix must include a regression test** that would have caught it.

---

## Implementation Phases

### Phase 1: Initial Implementation — COMPLETED (2026-03-08)

Repository setup, guardrails (rustfmt, clippy, cargo-deny, CI), and core implementation of HTTP/1.1, HTTP/2, FTP, FILE, WebSocket, MQTT, SMTP, IMAP, POP3, TFTP, DICT protocols. Includes Easy/Multi APIs, connection pooling, cookie engine, HSTS, SOCKS4/5 proxy, HTTP proxy, chunked encoding, gzip/br/zstd decompression, Basic/Bearer auth, progress callbacks, multipart uploads, range requests, DNS resolve overrides, fail_on_error. FFI layer with 17 CURLOPT options and 6 CURLINFO codes. CLI with 24 flags. 1124 tests, property-based tests, fuzz harnesses, and benchmarks. All guardrails pass.

### Phase 2: TLS Hardening + Authentication

**Goal:** Make TLS fully configurable and add missing authentication mechanisms so urlx can be used in enterprise environments.

- **TLS configuration API:** `ssl_verify_peer(bool)`, `ssl_verify_host(bool)`, `cacert(path)`, `capath(path)`, `client_cert(path)`, `client_key(path)`, `tls_version_min(TlsVersion)`, `ciphers(string)`, `tls13_ciphers(string)`
- **Certificate pinning:** `pinned_pubkey(hash)` for HPKP-style pinning
- **OCSP stapling:** Support via rustls
- **-k/--insecure CLI flag:** Skip peer certificate verification
- **Digest authentication:** RFC 7616 implementation (MD5, SHA-256)
- **NTLM authentication:** Basic NTLM challenge/response
- **Negotiate/Kerberos:** SPNEGO via system GSSAPI (feature-gated)
- **CURLOPT_HTTPAUTH:** Auth type selection bitmask in Easy API and FFI
- **CLI flags:** `--cert`, `--key`, `--cacert`, `--capath`, `--ciphers`, `--tlsv1.0/1.1/1.2/1.3`, `--digest`, `--ntlm`, `--negotiate`
- **FFI options:** CURLOPT_SSLCERT, CURLOPT_SSLKEY, CURLOPT_CAINFO, CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, CURLOPT_SSLVERSION, CURLOPT_HTTPAUTH, CURLOPT_USERPWD

### Phase 3: HTTP Completeness + Upload Streams

**Goal:** Complete HTTP protocol coverage including version negotiation, conditional requests, Expect-100, chunked request bodies, and streaming uploads.

- **HTTP version forcing:** `http_version(HttpVersion)` — support HTTP/1.0, HTTP/1.1, HTTP/2-only, HTTP/2-with-fallback
- **Expect 100-continue:** Send `Expect: 100-continue` header, wait for 100 response before sending body
- **Chunked request body encoding:** Streaming request bodies with Transfer-Encoding: chunked
- **Conditional requests:** `time_condition(TimeCond)`, `time_value(SystemTime)` for If-Modified-Since / If-Unmodified-Since; ETag support via If-Match / If-None-Match
- **Streaming uploads:** `upload(bool)`, `read_function(callback)`, `in_filesize(u64)` for PUT/POST streaming from file or callback
- **Referer header:** `-e/--referer` CLI flag, `referer(url)` Easy API method
- **Max filesize:** `max_filesize(u64)` to abort transfers exceeding a size limit
- **HTTP trailers:** Support reading HTTP trailers in chunked responses
- **CLI flags:** `--http1.0`, `--http1.1`, `--http2`, `--post301`, `--post302`, `--post303`, `--location-trusted`, `-e/--referer`, `--max-filesize`, `-T/--upload-file`, `-G/--get`
- **FFI options:** CURLOPT_HTTP_VERSION, CURLOPT_UPLOAD, CURLOPT_INFILESIZE, CURLOPT_READFUNCTION, CURLOPT_READDATA, CURLOPT_TIMECONDITION, CURLOPT_TIMEVALUE, CURLOPT_EXPECT_100_TIMEOUT_MS, CURLOPT_REFERER

### Phase 4: Retry, Rate Limiting + Networking Controls

**Goal:** Add retry logic, bandwidth throttling, and low-level networking options that enterprise and scripting users depend on.

- **Retry logic:** `--retry <n>`, `--retry-delay <secs>`, `--retry-max-time <secs>`, `--retry-all-errors` with exponential backoff; Easy API: `retry(RetryConfig)`
- **Rate limiting:** `--limit-rate <speed>` bandwidth throttling via token-bucket; Easy API: `max_recv_speed(u64)`, `max_send_speed(u64)`
- **Speed limits:** `--speed-limit <bps>` + `--speed-time <secs>` to abort slow transfers; Easy API: `low_speed_limit(u64)`, `low_speed_time(Duration)`
- **Interface binding:** `--interface <name>` to bind outbound connections to a local interface
- **Local port:** `--local-port <range>` for outbound port selection
- **TCP options:** `tcp_keepalive(bool)`, `tcp_keepidle(Duration)`, `tcp_keepintvl(Duration)`, `tcp_nodelay(bool)`
- **Unix sockets:** `--unix-socket <path>`, `--abstract-unix-socket <path>`; Easy API: `unix_socket_path(path)`
- **IP version selection:** `--ipv4` / `--ipv6` to force IPv4 or IPv6; Easy API: `ip_resolve(IpResolve)`
- **Connect-to:** `--connect-to <host:port:addr:port>` for connection remapping
- **FFI options:** CURLOPT_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_TIME, CURLOPT_MAX_RECV_SPEED_LARGE, CURLOPT_MAX_SEND_SPEED_LARGE, CURLOPT_INTERFACE, CURLOPT_LOCALPORT, CURLOPT_TCP_KEEPALIVE, CURLOPT_TCP_NODELAY, CURLOPT_UNIX_SOCKET_PATH, CURLOPT_IPRESOLVE, CURLOPT_CONNECT_TO

### Phase 5: CLI Parity + Configuration Files

**Goal:** Bring CLI flag count from 24 to 100+ and add config file support so urlx can serve as a real drop-in for the `curl` binary.

- **Config file loading:** `-K/--config <file>`, `.curlrc` auto-loading; parse curl config file format (one flag per line, comments with #)
- **Netrc support:** `--netrc`, `--netrc-file <path>`, `--netrc-optional`; parse standard .netrc format for automatic credentials
- **Output control:** `-O/--remote-name` (save with server filename), `--remote-header-name` (Content-Disposition), `--create-dirs`, `-o` with `#` expansion for multi-URL, `-J/--remote-header-name`
- **Data variants:** `--data-urlencode`, `--data-binary`, `--form-string`, `--data-ascii`
- **Protocol whitelist:** `--proto <list>`, `--proto-redir <list>` to restrict allowed protocols
- **Parallel control:** `--parallel`, `--parallel-max <n>`, `--parallel-immediate`
- **Cookie CLI:** `-b/--cookie <data|file>`, `-c/--cookie-jar <file>`
- **Resolve CLI:** `--resolve <host:port:addr>` (wiring existing Easy API to CLI)
- **Misc flags:** `--compressed` improvements, `--raw`, `--path-as-is`, `--request-target`, `--oauth2-bearer`, `--no-alpn`, `--no-sessionid`, `--trace`, `--trace-ascii`, `--stderr`
- **Exit codes:** Match curl's exit code behavior for all error scenarios

### Phase 6: FFI API Expansion + Multi C API

**Goal:** Expand FFI coverage from ~17 CURLOPT to 80+ and expose the Multi API through C ABI so liburlx-ffi is a credible libcurl replacement.

- **CURLOPT expansion:** Map all options added in Phases 2-5 to FFI integer constants; target 80+ CURLOPT codes
- **CURLINFO expansion:** Add all timing info codes (CURLINFO_NAMELOOKUP_TIME, CURLINFO_CONNECT_TIME, CURLINFO_APPCONNECT_TIME, CURLINFO_PRETRANSFER_TIME, CURLINFO_STARTTRANSFER_TIME, CURLINFO_REDIRECT_TIME), size codes (CURLINFO_HEADER_SIZE, CURLINFO_REQUEST_SIZE, CURLINFO_SPEED_DOWNLOAD, CURLINFO_SPEED_UPLOAD), connection info (CURLINFO_PRIMARY_IP, CURLINFO_PRIMARY_PORT, CURLINFO_LOCAL_IP, CURLINFO_LOCAL_PORT, CURLINFO_NUM_CONNECTS), SSL info (CURLINFO_SSL_VERIFYRESULT, CURLINFO_CERTINFO), protocol info (CURLINFO_PROTOCOL, CURLINFO_EFFECTIVE_METHOD, CURLINFO_COOKIELIST, CURLINFO_FTP_ENTRY_PATH, CURLINFO_REDIRECT_URL, CURLINFO_CONDITION_UNMET). Target 35+ CURLINFO codes
- **curl_multi_* FFI:** `curl_multi_init`, `curl_multi_cleanup`, `curl_multi_add_handle`, `curl_multi_remove_handle`, `curl_multi_perform`, `curl_multi_wait`, `curl_multi_wakeup`, `curl_multi_timeout`, `curl_multi_fdset`, `curl_multi_info_read`, `curl_multi_setopt`
- **curl_share_* FFI:** `curl_share_init`, `curl_share_cleanup`, `curl_share_setopt` for cookie/DNS/SSL session sharing between handles
- **curl_url_* FFI:** URL builder/parser API (`curl_url`, `curl_url_set`, `curl_url_get`, `curl_url_cleanup`, `curl_url_dup`)
- **curl_mime_* FFI:** Structured MIME/multipart builder (`curl_mime_init`, `curl_mime_addpart`, `curl_mime_name`, `curl_mime_data`, `curl_mime_filedata`, `curl_mime_type`, `curl_mime_free`)
- **curl_slist_* FFI:** Linked list API (`curl_slist_append`, `curl_slist_free_all`)
- **Global functions:** `curl_global_init`, `curl_global_cleanup`, `curl_version_info` (with feature bitmask and protocol list)
- **C test programs:** One test per major API surface (easy, multi, share, url, mime, slist)

### Phase 7: Missing Protocols + Protocol Hardening

**Goal:** Implement remaining protocols and harden existing ones so all of curl's protocol surface is covered.

- **HTTP/3:** QUIC transport via `quinn` crate, H3 codec, ALPN for h3, `--http3` CLI flag, feature-gated behind `http3`
- **SCP/SFTP:** SSH-based file transfer via `ssh2` crate, feature-gated behind `sftp`
- **Telnet:** Interactive bidirectional protocol handler
- **RTSP:** Real-Time Streaming Protocol (DESCRIBE, SETUP, PLAY, TEARDOWN)
- **LDAP/LDAPS:** Directory protocol via `ldap3` crate, feature-gated behind `ldap`
- **SMB/SMBS:** Windows file sharing protocol via `pavao` or custom, feature-gated
- **Gopher:** Simple text protocol handler
- **Protocol hardening:** Wire existing protocol implementations (SMTP, IMAP, POP3, MQTT, DICT, TFTP, FTP, WebSocket, FILE) into the transfer state machine so they work end-to-end through the Easy/Multi API, not just as standalone codec modules. Add integration tests with real mock servers for each
- **FTPS/IMAPS/SMTPS/POP3S:** TLS upgrade (STARTTLS) for each protocol that supports it
- **FTP active mode:** PORT command for active FTP connections
- **FTP directory creation:** `--ftp-create-dirs` support
- **WebSocket over TLS:** wss:// support with proper TLS handshake
- **OAuth2 for mail protocols:** SMTP/IMAP/POP3 with XOAUTH2 authentication

### Phase 8: DNS + Connection Infrastructure

**Goal:** Advanced DNS resolution, connection pooling configuration, and Happy Eyeballs for robust networking.

- **Async DNS resolver:** Integrate `hickory-dns` behind `dns-over-https` feature flag
- **Custom DNS servers:** `--dns-servers <list>` CLI flag, `dns_servers(list)` Easy API
- **DNS cache control:** `dns_cache_timeout(Duration)` to configure TTL, DNS cache flushing
- **Happy Eyeballs (RFC 8305):** Concurrent IPv4/IPv6 connection racing with configurable delay
- **Connection pool configuration:** Expose pool size, idle timeout, max connections per host
- **HTTP/2 multiplexing controls:** Stream priorities, SETTINGS frame configuration, concurrent stream limits
- **Connection filter chain:** Formalize the filter pipeline (DNS → TCP → TLS → Proxy → Protocol) with composable filter traits
- **Platform-native TLS backends:** SecureTransport (macOS), Schannel (Windows) behind `native-tls` feature flag
- **SSL session caching:** Reuse TLS sessions across connections to the same host

### Phase 9: Curl Test Suite Porting + Differential Testing

**Goal:** Systematically port curl's test suite to validate behavioral compatibility and catch divergences.

- **Python HTTP test porting:** Port curl's ~280 pytest-based HTTP tests from `tests/http/test_*.py` to Rust integration tests
- **XML test data runner:** Build a test runner that parses curl's XML test format (tests/data/test1 through test1918), spins up mock servers, and verifies urlx matches curl's expected wire protocol
- **Differential test framework:** `cargo test --features differential-testing` runs operations against both urlx and the real curl binary, comparing status codes, headers, and response bodies
- **Mapping file:** Maintain `tests/curl_test_compat/MAPPING.md` tracking which curl test ID maps to which urlx test
- **HTTP test target:** Port ~893 HTTP-only XML tests (636 GET + 109 POST + 49 PUT + 99 redirect)
- **C unit test porting:** Selectively port curl's 59 C unit tests that test internal functions relevant to FFI compatibility
- **Coverage gate:** Achieve 80%+ code coverage measured by cargo-tarpaulin

### Phase 10: Codebase Review — Drop-in Readiness Audit

**Goal:** Comprehensive review of the entire codebase against curl/libcurl to identify remaining gaps, inconsistencies, and quality issues. This is a mandatory review phase — no new features, only analysis and planning.

- **CLI flag audit:** Compare every curl CLI flag against urlx-cli; document which are implemented, which are missing, and prioritize remaining gaps
- **CURLOPT audit:** Compare every CURLOPT_* constant in curl's `include/curl/curl.h` against liburlx-ffi; document coverage percentage and missing options
- **CURLINFO audit:** Same for CURLINFO_* codes
- **Protocol integration audit:** For each protocol module, verify it works end-to-end through Easy::perform(), not just as an isolated codec. Document which protocols are fully wired vs. codec-only
- **Error code audit:** Compare CURLcode values and ensure every error path in urlx maps to the correct curl error code
- **Behavioral diff testing:** Run the differential test suite and catalog all behavioral differences between urlx and curl
- **Performance baseline:** Run benchmarks and compare throughput/latency against curl for common operations (HTTP GET, POST, file upload, parallel transfers)
- **Security review:** Audit all unsafe code in liburlx-ffi, review TLS configuration defaults, check for OWASP-style vulnerabilities
- **Output:** Updated CLAUDE.md with findings and a prioritized Phase 11-20 roadmap based on what the audit reveals

> **Mandatory review cadence:** Every 10th phase (Phase 10, Phase 20, Phase 30, ...) must be a full codebase review following this same template. No new features are implemented during review phases. The review produces an updated roadmap for the next 9 phases based on current gaps.

---

## Code Style & Conventions

### Error Handling

- Use `thiserror` for error type derivation.
- All public functions return `Result<T, UrlxError>`.
- Error types must be non-exhaustive (`#[non_exhaustive]`) to allow future additions.
- Never panic. Never `unwrap()` in library code. The `unwrap_used` clippy lint is denied.
- In test code, `unwrap()` and `expect()` are fine.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("connection failed: {0}")]
    Connect(#[source] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("HTTP protocol error: {0}")]
    Http(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    // Maps to CURLcode for FFI
    #[error("transfer error (code {code}): {message}")]
    Transfer { code: u32, message: String },
}
```

### Naming Conventions

- Crate names: `liburlx`, `liburlx-ffi`, `urlx-cli`
- Module names: `snake_case`
- Types: `PascalCase`
- Functions: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Feature flags: `kebab-case` (e.g., `http2`, `ftp`, `rustls`, `native-tls`)

### Documentation

- Every public item must have a doc comment.
- Every module must have a module-level doc comment explaining its purpose.
- Examples in doc comments must compile (enforced by `cargo test --doc`).
- Use `#![warn(missing_docs)]` in all crate roots.

### Async Architecture

The core is async (tokio). The Easy API provides a sync wrapper:

```rust
// Internal: async core
pub(crate) async fn perform_transfer(opts: &TransferOptions) -> Result<Response> {
    // ...async implementation...
}

// Public: blocking Easy API (wraps async)
impl Easy {
    pub fn perform(&mut self) -> Result<Response> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(perform_transfer(&self.options))
    }
}

// Public: async Multi API (native)
impl Multi {
    pub async fn perform(&mut self) -> Result<Vec<Response>> {
        // ...direct async...
    }
}
```

### Feature Flags

In `crates/liburlx/Cargo.toml`:

```toml
[features]
default = ["http", "rustls", "cookies", "decompression"]

# Protocols
http = []
http2 = ["dep:h2"]
http3 = ["dep:quinn"]
ftp = []
mqtt = []
ws = []              # WebSocket
smtp = []
imap = []
pop3 = []
sftp = ["dep:ssh2"]
file = []
ldap = ["dep:ldap3"]

# TLS
rustls = ["dep:rustls", "dep:webpki-roots"]
native-tls = ["dep:native-tls"]

# Features
cookies = []
decompression = ["dep:flate2", "dep:brotli", "dep:zstd"]
hsts = []
dns-over-https = []
socks = []
```

---

## Porting curl's Test Suite

### Strategy

curl has three test layers. We port them in order of value:

#### 1. Python HTTP Tests (highest value, port first)

Located in `curl/tests/http/test_*.py`. These are modern pytest-based tests that speak to real HTTP servers. There are ~280 test functions covering basic HTTP, downloads, uploads, proxies, auth, TLS, WebSockets, etc.

**Porting approach:**
- Rewrite each Python test as a Rust integration test in `tests/`.
- Replace `CurlClient` invocations with `liburlx::Easy` calls.
- Replace curl's httpd/nghttpx test servers with our own Rust test servers.
- Maintain a mapping file (`tests/curl_test_compat/MAPPING.md`) tracking which curl test maps to which urlx test.

#### 2. XML Test Data (high value, port second)

Located in `curl/tests/data/test1` through `test1918`. Each defines a mock server response, the curl command to run, and the expected wire protocol.

**Porting approach:**
- Write a Rust test runner that parses curl's XML test format.
- For each test, spin up a mock server that returns the specified response.
- Execute the equivalent operation via `liburlx`.
- Verify the request sent matches the expected protocol output.
- Track pass/fail rates. Start by targeting HTTP-only tests (~636 GET + ~109 POST + ~49 PUT + ~99 redirect = ~893 tests).

#### 3. C Unit Tests (lower priority)

59 unit tests in `curl/tests/unit/`. These test internal libcurl functions. Relevant for FFI compatibility but not for the Rust-native API. Port selectively as needed during Phase 5.

### Differential Testing

For maximum confidence, set up a differential test mode:

```rust
/// Run the same operation with both urlx and real curl, compare results.
#[cfg(feature = "differential-testing")]
fn differential_test(url: &str, opts: &[&str]) {
    let urlx_result = run_with_urlx(url, opts);
    let curl_result = run_with_curl_binary(url, opts);

    assert_eq!(urlx_result.status, curl_result.status);
    assert_eq!(urlx_result.headers, curl_result.headers);
    assert_eq!(urlx_result.body, curl_result.body);
}
```

---

## What We're Replacing: Component Map

For reference, here is the complete component inventory of curl/libcurl with line counts, priorities, and the Rust crate/approach for each.

### Protocol Handlers (~60K lines of C)

| Protocol | C Lines | Priority | Rust Approach |
|----------|--------:|----------|--------------|
| HTTP/1+2+3 | 16,571 | P0 | Custom h1 codec + h2 crate + quinn |
| FTP/FTPS | 10,123 | P2 | Custom implementation |
| IMAP/IMAPS | 4,720 | P3 | async-imap or custom |
| SMTP/SMTPS | 4,082 | P3 | lettre or custom |
| WebSocket | 4,022 | P1 | tokio-tungstenite |
| POP3/POP3S | 3,498 | P3 | Custom |
| Telnet | 3,216 | P4 | Custom |
| TFTP | 2,742 | P4 | Custom |
| SMB/SMBS | 2,524 | P3 | pavao |
| RTSP | 2,192 | P4 | Custom |
| MQTT | 2,082 | P2 | rumqttc |
| LDAP/LDAPS | 2,070 | P3 | ldap3 |
| FILE | 1,318 | P1 | std::fs |
| DICT | 628 | P4 | Custom |
| Gopher | 486 | P4 | Custom |

### TLS (~23K lines) → rustls as default, trait for alternatives
### SSH (~7K lines) → ssh2 crate
### Connection Filters (~6.5K lines) → Custom filter chain trait
### Authentication (~5K lines) → Custom, per-mechanism
### DNS (~4K lines) → hickory-dns
### Core Infrastructure (~22K lines) → Custom Rust architecture
### CLI Tool (~19K lines) → clap-based argument parsing

---

## Agent Instructions

When working on this project:

### Guardrails

1. **Always check guardrails after every change.** Run `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc` after every meaningful code change. Fix issues immediately. Do not proceed with broken guardrails.

2. **Never suppress warnings.** If clippy or the compiler warns about something, fix it properly. The only allowed suppressions are targeted `#[allow(...)]` with a comment explaining why.

### Test-Driven Development

3. **Write the test before the implementation.** If you find yourself writing implementation code without a corresponding test, stop and write the test first.

4. **Every bug fix must include a regression test** that would have caught it.

### Commits

5. **Use conventional commits for every commit.** Format: `<type>(<scope>): <description>`. Never commit with a freeform message. Examples:
   - `feat(http): add chunked transfer encoding`
   - `test(url): add edge case tests for IDN domains`
   - `fix(cookie): match curl behavior for expired cookie cleanup`
   - `chore: update dependencies`
   - `docs: update CLAUDE.md — mark Phase 1 complete`

6. **Commit atomically.** Each commit should be one logical change with one type. If a commit needs both `feat` and `test`, split it into `test(...): add tests for X` followed by `feat(...): implement X`. The test commit comes first.

7. **Scope names** must match crate or module names: `http`, `ftp`, `tls`, `url`, `cookie`, `dns`, `proxy`, `auth`, `ffi`, `cli`, `pool`, `filter`, `ws`, `mqtt`, `smtp`, `imap`. Use no scope for cross-cutting changes.

### Maintaining CLAUDE.md

8. **This file is a living document. Update it as you work.** CLAUDE.md must always reflect the current state of the project and the immediate next steps. Specifically:

   - **When a phase or section is fully complete,** remove the detailed implementation steps for that phase and replace them with a brief "Completed" summary noting what was built and when. Do not leave stale instructions that have already been followed.

   - **When starting a new phase,** expand the next phase's section with detailed, actionable implementation steps — the specific tests to write, the specific modules to create, the specific behaviors to implement. Future phases should remain as brief outlines until they become current.

   - **When plans change** (a dependency doesn't work out, a design decision is revised, a new problem is discovered), update this file immediately. Do not leave instructions that contradict reality.

   - **Add a `## Current Status` section at the top** (below Project Identity) that is updated with every phase transition. It should contain:
     - What phase the project is in
     - What was most recently completed
     - What is currently being worked on
     - Any blockers or open questions

   - **Add a `## Decision Log` section** where significant architectural or design decisions are recorded with date and rationale. This prevents re-litigating settled decisions.

   Example status section:
   ```markdown
   ## Current Status
   **Phase:** 1 — HTTP GET Works
   **Last completed:** Phase 0 (repo setup, guardrails, CI) — 2026-03-15
   **In progress:** URL parser with curl compatibility quirks
   **Blockers:** None
   **Next up:** TCP connector with Happy Eyeballs
   ```

   Example decision log entry:
   ```markdown
   ## Decision Log
   - **2026-03-10:** Chose `rustls` over `native-tls` as default TLS backend. Rationale: pure Rust, no OpenSSL dependency, audited, used by Cloudflare in production. Platform-native backends (Schannel, SecureTransport) available behind `native-tls` feature flag.
   ```

### Review Phases

9. **Every 10th phase is a mandatory codebase review.** Phases 10, 20, 30, etc. are dedicated to auditing the entire codebase against curl/libcurl. No new features are implemented during review phases. The review compares CLI flags, CURLOPT/CURLINFO coverage, protocol integration, error codes, behavioral differences, and performance. The output is an updated CLAUDE.md with a prioritized roadmap for the next 9 phases.

### Behavioral Correctness

10. **When stuck on behavior, check curl.** Clone curl's repo and examine the relevant source file. curl's behavior is the specification. When curl's behavior seems wrong, document it and match it anyway (with a comment noting the curl compat quirk and a link to the relevant curl source).

11. **Keep the scope tight.** Implement the minimum for the current phase. Do not speculatively add protocols or features ahead of schedule.

### Protocol Implementation Checklist

12. **When implementing a protocol handler,** follow this order:
    a. Write integration tests with a mock server
    b. Define the protocol-specific error variants
    c. Implement the happy path
    d. Add error handling for each failure mode (with tests)
    e. Add edge case handling (with tests)
    f. Run clippy, fmt, doc
    g. Add a fuzz harness for any parser
    h. Commit: `test(<proto>): add tests for <feature>` then `feat(<proto>): implement <feature>`

### FFI Safety

13. **For the FFI layer,** every `#[no_mangle] pub extern "C" fn` must have:
    - A `// SAFETY:` comment on every `unsafe` block
    - Null pointer checks on all pointer arguments
    - Proper error code returns (never panic across FFI boundary)
    - A corresponding C test program that exercises it
    - A catch_unwind wrapper to prevent Rust panics from unwinding into C
