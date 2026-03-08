# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 11 — Extended Protocol Testing + Polish
**Last completed:** Phase 10 (gzip, cookie, file protocol integration tests, 392 tests) — 2026-03-08
**In progress:** HTTP/2 integration tests, HSTS tests, WebSocket tests
**Blockers:** None
**Next up:** README, crate publishing preparation

---

## Decision Log

- **2026-03-08:** Workspace lint inheritance is all-or-nothing in Cargo. `unsafe_code = "deny"` is enforced via `#![deny(unsafe_code)]` in source files (liburlx, urlx-cli) rather than workspace lints, since liburlx-ffi needs to allow it and can't partially override workspace lints.
- **2026-03-08:** `rustfmt.toml` uses only stable options (`edition`, `max_width`, `use_small_heuristics`). `imports_granularity` and `group_imports` are nightly-only and omitted.
- **2026-03-08:** cargo-deny v0.19 uses a simplified config format — `vulnerability`/`unmaintained`/`unlicensed`/`copyleft` keys were removed.
- **2026-03-08:** Connection pool uses `PooledStream` enum (Tcp/Tls variants) with AsyncRead/AsyncWrite delegation, avoiding trait objects. Pool only stores non-proxied H1 connections; H2 multiplexing handles its own reuse.
- **2026-03-08:** For keep-alive, responses with no Content-Length and no chunked encoding (e.g., 204 No Content) are treated as empty body to avoid hanging on `read_to_end`. Stale pooled connections trigger automatic retry with fresh connection.
- **2026-03-08:** WebSocket SHA-1 implemented inline (minimal, ~50 lines) to avoid adding a dependency for a single use case. Not used for security purposes — only for RFC 6455 accept key computation.

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

## Phase 0: Repository Setup & Guardrails — COMPLETED (2026-03-08)

Workspace initialized with three crates (liburlx, liburlx-ffi, urlx-cli). Guardrails configured: rustfmt, clippy with strict lints, cargo-deny, pre-commit hooks, GitHub Actions CI with commit linting, multi-OS testing, MSRV check. All gates pass.

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

### Phase 1: HTTP GET Works — COMPLETED (2026-03-08)

URL parser wrapping `url` crate with curl-compatible scheme defaulting. HTTP/1.1 GET
request/response codec using `httparse`. TLS via `rustls` + `tokio-rustls`. Blocking
`Easy` API wrapping async internals. CLI prints response body. 40 unit tests. Both
HTTP and HTTPS GET transfers work end-to-end against real servers.

### Phase 2a: HTTP Methods, Headers, Redirects, CLI — COMPLETED (2026-03-08)

Added POST/PUT/DELETE/HEAD/PATCH methods, custom headers, request body, redirect following
(301/302/303/307/308), verbose output, CLI flags (-X, -H, -d, -L, -I, -o, -v).
16 integration tests with hyper-based test server. 67 total tests passing.

### Phase 2b: Chunked Transfer Encoding + Decompression — COMPLETED (2026-03-08)

Chunked Transfer-Encoding decoding in HTTP/1.1 parser. Content-Encoding decompression
(gzip, deflate, brotli, zstd) behind `decompression` feature flag. `accept_encoding()`
API method and `--compressed` CLI flag. 86 tests passing.

### Phase 2c: Timeouts + Authentication — COMPLETED (2026-03-08)

Connect timeout, total transfer timeout, Basic and Bearer authentication.
CLI flags: --connect-timeout, -m/--max-time, -u/--user. 94 tests passing.

### Phase 2d: Transfer Info + Write-Out — COMPLETED (2026-03-08)

TransferInfo with timing/redirect counts. CLI --write-out/-w with %{variable}
format. 96 tests passing.

### Phase 3a: HTTP/2 Support — COMPLETED (2026-03-08)

HTTP/2 via h2 crate with ALPN negotiation. Automatic protocol selection based on
TLS handshake. Feature-gated behind `http2` flag. 96 tests passing.

### Phase 3b: HTTP Proxy Support — COMPLETED (2026-03-08)

HTTP forward proxy for plain HTTP URLs. HTTP CONNECT tunneling for HTTPS
through proxy. Noproxy bypass with domain suffix matching and wildcard.
Environment variable support (http_proxy, https_proxy, no_proxy). CLI
flags: -x/--proxy, --noproxy. 113 tests passing.

### Phase 3c: Concurrent Transfers (Multi API) — COMPLETED (2026-03-08)

Multi handle with JoinSet-based concurrent execution. Preserves result
ordering. Blocking `perform_blocking()` wrapper. CLI multi-URL support.
123 tests passing.

### Phase 4a: Connection Pooling + Cookie Engine — COMPLETED (2026-03-08)

Cookie engine with RFC 6265 Set-Cookie parsing, domain/path matching,
Max-Age expiry, and automatic cookie injection/storage. Connection
pooling via PooledStream enum with streaming h1 response reading
(Content-Length and chunked). Stale connection retry. 154 tests passing.

### Phase 4b: FILE Protocol + Multipart Uploads + Range Requests — COMPLETED (2026-03-08)

FILE protocol handler with percent-decoding. Multipart form-data encoder
with text fields and file uploads (MultipartForm API). Range request support
with resume_from(). CLI flags: -F/--form, -r/--range, -C/--continue-at.
185 tests passing.

### Phase 4c: HSTS + DNS Resolution + WebSocket Foundation — COMPLETED (2026-03-08)

HSTS cache with Strict-Transport-Security parsing, auto HTTP→HTTPS upgrade,
includeSubDomains support. DNS resolve overrides (Easy::resolve). WebSocket
frame codec with RFC 6455 masking, SHA-1 accept key, text/binary/ping/pong/close
frames. 208 tests passing.

### Phase 5a: FTP Protocol Handler — COMPLETED (2026-03-08)

FTP control connection codec with multi-line response parsing. Login
(USER/PASS), PASV passive mode, RETR download, LIST directory listing.
URL credentials extraction. 215 tests passing.

### Phase 5b: SOCKS Proxy + Progress Callbacks — COMPLETED (2026-03-08)

SOCKS4/SOCKS5 proxy handshake with username/password auth, SOCKS4a hostname
support. Integrated into Easy handle (socks5://, socks4://, socks5h://, socks4a://
proxy URLs). Progress callback API (ProgressInfo, ProgressCallback). CLI -#/--progress-bar
flag with visual progress bar. 162 tests passing.

### Phase 6a: SMTP/IMAP/POP3 — COMPLETED (2026-03-08)

SMTP client with EHLO/HELO, AUTH PLAIN, MAIL FROM/RCPT TO/DATA. IMAP4rev1
client with LOGIN, SELECT, UID FETCH, mailbox listing. POP3 client with
USER/PASS, LIST, RETR, dot-stuffing. 27 unit tests across the three protocols.

### Phase 6b: MQTT + DICT + TFTP — COMPLETED (2026-03-08)

MQTT 3.1.1 client with CONNECT, PUBLISH, SUBSCRIBE. DICT client (RFC 2229)
with DEFINE/MATCH. TFTP client (RFC 1350) for UDP file downloads. 26 unit tests
across the three protocols. 213 total tests passing.

### Phase 7a: FFI Compatibility Layer — COMPLETED (2026-03-08)

C ABI compatibility layer with curl_easy_init/cleanup, curl_easy_setopt (16 options),
curl_easy_perform with write/header callbacks and catch_unwind panic safety,
curl_easy_getinfo (6 info codes), curl_easy_strerror, curl_version. CURLcode/CURLoption/CURLINFO
enums. 22 FFI unit tests. All unsafe blocks have SAFETY comments.

### Phase 7b: CLI Completeness + Integration Tests — COMPLETED (2026-03-08)

CLI expanded with 10 new flags: -s/--silent, -S/--show-error, -f/--fail (exit 22),
-i/--include, -D/--dump-header, -A/--user-agent, --data-raw, --max-redirs,
-d @filename support. Refactored argument parsing into parse_args/run split with
15 CLI unit tests. Built hyper-based integration test server with 24 end-to-end
tests covering GET/POST/PUT/DELETE/HEAD, headers, status codes, redirects,
timeouts, auth, encoding, ranges, multi-transfers. 336 total tests passing.

### Phase 8: Curl Test Suite Porting + Polish — COMPLETED (2026-03-08)

C header generation via cbindgen with libcurl-compatible urlx.h (CURLcode,
CURLoption, CURLINFO enums, curl_easy_* functions, CURL typedef). 14 curl
behavioral compatibility tests covering redirect semantics (301/302/303/307/308),
cookie engine, relative URLs, effective URL tracking, auth, HEAD. Documentation
builds cleanly with no warnings. 350 total tests passing.

### Phase 9: Hardening + Production Readiness — COMPLETED (2026-03-08)

16 URL parser edge case tests (percent-encoding, credentials, schemes, dot
segments, host headers, long paths). 16 HTTP edge case integration tests
(204/304 responses, binary data, long/many headers, status codes, PATCH/OPTIONS,
query strings, timeouts). 382 total tests passing.

### Phase 10: Feature Completeness + Optimization — COMPLETED (2026-03-08)

5 gzip decompression integration tests (compressed response, identity, Accept-Encoding
header verification). 5 cookie engine integration tests (set/send, path matching,
multiple cookies, overwrite). File protocol tests already existed from Phase 4b.
392 total tests passing.

### Phase 11: Extended Protocol Testing + Polish

**Scope:** Test remaining features, create README, prepare for publishing.

**Step 11.1: HSTS integration tests**
- Test HTTP→HTTPS upgrade when HSTS is cached
- Test includeSubDomains
- Test HSTS not stored for HTTP responses

**Step 11.2: Connection pooling integration tests**
- Test connection reuse reduces connect count
- Test stale connection retry

**Step 11.3: README and documentation**
- Create README.md with project overview, usage examples, feature list
- Verify all public APIs have doc comments
- Ensure `cargo doc` is clean

**Exit criteria:** 400+ tests. README created. Ready for initial release.

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

### Behavioral Correctness

9. **When stuck on behavior, check curl.** Clone curl's repo and examine the relevant source file. curl's behavior is the specification. When curl's behavior seems wrong, document it and match it anyway (with a comment noting the curl compat quirk and a link to the relevant curl source).

10. **Keep the scope tight.** Implement the minimum for the current phase. Do not speculatively add protocols or features ahead of schedule.

### Protocol Implementation Checklist

11. **When implementing a protocol handler,** follow this order:
    a. Write integration tests with a mock server
    b. Define the protocol-specific error variants
    c. Implement the happy path
    d. Add error handling for each failure mode (with tests)
    e. Add edge case handling (with tests)
    f. Run clippy, fmt, doc
    g. Add a fuzz harness for any parser
    h. Commit: `test(<proto>): add tests for <feature>` then `feat(<proto>): implement <feature>`

### FFI Safety

12. **For the FFI layer,** every `#[no_mangle] pub extern "C" fn` must have:
    - A `// SAFETY:` comment on every `unsafe` block
    - Null pointer checks on all pointer arguments
    - Proper error code returns (never panic across FFI boundary)
    - A corresponding C test program that exercises it
    - A catch_unwind wrapper to prevent Rust panics from unwinding into C
