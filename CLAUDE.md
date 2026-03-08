# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 3a — HTTP/2 Support
**Last completed:** Phase 2d (transfer info, --write-out) — 2026-03-08
**In progress:** HTTP/2 via h2 crate, ALPN negotiation
**Blockers:** None
**Next up:** Phase 3b (proxy support), Phase 3c (concurrent transfers)

---

## Decision Log

- **2026-03-08:** Workspace lint inheritance is all-or-nothing in Cargo. `unsafe_code = "deny"` is enforced via `#![deny(unsafe_code)]` in source files (liburlx, urlx-cli) rather than workspace lints, since liburlx-ffi needs to allow it and can't partially override workspace lints.
- **2026-03-08:** `rustfmt.toml` uses only stable options (`edition`, `max_width`, `use_small_heuristics`). `imports_granularity` and `group_imports` are nightly-only and omitted.
- **2026-03-08:** cargo-deny v0.19 uses a simplified config format — `vulnerability`/`unmaintained`/`unlicensed`/`copyleft` keys were removed.

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

### Phase 2b: Chunked Transfer Encoding + Content-Encoding Decompression (CURRENT)

**Scope:** Handle chunked transfer encoding and compressed responses. Without these,
many real-world HTTP responses are broken.

**Step 2b.1: Chunked transfer encoding**
- Add chunked decoding to `parse_response()` in h1.rs
- Detect `Transfer-Encoding: chunked` header
- Parse chunk size + data format (size\r\n data\r\n ... 0\r\n\r\n)
- Unit tests for chunked parsing (single chunk, multiple chunks, empty, trailers)
- Integration test with hyper (hyper sends chunked by default for streaming bodies)

**Step 2b.2: Content-Encoding decompression**
- Add `decompression` feature flag with deps: flate2, brotli, zstd
- Send `Accept-Encoding: gzip, deflate, br, zstd` when decompression enabled
- Detect `Content-Encoding` header and decompress body
- Add `accept_encoding()` method to Easy API
- Add `--compressed` CLI flag
- Unit tests for each encoding
- Integration test with gzip-compressed server response

**Exit criteria:** Chunked responses and gzip/br/zstd compressed responses decode correctly.

### Phase 2b: Chunked Transfer Encoding + Decompression — COMPLETED (2026-03-08)

Chunked Transfer-Encoding decoding in HTTP/1.1 parser. Content-Encoding decompression
(gzip, deflate, brotli, zstd) behind `decompression` feature flag. `accept_encoding()`
API method and `--compressed` CLI flag. 86 tests passing.

### Phase 2c: Timeouts + Authentication (CURRENT)

**Scope:** Add connect and transfer timeouts for robustness, plus Basic and Bearer
HTTP authentication for API usage.

**Step 2c.1: Connect timeout**
- Add `connect_timeout()` setter to Easy API (Duration)
- Wrap TCP connect with `tokio::time::timeout`
- Unit test for timeout configuration
- Integration test with non-routable address (10.255.255.1) for timeout behavior

**Step 2c.2: Transfer timeout**
- Add `timeout()` setter to Easy API (total transfer time limit)
- Wrap entire transfer with `tokio::time::timeout`
- Integration test with slow server

**Step 2c.3: Basic authentication**
- Add `basic_auth(user, password)` to Easy API
- Generate `Authorization: Basic <base64>` header
- CLI flags: `-u`/`--user` (user:password format)
- Integration test verifying auth header is sent

**Step 2c.4: Bearer authentication**
- Add `bearer_token(token)` to Easy API
- Generate `Authorization: Bearer <token>` header
- Integration test

**Exit criteria:** Timeouts prevent hangs. Basic/Bearer auth works with APIs.

### Phase 2c: Timeouts + Authentication — COMPLETED (2026-03-08)

Connect timeout, total transfer timeout, Basic and Bearer authentication.
CLI flags: --connect-timeout, -m/--max-time, -u/--user. 94 tests passing.

### Phase 2d: Transfer Info + Write-Out (CURRENT)

**Scope:** Add transfer timing/info queries and --write-out support for
extracting response metadata. These are essential for scripting and debugging.

**Step 2d.1: Transfer info on Response**
- Add timing fields to Response (or separate TransferInfo struct)
- Track: total_time, connect_time, response status code (already have)
- Track: effective_url (already have), content_type, response_code
- Track: size_download (body length)

**Step 2d.2: --write-out / -w CLI support**
- Parse format string with %{variable} placeholders
- Support: http_code, url_effective, content_type, size_download,
  time_total, time_connect, num_redirects
- Add `-w`/`--write-out` flag to CLI

**Exit criteria:** `urlx -w '%{http_code}\n' -o /dev/null` prints status code.

### Phase 2d: Transfer Info + Write-Out — COMPLETED (2026-03-08)

TransferInfo with timing/redirect counts. CLI --write-out/-w with %{variable}
format. 96 tests passing.

### Phase 3a: HTTP/2 Support (CURRENT)

**Scope:** Add HTTP/2 protocol support using the `h2` crate. HTTP/2 provides
multiplexing, header compression, and better performance for modern APIs.

**Step 3a.1: h2 dependency and feature flag**
- Add `http2` feature flag with `dep:h2`
- Feature-gate HTTP/2 code behind `http2` feature
- Add h2 to default features

**Step 3a.2: ALPN negotiation**
- Configure rustls to advertise both h2 and http/1.1 via ALPN
- Detect negotiated protocol after TLS handshake
- Route to h2 or h1 codec based on ALPN result

**Step 3a.3: HTTP/2 request/response**
- Implement h2 request sending using the h2 crate
- Handle h2 response reading
- Wire into do_single_request()
- Support all HTTP methods, headers, body

**Step 3a.4: Integration tests**
- Test h2 request against a real h2 server (use hyper with http2 feature)
- Verify ALPN negotiation works
- Verify fallback to h1 when server doesn't support h2

**Exit criteria:** HTTPS requests automatically use HTTP/2 when server supports it.

### Phase 3b: HTTP Proxy Support

- HTTP proxy (forward proxy for HTTP URLs)
- HTTPS proxy (CONNECT tunneling for HTTPS URLs)
- CLI: -x/--proxy flag
- Environment variable support (http_proxy, https_proxy, no_proxy)

### Phase 3c: Concurrent Transfers (Multi API)

- Multi handle for running multiple transfers concurrently
- Async-native API using tokio tasks
- CLI: parallel URL support

### Phase 4: Protocol Expansion

**Write tests first for each protocol before implementing:**
- FTP/FTPS (active, passive, upload, download, directory listing, resume)
- MQTT (connect, publish, subscribe)
- SCP/SFTP
- SMTP/IMAP/POP3
- FILE protocol
- LDAP

### Phase 5: Drop-in Replacement

**The test suite IS the specification here:**
- Port curl's 1,918 test cases to run against `liburlx-ffi`
- Map all 291 CURLOPT_* options
- Map all 118 CURLINFO_* codes
- Map all 146 CURLE_* error codes
- Build `.so`/`.dylib` that can replace libcurl
- `urlx` CLI supports all ~250 of curl's command-line flags

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
