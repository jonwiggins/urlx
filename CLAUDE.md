# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 5 — Multi API Event-Driven Architecture
**Last completed:** Phase 4 (FTP completeness) — 2026-03-08
**Total tests:** 1470+
**In progress:** Planning Phase 5
**Blockers:** None
**Next up:** Poll-based event loop, socket/timer callbacks, message queue

### Completeness Summary

| Feature Area | Parity | Notes |
|---|---|---|
| HTTP/1.1 | 85% | Solid; no Expect: 100-continue |
| HTTP/2 | 60% | Works; no server push |
| HTTP/3 | 0% | Not implemented |
| TLS | 80% | rustls with insecure mode, custom CA, client certs, pinning, version selection |
| Authentication | 50% | Basic, Bearer, Digest (MD5/SHA-256), AWS SigV4 |
| Cookie engine | 75% | In-memory only, no persistence |
| Proxy | 80% | HTTP + SOCKS + proxy auth; no HTTPS proxy or PAC |
| DNS | 60% | Cache with TTL, Happy Eyeballs (RFC 6555), DNS shuffle; no async resolver or DoH |
| FTP | 70% | Session API, upload, resume, dir ops, FEAT; no FTPS or active mode |
| SSH/SFTP/SCP | 0% | Not implemented |
| Multi API | 30% | Simple concurrency; no event-driven model |
| FFI (libcurl C ABI) | ~8% | 19/300+ options, 6/50+ info codes |
| CLI | ~14% | ~43 of ~250 flags |
| Connection | 80% | Pool, TCP_NODELAY, keepalive, Unix sockets, interface/port binding |
| Overall | ~42% | ~88% for basic HTTP/HTTPS use cases |

---

## Decision Log

- **2026-03-08:** Workspace lint inheritance is all-or-nothing in Cargo. `unsafe_code = "deny"` is enforced via `#![deny(unsafe_code)]` in source files (liburlx, urlx-cli) rather than workspace lints, since liburlx-ffi needs to allow it and can't partially override workspace lints.
- **2026-03-08:** `rustfmt.toml` uses only stable options (`edition`, `max_width`, `use_small_heuristics`). `imports_granularity` and `group_imports` are nightly-only and omitted.
- **2026-03-08:** cargo-deny v0.19 uses a simplified config format — `vulnerability`/`unmaintained`/`unlicensed`/`copyleft` keys were removed.
- **2026-03-08:** Connection pool uses `PooledStream` enum (Tcp/Tls variants) with AsyncRead/AsyncWrite delegation, avoiding trait objects. Pool only stores non-proxied H1 connections; H2 multiplexing handles its own reuse.
- **2026-03-08:** For keep-alive, responses with no Content-Length and no chunked encoding (e.g., 204 No Content) are treated as empty body to avoid hanging on `read_to_end`. Stale pooled connections trigger automatic retry with fresh connection.
- **2026-03-08:** WebSocket SHA-1 implemented inline (minimal, ~50 lines) to avoid adding a dependency for a single use case. Not used for security purposes — only for RFC 6455 accept key computation.
- **2026-03-08:** Found and fixed WebSocket accept key GUID typo (`5AB5DC85B11B` → `C5AB0DC85B11`). The existing unit test was written against the buggy implementation. Discovered via RFC 6455 example test in integration tests.
- **2026-03-08:** Certificate pinning uses a minimal inline DER parser (~50 lines) to extract SPKI from X.509 certs, avoiding adding an ASN.1 parsing dependency. Only the SPKI portion is needed for SHA-256 hashing.
- **2026-03-08:** AWS SigV4 uses inline HMAC-SHA256 implementation (~20 lines) rather than adding the `hmac` crate, since it's the only HMAC user. Same approach as WebSocket SHA-1.
- **2026-03-08:** NTLM and Negotiate/SPNEGO auth deferred from Phase 2 — they are complex, platform-specific, and rarely needed. Can be added later if demanded.
- **2026-03-08:** Cipher suite selection deferred from Phase 2 — rustls defaults are secure and appropriate. The `CryptoProvider` API exists for future use if needed.
- **2026-03-08:** Migrated from `rustls-pemfile` (RUSTSEC-2025-0134, unmaintained) to `rustls-pki-types` `PemObject` trait for PEM parsing. The `rustls-pki-types` API is the maintained replacement.
- **2026-03-08:** TCP_NODELAY defaults to `true` (matching curl behavior). TCP keepalive uses `socket2` crate (already in dependency tree via tokio) for cross-platform `SO_KEEPALIVE` + `TCP_KEEPIDLE`.
- **2026-03-08:** TransferInfo timing now separates `time_namelookup` from `time_connect` — DNS resolution via `tokio::net::lookup_host` is explicit, with caching. Previous approach had them equal since `TcpStream::connect` does both.
- **2026-03-08:** Happy Eyeballs uses 250ms delay (RFC 6555 recommendation) before starting IPv4 after IPv6. Uses `tokio::select!` for racing. Falls back to sequential if only one address family available.
- **2026-03-08:** DNS shuffle uses inline xorshift32 PRNG seeded from nanosecond timestamp. Avoids adding a `rand` dependency for a simple shuffle operation.
- **2026-03-08:** Local interface/port binding uses `socket2::Socket` for pre-bind + non-blocking connect, with platform-specific `EINPROGRESS` handling (code 36 on macOS, 115 on Linux, 10036 on Windows).
- **2026-03-08:** FTP refactored from standalone functions to `FtpSession` struct to eliminate code duplication (login, PASV, data connection). Original `download()`/`list()` functions preserved as convenience wrappers.
- **2026-03-08:** SSH/SFTP deferred — `russh` (pure-Rust) preferred over `ssh2` (C bindings via libssh2) to maintain zero-unsafe-outside-FFI principle. Significant effort to implement properly.

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

## Implementation Phases

### Phase 1: Foundation — COMPLETED (2026-03-08)

Repository setup, CI/CD, and core library implementation. Built from scratch over 34 sub-phases:

- **Workspace & guardrails:** Three-crate workspace (liburlx, liburlx-ffi, urlx-cli). Rustfmt, clippy, cargo-deny, pre-commit hooks, GitHub Actions CI with commit linting, multi-OS testing, MSRV check.
- **HTTP/1.1:** Full request/response codec (GET/POST/PUT/DELETE/HEAD/PATCH/OPTIONS), custom headers, chunked transfer encoding, Content-Encoding decompression (gzip, deflate, brotli, zstd), redirects (301/302/303/307/308), fail_on_error, verbose output.
- **HTTP/2:** Via h2 crate with ALPN negotiation, automatic protocol selection.
- **TLS:** rustls + tokio-rustls with system root certificates, SNI, ALPN.
- **Easy API:** 26 public methods — URL, method, headers, body, auth (Basic/Bearer), proxy, timeouts, cookies, HSTS, resolve overrides, multipart forms, range/resume, progress callbacks, fail_on_error.
- **Multi API:** JoinSet-based concurrent execution with result ordering, perform_blocking wrapper.
- **Connection pooling:** PooledStream enum (Tcp/Tls), stale connection retry, per-host caching.
- **Cookie engine:** RFC 6265 Set-Cookie parsing, domain/path matching, Max-Age, Secure, HttpOnly, SameSite (stored). In-memory only.
- **HSTS cache:** Strict-Transport-Security parsing, auto HTTP→HTTPS upgrade, includeSubDomains.
- **Proxy:** HTTP forward proxy, HTTP CONNECT tunneling, SOCKS4/SOCKS4a/SOCKS5 with auth, noproxy bypass, environment variables.
- **Protocols:** FTP (download/LIST), WebSocket (RFC 6455 frames), SMTP, IMAP, POP3, MQTT 3.1.1, DICT, TFTP, FILE.
- **FFI:** curl_easy_init/cleanup/setopt (19 options)/perform/getinfo (6 codes)/strerror, curl_version. CURLcode (9 codes), cbindgen header generation.
- **CLI:** 27+ flags including -X, -H, -d, -L, -I, -o, -v, -s, -S, -f, -i, -D, -A, -u, -F, -r, -C, -x, -w, -m, --compressed, --max-redirs, --noproxy, --data-raw, multi-URL support.
- **Testing:** 1331+ tests — unit, integration (hyper-based test server), property-based (proptest), fuzz harnesses (cargo-fuzz), E2E scenarios, curl behavioral compatibility tests, benchmarks (criterion).

---

### Phase 2: TLS Hardening + Authentication — COMPLETED (2026-03-08)

TLS configuration and authentication mechanisms:

- **TLS config:** `TlsConfig` struct with `verify_peer`, `verify_host`, `ca_cert`, `client_cert`, `client_key`, `min_tls_version`, `max_tls_version`, `pinned_public_key`. `NoVerifier` for insecure mode. PEM loading via `rustls-pemfile`.
- **TLS version selection:** `TlsVersion` enum (Tls12/Tls13) with `builder_with_protocol_versions()`. CLI flags: `--tlsv1.2`, `--tlsv1.3`, `--tls-max`.
- **Certificate pinning:** Inline DER parser extracts SPKI from X.509 certs, SHA-256 hash compared against pin. CLI flag: `--pinnedpubkey sha256//<base64>`.
- **Digest auth:** `DigestChallenge` parser + `respond()` method. MD5 and SHA-256 algorithms, `qop=auth`, opaque echo. Challenge-response retry loop in `perform_transfer`.
- **Proxy auth:** `proxy_auth()` method adds `Proxy-Authorization: Basic` header. Forward to CONNECT tunnel. CLI flag: `--proxy-user`.
- **AWS SigV4:** `AwsSigV4Config` with `provider:region:service` parsing. Full signing pipeline (canonical request, HMAC-SHA256, signing key). CLI flag: `--aws-sigv4`.
- **CLI flags added:** `-k/--insecure`, `--cacert`, `--cert`, `--key`, `--digest`, `--proxy-user`, `--tlsv1.2`, `--tlsv1.3`, `--tls-max`, `--pinnedpubkey`, `--aws-sigv4` (11 new flags).
- **Deferred:** NTLM, Negotiate/SPNEGO, cipher suite selection (see Decision Log).

---

### Phase 3: DNS + Connection Infrastructure — COMPLETED (2026-03-08)

DNS caching (TTL-based, 60s default), Happy Eyeballs (RFC 6555, 250ms IPv6 head start), DNS shuffle, TCP_NODELAY (default on), TCP keepalive (socket2), Unix domain sockets, local interface/port binding (socket2), TransferInfo timing fields (namelookup, connect, appconnect, pretransfer, starttransfer, speed_download/upload, size_upload), CLI --write-out variables, --unix-socket, --interface, --local-port, --dns-shuffle flags. Migrated PEM parsing from unmaintained rustls-pemfile to rustls-pki-types.

**Deferred to later phases:** Async DNS resolver (hickory-dns), DNS-over-HTTPS, abstract Unix sockets.

---

### Phase 4: FTP Completeness + SSH/SFTP/SCP — COMPLETED (2026-03-08)

Refactored FTP into session-based `FtpSession` API. Added: STOR upload, APPE append, REST resume, FEAT detection with capability parsing, MKD/RMD/DELE directory operations, RNFR/RNTO rename, SITE command, PWD/CWD, SIZE, MLSD (RFC 3659), TYPE A/I switching. Wired FTP upload into Easy API (PUT method → STOR) and CLI `-T/--upload-file` flag. Backward-compatible `download()`/`list()`/`upload()` convenience functions preserved.

**Deferred to later phases:** Active mode (PORT/EPRT), FTPS (AUTH TLS), SSH/SFTP/SCP (requires `russh` crate — pure-Rust SSH, avoids `ssh2`'s C dependency).

---

### Phase 5: Multi API Event-Driven Architecture

**Goal:** Full libcurl multi interface parity for event-loop integration.

- Poll-based event loop — `curl_multi_poll`/`curl_multi_wait` equivalents
- Socket callback interface — `CURLMOPT_SOCKETFUNCTION`, `curl_multi_assign`
- Timer callback interface — `CURLMOPT_TIMERFUNCTION`
- File descriptor set — `curl_multi_fdset` equivalent
- Message queue — `curl_multi_info_read` for per-transfer completion status
- Dynamic add/remove during perform — add new transfers while others are running
- Max concurrent connections — `CURLMOPT_MAX_TOTAL_CONNECTIONS`, `CURLMOPT_MAX_HOST_CONNECTIONS`
- Pipelining/multiplexing control — `CURLMOPT_PIPELINING`
- Share interface — `curl_share_init`, `curl_share_setopt` for sharing DNS cache, cookies, TLS sessions across handles

---

### Phase 6: FFI Expansion

**Goal:** Make liburlx-ffi a realistic drop-in for libcurl consumers.

**CURLcode expansion:**
- Map all 92 libcurl error codes (currently 9)

**CURLoption expansion (target: top 100 most-used options):**
- All TLS options from Phase 2
- All DNS/connection options from Phase 3
- Cookie file I/O — `CURLOPT_COOKIEFILE`, `CURLOPT_COOKIEJAR`
- Upload — `CURLOPT_UPLOAD`, `CURLOPT_INFILESIZE`
- Auth — `CURLOPT_HTTPAUTH`, `CURLOPT_PROXYAUTH`
- Rate limiting — `CURLOPT_MAX_SEND_SPEED_LARGE`, `CURLOPT_MAX_RECV_SPEED_LARGE`
- Callbacks — `CURLOPT_READFUNCTION`, `CURLOPT_PROGRESSFUNCTION`, `CURLOPT_DEBUGFUNCTION`
- Handle options — `CURLOPT_PRIVATE`, `CURLOPT_SHARE`

**CURLINFO expansion:**
- All timing fields (namelookup, connect, appconnect, starttransfer, pretransfer, redirect)
- Speed fields (download, upload)
- Size fields (upload, download, header)
- TLS info (SSL_VERIFYRESULT, CERTINFO)
- Connection info (LOCAL_IP, LOCAL_PORT, PRIMARY_IP, PRIMARY_PORT)

**Additional FFI functions:**
- `curl_multi_*` — init, add_handle, remove_handle, perform, poll, info_read, cleanup
- `curl_easy_duphandle` — handle cloning
- `curl_mime_*` — structured multipart API
- `curl_url_*` — URL parsing API
- `curl_slist_*` — linked list for headers

---

### Phase 7: CLI Completeness

**Goal:** Support all commonly-used curl command-line flags.

**Cookie flags:**
- `-b/--cookie` — read cookies from file or string
- `-c/--cookie-jar` — write cookies to file after transfer

**TLS flags:** (from Phase 2 implementation)
- `--cert`, `--key`, `--cacert`, `--capath`, `-k/--insecure`, `--pinnedpubkey`
- `--tls-max`, `--tlsv1.2`, `--tlsv1.3`, `--ciphers`

**Auth flags:**
- `--digest`, `--ntlm`, `--negotiate`, `--aws-sigv4`, `--proxy-user`

**Transfer flags:**
- `--retry`, `--retry-delay`, `--retry-max-time`
- `--limit-rate` — bandwidth throttling
- `--speed-limit`, `--speed-time` — minimum speed enforcement
- `-T/--upload-file` — PUT upload from file
- `--data-binary`, `--data-urlencode` — POST data variants

**Debug/output flags:**
- `--trace`, `--trace-ascii`, `--trace-time` — wire-level logging
- `--stderr` — redirect stderr
- `-K/--config` — read flags from config file
- `--libcurl` — output equivalent C code

**Protocol flags:**
- `--http2`, `--http2-prior-knowledge`, `--http3`
- `--ftp-pasv`, `--ftp-port`, `--ftp-ssl`
- `--socks5-hostname`, `--proxy-header`

**Miscellaneous:**
- `--dns-servers`, `--doh-url`
- `--unix-socket`, `--abstract-unix-socket`
- `--interface`, `--local-port`
- `-Z/--parallel`, `--parallel-max`, `--parallel-immediate` — parallel transfer control
- `--styled-output`, `--no-styled-output`

---

### Phase 8: HTTP Completeness + HTTP/3

**Goal:** Full HTTP protocol feature parity.

**HTTP/1.1:**
- Expect: 100-continue protocol — `CURLOPT_EXPECT_100_TIMEOUT_MS`
- Trailer headers (chunked encoding trailers)
- HTTP/1.0 explicit mode — `CURLOPT_HTTP_VERSION`

**HTTP/2:**
- Server push — `CURLMOPT_PUSHFUNCTION`, `CURLMOPT_PUSHDATA`
- Stream priority/weight — `CURLOPT_STREAM_WEIGHT`
- SETTINGS frame customization
- Window size configuration

**HTTP/3:**
- QUIC transport via quinn crate (feature-gated `http3`)
- QUIC connection migration
- Alt-Svc header parsing and caching — `CURLOPT_ALTSVC`
- 0-RTT early data

**Other:**
- Alt-Svc persistence — `CURLOPT_ALTSVC_CTRL`
- HSTS preload list support
- Retry-After header handling

---

### Phase 9: Advanced Transfer Features + Cookie Persistence

**Goal:** Production-grade transfer reliability and cookie management.

**Transfer reliability:**
- Automatic retry with configurable count and delay
- Rate limiting (upload and download) — `CURLOPT_MAX_SEND_SPEED_LARGE`, `CURLOPT_MAX_RECV_SPEED_LARGE`
- Minimum speed enforcement — `CURLOPT_LOW_SPEED_LIMIT`, `CURLOPT_LOW_SPEED_TIME`
- Transfer abort on stall

**Cookie persistence:**
- Netscape cookie file format (read/write)
- Mozilla cookie file format
- Cookie file export (`-c/--cookie-jar`)
- Cookie file import (`-b/--cookie`)
- Public suffix list for domain validation
- Session vs persistent cookies

**TLS session management:**
- SSL session caching and reuse
- OCSP stapling — `CURLOPT_SSL_VERIFYSTATUS`
- Certificate transparency

**Other:**
- MIME API for structured multipart (replacing simple MultipartForm)
- URL API (curl_url_*) for programmatic URL building/parsing
- `--libcurl` CLI flag — output equivalent C code for a transfer

---

### Phase 10: Completeness Review + Curl Test Suite Porting

**Goal:** Full codebase audit and differential testing against real curl.

**This is a mandatory review phase.** Every 10th phase (10, 20, 30, ...) is a comprehensive review of the entire codebase to assess what is still needed for a complete, robust drop-in replacement.

**Review checklist:**
- Audit every public API method against libcurl's documentation
- Run urlx CLI against curl's Python HTTP test suite (`tests/http/test_*.py`)
- Set up differential testing — run same operations with both urlx and real curl, compare outputs
- Port curl's XML test data runner (start with HTTP-only: ~893 tests)
- Measure FFI option coverage against libcurl.h
- Profile performance against curl for common operations (GET, POST, download, upload)
- Identify and document all remaining gaps in a gap-analysis report
- Update the Completeness Summary table in Current Status
- Plan the next 10 phases based on findings

**Curl test suite porting strategy:**

1. **Python HTTP tests** (`curl/tests/http/test_*.py`): Rewrite as Rust integration tests. ~280 test functions covering HTTP, downloads, uploads, proxies, auth, TLS, WebSockets.

2. **XML test data** (`curl/tests/data/test1` through `test1918`): Build a test runner that parses curl's XML format, starts mock servers, runs equivalent urlx operations, verifies wire protocol matches.

3. **Differential testing**: For any test that passes with urlx, also run with real curl binary and compare outputs.

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

## Test-Driven Development Protocol

### The TDD Cycle for Every Feature

1. **Write the test first.** The test must fail (or not compile) before any implementation.
2. **Write the minimum code to pass.** No speculative features.
3. **Refactor.** Clean up while all tests still pass.
4. **Verify guardrails.** `cargo clippy`, `cargo fmt`, `cargo doc` must all pass.

### Test Categories

#### Unit Tests (in-crate `#[cfg(test)]` modules)

Every public function, every struct method, every non-trivial private function. Located alongside the code in each crate. Run with `cargo test --lib`.

#### Integration Tests (`tests/` directory)

Test the library through its public API against real servers. Each test file focuses on one behavioral area. Run with `cargo test --test '*'`. Test servers written in Rust (using `hyper`, `tokio`) run on random ports.

#### Property-Based Tests

Use `proptest` for parser correctness (URL, cookie, HSTS, WebSocket, FTP, multipart).

#### Fuzz Harnesses

4 cargo-fuzz harnesses (URL, HTTP, cookie, HSTS parsers) in `fuzz/`.

#### FFI Tests

C-language test programs linking against liburlx-ffi to verify ABI compatibility.

### Coverage Requirements

- **Unit test coverage target: 80%+** for all crates. Measured by `cargo-tarpaulin`.
- **Integration test coverage: every public API function** must be exercised.
- **Every bug fix must include a regression test** that would have caught it.

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

   - **When a phase is fully complete,** collapse its detailed steps into a brief "Completed" summary. Do not leave stale instructions.

   - **When starting a new phase,** expand it with detailed, actionable implementation steps. Future phases should remain as brief outlines until they become current.

   - **When plans change,** update this file immediately.

   - **Update the Current Status section** with every phase transition.

   - **Record decisions in the Decision Log** when significant architectural or design choices are made.

### Milestone Review Phases

9. **Every 10th phase (10, 20, 30, ...) must be a comprehensive review.** These phases are dedicated to auditing the entire codebase against curl/libcurl for completeness, running differential tests, measuring FFI coverage, profiling performance, and planning the next 10 phases. No new features are added during review phases — only testing, gap analysis, and planning.

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
