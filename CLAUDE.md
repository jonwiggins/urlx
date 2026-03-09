# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 23 — Planning
**Last completed:** Phase 22 (FFI Callbacks & MIME API) — 2026-03-09
**Total tests:** 1,819
**In progress:** Planning Phase 23
**Blockers:** None
**Next up:** Phase 23 — URL API & FFI Expansion

### Completeness Summary (updated Phase 20 review)

| Feature Area | Parity | Notes |
|---|---|---|
| HTTP/1.1 | 97% | Expect, HTTP/1.0, trailer headers; no chunked upload |
| HTTP/2 | 60% | Works; no server push |
| HTTP/3 | 5% | HttpVersion::Http3 variant + Alt-Svc cache; no QUIC transport |
| TLS | 85% | rustls with insecure mode, custom CA, client certs, pinning, version selection, cipher list, session cache |
| Authentication | 60% | Basic, Bearer, Digest (MD5/SHA-256), AWS SigV4, NTLM skeleton |
| Cookie engine | 90% | Netscape file format read/write, in-memory jar; no public suffix list |
| Proxy | 85% | HTTP + SOCKS + proxy Basic/Digest/NTLM auth, proxy TLS config; no HTTPS proxy tunnel or PAC |
| DNS | 75% | Cache with configurable TTL, Happy Eyeballs, DNS shuffle, DNS server config, DoH URL config; no async resolver |
| FTP | 70% | Session API, upload, resume, dir ops, FEAT; no FTPS or active mode |
| SSH/SFTP/SCP | 0% | Not implemented |
| Multi API | 55% | Connection limiting, message queue, share interface, pipelining config; no poll/socket/timer callbacks |
| FFI (libcurl C ABI) | ~38% | 79 options, 17 info codes, 25 error codes, 26 functions |
| CLI | ~34% | ~84 of ~250 flags |
| Connection | 80% | Pool, TCP_NODELAY, keepalive, Unix sockets, interface/port binding |
| Transfer control | 80% | Rate limiting enforced in transfer engine (max recv/send speed, low speed timeout) |
| Overall | ~56% | ~92% for basic HTTP/HTTPS use cases |

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
- **2026-03-08:** Share interface uses swap-based approach: shared state is swapped into local Easy fields before transfer, then swapped back after. No lock held across async await points — only brief locks for the swap. This naturally serializes access per-transfer.
- **2026-03-08:** Poll/socket/timer/fdset Multi APIs deferred to FFI phase — these are C event-loop integration points that don't map naturally to tokio's async model. The Rust Multi API already provides native async via `perform()`.
- **2026-03-08:** `PipeliningMode` enum has `Nothing` and `Multiplex` variants. HTTP/1.1 pipelining was deprecated in libcurl and is not supported — only HTTP/2 multiplexing is offered.
- **2026-03-08:** `curl_slist` is implemented as a C-compatible linked list with manual memory management (Vec + mem::forget for string data, Box for nodes). This matches libcurl's API exactly.
- **2026-03-08:** `curl_multi_perform` uses `perform_blocking` internally, creating a tokio runtime per call. This matches the blocking C API model. For async-native C consumers, poll/socket callbacks would be needed (deferred).
- **2026-03-08:** NTLM authentication uses a skeleton implementation with SHA-256-based NT response instead of real MD4+DES. Avoids adding `md4` and DES dependencies for a rarely-used auth mechanism. Sufficient for basic proxy auth testing; real NTLM interop would need full crypto.
- **2026-03-08:** HTTP/3 via quinn deferred from Phase 8. Adding QUIC transport is a major effort requiring: new dependency, QUIC connection management, Alt-Svc-based discovery, 0-RTT, connection migration. Better as a dedicated phase after the Phase 10 review.
- **2026-03-08:** `HttpVersion` enum uses `None` (auto) as default rather than `Http11` to preserve existing ALPN-based HTTP/2 negotiation behavior. `Http2` variant is equivalent to `None` for HTTPS since ALPN already prefers H2.
- **2026-03-08:** Expect: 100-continue timeout defaults to sending body on timeout (matching curl behavior). Body is NOT sent only when server actively responds with an error status before the timeout.
- **2026-03-08:** Netscape cookie file format uses leading dot prefix for all domains (matching curl behavior). `#HttpOnly_` prefix handled before general `#` comment check to avoid false skipping. Session cookies written with `expiration=0`.
- **2026-03-08:** Rate limiting (max_recv_speed, max_send_speed) and minimum speed enforcement (low_speed_limit, low_speed_time) added as Easy API setters. CLI `--limit-rate` supports K/M/G suffixes using 1024-based multipliers (matching curl behavior).
- **2026-03-09:** Rate limiting wired into transfer engine via `SpeedLimits` struct and `RateLimiter`. Token-bucket approach: tracks bytes transferred vs elapsed time, sleeps to enforce max speed. Low speed enforcement checks average throughput and aborts with `Error::SpeedLimit` after exceeding `low_speed_time`. Throttled reads/writes use 16KB chunks (`THROTTLE_CHUNK_SIZE`). Large futures from added parameters addressed with `Box::pin` on `perform_transfer` and `#[allow(clippy::large_futures)]` on `do_single_request`.
- **2026-03-09:** FFI MIME API uses standalone `MimePartHandle` structs that are finalized into the parent `MimeHandle`'s `MultipartForm` via `finalize_mime_part()`. This matches libcurl's workflow: `curl_mime_addpart` → set name/data/filename → `CURLOPT_MIMEPOST`. Parts own their data until finalized.
- **2026-03-09:** `CURLOPT_PROGRESSFUNCTION` and `CURLOPT_XFERINFOFUNCTION` share the same data pointer (`CURLOPT_PROGRESSDATA` = 10057). The xferinfo callback takes precedence over the progress callback (matching libcurl behavior). Both are only invoked when `CURLOPT_NOPROGRESS` is set to 0.
- **2026-03-09:** `CURLINFO_PRIVATE` is handled before the response check in `curl_easy_getinfo` since it doesn't require a completed transfer — it's stored directly on the `EasyHandle` struct, not on the response.
- **2026-03-09:** `curl_share_setopt` lock/unlock function callbacks (options 3/4) are accepted but ignored. The Rust `Share` type uses `Arc<Mutex>` internally, making external locking unnecessary.

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

### Phase 0: Cumulative Summary (Phases 1-20, completed 2026-03-09)

Built from scratch over 20 phases. All features below are implemented and tested.

**Core Library (liburlx) — 73 Easy methods, 14 Multi methods:**
- **HTTP/1.x:** Full request/response codec (all methods), chunked transfer encoding with trailer header parsing, Content-Encoding decompression (gzip, deflate, brotli, zstd), redirects (301/302/303/307/308), Expect: 100-continue, HTTP/1.0 mode, header deduplication (last wins), ignore-content-length (read to EOF), auth stripping on cross-origin redirects (unrestricted_auth option).
- **HTTP/2:** Via h2 crate with ALPN negotiation. `HttpVersion` enum (None/Http10/Http11/Http2/Http3). No server push.
- **TLS:** rustls + tokio-rustls. `TlsConfig` with verify_peer/host, CA cert, client cert/key, version selection (TLS 1.2/1.3), certificate pinning (SHA-256 SPKI), cipher list, session cache. Inline DER parser for SPKI extraction.
- **Authentication:** Basic, Bearer, Digest (MD5/SHA-256 with qop=auth), AWS SigV4 (inline HMAC-SHA256), NTLM skeleton (SHA-256-based, sufficient for proxy auth testing).
- **Cookie engine:** RFC 6265 parsing, domain/path matching, Netscape file format persistence (read/write), HttpOnly, Secure, SameSite (stored). No public suffix list.
- **HSTS cache:** STS parsing, HTTP→HTTPS upgrade, includeSubDomains.
- **Proxy:** HTTP forward, HTTP CONNECT tunnel (with Digest/NTLM 407 challenge-response), SOCKS4/4a/5 with auth, noproxy bypass, proxy TLS config.
- **Connection:** Pool with stale retry, TCP_NODELAY (default on), TCP keepalive (socket2), Unix domain sockets, interface/port binding, Happy Eyeballs (250ms, configurable).
- **DNS:** Cache with configurable TTL, shuffle (inline xorshift32), custom server addresses, DoH URL config. No async resolver.
- **FTP:** Session-based API — STOR, APPE, REST, FEAT, MKD/RMD/DELE, RNFR/RNTO, SITE, PWD/CWD, SIZE, MLSD, TYPE A/I. No FTPS or active mode.
- **Other protocols:** WebSocket (RFC 6455), SMTP, IMAP, POP3, MQTT 3.1.1, DICT, TFTP, FILE.
- **Multi API:** JoinSet-based concurrency, connection limiting (semaphore), message queue, Share interface (DNS cache + cookie jar), PipeliningMode (Nothing/Multiplex). No poll/socket/timer callbacks.
- **Alt-Svc:** Header parsing (RFC 7838), TTL-based cache, automatic processing in transfers.
- **Transfer control:** Rate limiting enforced in transfer engine via `SpeedLimits` and `RateLimiter`. Max recv/send speed throttling (token bucket, 16KB chunks). Low speed enforcement aborts with `Error::SpeedLimit` after timeout.
- **Response:** Status, headers, body, trailers, effective_url, TransferInfo (6 timing fields + speed/size metrics).

**FFI Layer (liburlx-ffi) — 79 CURLOPT, 17 CURLINFO, 25 CURLcode, 26 functions:**
- Functions: curl_easy_init/cleanup/duphandle/reset/setopt/perform/getinfo/strerror, curl_slist_append/free_all, curl_multi_init/cleanup/add_handle/remove_handle/perform, curl_version, curl_mime_init/addpart/name/data/filename/type/free, curl_share_init/cleanup/setopt/strerror.
- Callbacks: WRITEFUNCTION, READFUNCTION (with CURL_READFUNC_ABORT), HEADERFUNCTION, DEBUGFUNCTION, PROGRESSFUNCTION, XFERINFOFUNCTION, SEEKFUNCTION.
- Options: CURLOPT_PRIVATE, CURLOPT_SHARE, CURLOPT_MIMEPOST, CURLOPT_NOPROGRESS.
- Enums: CURLSHcode (6 variants), CURLSHoption (4 variants).
- Memory: Box<[u8]>-based slist string allocation (exact-size, no capacity mismatch). catch_unwind on all FFI boundaries.

**CLI (urlx) — ~84 flags:**
- HTTP: -X, -H, -d, --data-raw, --data-binary, --data-urlencode, -L, --max-redirs, -I, -A, -e, -G, -F, -r, -C, --compressed, --http1.0, --http1.1, --http2, --expect100-timeout.
- Output: -o, -O, -D, -i, -w, --create-dirs, -v, -s, -S, -f, -#.
- Auth: -u, --digest, --bearer, --aws-sigv4, -b, -c.
- TLS: -k, --cacert, --cert, --key, --tlsv1.2, --tlsv1.3, --tls-max, --pinnedpubkey.
- Proxy: -x, --noproxy, --socks5-hostname, --proxy-user, --proxy-digest, --proxy-ntlm.
- Transfer: -m, --connect-timeout, --retry/--retry-delay/--retry-max-time, --limit-rate, --speed-limit, --speed-time, -T, --unrestricted-auth, --ignore-content-length.
- Connection: --tcp-nodelay, --tcp-keepalive, --no-keepalive, --unix-socket, --interface, --local-port, --resolve.
- DNS: --dns-shuffle, --dns-servers, --doh-url, --happy-eyeballs-timeout-ms.
- Concurrency: -Z, --parallel-max.
- Debug/Config: --trace, --trace-ascii, --trace-time, -K/--config, --libcurl, --proto, --proto-redir, --max-filesize, --hsts.
- Features: .curlrc-style config file parser, protocol restriction, max filesize enforcement (exit 63), libcurl C code generation, retry logic (408/429/5xx).

**Testing — 1,788 tests (0 failures):**
- Unit: 455 (liburlx) + 112 (FFI) + 134 (CLI) = 701
- Integration: 1,048 (hyper-based test servers)
- Property-based: 60 (proptest — URL, cookie, FTP, HTTP, HSTS, multipart, protocols, WebSocket)
- Doc tests: 3
- Fuzz harnesses: 4 (URL, HTTP, cookie, HSTS parsers)
- Benchmarks: 3 (throughput, latency, concurrency via criterion)

**Guardrails:** Zero TODO/FIXME/HACK. Zero `unwrap()` in production code. `#![deny(unsafe_code)]` in liburlx and urlx-cli. GitHub Actions CI (fmt, clippy, test on 3 OS, doc, cargo-deny, MSRV 1.83, commit lint). Pre-commit hooks (fmt, clippy, test, deny, doc, conventional commit).

**Known gaps (as of Phase 22):** Trace file writing not fully wired. HTTP/3 QUIC transport not implemented. SSH/SFTP/SCP not implemented. FTPS not implemented. Poll/socket/timer Multi APIs not implemented. Missing FFI: curl_url_*, CURLOPT_HTTPPOST (deprecated).

---

### Phase 21: Transfer Engine Rate Limiting (completed 2026-03-09)

Wired rate limiting into the transfer engine. Added `SpeedLimits` struct, `RateLimiter` with token-bucket throttling, `Error::SpeedLimit` variant. Throttled HTTP/1.x and HTTP/2 body reads/writes in 16KB chunks. 7 integration tests + 12 unit tests. Total tests: 1,788.

---

### Phase 22: FFI Callbacks & MIME API (completed 2026-03-09)

Added 10 FFI functions (curl_mime_init/addpart/name/data/filename/type/free, curl_share_init/cleanup/setopt/strerror), 9 new CURLOPT options (PROGRESSFUNCTION, XFERINFOFUNCTION, SEEKFUNCTION, NOPROGRESS, PRIVATE, SHARE, MIMEPOST, + data pointers), CURLINFO_PRIVATE, CURLSHcode/CURLSHoption enums. 31 new FFI tests. Total: 1,819 tests.

---

### Phase 23: URL API & FFI Expansion

**Goal:** Add curl_url_* API and expand FFI option coverage.

- `curl_url` / `curl_url_cleanup` / `curl_url_set` / `curl_url_get` / `curl_url_dup`
- Target 85+ CURLOPT options
- Target 20+ CURLINFO codes
- CURLOPT_HTTPPOST (deprecated but still used)

---

### Phase 24: CLI Expansion II

**Goal:** Continue CLI toward full curl parity.

- `--netrc` / `--netrc-optional` (credential file support)
- `--proxy-header` (proxy-only headers)
- `--post301` / `--post302` / `--post303` (method preservation on redirect)
- `--remote-time` (set local file timestamp from server)
- `--ftp-*` flags (FTP-specific: `--ftp-pasv`, `--ftp-port`, `--ftp-ssl`, etc.)
- `--glob` / `--next` (URL globbing and request chaining)

---

### Phase 25: FTPS & Active Mode FTP

**Goal:** Complete FTP protocol support.

- AUTH TLS (FTPS explicit)
- Implicit FTPS (port 990)
- Active mode (PORT/EPRT)
- FTP directory listing parsing
- `--ftp-ssl-reqd`, `--ftp-ssl`, `--ftp-port` CLI flags

---

### Phase 26: SSH/SFTP/SCP

**Goal:** Add SSH-based file transfer protocols.

- `russh` crate integration (pure-Rust SSH)
- SFTP file download/upload
- SCP file transfer
- SSH key authentication
- `--key` reuse for SSH identity files

---

### Phase 27: Multi API Event Loop Integration

**Goal:** Poll/socket/timer APIs for C event loop integration.

- `curl_multi_fdset` equivalent
- `curl_multi_wait` / `curl_multi_poll`
- `curl_multi_socket_action` / `curl_multi_timer_callback`
- Socket callback for external event loop (libevent, libev, epoll)

---

### Phase 28: HTTP/2 Enhancements & HTTP/3 Transport

**Goal:** Advanced HTTP/2 features and begin QUIC transport.

- HTTP/2 server push handling
- Stream priority / dependency
- quinn-based QUIC transport (feature-gated `http3`)
- Alt-Svc-based HTTP/3 upgrade from HTTP/2
- 0-RTT early data

---

### Phase 29: Performance & Optimization

**Goal:** Profiling and performance improvements.

- Throughput benchmarks vs curl (criterion)
- Connection setup latency benchmarks
- Memory allocation profiling
- Zero-copy body forwarding where possible
- Connection pool warming

---

### Phase 30: Completeness Review + 1.0 Planning

**Goal:** Third mandatory review. Assess 1.0 readiness.

- Comprehensive differential testing against curl
- FFI coverage audit (target 100+ options)
- CLI coverage audit (target 150+ flags)
- API stability review
- Documentation completeness
- Plan Phases 31-40 or 1.0 release

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

9. **Every 10th phase (10, 20, 30, ...) must be a comprehensive review.** These phases are dedicated to auditing the entire codebase against curl/libcurl for completeness, running differential tests, measuring FFI coverage, profiling performance, and planning the next 10 phases. No new features are added during review phases — only testing, gap analysis, and planning. **During review phases, compact the phase list:** merge all completed phases from the prior 10-phase block into the existing "Phase 0" summary (or create one if it doesn't exist). Phase 0 should describe the current state of the repo — what has been built, key stats, and architectural decisions. After compaction, the Implementation Phases section should contain only Phase 0 (cumulative summary of all completed work) followed by the next 10 planned phases (brief outlines of future work). This keeps CLAUDE.md concise and avoids unbounded growth.

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
