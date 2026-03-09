# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Phase:** 32 — HTTPS Proxy & Trace Output
**Last completed:** Phase 31 (Cookie Domain Indexing) — 2026-03-09
**Total tests:** 1,958
**In progress:** Phase 32 — HTTPS Proxy & Trace Output
**Blockers:** None
**Next up:** Phase 32 — HTTPS Proxy & Trace Output

### Completeness Summary (updated Phase 30 review)

| Feature Area | Parity | Notes |
|---|---|---|
| HTTP/1.1 | 97% | Expect, HTTP/1.0, trailer headers; no chunked upload |
| HTTP/2 | 75% | Works with server push collection; no stream priority/dependency |
| HTTP/3 | 40% | QUIC transport via quinn, h3 request/response, rate limiting; no 0-RTT or Alt-Svc upgrade |
| TLS | 85% | rustls with insecure mode, custom CA, client certs, pinning, version selection, cipher list, session cache |
| Authentication | 60% | Basic, Bearer, Digest (MD5/SHA-256), AWS SigV4, NTLM skeleton |
| Cookie engine | 92% | Netscape file format read/write, domain-indexed jar; no public suffix list |
| Proxy | 85% | HTTP + SOCKS + proxy Basic/Digest/NTLM auth, proxy TLS config; no HTTPS proxy tunnel or PAC |
| DNS | 75% | Cache with configurable TTL, Happy Eyeballs, DNS shuffle, DNS server config, DoH URL config; no async resolver |
| FTP | 85% | Session API, upload, resume, dir ops, FEAT, explicit/implicit FTPS, active mode (PORT/EPRT) |
| SSH/SFTP/SCP | 60% | SFTP download/upload/list, SCP download/upload, password + pubkey auth; no known_hosts |
| Multi API | 75% | Connection limiting, message queue, share, pipelining, wait/poll/wakeup/fdset/socket_action/timeout/info_read |
| FFI (libcurl C ABI) | ~48% | 86 options, 22 info codes, 25 error codes, 43 functions |
| CLI | ~36% | ~89 of ~250 flags |
| Connection | 80% | Pool, TCP_NODELAY, keepalive, Unix sockets, interface/port binding |
| Transfer control | 80% | Rate limiting enforced in transfer engine (max recv/send speed, low speed timeout) |
| Performance | — | Hot-path string allocation optimizations, criterion benchmarks |
| Overall | ~60% | ~92% for basic HTTP/HTTPS use cases |

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
- **2026-03-09:** `curl_url_*` API uses an FFI-specific `UrlHandle` struct with mutable component storage, since the core `Url` type is immutable. Components are stored individually and reassembled on `curl_url_get(CURLUPART_URL)`. Strings returned by `curl_url_get` are allocated via `CString::into_raw` and must be freed with `curl_free`.
- **2026-03-09:** `CURLOPT_NOSIGNAL`, `CURLOPT_AUTOREFERER`, `CURLOPT_LOCALPORTRANGE`, and `CURLOPT_AWS_SIGV4` are accepted as no-ops. NOSIGNAL is irrelevant (tokio doesn't use signals), AUTOREFERER is not yet implemented, LOCALPORTRANGE supplements LOCALPORT (which is implemented), and AWS_SIGV4 auth is configured through separate credential setters.
- **2026-03-09:** `.netrc` credential loading is deferred from argument parsing to the `run()` function, where the URL is known. This allows extracting the hostname for lookup. `--netrc-optional` silently ignores missing files; `--netrc` fails if the file doesn't exist.
- **2026-03-09:** `--remote-time` uses the `filetime` crate for cross-platform file mtime setting. HTTP date parsing is inline (RFC 7231 format only) to avoid adding a date-parsing dependency for a single use case.
- **2026-03-09:** `--post301/--post302/--post303` flags map to `post301`/`post302`/`post303` bool fields on Easy. The redirect logic in `perform_transfer` checks these before converting POST→GET on 301/302/303 redirects. This matches curl's `CURLOPT_POSTREDIR` bitmask approach.
- **2026-03-09:** `FtpStream` enum follows the same pattern as `PooledStream` (Plain/Tls variants with `#[cfg(feature = "rustls")]` on the Tls variant, `#[allow(clippy::large_enum_variant)]`). `AsyncRead`/`AsyncWrite` delegation via `Pin::new(s).poll_*`.
- **2026-03-09:** `TlsConnector::new_no_alpn()` added via internal `build(tls_config, use_http_alpn)` refactor. FTP/SMTP/IMAP don't use HTTP ALPN protocols; sending them could cause some servers to reject the connection. No public API change to existing `new()`.
- **2026-03-09:** Explicit FTPS uses AUTH TLS → PBSZ 0 → PROT P sequence before login (RFC 4217). `auth_tls()` consumes self because it needs to reassemble the split reader/writer, extract TcpStream, TLS-wrap it, and re-split. PBSZ/PROT happen on the (now TLS) control connection after upgrade.
- **2026-03-09:** Active mode FTP uses `tokio::net::TcpListener::bind(local_ip, 0)` for OS-assigned ports. PORT command formats IPv4 octets; EPRT supports both IPv4/IPv6. `--ftp-port "-"` uses the control connection's local address (stored during connect).
- **2026-03-09:** `ftps://` URL scheme defaults to port 990 (implicit FTPS). The `url` crate doesn't know about `ftps`, so `port_or_default()` has a fallback match. In `do_single_request`, `ftps://` always maps to `FtpSslMode::Implicit`.
- **2026-03-09:** SSH/SFTP/SCP uses russh 0.57 + russh-sftp 2.1 (pure-Rust). russh 0.48 does not have a `ring` feature; `ring` support was added in v0.53.0. Using `default-features = false, features = ["ring"]` to match our existing ring 0.17 dependency (from rustls).
- **2026-03-09:** `SshHandler` accepts all server host keys by default (matching curl's behavior without `--known-hosts`). Known hosts verification deferred to a future phase.
- **2026-03-09:** `best_supported_rsa_hash()` in russh 0.57 returns `Result<Option<Option<HashAlg>>>` — triple-nested. Flattened with `.ok().flatten().flatten()` to get `Option<HashAlg>` for `PrivateKeyWithHashAlg::new()`.
- **2026-03-09:** SCP protocol implemented via exec channel (`scp -f` for download, `scp -t` for upload) rather than SFTP subsystem. SCP header parsing extracts file size from "C<mode> <size> <filename>" format. Acknowledgement is single null byte; error codes 1/2 include message text.
- **2026-03-09:** `--key` flag (CURLOPT_SSH_PRIVATE_KEYFILE in libcurl) sets both TLS client key and SSH identity in the CLI, matching curl's dual-purpose behavior. At transfer time, the appropriate one is used based on URL scheme.
- **2026-03-09:** SSH auth fallback order: explicit `--key` → URL password → default keys (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`). If no credentials available, returns `Error::Ssh` with guidance message.
- **2026-03-09:** Multi API event loop FFI functions use pragmatic stubs: tokio owns socket polling, so `curl_multi_fdset` returns max_fd=-1, `curl_multi_wait/poll` provide simple `thread::sleep`, `curl_multi_socket_action` delegates to `curl_multi_perform` on `CURL_SOCKET_TIMEOUT` (-1). Socket/timer callbacks are accepted and stored but not actively invoked. `curl_multi_info_read` returns `CURLMsg` pointers from a Vec-based message queue populated during `curl_multi_perform`.
- **2026-03-09:** `CURLMsg` returned by `curl_multi_info_read` uses a rotate-to-back strategy: the consumed message is removed from the front and pushed to the back, with a pointer to the last element returned. This keeps the pointer valid until the next call (matching libcurl's lifetime guarantee).
- **2026-03-09:** `CURLMOPT_MAXCONNECTS` (6) and `CURLMOPT_MAX_TOTAL_CONNECTIONS` (13) both map to `Multi::max_total_connections()`. In libcurl they have subtly different semantics (cache size vs active limit), but for our implementation the distinction is irrelevant since tokio manages connection lifecycle.
- **2026-03-09:** HTTP/2 server push uses `response_fut.push_promises()` which clones h2 internal state, allowing independent collection in a background task without blocking the main response await. Spawned as a `tokio::spawn` task that runs concurrently with response body reading.
- **2026-03-09:** HTTP/3 via quinn/h3/h3-quinn uses `bytes` crate as a direct dependency (feature-gated behind `http3`) because h3's `recv_data()` returns `impl Buf` which requires the `Buf` trait in scope. The `bytes` crate is already a transitive dependency via h3/quinn.
- **2026-03-09:** HTTP/3 dispatch in easy.rs bypasses TCP connection and TLS — it uses the resolved DNS address directly for QUIC (UDP). The QUIC endpoint binds to 0.0.0.0:0 (OS-assigned port). Connection errors map to `Error::Connect` to match the existing error taxonomy.

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

### Phase 0: Cumulative Summary (Phases 1-29, completed 2026-03-09)

Built from scratch over 29 phases. All features below are implemented and tested.

**Core Library (liburlx) — 79 Easy methods, 14 Multi methods:**
- **HTTP/1.x:** Full request/response codec (all methods), chunked transfer encoding with trailer header parsing, Content-Encoding decompression (gzip, deflate, brotli, zstd), redirects (301/302/303/307/308), Expect: 100-continue, HTTP/1.0 mode, header deduplication (last wins), ignore-content-length (read to EOF), auth stripping on cross-origin redirects (unrestricted_auth option).
- **HTTP/2:** Via h2 crate with ALPN negotiation. `HttpVersion` enum (None/Http10/Http11/Http2/Http3). Server push collection via `push_promises()` stream — `PushedResponse` struct with URL, status, headers, body.
- **TLS:** rustls + tokio-rustls. `TlsConfig` with verify_peer/host, CA cert, client cert/key, version selection (TLS 1.2/1.3), certificate pinning (SHA-256 SPKI), cipher list, session cache. Inline DER parser for SPKI extraction.
- **Authentication:** Basic, Bearer, Digest (MD5/SHA-256 with qop=auth), AWS SigV4 (inline HMAC-SHA256), NTLM skeleton (SHA-256-based, sufficient for proxy auth testing).
- **Cookie engine:** RFC 6265 parsing, domain/path matching, Netscape file format persistence (read/write), HttpOnly, Secure, SameSite (stored). Domain-indexed jar (HashMap by domain for O(1) lookup). No public suffix list.
- **HSTS cache:** STS parsing, HTTP→HTTPS upgrade, includeSubDomains.
- **Proxy:** HTTP forward, HTTP CONNECT tunnel (with Digest/NTLM 407 challenge-response), SOCKS4/4a/5 with auth, noproxy bypass, proxy TLS config.
- **Connection:** Pool with stale retry, TCP_NODELAY (default on), TCP keepalive (socket2), Unix domain sockets, interface/port binding, Happy Eyeballs (250ms, configurable).
- **DNS:** Cache with configurable TTL, shuffle (inline xorshift32), custom server addresses, DoH URL config. No async resolver.
- **FTP:** Session-based API — STOR, APPE, REST, FEAT, MKD/RMD/DELE, RNFR/RNTO, SITE, PWD/CWD, SIZE, MLSD, TYPE A/I. Explicit FTPS (AUTH TLS + PBSZ 0 + PROT P, RFC 4217), implicit FTPS (port 990, direct TLS). Active mode (PORT for IPv4, EPRT for IPv4/IPv6). `FtpStream` enum (Plain/Tls) with `AsyncRead`/`AsyncWrite` delegation. `ftps://` URL scheme with default port 990. `TlsConnector::new_no_alpn()` for non-HTTP TLS.
- **SSH/SFTP/SCP:** Via russh + russh-sftp (pure-Rust, async). `SshSession` with password and public key auth. SFTP download/upload/list via `SftpSession`. SCP download/upload via exec channel with SCP protocol parsing. Auto-discovery of `~/.ssh/id_{ed25519,rsa,ecdsa}` keys. Feature-gated behind `ssh` (optional). `sftp://` and `scp://` URL schemes with default port 22. `Error::Ssh` variant.
- **HTTP/3:** Via quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10 for QUIC transport (feature-gated `http3`). QUIC client config with ALPN "h3", insecure cert verifier for -k mode. Rate-limited body send/recv. Wired into easy.rs dispatch for `HttpVersion::Http3`. No 0-RTT or Alt-Svc upgrade.
- **Other protocols:** WebSocket (RFC 6455), SMTP, IMAP, POP3, MQTT 3.1.1, DICT, TFTP, FILE.
- **Multi API:** JoinSet-based concurrency, connection limiting (semaphore), message queue, Share interface (DNS cache + cookie jar), PipeliningMode (Nothing/Multiplex). FFI event loop: wait/poll/wakeup, fdset, socket_action, timeout, info_read, setopt, strerror.
- **Alt-Svc:** Header parsing (RFC 7838), TTL-based cache, automatic processing in transfers.
- **Transfer control:** Rate limiting enforced in transfer engine via `SpeedLimits` and `RateLimiter`. Max recv/send speed throttling (token bucket, 16KB chunks). Low speed enforcement aborts with `Error::SpeedLimit` after timeout.
- **Performance:** Hot-path string allocation elimination — cookie domain matching, DNS cache keys, response header lookup, decompression encoding dispatch, multipart content type guessing all use `eq_ignore_ascii_case` instead of `to_lowercase()`. Criterion benchmarks for URL parsing, cookie jar, HSTS cache, DNS cache, response headers, and cookie domain matching.
- **Response:** Status, headers, body, trailers, effective_url, TransferInfo (6 timing fields + speed/size metrics).

**FFI Layer (liburlx-ffi) — 86 CURLOPT, 22 CURLINFO, 25 CURLcode, 43 functions:**
- Functions: curl_easy_init/cleanup/duphandle/reset/setopt/perform/getinfo/strerror, curl_slist_append/free_all, curl_multi_init/cleanup/add_handle/remove_handle/perform/info_read/setopt/timeout/wait/poll/wakeup/fdset/socket_action/strerror, curl_version, curl_mime_init/addpart/name/data/filename/type/free, curl_share_init/cleanup/setopt/strerror, curl_url/url_cleanup/url_dup/url_set/url_get, curl_free.
- Callbacks: WRITEFUNCTION, READFUNCTION (with CURL_READFUNC_ABORT), HEADERFUNCTION, DEBUGFUNCTION, PROGRESSFUNCTION, XFERINFOFUNCTION, SEEKFUNCTION.
- Options: CURLOPT_PRIVATE, CURLOPT_SHARE, CURLOPT_MIMEPOST, CURLOPT_NOPROGRESS, CURLOPT_REFERER, CURLOPT_HTTP_VERSION, CURLOPT_XOAUTH2_BEARER, CURLOPT_RESUME_FROM_LARGE, CURLOPT_NOSIGNAL, CURLOPT_AUTOREFERER, CURLOPT_LOCALPORTRANGE, CURLOPT_AWS_SIGV4.
- Multi options: CURLMoption (SOCKETFUNCTION, SOCKETDATA, PIPELINING, TIMERFUNCTION, TIMERDATA, MAXCONNECTS, MAX_HOST_CONNECTIONS, MAX_TOTAL_CONNECTIONS).
- Enums: CURLSHcode (6), CURLSHoption (4), CURLUcode (10), CURLUPart (11), CURLMcode (6), CURLMSG (1), CURLMoption (8).
- URL API: Mutable UrlHandle with component-level get/set (scheme, user, password, host, port, path, query, fragment).
- Memory: Box<[u8]>-based slist string allocation (exact-size, no capacity mismatch). catch_unwind on all FFI boundaries.

**CLI (urlx) — ~89 long flags + short aliases:**
- HTTP: -X, -H, -d, --data-raw, --data-binary, --data-urlencode, -L, --max-redirs, -I, -A, -e, -G, -F, -r, -C, --compressed, --http1.0, --http1.1, --http2, --http3, --expect100-timeout, --post301, --post302, --post303.
- Output: -o, -O, -D, -i, -w, --create-dirs, -v, -s, -S, -f, -#, -R/--remote-time.
- Auth: -u, --digest, --bearer, --aws-sigv4, -b, -c, --netrc, --netrc-file, --netrc-optional.
- TLS/SSH: -k, --cacert, --cert, --key (TLS client key + SSH identity), --tlsv1.2, --tlsv1.3, --tls-max, --pinnedpubkey.
- Proxy: -x, --noproxy, --socks5-hostname, --proxy-user, --proxy-digest, --proxy-ntlm, --proxy-header.
- Transfer: -m, --connect-timeout, --retry/--retry-delay/--retry-max-time, --limit-rate, --speed-limit, --speed-time, -T, --unrestricted-auth, --ignore-content-length.
- Connection: --tcp-nodelay, --tcp-keepalive, --no-keepalive, --unix-socket, --interface, --local-port, --resolve.
- DNS: --dns-shuffle, --dns-servers, --doh-url, --happy-eyeballs-timeout-ms.
- Concurrency: -Z, --parallel-max.
- Debug/Config: --trace, --trace-ascii, --trace-time, -K/--config, --libcurl, --proto, --proto-redir, --max-filesize, --hsts, --next.
- FTP: --ftp-pasv, --ftp-ssl, --ssl, --ftp-ssl-reqd, --ssl-reqd, --ftp-port.
- Features: .curlrc-style config file parser, protocol restriction, max filesize enforcement (exit 63), libcurl C code generation, retry logic (408/429/5xx), netrc credential lookup.

**Testing — 1,958 tests (0 failures):**
- Unit + integration tests across all crates
- Integration: 1,048 (hyper-based test servers)
- Property-based: 60 (proptest — URL, cookie, FTP, HTTP, HSTS, multipart, protocols, WebSocket)
- Doc tests: 3
- Fuzz harnesses: 4 (URL, HTTP, cookie, HSTS parsers)
- Benchmarks: 3 (throughput, latency, concurrency via criterion)

**Guardrails:** Zero TODO/FIXME/HACK. Zero `unwrap()` in production code. `#![deny(unsafe_code)]` in liburlx and urlx-cli. GitHub Actions CI (fmt, clippy, test on 3 OS, doc, cargo-deny, MSRV 1.83, commit lint). Pre-commit hooks (fmt, clippy, test, deny, doc, conventional commit).

**Known gaps (as of Phase 31):** Trace file writing not fully wired. HTTP/3 missing 0-RTT and Alt-Svc-based upgrade from HTTP/2. HTTP/2 missing stream priority/dependency. SSH known_hosts verification not implemented. Socket/timer callbacks stored but not actively invoked (tokio manages I/O). Missing FFI: CURLOPT_HTTPPOST (deprecated). URL globbing (--glob) not yet implemented. No async DNS resolver (hickory-dns). No cookie public suffix list. NTLM auth is skeleton only.

---

### Phase 30: Completeness Review (2026-03-09)

Third mandatory review phase. Audited the codebase against curl/libcurl. Compacted phases 21-29 into Phase 0.

**Audit results:**
- 43 FFI functions, 86 CURLOPT, 22 CURLINFO, 25 CURLcode
- 79 Easy API methods, 14 Multi methods
- ~89 CLI long flags + short aliases
- 18 protocol modules (10 top-level + 8 HTTP submodules)
- 1,954 tests (0 failures)
- Hot-path string allocation optimizations applied

**Completeness assessment:**
- ~92% for basic HTTP/HTTPS use cases
- ~60% overall curl feature parity
- FFI at ~46% (43 of ~90+ libcurl functions)
- CLI at ~36% (~89 of ~250 flags)

**Key gaps for 1.0:**
1. Async DNS resolver (hickory-dns) for non-blocking resolution
2. HTTP/3 Alt-Svc upgrade and 0-RTT
3. HTTP/2 stream priority/dependency
4. HTTPS proxy tunneling
5. Trace file output (--trace writes to file)
6. URL globbing (--glob)
7. Additional FFI functions (curl_formadd, curl_getdate, curl_escape/unescape)
8. Additional CLI flags (50+ remaining common flags)
9. Cookie public suffix list
10. NTLM full implementation (MD4+DES crypto)

---

### Phase 31: Cookie Domain Indexing (2026-03-09)

Domain-indexed cookie jar for O(1) lookup. HashMap<String, Vec<usize>> maps domains to cookie indices. cookie_header() walks exact + parent domains via index. Index rebuilt on mutation. 4 new tests. Remaining items (hickory-dns async resolver, cookie public suffix list, DoH implementation) deferred to Phase 36+.

---

### Phase 32: HTTPS Proxy & Trace Output

**Goal:** Complete proxy and debug features.

- HTTPS proxy tunnel (CONNECT through TLS proxy)
- PAC file support (basic)
- Trace file writing (--trace, --trace-ascii output to file)
- --stderr flag for error output redirection

---

### Phase 33: CLI Expansion III

**Goal:** Continue CLI toward full curl parity.

- `--globoff` / URL globbing support
- `--path-as-is` (don't normalize dots in path)
- `--raw` (disable HTTP decoding)
- `--remote-header-name` (Content-Disposition filename)
- `--styled-output` / `--no-styled-output`
- `--url-query` (append query parameters)
- `--json` (shorthand for JSON POST)
- `--rate` (request rate limiting for parallel)

---

### Phase 34: FFI Expansion II

**Goal:** Expand FFI toward 100+ options and 50+ functions.

- curl_formadd / curl_formfree (deprecated but used)
- curl_getdate (RFC 2822 date parsing)
- curl_escape / curl_unescape (URL encoding)
- CURLOPT_HTTPPOST (deprecated multipart API)
- Additional CURLINFO codes (local IP/port, redirect URL, condition unmet)
- Target: 100+ CURLOPT, 30+ CURLINFO, 50+ functions

---

### Phase 35: WebSocket Enhancements

**Goal:** Improve WebSocket support.

- WebSocket compression (permessage-deflate)
- Ping/pong handling
- Close frame handling with status codes
- Binary message support improvements
- WSS (WebSocket over TLS)

---

### Phase 36: HTTP/3 Maturity

**Goal:** Complete HTTP/3 support.

- Alt-Svc-based HTTP/3 upgrade from HTTP/2
- 0-RTT early data
- Connection migration
- QUIC connection pooling
- HTTP/3 server push

---

### Phase 37: Platform & Build

**Goal:** Cross-platform improvements.

- native-tls backend (Schannel/SecureTransport)
- Platform-specific socket options
- Static linking support
- pkg-config integration for FFI
- cbindgen header generation automation

---

### Phase 38: CLI Expansion IV

**Goal:** Additional CLI flags for specialized use cases.

- `--ciphers` (TLS cipher selection)
- `--negotiate` / `--ntlm` (auth flags)
- `--delegation` (Kerberos delegation)
- `--sasl-authzid` / `--sasl-ir` (SASL options)
- `--mail-from` / `--mail-rcpt` / `--mail-auth` (SMTP flags)
- `--ftp-create-dirs` / `--ftp-method` (FTP flags)

---

### Phase 39: Differential Testing

**Goal:** Systematic testing against curl behavior.

- Port curl test cases from tests/data/ format
- Side-by-side output comparison tool
- Edge case coverage for redirects, encoding, auth
- Error code mapping verification
- Timing/performance comparison benchmarks

---

### Phase 40: 1.0 Release Preparation

**Goal:** Fourth mandatory review. Final 1.0 readiness assessment.

- API stability freeze
- Comprehensive changelog
- Documentation review
- Security audit
- Performance baseline
- Plan 1.0 release or phases 41-50

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
