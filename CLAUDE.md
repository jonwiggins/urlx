# CLAUDE.md — urlx / liburlx

## Project Identity

**urlx** is a memory-safe Rust reimplementation of curl and libcurl. The project produces three artifacts:

- `liburlx` — An idiomatic Rust transfer library (the core)
- `liburlx-ffi` — A C ABI compatibility layer that is a drop-in replacement for libcurl
- `urlx` — A command-line tool that is a drop-in replacement for the `curl` command

The project is MIT-licensed. The name "urlx" stands for "URL transfer."

---

## Current Status

**Version:** v0.1.0 published (crates.io + GitHub Releases + Homebrew)
**Last completed:** Phase 66 — Wire Unwired Easy API Fields — 2026-03-10
**Total tests:** 2,605
**In progress:** Phase 67
**Blockers:** None

### Completeness Summary (post-Phase 66)

| Feature Area | Parity | Notes |
|---|---|---|
| HTTP/1.1 | 98% | Expect, HTTP/1.0, trailer headers, chunked upload |
| HTTP/2 | 75% | ALPN, multiplexing, flow control, connection pooling, server push work; **all 7 tuning options stored but not wired to h2 crate** |
| HTTP/3 | 55% | QUIC via quinn, Alt-Svc, 0-RTT; no pooling/push; **untested** |
| TLS | 88% | rustls, insecure mode, CA/client certs, pinning, version selection, cipher list, blob cert options |
| Authentication | 65% | Basic, Bearer, Digest, AWS SigV4 fully wired; **NTLMv2 proxy-only (not wired for HTTP 401)**; **SCRAM-SHA-256 implemented but wired to nothing** |
| Cookie engine | 97% | Netscape file format, domain-indexed jar, PSL validation, SameSite enforcement |
| Proxy | 85% | HTTP + SOCKS + HTTPS tunnel (TLS-in-TLS), proxy NTLM auth, proxy_port, proxy_type, proxy_headers wired; **pre_proxy not wired**; no PAC |
| DNS | 86% | Cache, Happy Eyeballs (RFC 8305), shuffle, custom servers, DoH, DoT, hickory-dns; doh_insecure accepted |
| FTP | 85% | Session API, FTPS, active/passive mode, resume, MLST/MLSD; EPSV/EPRT, skip_pasv_ip, ACCT, create_dirs, FtpMethod all wired via FtpConfig |
| SSH/SFTP/SCP | 72% | Download/upload, password + pubkey auth, known_hosts, SHA-256 fingerprint, symlink following; ssh_auth_types filtering wired |
| WebSocket | 92% | RFC 6455, CloseCode, fragmentation, permessage-deflate (RFC 7692), ws:// wss:// dispatch |
| Multi API | 40% | Connection limiting, share; **curl_multi_fdset, curl_multi_socket_action, curl_multi_wakeup are no-ops**; event loop incompatible with tokio architecture |
| FFI (libcurl C ABI) | ~60% | 119 CURLOPT, 47 CURLINFO, 42 CURLcode, 56 functions, C test harness; **~15 options return OK but do nothing; curl_easy_pause is a no-op** |
| CLI | ~70% | 246 long + 39 short flags; **87 flags (30%) are silent no-ops**; ~159 functional flags |
| Connection | 90% | Pool (TTL, max-per-host, max-total, cleanup), TCP_NODELAY, keepalive, Unix sockets, Happy Eyeballs; fresh_connect, forbid_reuse, connect_to, haproxy_protocol wired |
| Transfer control | 80% | Rate limiting enforced; path_as_is wired; **curl_easy_pause is a no-op; abstract_unix_socket returns error** |
| Overall | ~68% | ~92% for basic HTTP/HTTPS use cases |

### Known Issues (post-Phase 66)

- **~15 remaining unwired fields** — pre_proxy (complex two-hop chain), abstract_unix_socket (needs OS-specific API), doh_insecure (accepted but not enforced by hickory)
- **NTLMv2 not wired for HTTP 401** — only works for proxy 407 (see Phase 67)
- **SCRAM-SHA-256 fully implemented but wired to no protocol** — dead code (see Phase 67)
- **FFI returns CURLE_OK for ~15 unimplemented options** — silent compatibility hazard (see Phase 67)
- **87 of 285 CLI flags are no-ops** — no warning emitted (see Phase 68)
- **All 7 HTTP/2 tuning options stored but not passed to h2** (see Phase 68)
- **curl_easy_pause() returns OK but does nothing** (see Phase 69)
- **Multi API event loop functions are no-ops** — tokio architecture mismatch (see Phase 69)
- HTTP/3 untested (needs quinn test server)
- Some integration tests hang/timeout (pre-existing, not affecting lib tests)

---

## Implementation Phases

### Phase 0 — Cumulative Summary (Phases 1-59)

**What has been built:** A functional curl replacement covering HTTP/1.0-1.1, HTTP/2 (with ALPN, multiplexing, connection pooling, server push), HTTP/3 (QUIC via quinn), TLS (rustls + native-tls), FTP/FTPS (full session, active mode, MLST/MLSD, resume), SSH/SFTP/SCP, WebSocket (RFC 6455 + permessage-deflate), MQTT (QoS 0/1/2), SMTP, IMAP, POP3, DICT, TFTP, file://, DNS (system + hickory + DoH + DoT + Happy Eyeballs), cookies (Netscape format, domain-indexed, PSL, SameSite), HSTS (persistence), proxies (HTTP/SOCKS4/SOCKS4a/SOCKS5/HTTPS tunnel), authentication (Basic, Digest, Bearer, AWS SigV4, NTLMv2, SCRAM-SHA-256), connection pooling, rate limiting, multipart form upload, decompression (gzip, deflate, br, zstd), and a C ABI compatibility layer (liburlx-ffi).

**Key stats (Phase 60 audit):**
- Tests: 2,515
- CLI flags: 246 long + 40 short (curl has ~250 long flags)
- FFI: 119 unique CURLOPT, 47 CURLINFO, 42 CURLcode, 56 exported functions, C test harness
- Benchmark suite: 9 groups (URL parsing, cookies, HSTS, DNS, headers, HTTP parsing, multipart)
- Feature flags: 20+ (http, http2, http3, ftp, ssh, ws, mqtt, smtp, imap, pop3, etc.)
- 4 fuzz harnesses (URL, HTTP, cookie, HSTS)

**Phases 52-59 summary:** CLI drop-in essentials (--help, --version, combined short flags, h2 stream fix), protocol dispatch for all schemes, HTTP/2 robustness (pooling, chunked upload, push), FFI hardening (145 CURLOPT, blob certs, protocol restriction), authentication completeness (NTLMv2, SCRAM-SHA-256, SameSite), protocol polish (WS deflate, MQTT QoS, SFTP symlinks, TFTP errors), Criterion benchmarks with optimization, and CLI completeness (~199 long flags, conditional requests, retry logic).

### Phase 60 — Comprehensive Review (In Progress)

Milestone review phase. Audit results:

**FFI Coverage:**
- 119 unique CURLOPT options in enum (curl has ~300)
- 47 unique CURLINFO options (curl has ~60)
- 42 CURLcode error codes (curl has ~99)
- 56 no_mangle exported functions (curl has ~80)
- C test harness: 11 tests

**CLI Coverage:**
- 199 unique long flags + 36 short flags
- curl has ~250 long flags → ~80% coverage
- Missing: man page generation, ~4 low-frequency flags

**Known Gaps:**
- WebSocket not dispatched from Easy API (needs high-level handler)
- HTTP/3 untested (needs quinn test server)
- SCRAM-SHA-256 not wired to SMTP/IMAP/POP3
- `curl_easy_pause()` is a no-op stub
- No C test harness for FFI
- LDAP, RTSP, Kerberos/Negotiate not implemented
- PAC proxy auto-configuration not implemented

### Phase 61 — WS Dispatch & Protocol Auth (Completed 2026-03-10)

Wired ws:// and wss:// scheme dispatch in `do_single_request` via new `ws::connect()` function. The connect handler performs TCP connection (plain for ws://, TLS via `TlsConnector::new_no_alpn` for wss://), sends HTTP upgrade request with Sec-WebSocket-Key, validates Sec-WebSocket-Accept in response, returns Response with 101 status. Added `parse_upgrade_response()` helper. 4 new tests (parse_upgrade_response 101/403/invalid_accept, ws_connect_mock_server). HTTP/3 testing and SCRAM-SHA-256 wiring deferred to Phase 62.

### Phase 62 — FFI Parity Push (Completed 2026-03-10)

Added 17 new CURLOPT options (PORT, INFILESIZE, RESUME_FROM, PROXYPORT, FILETIME, BUFFERSIZE, PROXYTYPE, IPRESOLVE, FTP_FILEMETHOD, SOCKS5_AUTH, POSTFIELDSIZE_LARGE, CAPATH, MAXCONNECTS, PIPEWAIT, STREAM_WEIGHT, TCP_FASTOPEN, HTTP09_ALLOWED), 4 CURLINFO getters (REQUEST_SIZE, HTTP_CONNECTCODE, HTTPAUTH_AVAIL, PROXYAUTH_AVAIL), 10 CURLcode error variants. Created C test harness (11 tests covering init/cleanup, setopt, duphandle, reset, strerror, version, pause, slist, URL API, getinfo). 20 new Rust tests. SCRAM-SHA-256 SMTP wiring deferred to Phase 64.

### Phase 63 — CLI Flag Parity (Completed 2026-03-10)

Added ~40 curl flags: -4/--ipv4, -6/--ipv6, -j/--junk-session-cookies, -l/--list-only, -Q/--quote, --http3-only, --oauth2-bearer, --pubkey, --tcp-fastopen, --no-clobber, --suppress-connect-headers, --http0.9, --trace-ids, --disallow-username-in-url, --curves, --engine, --dns-interface, and 25+ more as no-ops. CLI now at 246 long + 40 short flags (~98% of curl's ~250 long flags). Man page generation and config file improvements deferred.

### Phase 64 — Error Handling & Diagnostics (Completed 2026-03-10)

Added curl-style verbose output: `* Trying <addr>...` and `* Connected to <host> (<ip>) port <port>`. Improved error-to-exit-code mapping with codes for unsupported protocol (1), partial file (18), upload failed (25), and send error (55). Added 7 tests for exit code mapping. SCRAM-SHA-256 SMTP wiring and trace output parity deferred.

### Phase 65 — Connection & Transfer Polish (Completed 2026-03-10)

Connection pool now has TTL-based expiry (118s default matching curl), per-host limit (5), total limit (25), FIFO eviction, and proactive cleanup. Happy Eyeballs upgraded to RFC 8305 with address interleaving. CURLOPT_MAXCONNECTS wired to Easy::max_pool_connections(). 23 new tests. HTTP/2 stream priority not wired (deprecated by RFC 9113).

### Phase 66 — Wire Unwired Easy API Fields (Completed 2026-03-10)

Wired ~20 previously stored-but-unused Easy API fields to their consumption points. Created FtpConfig struct bundling 7 FTP options (use_epsv, use_eprt, skip_pasv_ip, account, create_dirs, method, active_port) with EPSV/PASV fallback, ACCT command, MKD directory creation, and FtpMethod CWD strategies. Wired fresh_connect/forbid_reuse to connection pool get/put. Wired proxy_port, proxy_type (scheme rewriting), proxy_headers (CONNECT request injection). Added connect_to host:port remapping, path_as_is raw URL path preservation, haproxy_protocol PROXY v1 header. Wired ssh_auth_types bitmask filtering and ssh_public_keyfile passthrough. Added mail_auth (AUTH= in MAIL FROM), sasl_authzid, sasl_ir to SMTP. Passed doh_insecure to DoH resolver. Added Url::set_port/set_scheme helpers. Deferred: pre_proxy (complex two-hop), abstract_unix_socket (needs OS API). ~49 new tests.

### Phase 67 — Wire Authentication & Fix FFI Honesty

**Problem:** NTLMv2 only works for proxy auth, not HTTP 401. SCRAM-SHA-256 is fully implemented but wired to nothing. FFI returns CURLE_OK for ~15 options it doesn't implement.

#### NTLMv2 for HTTP server auth (easy.rs)
- In the 401-response handling path (~line 2075), add NTLM challenge-response alongside existing Digest handling
- Implement Type 1 → Type 2 → Type 3 message exchange over HTTP (two round trips)
- Test with mock server returning 401 + WWW-Authenticate: NTLM

#### SCRAM-SHA-256 wiring (protocol/smtp.rs, protocol/imap.rs, protocol/pop3.rs)
- Wire `auth/scram.rs` into SMTP AUTH command (after EHLO, check for AUTH SCRAM-SHA-256 capability)
- Wire into IMAP AUTHENTICATE command
- Wire into POP3 AUTH command
- Test each with mock server exercising the full SASL exchange

#### FFI honesty — return CURLE_NOT_BUILT_IN instead of CURLE_OK for unimplemented options
- Proxy TLS options: PROXY_CAPATH, PROXY_CRLFILE, PROXY_PINNEDPUBLICKEY, PROXY_SSLVERSION, PROXY_SSL_CIPHER_LIST, PROXY_TLS13_CIPHERS, SOCKS5_AUTH
- Other no-ops that claim success: auto-referer, TCP Fast Open, HTTP/0.9, HSTS file I/O, FTP clear command channel, FTP PRET, FTP compression
- Add CURLE_NOT_BUILT_IN variant to CURLcode if not present
- Document which options are accepted-but-ignored vs truly unimplemented

### Phase 68 — HTTP/2 Settings & CLI Honesty

**Problem:** All 7 HTTP/2 tuning options are stored but never passed to the h2 crate. 87 of 285 CLI flags are silent no-ops.

#### HTTP/2 settings wiring (easy.rs → protocol/http/h2.rs)
- `http2_window_size` → pass to h2::client::Builder::initial_window_size()
- `http2_connection_window_size` → pass to h2::client::Builder::initial_connection_window_size()
- `http2_max_frame_size` → pass to h2::client::Builder::max_frame_size()
- `http2_max_header_list_size` → pass to h2::client::Builder::max_header_list_size()
- `http2_enable_push` → pass to h2::client::Builder::enable_push()
- `http2_ping_interval` → spawn keepalive ping task on the h2 connection
- Skip `http2_stream_weight` — stream priority is deprecated in RFC 9113, document why

#### CLI flag audit (urlx-cli/src/args.rs)
- For each of the 87 no-op flags, categorize:
  - **Can implement now:** flags where the underlying Easy API supports it (e.g., `--ipv4`/`--ipv6` → `ip_resolve`, `--junk-session-cookies` → cookie jar clear, `--tcp-fastopen` if wired)
  - **Needs underlying work:** flags where the Easy API doesn't support it yet
  - **Genuinely unnecessary:** flags for features urlx will never support (e.g., `--metalink`, `--ntlm-wb`)
- Wire flags in the first category to their Easy API equivalents
- For genuinely unnecessary flags, emit a warning to stderr when used: `urlx: warning: --flag is not supported and has no effect`
- Fix short flag count: verify 39 vs 40, correct CLAUDE.md

### Phase 69 — curl_easy_pause, Multi API, & Transfer Control

**Problem:** `curl_easy_pause()` returns OK but does nothing. Multi API event loop functions are no-ops. Several transfer control features are stubs.

#### curl_easy_pause (liburlx-ffi)
- Implement actual pause/resume for transfers using tokio channel or flag
- Pause should stop reading from the socket (backpressure via not polling the read future)
- Resume should re-poll the read future
- CURLPAUSE_RECV, CURLPAUSE_SEND, CURLPAUSE_ALL, CURLPAUSE_CONT
- Test with FFI C test and Rust unit test

#### curl_easy_upkeep (liburlx-ffi)
- Implement connection keepalive check (ping pooled connections, evict dead ones)
- Useful for long-lived applications that hold a curl handle

#### Multi API improvements (liburlx-ffi)
- `curl_multi_fdset()` — Expose underlying tokio socket FDs if possible, or document why not
- `curl_multi_socket_action()` — Bridge to tokio reactor, or return CURLE_NOT_BUILT_IN
- Document architectural mismatch: tokio owns the event loop, libcurl's Multi expects the caller to own it

### Phase 70 — v0.2.0 Release

**Milestone release.** All audit remediation from Phases 66-69 is complete. Ship v0.2.0 with honest metrics.

#### Pre-release audit
- Compact phases 60-69 into Phase 0 summary
- Re-count all metrics (tests, flags, FFI options) and update Completeness Summary
- Verify all previously-unwired Easy API fields are now consumed or removed
- Verify FFI no longer returns CURLE_OK for unimplemented options
- Run full test suite (`cargo test --all`), clippy, fmt, doc — zero warnings
- Differential testing against curl for top-20 use cases (GET, POST, upload, redirect, auth, proxy, FTP, cookies, HEAD, PUT, multipart, range, resume, compressed, HTTP/2, verbose, headers, timeout, retry, cert)

#### Version bump
- Bump version to `0.2.0` in all Cargo.toml files (workspace root, liburlx, liburlx-ffi, urlx-cli)
- Update CHANGELOG.md with all changes since v0.1.0, organized by category:
  - **Fixed:** Unwired fields, FFI honesty, NTLMv2 HTTP auth, CLI no-op warnings
  - **Added:** SCRAM-SHA-256 for SMTP/IMAP/POP3, HTTP/2 tuning, curl_easy_pause, pool improvements
  - **Changed:** Completeness percentages now reflect actual wired functionality

#### Documentation
- Update README.md:
  - Revised completeness table, new features since v0.1.0, honest "what works" section
  - Add `brew install urlx` to installation section (Homebrew is already set up)
  - Add a Quick Start section with example commands showing common usage (GET request, POST JSON, download file, upload, follow redirects, custom headers, verbose output, auth, etc.) — make it easy for someone to start using urlx immediately
- Update API docs (`cargo doc`): ensure all newly-wired options have accurate doc comments
- Remove any doc comments that claim functionality that doesn't exist

#### Publish
- `cargo publish -p liburlx` → crates.io
- `cargo publish -p liburlx-ffi` → crates.io
- `cargo publish -p urlx-cli` → crates.io
- Create GitHub Release v0.2.0 with release notes from CHANGELOG.md
- Update Homebrew formula with new version and SHA

#### Post-release
- **STOP and report to the agent's driver.** Provide a summary of:
  - What was accomplished in Phases 66-70
  - Updated completeness percentages (before vs after)
  - Total test count
  - Remaining known gaps and recommended next phases (71-80)
  - Any decisions that need human input before proceeding

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
├── .github/workflows/         # CI (ci.yml) and release (release.yml) pipelines
├── .pre-commit-config.yaml    # Pre-commit hooks
├── crates/
│   ├── liburlx/               # Core library (pure Rust, idiomatic API)
│   │   └── src/               # lib.rs, easy.rs, multi.rs, error.rs, options.rs, info.rs,
│   │                          # url.rs, transfer.rs, pool.rs, filter.rs, cookie.rs,
│   │                          # protocol/{http,ftp,ws,mqtt,smtp,imap,pop3,file,...},
│   │                          # tls/{rustls,native}, dns/{system,hickory},
│   │                          # proxy/{http,socks}, auth/{basic,digest,bearer,negotiate}
│   ├── liburlx-ffi/           # C ABI compatibility layer
│   │   ├── cbindgen.toml      # C header generation config
│   │   ├── include/urlx.h     # Generated C header (libcurl-compatible)
│   │   └── src/               # lib.rs, easy.rs, multi.rs, options.rs, info.rs, error.rs
│   └── urlx-cli/              # Command-line tool
│       └── src/               # main.rs, args.rs, config.rs, output.rs, progress.rs
├── tests/                     # Integration tests, fixtures, test servers
├── benches/                   # Criterion benchmarks (throughput, latency, concurrency)
└── fuzz/                      # 4 cargo-fuzz harnesses (URL, HTTP, cookie, HSTS)
```

---

## Code Style & Conventions

### Error Handling

- Use `thiserror` for error type derivation.
- All public functions return `Result<T, UrlxError>`.
- Error types must be non-exhaustive (`#[non_exhaustive]`) to allow future additions.
- Never panic. Never `unwrap()` in library code. The `unwrap_used` clippy lint is denied.
- In test code, `unwrap()` and `expect()` are fine.

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

The core is async (tokio). The Easy API provides a sync wrapper via `tokio::runtime::Builder::new_current_thread()`. The Multi API is native async.

### Feature Flags

Default features: `http`, `rustls`, `cookies`, `decompression`. Optional: `http2`, `http3`, `ftp`, `mqtt`, `ws`, `smtp`, `imap`, `pop3`, `ssh`, `file`, `hsts`, `dns-over-https`, `socks`, `hickory-dns`, `native-tls`.

---

## Test-Driven Development Protocol

### The TDD Cycle for Every Feature

1. **Write the test first.** The test must fail (or not compile) before any implementation.
2. **Write the minimum code to pass.** No speculative features.
3. **Refactor.** Clean up while all tests still pass.
4. **Verify guardrails.** `cargo clippy`, `cargo fmt`, `cargo doc` must all pass.

### Test Categories

- **Unit tests:** In-crate `#[cfg(test)]` modules. Run with `cargo test --lib`.
- **Integration tests:** `tests/` directory, against real servers (hyper/tokio on random ports). Run with `cargo test --test '*'`.
- **Property-based:** `proptest` for parser correctness (URL, cookie, HSTS, WebSocket, FTP, multipart).
- **Fuzz harnesses:** 4 cargo-fuzz harnesses in `fuzz/`.
- **FFI tests:** C-language test programs linking against liburlx-ffi.

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
