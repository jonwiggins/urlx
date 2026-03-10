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
**Last completed:** Phase 53 — Protocol Dispatch & Integration — 2026-03-10
**Total tests:** 2,318
**In progress:** Phase 54
**Blockers:** None

### Completeness Summary (post-v0.1.0 audit)

| Feature Area | Parity | Notes |
|---|---|---|
| HTTP/1.1 | 97% | Expect, HTTP/1.0, trailer headers; no chunked upload |
| HTTP/2 | 85% | ALPN, multiplexing, flow control, google.com compat; no connection pooling |
| HTTP/3 | 55% | QUIC via quinn, Alt-Svc, 0-RTT; no pooling/push; **untested** |
| TLS | 85% | rustls, insecure mode, CA/client certs, pinning, version selection, cipher list, session cache |
| Authentication | 65% | Basic, Bearer, Digest (CSPRNG cnonce), AWS SigV4, NTLM skeleton |
| Cookie engine | 95% | Netscape file format, domain-indexed jar, PSL validation |
| Proxy | 90% | HTTP + SOCKS + HTTPS tunnel (TLS-in-TLS), proxy auth; no PAC |
| DNS | 85% | Cache, Happy Eyeballs, shuffle, custom servers, DoH, DoT, hickory-dns |
| FTP | 87% | Full session API, FTPS, active mode, FtpMethod; no MLST |
| SSH/SFTP/SCP | 65% | Download/upload, password + pubkey auth, known_hosts, SHA-256 fingerprint |
| WebSocket | 85% | RFC 6455, CloseCode, fragmentation; no permessage-deflate |
| Multi API | 75% | Connection limiting, share, pipelining, FFI event loop stubs |
| FFI (libcurl C ABI) | ~60% | 102 CURLOPT, 43 CURLINFO, 32 CURLcode, 56 functions |
| CLI | ~65% | ~150 flags, --help, --version, combined short flags (-sSfL) |
| Connection | 80% | Pool, TCP_NODELAY, keepalive, Unix sockets, interface/port binding |
| Transfer control | 80% | Rate limiting enforced (max recv/send speed, low speed timeout) |
| Overall | ~64% | ~92% for basic HTTP/HTTPS use cases |

### Known Issues

- WebSocket (ws://, wss://) not dispatched from Easy API (needs high-level handler)
- HTTP/3 untested (needs quinn test server)
- NTLM auth is a skeleton (SHA-256, not real MD4+DES)

---

## Implementation Phases

### Phase 52 — CLI Drop-in Essentials (Completed 2026-03-10)

Added `--help`/`-h`, `--version`/`-V`, combined short flags (`-sSfL`), `ResponseHttpVersion` enum tracking across h1/h2/h3, fixed `%{http_version}` write-out, fixed h2 google.com stream error (removed Host header in favor of `:authority`, added `client.ready()`), handled TLS `close_notify` as EOF in h1.

### Phase 53 — Protocol Dispatch & Integration (Completed 2026-03-10)

Wired smtp://, imap://, pop3://, mqtt://, dict:// dispatch in `do_single_request`. Updated SMTP `send_mail` to accept optional `mail_from`/`mail_rcpt` and return `Response`. Added integration tests with mock TCP servers for dict, pop3, imap, smtp. Added HSTS file persistence (`load_from_file`/`save_to_file`). Deferred ws:// dispatch (needs handler) and HTTP/3 tests (needs quinn server).

### Phase 54 — HTTP/2 Robustness

Improve HTTP/2 to work reliably against real-world servers.

- HTTP/2 connection pooling (reuse h2 connections across requests)
- Server push exposure to caller
- Chunked transfer encoding for request uploads (HTTP/1.1)
- HTTP/2 stream priority (RFC 9113 deprecated but API compat)

### Phase 55 — FFI Hardening

Improve FFI coverage and add C-side testing.

- Create C test harness (compile and link C programs against liburlx-ffi)
- Wire blob cert options (`CURLOPT_SSLCERT_BLOB`, `SSLKEY_BLOB`, `CAINFO_BLOB`)
- Wire `CURLOPT_PROTOCOLS_STR` / `CURLOPT_REDIR_PROTOCOLS_STR` enforcement
- Implement `curl_easy_pause()` (pause/unpause transfers)
- Add 20+ new CURLOPT options for FTP, SSH, proxy

### Phase 56 — Authentication & Security

Fill auth gaps and harden security features.

- Full NTLMv2 implementation (MD4 + DES per MS-NLMP spec)
- SASL mechanism support (SCRAM-SHA-256)
- SameSite cookie enforcement
- FTP resume (wire REST command to upload/download)
- SFTP ed25519 key support

### Phase 57 — Protocol Polish

Improve protocol implementations to near-complete parity.

- WebSocket `permessage-deflate` (RFC 7692)
- MQTT QoS 1/2 support
- FTP MLST/MLSD (RFC 3659)
- SFTP symlink following, permission preservation
- TFTP RFC 2478 error extensions

### Phase 58 — Performance & Benchmarking

Profile, optimize, and publish benchmarks.

- Benchmark against curl for throughput, latency, concurrency
- HTTP/2 multiplexing performance
- Connection pool efficiency
- Memory usage profiling
- Publish benchmark results in README

### Phase 59 — CLI Completeness

Push CLI toward full curl flag parity.

- Implement remaining ~100 curl flags (prioritized by usage frequency)
- PAC proxy auto-configuration
- Kerberos/Negotiate authentication
- LDAP/RTSP protocol stubs
- Man page generation

### Phase 60 — Comprehensive Review

Milestone review phase (every 10th phase).

- Audit full codebase against curl for completeness
- Differential testing against curl with real-world URLs
- FFI coverage measurement
- Performance profiling
- Plan phases 61-70

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
