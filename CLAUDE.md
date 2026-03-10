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
**Total tests:** ~2,596
**In progress:** Phase 65
**Blockers:** None

### Audit Results (2026-03-10)

An independent audit ran curl's own test suite (`runtests.pl`) and differential tests against the urlx binary. Results:

- **curl test harness:** 0/13 HTTP tests passed (tests 1-13). 2/12 file:// tests passed (200, 202).
- **Differential testing (real endpoints):** ~74% functional parity after discounting User-Agent differences.
- **Hangs:** Tests involving HEAD requests or Connection: close responses hang indefinitely.
- **Test count verified:** ~2,596 (via `cargo test -- --list`), not 2,605 as previously claimed.
- **CLI flags verified:** 238 long (not 246), 40 short (not 39), ~89 no-ops (not 87).
- **FFI:** 56 exported functions confirmed. Only 1/56 has catch_unwind (CLAUDE.md requires all 56).

### Failure Categories from curl Test Suite

| Category | Severity | Tests Affected | Root Cause |
|---|---|---|---|
| Header ordering | High (blocks all harness tests) | 1-13 | urlx sends Accept before User-Agent; curl sends Host, User-Agent, Accept |
| Hangs | Critical | 14, 31+ | HEAD and Connection: close responses never complete |
| Cookie `-b` parsing | High | 6, 7, 8 | Multi-cookie syntax only sends last cookie; cookie file parsing broken |
| Redirect following | High | 11 | Follows wrong URL (sends to /verifiedserver instead of Location target) |
| Missing auto Content-Type | Medium | 3 | POST with `-d` doesn't add `Content-Type: application/x-www-form-urlencoded` |
| Proxy behavior | Medium | 5 | Fragment leaks into proxy URL; `Connection: close` instead of `Proxy-Connection: Keep-Alive` |
| Multipart Content-Length | Medium | 9 | Wrong size (471 vs expected 431) |
| Exit codes | Medium | 19, 20 | Wrong codes for unsupported protocol (returns 3, expected 1) and bad URL |
| Header casing (`-i`) | Low | 15 | urlx lowercases response headers; curl preserves original case |
| FTP command sequence | Medium | 100-105 | Missing PWD, different command ordering, wrong default password |

### Known Issues (carried forward)

- HTTP/3 untested (needs quinn test server)
- FFI returns CURLE_OK for ~15 unimplemented options
- 55/56 FFI functions lack catch_unwind wrappers
- curl_easy_pause() returns OK but does nothing
- Multi API event loop functions are no-ops (tokio architecture mismatch)

---

## Implementation Phases

### Phase 0 — Cumulative Summary (Phases 1-66)

**What has been built:** A functional curl replacement covering HTTP/1.0-1.1, HTTP/2 (with ALPN, multiplexing, connection pooling, server push), HTTP/3 (QUIC via quinn), TLS (rustls + native-tls), FTP/FTPS (full session, active/passive mode, MLST/MLSD, resume, EPSV/EPRT, FtpConfig with 7 options), SSH/SFTP/SCP (password + pubkey auth, known_hosts, SHA-256 fingerprint), WebSocket (RFC 6455 + permessage-deflate, ws:// wss:// dispatch), MQTT (QoS 0/1/2), SMTP (AUTH PLAIN/LOGIN, mail_auth, sasl_authzid), IMAP, POP3, DICT, TFTP, file://, DNS (system + hickory + DoH + DoT + Happy Eyeballs RFC 8305), cookies (Netscape format, domain-indexed, PSL, SameSite), HSTS (persistence), proxies (HTTP/SOCKS4/SOCKS4a/SOCKS5/HTTPS tunnel, proxy_port/proxy_type/proxy_headers wired), authentication (Basic, Digest, Bearer, AWS SigV4, NTLMv2, SCRAM-SHA-256), connection pooling (TTL 118s, per-host limit 5, max-total 25, FIFO eviction), rate limiting, multipart form upload, decompression (gzip, deflate, br, zstd), and a C ABI compatibility layer (liburlx-ffi with 56 exported functions).

**Key stats (verified by independent audit):**
- Tests: ~2,596 (819 liburlx lib + 278 FFI lib + 309 CLI + ~1,187 integration/proptest + 3 doc)
- CLI flags: 238 long + 40 short (curl has ~250 long flags); ~89 are no-ops
- FFI: 119 unique CURLOPT, 47 CURLINFO, 42 CURLcode, 56 exported functions, C test harness (11 tests)
- Benchmark suite: 9 groups (URL parsing, cookies, HSTS, DNS, headers, HTTP parsing, multipart)
- Feature flags: 20+ (http, http2, http3, ftp, ssh, ws, mqtt, smtp, imap, pop3, etc.)
- 4 fuzz harnesses (URL, HTTP, cookie, HSTS)
- 141 Rust source files, ~59,000 lines of code

**Phases 60-66 summary:** Comprehensive review (Phase 60), WS dispatch + protocol auth (Phase 61), FFI parity push with 17 new CURLOPT + C test harness (Phase 62), CLI flag parity ~238 long flags (Phase 63), error handling + exit code mapping (Phase 64), connection pool TTL + Happy Eyeballs RFC 8305 (Phase 65), wiring ~20 Easy API fields including FtpConfig, proxy, connect_to, haproxy_protocol, ssh_auth_types, SMTP SASL options (Phase 66).

### Phase 65 — HTTP Header Ordering & Connection Handling

**Goal:** Pass curl test harness tests 1-14 by fixing the two most impactful issues: header ordering and connection close handling.

**Validated by:** curl's `runtests.pl` tests 1, 2, 10, 12, 13, 14 (pure header ordering + HEAD hang).

#### Header ordering (protocol/http/h1.rs)
- curl sends headers in this order: Host, User-Agent, Accept, then remaining headers
- urlx currently sends Accept before User-Agent — every curl test fails on this diff
- Fix `build_request()` or equivalent in h1.rs to match curl's header order: Host first, then User-Agent, then Accept, then any auth/cookie/content headers, then custom headers
- Ensure `-H "User-Agent: custom"` replaces rather than appends (curl behavior)
- Write unit tests that assert exact header order for GET, POST, PUT, DELETE, HEAD

#### HEAD / Connection: close hang (protocol/http/h1.rs, easy.rs)
- Test 14 (HTTP HEAD) hangs indefinitely — urlx waits for a body that will never arrive
- Must detect HEAD responses (or `Content-Length: 0` + `Connection: close`) and stop reading
- Also fix any response where the server closes the connection — urlx must treat TCP close as end-of-response, not hang
- Test with mock server: HEAD request, 200 + Connection: close, empty-body response

#### Default User-Agent
- urlx should send `User-Agent: urlx/VERSION` by default (it does), but verify `-A` flag fully replaces it (not appends)

### Phase 66 — Cookie Engine & POST Conformance

**Goal:** Pass curl test harness tests 3, 6, 7, 8, 9 by fixing cookie parsing and POST content-type behavior.

**Validated by:** curl's `runtests.pl` tests 3, 6, 7, 8, 9.

#### Cookie `-b` multi-cookie parsing (cookie.rs, easy.rs)
- `curl -b "name=contents;name2=content2; name3=content3"` should send ALL cookies
- urlx currently only sends the last one (`name3=content3`)
- Fix the inline cookie parser to split on `;` and send all cookies in a single `Cookie:` header
- Test: `-b "a=1;b=2;c=3"` must produce `Cookie: a=1; b=2; c=3`

#### Cookie file parsing (`-b filename`)
- `curl -b cookiefile.txt` reads cookies from a Netscape cookie file and sends matching ones
- Test 8 sends 7 cookies from a file; urlx sends none
- Verify the cookie jar file loading path works and domain-matches properly
- Test with curl's test fixture data

#### Cookie `-c` / `-b` jar interaction
- Test 7 uses `-b` + `-c` (read initial cookies + save new ones from Set-Cookie)
- urlx sends `Cookie: none` (wrong) and makes an extra request to `/verifiedserver`
- Debug the cookie jar → request flow to ensure Set-Cookie headers are consumed and re-sent

#### Auto Content-Type for POST (easy.rs)
- `curl -d "data"` automatically adds `Content-Type: application/x-www-form-urlencoded`
- urlx omits this header (test 3)
- Add the header when `-d`/`--data` is used and no explicit Content-Type is set

#### Multipart Content-Length (protocol/http/multipart.rs)
- Test 9: urlx calculates Content-Length as 471, expected 431
- Debug the multipart encoder — likely extra CRLF or boundary padding
- Fix and add a unit test asserting exact byte count for a known multipart body

### Phase 67 — Redirect, Proxy & Exit Code Correctness

**Goal:** Pass curl test harness tests 5, 11, 19, 20 and fix incorrect behavior in redirects, proxies, and exit codes.

**Validated by:** curl's `runtests.pl` tests 5, 11, 19, 20; differential exit code tests.

#### Redirect following (easy.rs)
- Test 11: urlx follows a redirect to `/verifiedserver` instead of the correct Location URL
- Debug the 3xx handling path — likely misparses the Location header or has a URL resolution bug
- Verify relative URL resolution (RFC 3986) works: `Location: /path` relative to the request URL
- Test with chain of redirects (301 → 302 → 200) and verify each hop goes to the right URL

#### Proxy request format (proxy/http.rs, easy.rs)
- Test 5 (HTTP over proxy) has three issues:
  1. Fragment `#5` leaks into the proxy request URL — must strip fragments before sending to proxy
  2. Uses `Connection: close` instead of `Proxy-Connection: Keep-Alive`
  3. Header ordering (fixed in Phase 65)
- Fix fragment stripping for proxy requests
- Add `Proxy-Connection: Keep-Alive` header for HTTP proxy requests (curl's default behavior)

#### Exit codes (error.rs, easy.rs)
- Unsupported protocol (`gopher://...`) should return exit code 1 (CURLE_UNSUPPORTED_PROTOCOL), currently returns 3
- Non-existent hostname should return exit code 6 (CURLE_COULDNT_RESOLVE_HOST), currently returns 7
- Connection refused should return exit code 7 (CURLE_COULDNT_CONNECT) — this already works
- Bad/missing URL should return exit code 3 (CURLE_URL_MALFORMAT), currently returns 7
- Audit all error-to-exit-code mappings against curl's CURLcode enum

#### Response header casing (protocol/http/response.rs)
- urlx lowercases response headers in `-i` output; curl preserves original case from server
- Preserve original header name casing when outputting with `--include` / `-i`
- Internal lookups can remain case-insensitive

### Phase 68 — FTP Conformance & Integration Test Harness

**Goal:** Pass curl FTP tests 100, 102, 104 and establish a permanent integration test harness using curl's test infrastructure.

**Validated by:** curl's `runtests.pl` tests 100, 102, 104; new Rust integration tests.

#### FTP protocol sequence (protocol/ftp.rs)
- Test 100 (FTP LIST): urlx sends `RETR` instead of `LIST`; missing `PWD` after login; sends `TYPE I` instead of `TYPE A` for directory listing
- Test 102 (FTP RETR): missing `PWD` and `SIZE` commands; different command order
- Test 104 (FTP HEAD/size-only): urlx sends RETR when it should just do MDTM+SIZE+REST for `--head`
- Fix: after USER/PASS, send `PWD` to establish working directory (curl always does this)
- Fix: use `TYPE A` for LIST operations, `TYPE I` for binary RETR
- Fix: `--head` on FTP should run MDTM+SIZE without downloading the file
- Fix: default anonymous password should be `ftp@example.com` (curl's default), not `urlx@`

#### Integration test harness (tests/)
- Create a Rust integration test file (`tests/curl_compat.rs`) that:
  - Starts a mock HTTP server (hyper on a random port)
  - Runs urlx as a subprocess against it
  - Asserts on: response body, exit code, and request headers the server received
- Port at least the following curl tests as permanent Rust tests:
  - Test 1: basic HTTP GET (header order)
  - Test 3: POST with auth + Content-Type
  - Test 6: cookie sending
  - Test 10: PUT from file
  - Test 11: redirect following
  - Test 13: custom HTTP method
  - Test 14: HEAD request
- These tests become the regression suite — they must pass before any future release

### Phase 69 — FFI Safety & Remaining Polish

**Goal:** Fix the FFI catch_unwind gap and clean up remaining audit findings before release.

#### FFI catch_unwind (liburlx-ffi/src/lib.rs)
- Only 1 of 56 exported functions (`curl_easy_perform`) has `catch_unwind`
- CLAUDE.md requires all exported functions to have it — this is a real safety bug
- Add `std::panic::catch_unwind(AssertUnwindSafe(|| { ... }))` to all 55 remaining exported functions
- Functions that return CURLcode should return CURLE_UNKNOWN_OPTION or similar on panic
- Functions that return pointers should return null on panic
- Add 4 missing `// SAFETY:` comments (curl_mime_free, curl_multi_add_handle, curl_slist_append, curl_slist_free_all)

#### FFI honesty — return CURLE_NOT_BUILT_IN for unimplemented options
- ~15 CURLOPT options currently return CURLE_OK but do nothing
- Change these to return CURLE_NOT_BUILT_IN so callers know the option isn't supported
- Document which options are accepted-but-ignored vs truly unimplemented

#### Final verification
- Run full `cargo test`, `cargo clippy --all-targets`, `cargo fmt --check`, `cargo doc`
- Run curl test harness tests 1-20, 100-105, 200-205 and record pass rate
- Run differential test suite against real endpoints and record pass rate
- Update test count and completeness metrics in CLAUDE.md

### Phase 70 — v0.2.0 Release

**Milestone release.** All audit-driven fixes from Phases 65-69 are complete. Ship v0.2.0.

#### Pre-release verification
- All curl harness tests targeted in Phases 65-68 must pass
- Differential test suite against real endpoints must show >90% parity (excluding User-Agent)
- `cargo test --all`, clippy, fmt, doc — zero errors
- Run the Rust integration tests from Phase 68

#### Version bump
- Bump version to `0.2.0` in all Cargo.toml files (workspace root, liburlx, liburlx-ffi, urlx-cli)
- Update CHANGELOG.md with changes since v0.1.0:
  - **Fixed:** Header ordering, HEAD hang, cookie parsing, redirect following, proxy fragment leak, POST Content-Type, multipart Content-Length, exit codes, header casing, FTP sequence, FFI safety
  - **Added:** Permanent curl-compat integration test suite, catch_unwind on all FFI functions

#### Documentation
- Update README.md with revised completeness table and Quick Start examples
- Update API docs (`cargo doc`)

#### Publish
- `cargo publish -p liburlx` → crates.io
- `cargo publish -p liburlx-ffi` → crates.io
- `cargo publish -p urlx-cli` → crates.io
- Create GitHub Release v0.2.0
- Update Homebrew formula

#### Post-release
- **STOP and report.** Provide summary of what was fixed, updated pass rates, test count, and recommended next phases

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
