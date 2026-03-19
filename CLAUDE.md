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
**curl test suite:** 1,173 pass / 83 fail / 71 skip out of 1,327 tests (93.4% pass rate, tests 1-1400)
**Rust test count:** 2,655
**Blockers:** None — infrastructure is live

### What Has Been Built

A functional curl replacement covering HTTP/1.0-1.1, HTTP/2, HTTP/3 (QUIC via quinn), TLS (rustls + native-tls + STARTTLS), FTP/FTPS, SSH/SFTP/SCP, WebSocket, MQTT, SMTP, IMAP, POP3, DICT, TFTP, file://, DNS (system + hickory + DoH + DoT + Happy Eyeballs), cookies (Netscape format, domain-indexed, PSL, SameSite), HSTS, proxies (HTTP/SOCKS4/SOCKS4a/SOCKS5/HTTPS tunnel), authentication (Basic, Digest, Bearer, AWS SigV4, NTLMv2, SCRAM-SHA-256, SASL CRAM-MD5/OAUTHBEARER/XOAUTH2/EXTERNAL), connection pooling, rate limiting, multipart form upload, decompression (gzip, deflate, br, zstd), and a C ABI compatibility layer (liburlx-ffi with 57 exported functions).

**Key stats:**
- CLI flags: 261 long + 46 short; curl has ~250 long flags
- FFI: 156 CURLOPT, 49 CURLINFO, 41 CURLcode, 57 exported functions (all with catch_unwind)
- 141 Rust source files, ~72,000 lines of code
- 4 fuzz harnesses, 9 benchmark groups, 20+ feature flags

### Known Issues

- HTTP/3 untested (needs quinn test server)
- FFI returns CURLE_OK for ~15 unimplemented options (should return CURLE_NOT_BUILT_IN)
- curl_easy_pause() returns OK but does nothing
- Multi API event loop functions are no-ops (tokio architecture mismatch)

---

## Development Methodology: curl Test Suite Driven

### Philosophy

**curl's test suite is the specification.** The project is no longer organized around feature phases. Instead, we import curl's own test suite, run it against our binaries, and use failing tests as the work queue. The goal is simple: pass more curl tests.

This is a fundamental reorientation. We are not "building a curl-like tool" — we are **building a drop-in replacement for curl**, and the measure of success is curl's own tests passing against our binaries.

### Infrastructure Setup

curl's test suite lives in curl's source tree under `tests/`. It uses:
- `runtests.pl` — the main Perl test runner
- `tests/data/testNNN` — individual test case definitions (XML-like format)
- Perl/Python test servers: `ftpserver.pl`, `http-server.pl`, `http2-server.pl`, `sshserver.pl`, `dictserver.py`, `smbserver.py`, etc.
- The `-c <path>` flag to run tests against a custom binary

**Setup steps:**
1. Clone curl source into `vendor/curl/` (git submodule)
2. Build only the test infrastructure: `cd vendor/curl/tests && make` (builds test helpers, not curl itself)
3. Run tests: `cd vendor/curl/tests && perl runtests.pl -a -c /path/to/urlx <test-numbers>`

**Wrapper script:** `scripts/run-curl-tests.sh` should automate this:
- Build urlx in release mode
- Run specified test numbers (or all) via runtests.pl with `-c` pointing to urlx binary
- Capture results, summarize pass/fail/skip counts
- Save detailed logs to `tests/log/`

### The Work Cycle

Every work session follows this cycle:

1. **Run the current batch.** Execute the curl tests in the active batch. Record which pass, fail, or skip.
2. **Analyze failures.** Read the test data file (`vendor/curl/tests/data/testNNN`) to understand what the test expects. Read the logs in `tests/log/` to see what urlx actually did.
3. **Fix urlx.** Make the minimum change to pass the failing test. Do not speculatively fix things outside the current batch.
4. **Verify no regressions.** Run all previously-passing tests plus the current batch. Nothing that was passing may break.
5. **Update CLAUDE.md.** Move newly-passing tests into the completed list. Update pass rate.
6. **Commit.** Use conventional commits: `fix(<scope>): <what was fixed to pass test NNN>`
7. **Next batch.** When all tests in the current batch pass (or are documented as permanently skipped with rationale), move to the next batch.

### Test Categories

curl's ~2,000+ tests are numbered and loosely grouped:
- **1-99:** HTTP basics (GET, POST, PUT, HEAD, cookies, redirects, auth, proxy, headers)
- **100-199:** FTP (LIST, RETR, STOR, resume, passive, active, FTPS)
- **200-299:** file:// protocol
- **300-399:** HTTPS, TLS features
- **400-499:** HTTP proxy, SOCKS proxy
- **500-599:** HTTP POST variations, multipart
- **600-699:** HTTP authentication (Digest, NTLM, Negotiate)
- **700-799:** Cookies, HSTS
- **800-899:** SSH, SFTP, SCP
- **900-999:** SMTP, IMAP, POP3
- **1000-1199:** HTTP/2
- **1200-1399:** Various (DICT, TFTP, MQTT, WebSocket)
- **1400+:** Advanced features, edge cases
- **2000+:** libcurl API tests (use `<tool>` tag, run C programs — skip these initially)

### Skipped Tests

Some tests are expected to be permanently skipped:
- Tests requiring `<tool>` (C test programs linked against libcurl) — these test libcurl internals, not CLI behavior
- Tests requiring curl debug builds (`feat:debug`, `feat:TrackMemory`)
- Tests requiring protocols we haven't implemented yet (mark as TODO with the protocol name)
- Tests checking curl-specific version strings
- **Source/build analysis tests** (17 tests, documented in `tests/excluded-tests.txt`): 745, 971, 1013, 1014, 1022, 1023, 1026, 1027, 1119, 1135, 1139, 1165, 1167, 1173, 1177, 1185, 1222 — these verify curl's own source code structure, build system, man pages, symbol consistency, and documentation sync; not applicable to urlx

Document every skip with a reason. Skips without rationale are not allowed.

---

## Remaining Work: Failure Analysis (as of 2026-03-19)

Full test suite run: 1,173 pass / 83 fail / 71 skip (tests 1-1400, 30s timeout). **93.4% pass rate.**
17 source/build analysis tests permanently excluded (see `tests/excluded-tests.txt`).

### Failing Tests by Category (83 total)

| # | Category | Tests | Count | Details |
|---|----------|-------|-------|---------|
| 1 | **IMAP edge cases** | 795, 800, 815, 816, 847, 897, 1221 | 7 | STORE/CLOSE/EXPUNGE custom commands, login options, IMAP via HTTP proxy |
| 2 | **HTTP NTLM auth** | 547, 548, 555, 560, 694, 775, 895 | 7 | NTLM with POST callback, Negotiate, multi-interface |
| 3 | **FTP over SOCKS/proxy** | 706, 707, 712, 713, 714, 715, 1050, 1059, 1069, 1105 | 10 | FTP via SOCKS4/5, HTTP CONNECT tunnel, IPv6 EPRT, proxy relay |
| 4 | **HTTP PUT/POST edge cases** | 186, 357, 490, 491, 492, 493, 1015, 1077, 1106 | 9 | Expect 100, PUT methods, POST encoding, cookies with POST |
| 5 | **HTTP headers/encoding** | 306, 313, 373, 379, 415, 471, 483 | 7 | HTTPS cert/CRL, chunked encoding, Content-Length edge cases, globbing |
| 6 | **Email via HTTP tunnel** | 1319, 1320, 1321 | 3 | POP3/SMTP/IMAP through HTTP CONNECT proxy |
| 7 | **HTTP etag/resume** | 338, 369, 481, 482, 484, 485, 487, 497 | 8 | Etag multi-URL, --no-clobber + resume, --remove-on-error |
| 8 | **CLI/globbing/output** | 760, 761, 762, 776, 988, 1134, 1265, 1268, 1292, 1299, 1328, 1370, 1371, 1400 | 14 | Globbing edge cases, --remote-time, -J Content-Disposition, --libcurl, NO_PROXY IPv6 |
| 9 | **FTP misc** | 203, 254, 590, 1217, 1224, 1225, 1226 | 7 | file:// edge case, IPv6 EPSV, FTP NLST, PASV RETR |
| 10 | **SMTP MIME/misc** | 609, 646, 647, 648, 649, 669 | 6 | Multipart MIME, IMAP APPEND upload, SMTP edge cases |
| 11 | **TLS/HTTPS** | 306, 313 | 2 | PEM cert validation, CRL checking |
| 12 | **Misc** | 1020, 1105, 1106, 1117, 1147, 1148, 1152 | 7 | Various HTTP edge cases, proxy interactions |

### Permanently Skipped (17 tests)

Source/build analysis tests (745, 971, 1013, 1014, 1022, 1023, 1026, 1027, 1119, 1135, 1139, 1165, 1167, 1173, 1177, 1185, 1222) are permanently excluded via `tests/excluded-tests.txt`. They verify curl's own source code structure, man pages, and build system — not applicable to urlx.

### Addressable Failures (~83 tests)

| Priority | Category | ~Tests | Effort |
|----------|----------|--------|--------|
| High | FTP over SOCKS/proxy | ~10 | 1-2 days |
| High | HTTP PUT/POST/Expect | ~9 | 1 day |
| High | IMAP edge cases | ~7 | 1 day |
| Medium | HTTP NTLM (POST callback) | ~7 | 1-2 days |
| Medium | CLI/globbing/output | ~14 | 2 days |
| Medium | HTTP etag/resume | ~8 | 1 day |
| Medium | Email via HTTP tunnel | ~3 | 0.5 day |
| Medium | SMTP MIME/misc | ~6 | 1 day |
| Low | HTTP headers/encoding | ~7 | 1 day |
| Low | FTP misc | ~7 | 1 day |
| Low | Misc | ~7 | 1-2 days |

### Path to 95%+

| Milestone | Pass Rate | Work |
|-----------|-----------|------|
| Current (source analysis skipped, auth cancellation resolved) | 93.4% (1,173/1,256 non-skipped) | Done |
| FTP proxy + HTTP PUT/POST | 95% (~1,192) | 1 week |
| IMAP + CLI + etag fixes | 97% (~1,220) | +1 week |
| Long tail (NTLM, MIME, misc) | 98%+ (~1,240) | +2 weeks |

---

## Test Suite Progress

1,173 of 1,327 tests pass (93.4%). The test suite spans tests 1-1400 with 71 skipped (54 libtests/missing features/debug-only + 17 source analysis permanently excluded).

### By Range

| Range | Description | Pass/Total | Notes |
|-------|-------------|------------|-------|
| 1-99 | HTTP basics | 97/97 | All pass |
| 100-199 | FTP, HTTP auth/forms | 88/93 | 5 failures (186, 190 timeout edge cases) |
| 200-399 | file://, HTTPS, proxy | 175/192 | Failures: HTTPS cert CRL, etag, chunked, proxy edge cases |
| 400-599 | HTTP proxy, POST | 75/103 | ~16 are libtests/skipped; failures in NTLM POST callback, SOCKS |
| 600-699 | SFTP/SCP, SMTP, IMAP | 63/82 | SMTP MIME, IMAP custom commands |
| 700-799 | Cookies, HSTS, headers | 73/82 | Globbing, NTLM, etag edge cases |
| 800-999 | SSH, SMTP, IMAP, POP3 | 270/282 | IMAP login options, 971 skipped (source analysis) |
| 1000-1199 | HTTP/2, misc, analysis | 158/188 | ~16 source analysis tests (N/A), FTP proxy, NTLM |
| 1200-1400 | Advanced features | 174/208 | CLI output, Content-Disposition, --libcurl |

---

## Guiding Principles

1. **curl's test suite is the specification.** When in doubt, match curl's behavior. The goal is not to be curl-like — it is to be curl-compatible. curl's tests are the acceptance criteria.
2. **Zero `unsafe` outside of `liburlx-ffi`.** The core library and CLI must be 100% safe Rust. All `unsafe` is confined to the FFI boundary in `liburlx-ffi` and must have `// SAFETY:` comments.
3. **Correctness over performance.** Get the behavior right first. Optimize later with benchmarks proving the need.
4. **No regressions.** Once a curl test passes, it must never regress. This is enforced by running all previously-passing tests in CI.
5. **Feature flags for optional functionality.** Each protocol, TLS backend, and optional feature is behind a Cargo feature flag. The default feature set covers HTTP/HTTPS. Minimal builds must be possible.
6. **Conventional commits.** Every commit message must follow the Conventional Commits specification. This is enforced by CI.
7. **This file is a living document.** CLAUDE.md is the project's source of truth. Update it as batches are completed and new batches are started.

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
├── scripts/
│   └── run-curl-tests.sh      # Wrapper to run curl tests against urlx
├── vendor/
│   └── curl/                  # curl source (git submodule) — for test suite only
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
├── tests/                     # Rust integration tests, fixtures, FFI test harness
├── benches/                   # Criterion benchmarks
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

## Agent Instructions

When working on this project:

### Guardrails

1. **Always check guardrails after every change.** Run `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc` after every meaningful code change. Fix issues immediately. Do not proceed with broken guardrails.

2. **Never suppress warnings.** If clippy or the compiler warns about something, fix it properly. The only allowed suppressions are targeted `#[allow(...)]` with a comment explaining why.

### Working with the curl Test Suite

3. **Read the test file first.** Before fixing a failing curl test, read `vendor/curl/tests/data/testNNN` to understand exactly what the test expects: what command it runs, what the server returns, and what output/protocol/exit code it verifies.

4. **Check curl's source when stuck.** Clone curl's repo and examine the relevant source file. curl's behavior is the specification. When curl's behavior seems wrong, document it and match it anyway (with a comment noting the curl compat quirk).

5. **No regressions.** After fixing a test, always re-run all previously-passing tests. If a fix for test N breaks test M, fix both before committing.

6. **Document skips.** If a test cannot pass (requires libcurl internals, debug builds, etc.), add it to the skip list with a clear rationale. Never silently skip tests.

### Commits

7. **Use conventional commits for every commit.** Format: `<type>(<scope>): <description>`. Examples:
   - `fix(http): match curl header ordering to pass tests 1-13`
   - `fix(cookie): parse multi-cookie -b strings (curl tests 6-8)`
   - `chore: add curl test suite as git submodule`
   - `docs: update CLAUDE.md batch status`

8. **Commit atomically.** Each commit should be one logical change. Reference the curl test numbers that the change addresses.

9. **Scope names** must match crate or module names: `http`, `ftp`, `tls`, `url`, `cookie`, `dns`, `proxy`, `auth`, `ffi`, `cli`, `pool`, `filter`, `ws`, `mqtt`, `smtp`, `imap`. Use no scope for cross-cutting changes.

### Maintaining CLAUDE.md

10. **Update this file as batches progress.** When tests in a batch start passing, update the Active Batch section. When a batch is complete, move it to Completed Batches and promote the next batch. Keep the pass rate current.

### FFI Safety

11. **For the FFI layer,** every `#[no_mangle] pub extern "C" fn` must have:
    - A `// SAFETY:` comment on every `unsafe` block
    - Null pointer checks on all pointer arguments
    - Proper error code returns (never panic across FFI boundary)
    - A catch_unwind wrapper to prevent Rust panics from unwinding into C
