<p align="center">
  <br>
  <code>urlx</code>
  <br>
  <i>curl, rewritten in Rust.</i>
  <br><br>
  <a href="https://github.com/jonwiggins/urlx/actions/workflows/ci.yml"><img src="https://github.com/jonwiggins/urlx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/liburlx"><img src="https://img.shields.io/crates/v/liburlx.svg" alt="crates.io"></a>
  <a href="https://docs.rs/liburlx"><img src="https://img.shields.io/docsrs/liburlx" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

**urlx** is a memory-safe, from-scratch reimplementation of [curl](https://curl.se/) and libcurl. No OpenSSL. No `unsafe` outside the FFI boundary. **1,300 of curl's own tests pass against urlx.**

```sh
# It's curl. Just in Rust.
urlx https://example.com
urlx -d '{"key":"val"}' -H 'Content-Type: application/json' https://api.example.com
urlx -Lo file.tar.gz https://example.com/file.tar.gz
urlx -u user:pass --digest https://api.example.com/admin
urlx -Z https://a.com https://b.com https://c.com   # parallel transfers
```

## Why?

curl is one of the most important pieces of software ever written. It's also 180,000 lines of C with a long history of memory safety CVEs. urlx asks: *what if we just rewrote it?*

- **Memory-safe** — zero `unsafe` in the core library and CLI
- **No OpenSSL** — TLS via [rustls](https://github.com/rustls/rustls), with optional OpenSSL for TLS-SRP
- **Drop-in CLI** — same flags, same output, same exit codes — 261 long flags, 46 short
- **Drop-in C library** — `liburlx-ffi` exposes the libcurl C ABI for existing C/C++ programs
- **Idiomatic Rust API** — async/sync `Easy`/`Multi` handles, `thiserror` errors, feature-flagged protocols
- **Tested against curl itself** — curl's own test suite is the spec

## Test Suite Compatibility

urlx is validated against curl's own test suite (tests 1–1400):

| Metric | Count |
|--------|-------|
| **Pass** | **1,300** |
| Skip (debug builds, missing platform features) | 92 |
| Permanently excluded (curl source analysis, libcurl C API) | 25 |
| **Pass rate of evaluated tests** | **100%** |

## What's Supported

| | Status |
|---|---|
| **HTTP/1.0, 1.1, 2, 3 (QUIC)** | Full (HTTP/3 untested) |
| **TLS 1.2 / 1.3** | rustls, cert pinning, client certs, STARTTLS |
| **Auth** | Basic, Digest, Bearer, NTLMv2, SCRAM-SHA-256, AWS SigV4, SASL |
| **FTP / FTPS** | Upload, resume, directory ops, active & passive, EPSV |
| **SSH / SFTP / SCP** | Password + pubkey auth, quote commands |
| **SMTP, IMAP, POP3** | STARTTLS, SASL, MIME |
| **WebSocket** | RFC 6455, close codes, fragmentation |
| **MQTT** | Subscribe, publish |
| **Gopher, DICT, TFTP, RTSP** | Full |
| **Cookies** | Netscape format, domain-indexed, PSL, SameSite |
| **HSTS** | Preload list |
| **Proxy** | HTTP CONNECT, SOCKS4/4a/5, HTTPS tunnel, proxy auth |
| **DNS** | Happy Eyeballs, DoH, DoT, custom servers, caching |
| **Decompression** | gzip, deflate, brotli, zstd |
| **CLI flags** | 261 long + 46 short (curl has ~250 long) |
| **FFI** | 156 CURLOPT, 49 CURLINFO, 57 exported C functions |

## Install

```sh
cargo install urlx-cli          # from crates.io
brew install jonwiggins/tap/urlx  # Homebrew
```

Or build from source:

```sh
git clone --recurse-submodules https://github.com/jonwiggins/urlx
cd urlx && cargo build --release
```

## Use as a Rust Library

```rust
let mut easy = liburlx::Easy::new();
easy.url("https://httpbin.org/get")?;
let response = easy.perform()?;
println!("{}", response.status());    // 200
println!("{}", response.body_str()?); // {"origin": "..."}
```

```toml
[dependencies]
liburlx = "0.2"
```

## Use as a C Library (libcurl ABI)

```c
#include "urlx.h"

CURL *curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
CURLcode res = curl_easy_perform(curl);
curl_easy_cleanup(curl);
```

Link against `liburlx_ffi` instead of `libcurl` — no code changes needed.

## Architecture

```
                    ┌─────────────┐
                    │   urlx CLI  │  Drop-in curl replacement
                    └──────┬──────┘
                           │
┌──────────────┐    ┌──────┴──────┐
│ liburlx-ffi  │────│   liburlx   │  Core Rust library
│  (C ABI)     │    │  (Rust API) │
└──────────────┘    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴───┐ ┌─────┴─────┐
        │ Protocols  │ │  TLS  │ │    DNS    │
        │ HTTP, FTP, │ │rustls │ │  Cache,   │
        │ WS, SMTP...│ │       │ │  HE, DoH  │
        └────────────┘ └───────┘ └───────────┘
```

Three crates, one workspace:

| Crate | What it does |
|---|---|
| [`liburlx`](crates/liburlx) | Core transfer library — pure Rust, async/sync API, 20+ feature flags |
| [`liburlx-ffi`](crates/liburlx-ffi) | C ABI layer — link against it instead of libcurl |
| [`urlx-cli`](crates/urlx-cli) | The `urlx` binary — drop-in `curl` replacement |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

```sh
cargo fmt && cargo clippy --all-targets && cargo test --workspace
```

Every commit must pass the full guardrail suite. Conventional commits are enforced by CI.

## Acknowledgements

urlx would not exist without [curl](https://curl.se/) by Daniel Stenberg. curl's behavior is our specification, and its test suite is our acceptance criteria.

Built with [tokio](https://tokio.rs/), [rustls](https://github.com/rustls/rustls), [h2](https://github.com/hyperium/h2), [quinn](https://github.com/quinn-rs/quinn), and [russh](https://github.com/warp-tech/russh).

## License

MIT
