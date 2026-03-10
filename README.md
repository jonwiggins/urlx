<p align="center">
  <b>urlx</b>
</p>

<p align="center">
  <i>A memory-safe Rust reimplementation of curl and libcurl.</i>
</p>

<p align="center">
  <a href="https://github.com/jonwiggins/urlx/actions/workflows/ci.yml"><img src="https://github.com/jonwiggins/urlx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/liburlx"><img src="https://img.shields.io/crates/v/liburlx.svg" alt="crates.io"></a>
  <a href="https://docs.rs/liburlx"><img src="https://img.shields.io/docsrs/liburlx" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

urlx is a from-scratch rewrite of [curl](https://curl.se/) in Rust. Zero `unsafe` outside the FFI boundary. Built on [tokio](https://tokio.rs/) and [rustls](https://github.com/rustls/rustls) — no OpenSSL. Behavioral compatibility with curl is the goal.

## Highlights

- **Memory-safe** — zero `unsafe` in the core library and CLI; all unsafe confined to the FFI crate with safety documentation
- **No OpenSSL** — TLS 1.2/1.3 via rustls, with cert pinning, custom CAs, and client certificates
- **Drop-in CLI** — `urlx` aims to accept the same flags and produce the same output as `curl`
- **Drop-in C library** — `liburlx-ffi` exposes the libcurl C ABI so existing C/C++ programs can link against it
- **Idiomatic Rust API** — `liburlx` provides a clean async/sync API modeled on curl's Easy/Multi handles
- **Broad protocol support** — HTTP/1.1, HTTP/2, HTTP/3 (QUIC), FTP/FTPS, SFTP/SCP, WebSocket, SMTP, IMAP, POP3, MQTT
- **2,200+ tests** — unit, integration (against real servers), property-based, and fuzz harnesses
- **Async core** — tokio runtime with a blocking `Easy` wrapper and native async `Multi` API

## Quick Start

### CLI

```sh
urlx https://example.com                                    # GET a URL
urlx -d '{"key":"val"}' -H 'Content-Type: application/json' # POST JSON
urlx -Lo archive.tar.gz https://example.com/archive.tar.gz  # Download file
urlx -u user:pass https://api.example.com/admin              # Basic auth
urlx -F "file=@photo.jpg" https://example.com/upload         # Multipart upload
urlx -Z https://a.com https://b.com https://c.com            # Parallel transfers
```

### Rust Library

```rust
let mut easy = liburlx::Easy::new();
easy.url("https://httpbin.org/get")?;
let response = easy.perform()?;

println!("{}", response.status());       // 200
println!("{}", response.body_str()?);    // {"origin": "..."}
```

```toml
[dependencies]
liburlx = "0.1"
```

### C Library (libcurl-compatible)

```c
#include "urlx.h"

CURL *curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
CURLcode res = curl_easy_perform(curl);
curl_easy_cleanup(curl);
```

## Installation

```sh
cargo install --path crates/urlx-cli   # from source
```

```sh
cargo build --workspace --release      # build everything
cargo test --workspace                 # run the test suite
```

## Components

| Crate | Role | Cargo Feature Flags |
|---|---|---|
| [`liburlx`](crates/liburlx) | Core transfer library (pure Rust, idiomatic API) | `http` `http2` `http3` `rustls` `ftp` `ssh` `ws` `decompression` ... |
| [`liburlx-ffi`](crates/liburlx-ffi) | C ABI compatibility layer — drop-in for libcurl | — |
| [`urlx-cli`](crates/urlx-cli) | Command-line tool — drop-in for `curl` | — |

## Protocol & Feature Parity

| Area | Coverage | Details |
|---|---|---|
| HTTP/1.1 | ~97% | Chunked encoding, trailers, `Expect: 100-continue`, decompression (gzip/br/zstd) |
| HTTP/2 | ~80% | ALPN negotiation, multiplexing, flow control, PING keep-alive |
| HTTP/3 | ~55% | QUIC via quinn, Alt-Svc upgrade, 0-RTT |
| TLS | ~85% | rustls, TLS 1.2/1.3, cert pinning, cipher selection, session cache |
| Authentication | ~60% | Basic, Bearer, Digest (MD5/SHA-256), AWS SigV4, NTLM skeleton |
| Cookies | ~95% | Netscape file format, domain-indexed jar, public suffix list |
| Proxy | ~90% | HTTP CONNECT, SOCKS4/4a/5, HTTPS tunnels (TLS-in-TLS), proxy auth |
| DNS | ~85% | Cache, Happy Eyeballs, DoH, DoT, custom servers, hickory-dns |
| FTP/FTPS | ~87% | Upload, resume, directory ops, explicit/implicit TLS, active mode |
| SSH/SFTP/SCP | ~60% | Download, upload, password + pubkey auth |
| WebSocket | ~85% | RFC 6455, close codes, fragmentation |
| CLI flags | ~55% | ~150 of ~250 curl flags implemented |
| FFI (libcurl C ABI) | ~60% | 116 `CURLOPT`, 43 `CURLINFO`, 32 `CURLcode`, 56 functions |

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

- **Zero `unsafe` outside FFI** — `liburlx` and `urlx-cli` are 100% safe Rust
- **Async core** — tokio runtime with blocking `Easy` wrapper and native async `Multi` API
- **No OpenSSL** — TLS entirely via rustls
- **Strict linting** — `clippy::all` denied, `unwrap_used` denied in library code, no panics

## Feature Flags

Default features: `http`, `http2`, `rustls`, `decompression`.

| Flag | Description |
|---|---|
| `http` | HTTP/1.x protocol support |
| `http2` | HTTP/2 via the `h2` crate |
| `http3` | HTTP/3 via `quinn` (QUIC) |
| `rustls` | TLS via rustls (no OpenSSL) |
| `ftp` | FTP/FTPS protocol |
| `ssh` | SFTP/SCP via `russh` |
| `ws` | WebSocket (RFC 6455) |
| `decompression` | gzip, deflate, brotli, zstd |
| `hickory-dns` | Async DNS resolver with DoH/DoT |
| `cookies` | Cookie engine with public suffix list |

## Contributing

urlx follows strict test-driven development — every feature starts with a failing test. The full guardrail suite (fmt, clippy, test, deny, doc) runs on every commit via pre-commit hooks and CI.

```sh
cargo fmt && cargo clippy --all-targets && cargo test --workspace
```

## Acknowledgements

urlx would not exist without [curl](https://curl.se/) by Daniel Stenberg. curl's behavior is our specification, and its decades of real-world testing inform every design decision.

Built with [tokio](https://tokio.rs/), [rustls](https://github.com/rustls/rustls), [h2](https://github.com/hyperium/h2), [quinn](https://github.com/quinn-rs/quinn), and [hyper](https://hyper.rs/) (test infrastructure).

## License

MIT
