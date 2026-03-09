# urlx

[![CI](https://github.com/jonwiggins/urlx/actions/workflows/ci.yml/badge.svg)](https://github.com/jonwiggins/urlx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

A memory-safe Rust reimplementation of **curl** and **libcurl**.

**urlx** is a from-scratch rewrite with zero `unsafe` code outside the FFI boundary, built on [tokio](https://tokio.rs/) and [rustls](https://github.com/rustls/rustls) — no OpenSSL dependency. It aims for behavioral compatibility with curl while providing an idiomatic Rust API.

## Components

| Crate | Description |
|-------|-------------|
| **`liburlx`** | Idiomatic Rust transfer library (the core) |
| **`liburlx-ffi`** | C ABI compatibility layer — drop-in replacement for libcurl |
| **`urlx`** | Command-line tool — drop-in replacement for the `curl` command |

## Quick Start

### As a library

```rust
use liburlx::Easy;

fn main() -> Result<(), liburlx::Error> {
    let mut easy = Easy::new();
    easy.url("https://httpbin.org/get")?;
    let response = easy.perform()?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.body_str()?);
    Ok(())
}
```

### As a CLI

```sh
# Simple GET
urlx https://example.com

# POST JSON
urlx -X POST -H 'Content-Type: application/json' \
     -d '{"key": "value"}' https://api.example.com/data

# Download a file with progress bar
urlx -# -o archive.tar.gz https://example.com/archive.tar.gz

# Follow redirects, show response headers
urlx -L -i https://example.com

# Silent health check — exit 22 on HTTP error
urlx -sf https://api.example.com/health

# HTTP Basic auth
urlx -u admin:secret https://api.example.com/admin

# Upload a file
urlx -T report.pdf https://example.com/upload

# Multiple URLs in parallel
urlx -Z https://example.com https://example.org

# Use a SOCKS5 proxy
urlx --socks5-hostname 127.0.0.1:1080 https://example.com

# POST form with file upload
urlx -F "photo=@image.jpg" -F "caption=sunset" https://example.com/upload
```

### As a C library (libcurl-compatible)

```c
#include "urlx.h"

int main(void) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (int)res;
}
```

## Features

### Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| HTTP/1.0, HTTP/1.1 | Full | Chunked encoding, trailers, decompression |
| HTTP/2 | Working | ALPN negotiation, multiplexing |
| HTTPS | Full | rustls, TLS 1.2/1.3, cert pinning |
| FTP | Working | Upload, resume, directory ops, FEAT |
| WebSocket | Working | RFC 6455 frames |
| SMTP, IMAP, POP3 | Basic | Send/receive/list |
| MQTT | Basic | 3.1.1 publish/subscribe |
| DICT, TFTP, file:// | Working | |

### Security & TLS

- TLS 1.2 and 1.3 via **rustls** (no OpenSSL)
- Custom CA certificates, client certificates
- Certificate pinning (SHA-256)
- Cipher suite selection
- Insecure mode (`-k`) for development

### Authentication

- HTTP Basic and Bearer
- HTTP Digest (MD5, SHA-256)
- AWS Signature V4
- Proxy auth (Basic, Digest, NTLM)

### Transfer

- Redirect following (301/302/303/307/308)
- Cookie engine with Netscape file persistence
- Content-Encoding decompression (gzip, deflate, brotli, zstd)
- Byte range requests and download resume
- Multipart form-data uploads
- Connection pooling with keep-alive
- HSTS (HTTP Strict Transport Security)
- Retry logic with backoff (408/429/5xx)
- Transfer timing and speed metrics

### Proxy

- HTTP forward proxy and CONNECT tunneling
- SOCKS4/4a/5 with authentication
- Proxy TLS configuration
- `http_proxy` / `https_proxy` / `no_proxy` environment variables

### DNS

- Caching with configurable TTL
- Happy Eyeballs (RFC 6555)
- Custom DNS servers
- DNS-over-HTTPS URL configuration
- DNS shuffle for load distribution

## Building

```sh
# Build everything
cargo build --workspace

# Run the full test suite (2,282 tests)
cargo test --workspace

# Build the CLI in release mode
cargo build -p urlx-cli --release

# Install the CLI
cargo install --path crates/urlx-cli
```

### Feature flags (liburlx)

| Flag | Default | Description |
|------|---------|-------------|
| `http` | Yes | HTTP/1.x protocol support |
| `http2` | Yes | HTTP/2 via the `h2` crate |
| `rustls` | Yes | TLS via rustls |
| `decompression` | Yes | gzip, deflate, brotli, zstd |

## Architecture

```
                    ┌─────────────┐
                    │   urlx CLI  │  Drop-in curl replacement
                    └──────┬──────┘
                           │
┌──────────────┐    ┌──────┴──────┐
│ liburlx-ffi  │────│   liburlx   │  Core transfer library
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
- **Strict linting** — clippy deny-all, no unwrap in library code, no panics

## License

MIT

