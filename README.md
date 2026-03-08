# urlx

A memory-safe Rust reimplementation of curl and libcurl.

**urlx** provides three components:

- **`liburlx`** — An idiomatic Rust transfer library (the core)
- **`liburlx-ffi`** — A C ABI compatibility layer (drop-in replacement for libcurl)
- **`urlx`** — A command-line tool (drop-in replacement for the `curl` command)

## Features

### Protocols
- HTTP/1.1 and HTTP/2 (with ALPN negotiation)
- HTTPS (via rustls)
- FTP (passive mode download, directory listing)
- WebSocket (RFC 6455)
- SMTP, IMAP, POP3
- MQTT 3.1.1
- DICT (RFC 2229)
- TFTP (RFC 1350)
- file://

### Transfer Features
- Redirect following (301/302/303/307/308) with configurable limits
- Cookie engine (Set-Cookie parsing, domain/path matching, auto-send)
- Content-Encoding decompression (gzip, deflate, brotli, zstd)
- Basic and Bearer authentication
- Multipart form-data uploads
- Byte range requests and download resume
- Connection pooling with keep-alive
- HSTS (HTTP Strict Transport Security)
- Progress callbacks
- Transfer timing and metadata

### Proxy Support
- HTTP forward proxy
- HTTP CONNECT tunneling (for HTTPS through proxy)
- SOCKS4/SOCKS4a proxy
- SOCKS5 proxy with authentication
- Environment variable support (`http_proxy`, `https_proxy`, `no_proxy`)

### Concurrency
- Multi handle for concurrent transfers
- Async-native internals (tokio)
- Blocking Easy API for simple use cases

## Quick Start

### Library Usage

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

### CLI Usage

```sh
# Simple GET
urlx https://example.com

# POST with data
urlx -X POST -d '{"key":"value"}' -H 'Content-Type: application/json' https://api.example.com

# Follow redirects, verbose output
urlx -L -v https://example.com

# Download with progress bar
urlx -# -o file.zip https://example.com/file.zip

# Silent mode, fail on error
urlx -sf https://api.example.com/health
```

### C API (libcurl-compatible)

```c
#include "urlx.h"

int main(void) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (int)res;
}
```

## Building

```sh
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Build the CLI
cargo build -p urlx-cli --release
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-X, --request <method>` | HTTP method |
| `-H, --header <header>` | Custom header |
| `-d, --data <data>` | Request body (use `@file` to read from file) |
| `--data-raw <data>` | Request body (no `@` interpretation) |
| `-L, --location` | Follow redirects |
| `--max-redirs <num>` | Maximum redirects (default: 50) |
| `-I, --head` | HEAD request |
| `-o, --output <file>` | Write body to file |
| `-D, --dump-header <file>` | Write headers to file |
| `-i, --include` | Include headers in output |
| `-v, --verbose` | Verbose output |
| `-s, --silent` | Silent mode |
| `-S, --show-error` | Show errors in silent mode |
| `-f, --fail` | Fail on HTTP errors (exit 22) |
| `--compressed` | Request and decompress gzip/deflate/brotli/zstd |
| `--connect-timeout <s>` | Connection timeout |
| `-m, --max-time <s>` | Total transfer timeout |
| `-u, --user <user:pass>` | Basic authentication |
| `-A, --user-agent <name>` | User-Agent header |
| `-w, --write-out <fmt>` | Output format after transfer |
| `-x, --proxy <url>` | Proxy URL |
| `--noproxy <list>` | Hosts to bypass proxy |
| `-F, --form <name=value>` | Multipart form field |
| `-r, --range <range>` | Byte range request |
| `-C, --continue-at <off>` | Resume from offset |
| `-#, --progress-bar` | Progress bar display |

## Architecture

- **Zero `unsafe` outside FFI** — The core library and CLI are 100% safe Rust
- **Async internals** — Built on tokio for efficient I/O
- **TLS via rustls** — No OpenSSL dependency
- **Connection pooling** — HTTP keep-alive with automatic stale connection retry
- **Feature flags** — Optional protocols and TLS backends

## License

MIT
