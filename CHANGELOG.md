# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-10

### Added

- **liburlx** — Core transfer library with idiomatic Rust API
  - HTTP/1.0, HTTP/1.1, HTTP/2 (ALPN), HTTP/3 (QUIC) protocol support
  - TLS via rustls — no OpenSSL dependency
  - FTP/FTPS with upload, resume, directory operations
  - SFTP/SCP via russh with password and public key auth
  - WebSocket (RFC 6455) with close codes and fragmentation
  - SMTP, IMAP, POP3, MQTT, DICT, TFTP, file:// protocols
  - Cookie engine with Netscape file format and public suffix list
  - Authentication: Basic, Bearer, Digest (MD5/SHA-256), AWS SigV4
  - Proxy support: HTTP CONNECT, SOCKS4/4a/5, HTTPS tunnels
  - DNS cache, Happy Eyeballs (RFC 6555), DNS-over-HTTPS, DNS-over-TLS
  - Content-Encoding decompression: gzip, deflate, brotli, zstd
  - Connection pooling, rate limiting, HSTS, retry logic
  - Certificate pinning (SHA-256), client certificates, cipher selection
  - Async core (tokio) with sync `Easy` wrapper and async `Multi` API

- **liburlx-ffi** — C ABI compatibility layer
  - 116 CURLOPT options, 43 CURLINFO queries, 32 CURLcode error codes
  - 56 exported functions compatible with libcurl's C API
  - Auto-generated `urlx.h` header via cbindgen
  - pkg-config support

- **urlx** — Command-line tool
  - ~150 curl-compatible CLI flags
  - Stdin data support (`-d @-`, `--data-binary @-`)
  - Curl-compatible exit codes (3, 6, 7, 22, 28, 35, 47, 60, 67)
  - `--write-out` variable expansion
  - Progress bar, verbose mode, trace output
  - Parallel transfers (`-Z`)
  - Config file support (`.curlrc`)

- **Testing** — 2,288 tests
  - Unit tests, integration tests against real protocol servers
  - Property-based tests (proptest) for parsers
  - 4 fuzz harnesses (URL, HTTP, cookie, HSTS)

[0.1.0]: https://github.com/jonwiggins/urlx/releases/tag/v0.1.0
