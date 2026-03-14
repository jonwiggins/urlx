# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **HTTP response parsing** — Preserve raw header bytes for exact wire-format `--include` output, correctly handling mixed CRLF/LF line endings and no-space-after-colon headers (e.g., `Set-Cookie:value`)
- **Header end detection** — Handle mixed line ending patterns (`\n\r\n`) and always find the earliest terminator, preventing body data from being parsed as headers
- **HEAD response hang** — Correctly detect HEAD responses and skip body reading
- **Resume hang** — Skip body read for failed Range requests without Content-Length, avoiding infinite wait when servers don't close the connection
- **Redirect hang** — Skip body read for 3xx redirects without Content-Length when server says Connection: close but doesn't close
- **Resume error handling** — 416 Range Not Satisfiable treated as success (file already downloaded), output headers only; non-206 resume errors output headers but preserve auto-resume source files
- **User-Agent suppression** — `-A ""` now fully suppresses the User-Agent header instead of sending an empty one
- **Digest auth** — Only emit `algorithm=` in Authorization header when server explicitly specified it in the challenge
- **Cookie jar output** — Write all cookies (not just persistent), track include_subdomains flag and domain display for Netscape format, validate Set-Cookie domain against request host
- **Config file parsing** — Handle `flag = value` syntax with `=` separator
- **Time condition** — Parse `-z` timestamp and suppress body when condition is not met
- **Version string** — Match curl's feature flag format for test suite compatibility
- **Test infrastructure** — Fix `urlx-as-curl` wrapper to default to release binary; export `URLX_BIN` from `run-curl-tests.sh`

### Changed

- curl test suite compatibility: **69/98 tests passing** (tests 1–99), up from 8/19

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
