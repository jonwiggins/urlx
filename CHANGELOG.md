# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **STARTTLS** — TLS upgrade support for FTPS, SMTP, IMAP, and POP3 (explicit TLS via `STARTTLS`/`AUTH TLS`)
- **Implicit TLS** — `smtps://`, `imaps://`, `pop3s://` connect directly over TLS
- **SASL authentication** — CRAM-MD5, NTLM, EXTERNAL, OAUTHBEARER, XOAUTH2, APOP, PLAIN, LOGIN for email protocols
- **NTLMv2 authentication** — Full challenge-response NTLM for HTTP and proxy auth
- **SCRAM-SHA-256** — SASL SCRAM-SHA-256 authentication mechanism
- **SFTP quote commands** — `-Q` commands for SFTP (rename, mkdir, rmdir, chmod, etc.), byte ranges, `--ftp-create-dirs`
- **FTP connection reuse** — Control connection reused across multi-URL transfers with proper CWD reset
- **IMAP protocol** — RFC 5092 URL parsing (UIDVALIDITY, SECTION), LIST/SEARCH/EXAMINE/FETCH, APPEND uploads, AUTHENTICATE
- **POP3 protocol** — AUTH mechanisms, RETR/LIST/DELE/UIDL/CAPA, custom commands
- **SMTP protocol rewrite** — VRFY/EXPN, multipart MIME upload, long line handling, custom commands, AUTH negotiation
- **MQTT protocol** — CONNECT/PUBLISH/SUBSCRIBE with QoS 0/1/2 (7 curl tests passing)
- **`--variable` and `--expand-data`** — Variable expansion with `{{var}}` syntax, file/stdin loading, byte ranges, function transforms
- **`--write-out` variables** — `%{certs}`, `%{header_json}`, `%{url.*}`, `%{method}`, `%{remote_ip}`, `%{remote_port}`, `%{stderr}`, `%output{file}`
- **`--skip-existing`** — Skip download if output file already exists
- **`--json`** — Shorthand for JSON POST with appropriate Content-Type and Accept headers

### Fixed

- **HTTP proxy CONNECT** — NTLM/Digest proxy auth for CONNECT tunnels, tunnel reuse, body suppression during auth negotiation
- **Auth credential stripping** — Authorization and Cookie headers properly stripped on cross-host redirects; `--oauth2-bearer` stripped
- **Cookie engine** — `-b` file vs string detection, 150-cookie-per-request cap, 8KB header cap, `Max-Age=0` expiry, secure cookie filtering, domain validation, jar preservation across multi-URL transfers, IP address domain handling
- **HSTS** — Trailing dot handling, proper enforcement
- **Content/chunked encoding** — `--raw` chunked passthrough, deflate decompression, trailer headers, `--max-filesize` with chunked, mixed CRLF/LF line endings
- **Expect: 100-continue** — Body sent only after 100 response, correct Content-Length when body suppressed, proper ordering
- **FTP** — URL encoding in paths (`%0a`, `%0d`), `NLST`, active `PORT` quirks, `--ftp-method nocwd`, quote commands, resume, `PASV`/`EPSV` fallback, `ACCT`, `TYPE A`, 421 service unavailable, 552 disk full, root CWD, cross-protocol redirects
- **SOCKS proxy** — SOCKS5 auth, SOCKS4 long usernames, hostname-mode, IPv4 address type, Proxy-Authorization header leak
- **HTTP resume** — Resume from end of file, beyond end, with `--fail`, 416 as success
- **Redirect handling** — 302/308 method conversion, duplicate Location headers, query string space encoding via proxy, `--follow` flag, credential forwarding
- **Content-Length** — Trailing char validation, comma-separated, conflicting duplicates, overflow detection
- **Multipart forms** — Content-Type boundary merging, `-F type=` parsing
- **Netrc** — Quoted password parsing with escape sequences, `NETRC` env var, multi-URL credential isolation
- **CLI** — `--next` header isolation, `-O` trailing slash defaults, `--output-dir`, `--create-dirs` for `--etag-save`, flag-like filename warnings, `--remote-name-all`/`--no-remote-name`, config file `=` separator, config recursion guard, `--long=value` syntax, glob escaping, `--fail-early`
- **SSH/SFTP/SCP** — Error code mapping (78 for file-not-found, 67 for login-denied), download/upload edge cases
- **HTTP misc** — 1xx intermediate headers, Host header first-wins, HTTP/0.9 denied by default, HTTP/1.0 body handling, version downgrade on auth retry, `-X` request target, IPv6 scope IDs, header line folding

### Changed

- **curl test suite compatibility: 1,171 pass / 102 fail / 54 skip** (tests 1–1400, 92% pass rate), up from 69/98 at v0.1.0
- **2,655 Rust tests**, up from 2,288
- **141 source files, ~72,000 lines of Rust**
- **261 long + 46 short CLI flags** (up from ~150)
- **156 CURLOPT, 49 CURLINFO, 41 CURLcode** in FFI layer

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
