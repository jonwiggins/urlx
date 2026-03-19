# Task 01: FTP over SOCKS/HTTP Proxy

## Status: Not Started

## Problem

FTP transfers through SOCKS4/5 and HTTP CONNECT proxies fail. urlx cannot properly tunnel FTP control and data connections through proxy layers, including chained proxy configurations (SOCKS5 + HTTP CONNECT).

Additionally, FTP-over-HTTP-proxy relay (where FTP URLs are sent as HTTP requests to the proxy) has edge cases with HTTP/1.0 downgrade and `ftp_proxy` env var.

## Tests (10)

| Test | Description |
|------|-------------|
| 706 | FTP dir list (PASV LIST) through SOCKS4 proxy |
| 707 | FTP dir list (PASV LIST) through SOCKS5 proxy |
| 712 | FTP file retrieve (PASV RETR) through SOCKS5 proxy |
| 713 | FTP file retrieve through SOCKS5 with --connect-to |
| 714 | FTP file retrieve through HTTP CONNECT tunnel with --connect-to |
| 715 | FTP file retrieve through dual proxy chain (--preproxy SOCKS5 + --proxy HTTP CONNECT) |
| 1050 | FTP-IPv6 dir list using EPRT with specified client IPv6 address |
| 1059 | HTTP CONNECT to FTP URL through proxy returning 501 — expects error 56 |
| 1069 | HTTP/1.0 PUT from stdin without Content-Length — expects error 25 |
| 1105 | HTTP POST with cookies and cookie jar saving through proxy |

## Work Needed

1. **SOCKS proxy FTP tunneling** (706, 707, 712, 713): Route FTP control connections through SOCKS4/5 proxies. The FTP data connection (EPSV/PASV) also needs to go through the proxy.
2. **HTTP CONNECT FTP tunneling** (714): Support `--proxytunnel` for FTP URLs by establishing an HTTP CONNECT tunnel, then running FTP protocol inside it.
3. **Chained proxies** (715): Support `--preproxy` (SOCKS5) + `--proxy` (HTTP CONNECT) chaining for FTP.
4. **IPv6 EPRT** (1050): Fix EPRT command formatting for IPv6 addresses (`EPRT |2|::1|port|`).
5. **CONNECT error handling** (1059): When HTTP proxy rejects CONNECT with 501, return error code 56 instead of hanging.
6. **HTTP/1.0 upload edge case** (1069): PUT from stdin with HTTP/1.0 (no chunked encoding) should fail with exit code 25 since Content-Length is unknown.
7. **Cookie jar with proxy** (1105): Ensure cookie jar is written correctly when using HTTP proxy for POST requests.

## Exit Criteria

All 10 tests pass: `runtests.pl 706 707 712 713 714 715 1050 1059 1069 1105`
