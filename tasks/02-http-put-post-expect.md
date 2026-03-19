# Task 02: HTTP PUT/POST and Expect: 100-continue Edge Cases

## Status: Not Started

## Problem

Several HTTP PUT and POST edge cases fail, including Expect: 100-continue retry after 417, multipart form MIME type handling, globbed PUT uploads, HSTS with proxy CONNECT, and --data-urlencode variants.

## Tests (9)

| Test | Description |
|------|-------------|
| 186 | Multipart form POST with custom MIME types on text fields |
| 357 | HTTP PUT with Expect: 100-continue, server returns 417, retry without Expect |
| 490 | Two globbed HTTP PUTs to the same URL using `{file1,file2}` |
| 491 | Two globbed HTTP PUTs where second file is missing — expects error 26 |
| 492 | Two globbed HTTP PUTs to two globbed URLs (2x2 = 4 transfers) |
| 493 | HSTS upgrade with HTTP proxy CONNECT rejected (403), verify `%{url_effective}` shows https |
| 1015 | `--data-urlencode` with multiple encoding forms: plain, key=value, @file, file content |
| 1077 | FTP over HTTP proxy with HTTP/1.1 to HTTP/1.0 downgrade on second request |
| 1106 | FTP URL with `ftp_proxy` env var, sent as HTTP GET through proxy |

## Work Needed

1. **Expect 417 retry** (357): When server responds with 417 Expectation Failed, retry the PUT without the `Expect: 100-continue` header. Currently urlx doesn't handle this retry.
2. **Multipart MIME types** (186): Custom MIME type on text form fields (e.g., `-F "field=value;type=text/plain"`) needs to set Content-Type correctly in the multipart body.
3. **Globbed PUT** (490, 491, 492): `-T "{file1,file2}"` should upload each file in sequence. Handle missing files (error 26) and cross-product with globbed URLs.
4. **HSTS + proxy** (493): When HSTS upgrades http→https and proxy CONNECT fails (403), `%{url_effective}` should still show the https URL.
5. **--data-urlencode** (1015): Support all forms: `content`, `=content`, `name=content`, `@filename`, `name@filename`.
6. **FTP proxy relay** (1077, 1106): FTP URLs sent through HTTP proxy as GET requests. Handle HTTP/1.0 downgrade on second request, and `ftp_proxy` env var.

## Exit Criteria

All 9 tests pass: `runtests.pl 186 357 490 491 492 493 1015 1077 1106`
