# Task 05: CLI, Globbing, and Output Edge Cases

## Status: Not Started

## Problem

Various CLI behaviors don't match curl: globbing error handling, `--remote-time` with old dates, `--next` with connection reuse, blank header values, `--request-target`, `-J` Content-Disposition filename, `--libcurl` output, progress bar, and filename-looks-like-flag warnings.

## Tests (14)

| Test | Description |
|------|-------------|
| 760 | Unsupported protocol error when using `--next` with malformed URL (qttp scheme) |
| 761 | Globbing expansion error when too many `{}` sets in URL |
| 762 | HTTP GET with `--remote-time` — set file timestamp from 1940 Last-Modified header |
| 776 | HTTP NTLM with very long NTLMv2 response — expects error 100 |
| 988 | IMAPS FETCH with quoted username/password and special characters using `--insecure` |
| 1134 | HTTP connection reuse with `--next` and different credentials between requests |
| 1265 | `NO_PROXY` env var with IPv6 numerical address to bypass proxy |
| 1268 | CLI warning when filename argument looks like a flag (e.g., `-q`) |
| 1292 | HTTP GET with blank header values using `-H "Host;"` and `-H "Accept;"` syntax |
| 1299 | HTTP OPTIONS with asterisk request target via `--request-target "*"` |
| 1328 | HTTP GET with globbed range `[1-2]` and `--fail` on 404 response |
| 1370 | HTTP GET with `-J` (Content-Disposition filename) and `-D` dump headers to file |
| 1371 | HTTP GET with `-J` (Content-Disposition filename) and `-D` dump headers to stdout |
| 1400 | `--libcurl` flag to generate C source code snippet for the transfer |

## Work Needed

1. **Globbing errors** (760, 761, 1328): Proper error messages and exit codes for bad glob patterns, too many expansions, and `--fail` interaction with globbed URLs.
2. **--remote-time** (762): Set output file mtime from `Last-Modified` header. Handle dates before 1970 gracefully.
3. **--next credential isolation** (1134): When using `--next`, different credentials per URL should not leak, but the TCP connection can be reused.
4. **NO_PROXY IPv6** (1265): `NO_PROXY=::1` should bypass proxy for IPv6 localhost.
5. **Filename flag warning** (1268): When an output filename starts with `-`, warn that it looks like a flag.
6. **Blank header values** (1292): `-H "Host;"` should send `Host:` with empty value (not remove the header).
7. **--request-target** (1299): `--request-target "*"` should override the request URI in the HTTP request line.
8. **-J Content-Disposition** (1370, 1371): `-J` should extract filename from Content-Disposition header. Must work with `-D` writing headers to file or stdout.
9. **--libcurl** (1400): Generate a C source file showing the equivalent libcurl calls for the request.
10. **IMAPS special chars** (988): Handle quoted usernames/passwords with special characters over IMAPS.

## Exit Criteria

All 14 tests pass: `runtests.pl 760 761 762 776 988 1134 1265 1268 1292 1299 1328 1370 1371 1400`
