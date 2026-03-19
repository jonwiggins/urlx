# Task 09: HTTP Headers, Encoding, and TLS Edge Cases

## Status: Not Started

## Problem

HTTP response parsing has edge cases with chunked encoding containing large null-byte chunks, HTTP/0.9 responses over HTTPS, CRL validation, very long cookie expiry dates, globbing with HTTP/2 connection reuse, `--remove-on-error` + `--no-clobber`, and negative Content-Length values.

## Tests (7)

| Test | Description |
|------|-------------|
| 306 | HTTPS GET without response headers (HTTP/0.9 style) — body only |
| 313 | CRL validation test with HTTPS certificate verification — expects error 60 |
| 373 | HTTP chunked transfer encoding with large null-byte chunks |
| 379 | HTTP GET with `--remove-on-error` and `--no-clobber` when file exists — expects error 18 |
| 415 | HTTP response with control character and negative Content-Length value |
| 471 | HTTP GET with globbing `{url1,url2}` and HTTP/1.1 to HTTP/2 protocol switch |
| 483 | HTTP cookies with very long expire dates |

## Work Needed

1. **HTTPS HTTP/0.9** (306): Handle HTTPS responses that send raw body without headers (HTTP/0.9 mode). Should output body data only.
2. **CRL checking** (313): Implement Certificate Revocation List (CRL) validation via `--crlfile`. Return error 60 when cert is revoked.
3. **Chunked null bytes** (373): Handle chunked responses containing large chunks filled with null bytes without truncation.
4. **--remove-on-error + --no-clobber** (379): When file exists and `--no-clobber` is set, return error 18 (partial file) and `--remove-on-error` should not delete the existing file.
5. **Negative Content-Length** (415): Reject responses with negative or control-character Content-Length values.
6. **Globbing + HTTP/2** (471): When globbing produces multiple URLs, handle HTTP/2 connection sharing correctly.
7. **Long cookie expiry** (483): Parse cookie Expires dates far in the future without overflow.

## Exit Criteria

All 7 tests pass: `runtests.pl 306 313 373 379 415 471 483`
