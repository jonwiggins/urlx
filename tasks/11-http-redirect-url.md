# Task 11: HTTP Redirect and URL Handling Fixes

## Summary

Fix HTTP redirect edge cases: protocol-less Location headers, query string handling with multiple `?`, credential stripping on cross-host redirect, IPv4→IPv6 redirect, chunked PUT through redirect, three-slash URLs, --path-as-is, and --proto-redir.

## Failing Tests (13)

| Test | Description | Root Cause |
|------|-------------|------------|
| 45 | simple HTTP Location: without protocol in initial URL | Redirect not followed when initial URL has no protocol prefix |
| 199 | HTTP with -d, -G and {} | -G should move -d data to query string with URL globbing |
| 257 | HTTP Location: following with --netrc-optional | Redirect with netrc auth not stripping creds |
| 276 | HTTP Location: following with multiple question marks in URLs | Query string with `?` inside path not handled |
| 479 | .netrc with redirect and default without password | Netrc default entry + redirect |
| 498 | Reject too large HTTP response headers on endless redirects | Not limiting total header size across redirects |
| 1056 | HTTP follow redirect from IPv4 to IPv6 with scope | IPv6 scope ID in redirect Location |
| 1073 | HTTP chunked PUT to HTTP 1.0 server with redirect | Chunked body + redirect + HTTP/1.0 |
| 1141 | HTTP redirect to http:/// (three slashes!) | Three-slash URL `http:///path` not parsed |
| 1241 | HTTP _without_ dotdot removal | --path-as-is should skip `..` normalization |
| 1245 | --proto deny must override --proto-redir allow | --proto takes precedence over --proto-redir |
| 1246 | URL with '#' at end of hostname instead of '/' | Fragment `#` in URL before path |
| 1290 | Verify URL globbing ignores [] | `[]` in URLs should be treated literally when not globbing |

## Key Changes

### 1. Protocol-less redirect (test 45)
When `Location:` header contains `//host/path` (no protocol), use the same protocol as the original request.

### 2. -d + -G interaction (test 199)
When `-G` is specified, `-d` data should be appended to the URL query string, not sent as POST body. This must also work with `{}` URL globbing.

### 3. Query string with multiple `?` (test 276)
Multiple `?` in a URL path should be handled correctly — only the first `?` separates path from query.

### 4. --path-as-is (test 1241)
When `--path-as-is` is specified, do NOT resolve `..` or `.` path segments. Pass the path exactly as given.

### 5. --proto / --proto-redir precedence (test 1245)
`--proto` restrictions must override `--proto-redir` permissions. If a protocol is denied by `--proto`, redirects to that protocol must also be denied.

### 6. URL fragment handling (test 1246)
A `#` immediately after the hostname (before `/`) should be treated as a fragment delimiter, not part of the hostname.

### 7. Large headers across redirects (test 498)
Track cumulative header size across redirect chains and reject when total exceeds limit.

### 8. IPv6 scope ID in redirect (test 1056)
Handle `Location:` headers containing IPv6 addresses with scope IDs like `http://[fe80::1%25lo0]/`.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  45 199 257 276 479 498 1056 1073 1141 1241 1245 1246 1290
```

All 13 tests must report OK. No regressions on redirect tests 11, 47, 57.
