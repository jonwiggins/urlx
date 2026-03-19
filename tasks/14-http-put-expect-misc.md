# Task 14: HTTP PUT, Expect: 100-continue, and Misc HTTP Fixes

## Summary

Fix HTTP PUT edge cases (multiple URLs, missing body), Expect: 100-continue handling (400/417 responses), HTTP version downgrade, If-Modified-Since, connection reuse, and header line folding.

## Failing Tests (7)

| Test | Description | Root Cause |
|------|-------------|------------|
| 1064 | HTTP PUT twice | No Content-Length/body sent on second PUT |
| 1065 | HTTP PUT with one file but two URLs | File not re-read for second URL |
| 1070 | HTTP POST with server closing connection before all data | Not handling partial send |
| 1074 | HTTP downgrade to HTTP/1.0 on second request | Should send HTTP/1.0 when server responded with 1.0 |
| 1128 | HTTP 200 If-Modified-Since with old+new documents | If-Modified-Since not sent on conditional request |
| 1131 | HTTP PUT expect 100-continue with a 400 | Body sent despite 400 response to Expect |
| 1274 | HTTP header line folding | Continuation lines not folded into previous header |

## Key Changes

### 1. HTTP PUT with multiple URLs (`crates/liburlx/src/transfer.rs`)
When uploading the same file to multiple URLs, the file must be re-read (seeked to beginning) for each URL. Currently, the second PUT has no body.

### 2. Expect: 100-continue rejection (tests 1131)
When server responds to `Expect: 100-continue` with a 400 or 417, do NOT send the body. Read the error response and return it.

### 3. HTTP version downgrade (test 1074)
When a server responds with `HTTP/1.0`, subsequent requests to the same server on the same connection should use HTTP/1.0.

### 4. If-Modified-Since (test 1128)
When `-z <date>` is specified, the `If-Modified-Since` header must be sent. Verify it's included in the outgoing request.

### 5. Header line folding (test 1274)
HTTP/1.1 header continuation lines (lines starting with whitespace) must be folded into the previous header value when presenting to the user. E.g.:
```
Server: test-server/
 fake
 folded
```
Should become: `Server: test-server/ fake folded`

### 6. Partial send handling (test 1070)
When the server closes the connection before all POST data is sent, handle gracefully — read whatever response was sent.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  1064 1065 1070 1074 1128 1131 1274
```

All 7 tests must report OK.
