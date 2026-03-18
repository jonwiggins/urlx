# Task 07: HTTP Redirects, Auth Edge Cases, and Resume

## Summary
Fix remaining HTTP redirect handling, Digest auth edge cases, auth header stripping on redirect, and HTTP resume issues.

## Estimated Effort
3-4 days

## Tests to Pass (32)
- **Redirects (12):** 276, 794, 796, 973, 975, 999, 1028, 1031, 1056, 1067, 1143, 1245
- **Digest Auth (10):** 153, 177, 388, 1071, 1072, 1079, 1095, 1284, 1285, 1286
- **Auth Stripping (5):** 257, 317, 318, 1087, 1088
- **HTTP Resume (5):** 1040, 1041, 1042, 1043, 1273

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 153 177 257 276 317 318 388 794 796 973 975 999 1028 1031 1040 1041 1042 1043 1056 1067 1071 1072 1079 1087 1088 1095 1143 1245 1273 1284 1285 1286
# All 32 tests should report OK
```

## Redirect Fixes

### 1. Auth header stripping on cross-host redirect (tests 317, 318, 898, 999)
When following a redirect to a different host, `Authorization` and `Cookie` headers must be stripped. `--location-trusted` preserves them. Current issue: headers may leak.
**File:** `crates/liburlx/src/easy.rs` — redirect loop

### 2. Cross-protocol redirect HTTP→FTP (tests 973, 975, 1028)
Redirect from HTTP to `ftp://` should work when `--proto-redir` allows it. The redirect handler needs to dispatch to the FTP protocol handler.
**File:** `crates/liburlx/src/easy.rs` — redirect target scheme check

### 3. Query string edge cases (tests 276, 1031)
- Test 276: Multiple `?` in redirect URL — only first `?` separates path from query
- Test 1031: Redirect to query-string-only URL (`?query`)
**File:** `crates/liburlx/src/url.rs`, `crates/liburlx/src/easy.rs`

### 4. --referer auto-update on redirect (test 1067)
When `--referer ';auto'` is set, the Referer header should be updated to the previous URL on each redirect hop.
**File:** `crates/liburlx/src/easy.rs` — redirect loop

### 5. IPv6 scope in redirect (test 1056)
Redirect to URL with IPv6 scope ID (e.g., `http://[fe80::1%25eth0]/path`).
**File:** `crates/liburlx/src/url.rs`

## Digest Auth Fixes

### 6. Stale nonce re-negotiation (test 153)
When server responds with `stale=true` in Digest challenge, retry with new nonce without re-prompting.
**File:** `crates/liburlx/src/auth/digest.rs`, `crates/liburlx/src/easy.rs`

### 7. Digest + redirect (test 177)
After successful Digest auth, redirect should not resend credentials to a different host.
**File:** `crates/liburlx/src/easy.rs`

### 8. Multiple qop values (test 388)
`Proxy-Authenticate: Digest qop=" auth, auth-int"` — parse with leading space and multiple values.
**File:** `crates/liburlx/src/auth/digest.rs`

### 9. Nonce-count incrementing (test 1286)
For keep-alive connections, the `nc` (nonce count) must increment on each request using the same nonce.
**File:** `crates/liburlx/src/auth/digest.rs`

### 10. Realm with escaped quotes (test 1095)
`realm="test\"realm"` — the realm value contains escaped quotes.
**File:** `crates/liburlx/src/auth/digest.rs`

## HTTP Resume Fixes

### 11. Resume from end of file (tests 1040, 1043)
When resuming from byte offset == file size, curl sends `Range: bytes=N-` and expects:
- 416 Range Not Satisfiable response
- The original file content should still be output

### 12. PUT resume uses Content-Range (test 1041)
PUT uploads with resume should use `Content-Range: bytes N-M/total` header, not `Range`.
**File:** `crates/liburlx/src/protocol/http/h1.rs`

### 13. Resume beyond file end (test 1042)
When resume offset > file size, should still attempt (let server decide).

## Key Files
- `crates/liburlx/src/easy.rs` — Redirect loop, auth stripping, resume headers
- `crates/liburlx/src/auth/digest.rs` — Digest parsing and response generation
- `crates/liburlx/src/url.rs` — URL manipulation for redirect targets
- `crates/liburlx/src/protocol/http/h1.rs` — Range/Content-Range headers

## Notes
- Test each redirect scenario individually — the expected protocol diff shows the exact header changes
- Digest auth tests often involve multi-request flows (initial → 401 → retry with Digest → 200)
- For resume tests, check the expected `Range` header format carefully
