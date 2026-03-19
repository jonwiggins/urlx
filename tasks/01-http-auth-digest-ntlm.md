# Task 01: HTTP Auth Header Ordering + Digest Hash Fix

## Summary

Fix two interrelated HTTP authentication bugs that together cause 39 curl test failures:

1. **Authorization header ordering**: urlx places the `Authorization:` header *after* `User-Agent:` and `Accept:`, but curl places it *before* them (right after `Host:`). This affects all auth mechanisms (Digest, NTLM, Basic).

2. **Digest response hash computation**: The Digest `response=` field in the Authorization header produces incorrect hash values compared to curl. This likely indicates a bug in how the HA2 or final response hash is computed (wrong URI, missing qop handling, or incorrect nonce-count).

## Failing Tests (39)

| Test | Type | Description |
|------|------|-------------|
| 64 | Digest | HTTP GET with Digest authorization |
| 65 | Digest | HTTP GET with Digest authorization with bad password |
| 72 | Digest | HTTP with Digest *OR* Basic authorization |
| 88 | Digest | HTTP PUT with Digest authorization |
| 153 | Digest | HTTP with Digest authorization with stale=true |
| 154 | Digest | HTTP PUT with --anyauth authorization (picking Digest) |
| 245 | Digest | HTTP POST --digest |
| 246 | Digest | HTTP POST --digest with server doing a 100 before 401 |
| 273 | Digest | HTTP with two Digest authorization headers |
| 335 | Digest | HTTP with proxy Digest and site Digest with creds in URLs |
| 338 | Digest | ANYAUTH connection reuse of non-authed connection |
| 388 | Digest | HTTP with Digest and multiple qop values with leading space |
| 1001 | Digest | HTTP POST --digest with PUT and resumed upload and modified method |
| 1002 | Digest | HTTP PUT with Digest auth, resumed upload and modified method, twice |
| 1030 | Digest | HTTP PUT with --anyauth authorization (picking Digest) |
| 1071 | Digest | Downgraded HTTP PUT to HTTP 1.0 with authorization |
| 1075 | Mixed | HTTP PUT with --anyauth authorization (picking Basic) |
| 1079 | Digest | HTTP retry after closed connection and empty response |
| 1087 | Digest | HTTP, proxy with --anyauth and Location: to new host |
| 1088 | Digest | HTTP, proxy with --anyauth and Location: using location-trusted |
| 1095 | Digest | HTTP with Digest and realm with quoted quotes |
| 1134 | Mixed | HTTP connection reuse with different credentials |
| 1204 | Basic | HTTP with WWW-Authenticate and multiple auths in a single line |
| 1229 | Digest | HTTP with Digest authorization with username needing escape |
| 1284 | Digest | HTTP POST --digest with user-specified Content-Length header |
| 1285 | Digest | HTTP PUT --digest with user-specified Content-Length header |
| 1286 | Digest | HTTP GET --digest increasing nonce-count |
| 67 | NTLM | HTTP with NTLM authorization |
| 68 | NTLM | HTTP with NTLM authorization and wrong password |
| 69 | NTLM | HTTP with NTLM, Basic or Wild-and-crazy authorization |
| 70 | Mixed | HTTP with Digest *OR* NTLM authorization |
| 76 | NTLM | HTTP with comma-separated WWW-Authenticate header |
| 89 | NTLM | HTTP with NTLM and follow-location |
| 90 | NTLM | HTTP with NTLM via --anyauth, and then follow-location with NTLM again |
| 91 | NTLM | HTTP with NTLM/Negotiate/Basic, anyauth and user with domain, with size 0 |
| 150 | NTLM | HTTP with NTLM authorization and --fail |
| 155 | NTLM | HTTP PUT with --anyauth authorization (picking NTLM) |
| 176 | NTLM | HTTP POST --ntlm to server not requiring any auth at all |
| 267 | NTLM | HTTP POST with NTLM authorization and added custom headers |
| 694 | NTLM | HTTP with NTLM twice, verify CURLINFO_HTTPAUTH_USED |
| 775 | NTLM | HTTP with NTLM with too long username |
| 776 | NTLM | HTTP with NTLM with too long NTLMv2 ntresplen |

## Failure Pattern

All tests show this diff pattern for header ordering:

```diff
 GET /67 HTTP/1.1[CR][LF]
 Host: 127.0.0.1:PORT[CR][LF]
-Authorization: NTLM TlRMTVNTUAABAAAA...[CR][LF]
 User-Agent: curl/0.1.0[CR][LF]
 Accept: */*[CR][LF]
+Authorization: NTLM TlRMTVNTUAABAAAA...[CR][LF]
```

For Digest tests, additionally the `response=` hash value differs from expected.

## What Needs to Change

### 1. Fix header ordering in HTTP request builder

**File**: `crates/liburlx/src/protocol/http.rs` (or wherever HTTP request headers are assembled)

The `Authorization` header must be inserted *before* `User-Agent` and `Accept`. In curl's implementation, the header order is:
1. `Host:`
2. `Authorization:` (if auth is active)
3. `User-Agent:`
4. `Accept:`
5. Other headers

Find where headers are assembled for HTTP requests and ensure auth headers are placed right after Host.

### 2. Fix Digest response hash computation

**File**: `crates/liburlx/src/auth/digest.rs`

The Digest `response=` value is computed as:
```
HA1 = MD5(username:realm:password)
HA2 = MD5(method:digestURI)
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
```

Common bugs:
- Using the wrong URI (e.g., full URL instead of just the path)
- Not handling `qop=auth` vs no qop correctly
- Wrong nonce-count formatting (must be 8-digit hex: `00000001`)
- Not handling multiple qop values (e.g., `qop="auth, auth-int"` — pick `auth`)
- Not handling realm with escaped quotes
- Not handling username with special characters that need escaping

### 3. Fix Digest stale=true handling (test 153)

When server responds with `stale=true` in the Digest challenge, curl re-authenticates with the new nonce without prompting. urlx must detect `stale=true` and retry with the new nonce.

### 4. Fix --anyauth mechanism selection

Tests 70, 1075 show --anyauth not correctly picking the strongest auth. curl's preference order: Negotiate > Digest > NTLM > Basic. Ensure the negotiation logic matches.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  64 65 67 68 69 70 72 76 88 89 90 91 150 153 154 155 176 \
  245 246 267 273 335 338 388 694 775 776 \
  1001 1002 1030 1071 1075 1079 1095 1134 1204 1229 1284 1285 1286
```

All 39 tests must report OK. No regressions on previously-passing tests 1-100.
