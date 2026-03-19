# Task 06: Cookie and HSTS Edge Cases

## Summary

Fix remaining cookie engine and HSTS bugs: domain matching, path matching per RFC 6265, Max-Age=0 deletion, secure cookie enforcement, localhost cookies, long expire dates, and HSTS interaction with --write-out.

## Failing Tests (10)

| Test | Description | Root Cause |
|------|-------------|------------|
| 327 | HTTP with cookiejar without cookies left | Cookie jar file should be empty after all cookies expire |
| 329 | HTTP cookie with Max-Age=0 | Max-Age=0 should immediately delete cookie, not send it |
| 331 | HTTP with cookie using hostname 'moo' | Cookie domain matching for short hostnames |
| 392 | HTTP secure cookies over localhost | Secure cookies should be sent over HTTP for localhost |
| 414 | HTTPS sec-cookie, HTTP redirect, same name cookie, redirect back | Secure cookie overwritten by non-secure during redirect chain |
| 483 | HTTP cookies with long expire dates | Cookie jar truncates or misformats dates far in the future |
| 493 | HSTS and %{url_effective} after upgrade | After HSTS upgrades HTTP→HTTPS, %{url_effective} should show https:// |
| 1218 | HTTP cookies and domains with same prefix | Domain matching: cookies for `example.com` must not match `notexample.com` |
| 1228 | HTTP cookie path match | Cookie path matching per RFC 6265 §5.1.4 |
| 1258 | HTTP, use cookies with localhost | Cookies set for `localhost` should be sent to `localhost` |

## Key Changes

### 1. Max-Age=0 deletion (`crates/liburlx/src/cookie.rs`)
When `Max-Age=0` is received, immediately remove the cookie from the jar. Do not send it on subsequent requests.

### 2. Domain matching
- A cookie for `example.com` must NOT match `notexample.com` (test 1218). The domain must match exactly or as a suffix after a `.` boundary.
- Short hostnames like `moo` (test 331) must work when cookies explicitly set `domain=moo`.
- `localhost` cookies (test 1258) must be stored and sent correctly.

### 3. Path matching (RFC 6265 §5.1.4)
Cookie path `/foo` should match request path `/foo/bar` but NOT `/foobar`. Must check for `/` boundary.

### 4. Secure cookie handling
- Secure cookies should be sent over plain HTTP to `localhost` and `127.0.0.1` (test 392).
- During redirect chains, a non-secure cookie with the same name should NOT overwrite a secure cookie (test 414).

### 5. Cookie jar formatting
Long expire dates (e.g., year 2100+) must be formatted correctly in the Netscape cookie jar file (test 483).

### 6. HSTS + write-out
After HSTS upgrades `http://` to `https://`, the `%{url_effective}` write-out variable must reflect the upgraded URL (test 493).

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  327 329 331 392 414 483 493 1218 1228 1258
```

All 10 tests must report OK. No regressions on cookie tests 6-8, 31, 46.
