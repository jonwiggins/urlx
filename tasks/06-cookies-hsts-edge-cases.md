# Task 06: Cookie and HSTS Edge Cases

## Summary
Fix remaining cookie jar, cookie matching, and HSTS bugs. These are scattered edge cases in the cookie engine that each affect 1-3 tests.

## Estimated Effort
2-3 days

## Tests to Pass (19)
327, 329, 331, 392, 414, 420, 427, 440, 441, 443, 444, 798, 898, 1151, 1160, 1218, 1228, 1258, 1331

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 327 329 331 392 414 420 427 440 441 443 444 798 898 1151 1160 1218 1228 1258 1331
# All 19 tests should report OK
```

## What Needs to Change

### Cookie Engine Fixes

**1. Max-Age=0 deletes cookies (test 329)**
`Set-Cookie: name=; Max-Age=0` should delete the cookie immediately. Verify `parse_set_cookie` handles Max-Age=0 as an expiry in the past.

**2. Cookie jar cleanup on save (tests 327, 420)**
When saving the cookie jar with `-c`, expired cookies should be filtered out. Test 327: last cookie has epoch expiry → jar should be empty. Test 420: similar cleanup scenario.

**3. 8KB Cookie header cap (tests 427, 443)**
curl limits the total Cookie header to ~8KB. When cookies exceed this, truncate. Test 427: many large cookies. Test 443: cookie count limit (150 per request already implemented, but total size limit may not be).

**4. Secure cookie handling (tests 392, 414)**
- Test 392: `Secure` cookies should only be sent over HTTPS, not HTTP
- Test 414: `Set-Cookie` with `Secure` flag from HTTP origin should be rejected

**5. Cookie path matching (test 1228)**
Cookie path matching needs to follow RFC 6265 rules: `/foo` matches `/foo`, `/foo/`, `/foo/bar` but NOT `/foobar`.

**6. Cross-domain cookie leaking (tests 1218, 1258)**
Cookies set for one domain should not be sent to a different domain. Verify domain matching handles:
- Public suffix list (PSL) blocking
- IP address cookies (no domain matching)
- Subdomain matching with leading dot

**7. Long cookie truncation (tests 1151, 1160)**
Cookies with very long values or domains should be handled gracefully. curl may truncate or reject cookies exceeding certain limits.

**8. Folded header parsing (test 798)**
HTTP header line folding (continuation with whitespace) in Set-Cookie headers. The header parser should unfold multi-line headers before cookie parsing.

**9. Cookie + auth on redirect (test 898)**
When redirecting cross-host, both cookies and Authorization headers should be stripped (unless --location-trusted).

**10. Proxy auth + cookies (test 1331)**
When using proxy auth, cookies should still be sent correctly to the target host (not the proxy).

### HSTS Fixes

**11. Trailing dot normalization (tests 440, 441)**
HSTS hostnames should be normalized: `example.com.` (trailing dot) should match `example.com`. Test 440: `--hsts` with trailing dot in the HSTS file. Test 441: similar.

**12. HSTS cookie interaction (test 444)**
When HSTS upgrades HTTP to HTTPS, cookies set during the HTTPS request should be marked as secure.

## Key Files
- `crates/liburlx/src/cookie.rs` — Cookie engine (parsing, matching, jar save/load)
- `crates/liburlx/src/hsts.rs` — HSTS cache
- `crates/liburlx/src/protocol/http/h1.rs` — Header folding
- `crates/liburlx/src/easy.rs` — Cookie + auth interaction on redirects

## Notes
- Run each test individually and check the diff to understand the specific failure
- Cookie tests often have multi-URL flows where the first URL sets cookies and the second verifies they're sent
- The Netscape cookie file format is tab-separated: `domain\tsubdomains\tpath\tsecure\texpiry\tname\tvalue`
- curl's `MAX_COOKIE_SEND_AMOUNT` is 150 (already implemented)
