# Task 04: Complete Email SASL Authentication (IMAP, POP3, SMTP)

## Status: COMPLETE

All 37 tests pass as of 2026-03-19. This work was completed in PR #5 (`feat/email-sasl-auth-completion`, commit 29045c7).

## Summary
While basic SASL mechanisms (PLAIN, LOGIN, CRAM-MD5, NTLM, EXTERNAL, XOAUTH2, OAUTHBEARER) are implemented, many SASL-related tests still fail due to edge cases: cancellation flows, --login-options forcing, --sasl-authzid, graceful downgrades, and specific mechanism ordering issues.

## Estimated Effort
3-5 days (shared code across protocols)

## Tests to Pass (37)
- **IMAP (14):** 779, 799, 827, 830, 831, 833, 834, 838, 839, 840, 844, 845, 848, 849
- **POP3 (13):** 873, 876, 877, 879, 880, 884, 885, 886, 888, 889, 890, 892, 893
- **SMTP (10):** 921, 932, 935, 936, 943, 944, 945, 948, 949, 992

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 779 799 827 830 831 833 834 838 839 840 844 845 848 849 873 876 877 879 880 884 885 886 888 889 890 892 893 921 932 935 936 943 944 945 948 949 992
# All 37 tests should report OK
```

## What Needs to Change

### 1. SASL Cancellation (tests 830, 831, 833, 834, 879, 880, 935, 936)
When the server sends an invalid challenge during CRAM-MD5 or NTLM auth, curl sends `*` to cancel the SASL exchange and falls through to the next mechanism or returns error 67.

**Current issue:** Our code treats invalid challenges as fatal errors instead of cancelling gracefully.

**Fix:** In each protocol's auth loop, when `parse_type2_message()` fails or CRAM-MD5 challenge decode fails:
1. Send `*\r\n` (SASL cancel)
2. Read the server's error response
3. Try the next mechanism in preference order

### 2. --login-options AUTH= Forcing (tests 799, 896, 992)
When `--login-options AUTH=PLAIN` is specified, ONLY the PLAIN mechanism should be tried, even if the server advertises others. The current `should_try()` logic handles this for EXTERNAL but may not work correctly for all mechanisms.

**Fix:** Ensure `forced` mechanism takes absolute priority — don't fall through to other mechanisms.

### 3. --sasl-authzid for PLAIN (tests 848, 849, 892, 893)
The SASL PLAIN mechanism format is `authzid\0authcid\0passwd`. When `--sasl-authzid` is set, it should be the first field. Current implementation may not correctly handle this for all three protocols.

**Fix:** Check that the PLAIN auth string format is `{sasl_authzid}\0{user}\0{pass}` when authzid is provided.

### 4. SASL-IR (Initial Response) Variants (tests 838-840, 884-886, 943-945)
The EXTERNAL mechanism tests with and without SASL-IR. Without SASL-IR, the flow is:
1. Send `AUTH EXTERNAL` / `AUTHENTICATE EXTERNAL`
2. Server sends `+` continuation
3. Client sends base64(username)

With SASL-IR:
1. Send `AUTH EXTERNAL base64(username)` in one line

**Fix:** Ensure SASL-IR is only used when the server advertises `SASL-IR` capability (IMAP) or when `--sasl-ir` is explicitly set.

### 5. OAUTHBEARER with --login-options (tests 844, 845, 888-890, 948, 949)
When `--oauth2-bearer` is set, the mechanism selection should prefer OAUTHBEARER over XOAUTH2 if the server advertises it. The `--login-options AUTH=OAUTHBEARER` should force OAUTHBEARER specifically.

### 6. HTTP redirect to email protocol (test 779)
An HTTP 302 redirect to `imap://` should follow the redirect and use the email protocol. This requires the redirect handler in `easy.rs` to dispatch to the IMAP handler.

### 7. Protocol-specific details

**IMAP specifics:**
- Tag counter must be correct (A001, A002, etc.) for each test
- PREAUTH handling (test 846 — skip LOGIN when server sends PREAUTH greeting)
- SASL-IR uses space-separated inline response (no continuation)

**POP3 specifics:**
- Continuation prompt is `+` (not `+ ` — some have space, some don't)
- APOP must be attempted when greeting contains `<timestamp>` before SASL

**SMTP specifics:**
- EHLO must be re-sent after successful auth (curl doesn't, but some tests check command ordering)
- AUTH cancellation sends `*` on its own line

## Key Files
- `crates/liburlx/src/protocol/imap.rs` — IMAP auth section (~lines 340-520)
- `crates/liburlx/src/protocol/pop3.rs` — POP3 auth section (~lines 220-460)
- `crates/liburlx/src/protocol/smtp.rs` — SMTP auth section (~lines 380-600)
- `crates/liburlx/src/auth/ntlm.rs` — NTLM Type 1/2/3
- `crates/liburlx/src/auth/cram_md5.rs` — CRAM-MD5
- `crates/liburlx/src/easy.rs` — Dispatch and --login-options handling

## Notes
- Run each test individually first to see the exact protocol diff
- Many tests share the same challenge string `<1972.987654321@curl>` — consistent test fixtures
- The auth mechanism preference order in curl is: EXTERNAL > OAUTHBEARER > XOAUTH2 > CRAM-MD5 > NTLM > LOGIN > PLAIN
- Some tests verify that auth FAILS correctly (wrong mechanism, cancelled, etc.)
