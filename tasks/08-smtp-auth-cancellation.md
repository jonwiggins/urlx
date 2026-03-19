# Task 08: SMTP/IMAP Auth Cancellation and Timeout

## Status: Complete

## Problem

SMTP auth cancellation tests were listed as hanging indefinitely. Investigation showed that tests 932 and 933 already pass — urlx correctly handles SASL cancellation during CRAM-MD5 and NTLM auth exchanges. When the server sends an invalid challenge, urlx sends `*` (SASL cancel per RFC 4954), reads the server's error response, and exits with error code 67 (CURLE_LOGIN_DENIED).

## Tests (3)

| Test | Description | Status |
|------|-------------|--------|
| 932 | SMTP CRAM-MD5 graceful cancellation — server sends invalid challenge, client cancels with `*` | **PASS** |
| 933 | SMTP NTLM graceful cancellation — server sends invalid Type 2 challenge, client cancels with `*` | **PASS** |
| 971 | Source analysis: options-in-versions documentation consistency (Perl script) | **SKIP** — N/A for urlx (checks curl's own docs/VERSIONS.md, docs/options-in-versions, docs/cmdline-opts) |

## Resolution

- **Tests 932, 933**: Already passing. The SMTP auth code in `crates/liburlx/src/protocol/smtp.rs` correctly handles SASL cancellation for both CRAM-MD5 (invalid base64 challenge → send `*`) and NTLM (invalid Type 2 message → send `*`), returning error code 67.
- **Test 971**: Permanently skipped. This is a curl source analysis test that runs a Perl script to verify curl's documentation files are in sync. These files don't exist in urlx.

## Exit Criteria

Tests 932 and 933 pass. Test 971 documented as skip (N/A for urlx).
