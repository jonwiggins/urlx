# Task 08: SMTP/IMAP Auth Cancellation and Timeout

## Status: Not Started

## Problem

SMTP auth cancellation tests hang indefinitely. When authentication is rejected mid-negotiation (e.g., server sends `*` to cancel CRAM-MD5 or NTLM), urlx doesn't handle the cancellation and hangs waiting for more data. The `--max-time` flag should kill the transfer, but stdin (`-T -`) keeps the process alive.

## Tests (3)

| Test | Description |
|------|-------------|
| 932 | SMTP CRAM-MD5 authentication — server cancels mid-negotiation, `--max-time 30` |
| 933 | SMTP NTLM authentication — server cancels mid-negotiation, `--max-time 30` |
| 971 | Source analysis: options-in-versions documentation consistency (Perl script) |

## Work Needed

1. **SASL cancellation handling** (932, 933): When the SMTP server sends `*` (cancel) during a SASL auth exchange (CRAM-MD5 or NTLM), urlx should detect this as an auth failure and return an appropriate error code instead of hanging.
2. **--max-time with stdin** (932, 933): The `--max-time` timeout must fire even when reading from stdin (`-T -`). Currently the stdin read blocks the timeout.
3. **Source analysis** (971): This is a Perl script checking documentation consistency — may need to be skipped as N/A for urlx.

## Exit Criteria

Tests 932 and 933 pass (or complete with correct error code within timeout). Test 971 documented as skip if N/A: `runtests.pl 932 933 971`
