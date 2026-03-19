# Task 12: Netrc Parsing Fixes

## Summary

Fix .netrc file parsing edge cases: multiple accounts for the same host (pick order), `default` entries, embedded NULL bytes, and CRLF line endings.

## Failing Tests (6)

| Test | Description | Root Cause |
|------|-------------|------------|
| 478 | .netrc with multiple accounts for same host | Wrong account picked (should pick first matching) |
| 480 | Reject .netrc with credentials using CRLF for POP3 | CRLF netrc should be rejected with error |
| 682 | netrc with multiple logins - pick first | First matching login for host not selected |
| 683 | netrc with multiple logins - pick second | When user provides `-u user:`, match that specific user in netrc |
| 685 | netrc with no login - provided user | When netrc has no `login` line, `-u user:` should still get password |
| 793 | .netrc with embedded NULL byte, with quoted token | NULL bytes in netrc should be handled/rejected |

## Key Changes

### File: `crates/liburlx/src/netrc.rs` (or wherever netrc parsing lives)

### 1. Multiple accounts for same host
When multiple `machine <host>` blocks exist for the same host:
- Without `-u user:`: use the FIRST matching block (test 478, 682)
- With `-u user:`: find the block matching that specific username (test 683)

### 2. Netrc + user flag interaction
When user provides `-u user:` (user but no password), search netrc for that user's password. If netrc has an entry with no `login` line, match it and use its `password` (test 685).

### 3. CRLF rejection (test 480)
Netrc files with CRLF line endings should be rejected with an appropriate error for POP3 protocol.

### 4. NULL byte handling (test 793)
Embedded NULL bytes in netrc files should be handled — either rejected or treated as string terminators. Quoted tokens containing NULL should not crash.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  478 480 682 683 685 793
```

All 6 tests must report OK. No regressions on netrc tests 131, 185.
