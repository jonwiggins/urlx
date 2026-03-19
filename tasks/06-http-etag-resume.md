# Task 06: HTTP ETag, Resume, and Clobber Edge Cases

## Status: Not Started

## Problem

Several ETag, resume, and file-clobber-related features have edge cases: `--etag-save` with bad paths, `--no-clobber` + `--continue-at` conflicts, `--remove-on-error` conflicts, multi-URL etag, anyauth connection reuse, variable expansion edge cases, and large accumulated headers.

## Tests (8)

| Test | Description |
|------|-------------|
| 338 | ANYAUTH connection reuse — non-authenticated connection before auth request |
| 369 | `--etag-save` with bad path, then working transfer with `--next` |
| 481 | `--no-clobber` with `--continue-at` (conflicting options) — expects error 2 |
| 482 | `--remove-on-error` with `--continue-at` (conflicting options) — expects error 2 |
| 484 | `--etag-compare` and `--etag-save` with multiple URLs — expects error 2 |
| 485 | `--etag-save` with multiple URLs (URLs specified first) — expects error 2 |
| 487 | Variable expansion with bad base64 data in `{{var:64dec}}` function |
| 497 | Reject too large accumulated HTTP response headers (>8KB limit) |

## Work Needed

1. **Option conflict detection** (481, 482, 484, 485): Detect and reject conflicting option combinations at parse time with exit code 2:
   - `--no-clobber` + `--continue-at`
   - `--remove-on-error` + `--continue-at`
   - `--etag-compare`/`--etag-save` with multiple URLs
2. **--etag-save error recovery** (369): When `--etag-save` path is invalid, fail that transfer but continue with `--next` transfers.
3. **ANYAUTH connection reuse** (338): When using `--anyauth`, if first request gets 401, the connection should be reused for the auth retry even though the initial request was unauthenticated.
4. **Variable base64 decode** (487): `{{var:64dec}}` with invalid base64 data should produce an error, not crash.
5. **Header size limit** (497): Reject responses with accumulated headers exceeding 8KB with appropriate error.

## Exit Criteria

All 8 tests pass: `runtests.pl 338 369 481 482 484 485 487 497`
