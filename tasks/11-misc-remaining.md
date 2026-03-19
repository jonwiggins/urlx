# Task 11: Miscellaneous Remaining Failures

## Status: Not Started

## Problem

A collection of smaller edge cases that don't fit neatly into other categories: file range output, HTTP invalid range retry, headers from file, progress bar output, FTP uneven PWD quotes, and HTTP connection reuse edge cases.

## Tests (7)

| Test | Description |
|------|-------------|
| 1020 | FILE range with `-r` flag to stdout (last 9 bytes) |
| 1117 | HTTP invalid range (416 error) then another valid range request with `--next` |
| 1147 | Get `-H` headers from file with `@filename` syntax |
| 1148 | Progress bar output with `-#` flag |
| 1152 | FTP with uneven/unmatched quote in PWD response |
| 669 | SMTP protocol edge case |

## Work Needed

1. **FILE range** (1020): `file://` URLs with `-r` byte range should output only the requested range to stdout.
2. **416 range retry** (1117): When first request gets 416 Range Not Satisfiable, `--next` should allow a second request with a valid range.
3. **Headers from file** (1147): `-H @filename` should read headers from a file, one per line.
4. **Progress bar** (1148): `-#` progress bar output format must match curl's format.
5. **PWD unmatched quotes** (1152): Handle FTP PWD responses with unmatched quotes (e.g., `257 "/path" extra`).

## Exit Criteria

All tests pass: `runtests.pl 1020 1117 1147 1148 1152 669`
