# Task 10: FTP Miscellaneous Edge Cases

## Status: Not Started

## Problem

FTP has several remaining edge cases: `file://` URL with single slash, IPv6 with `--disable-epsv`, SFTP post-quote errors, rubbish in PWD responses, root directory fetches with absolute paths, and uneven quotes in PWD.

## Tests (7)

| Test | Description |
|------|-------------|
| 203 | `file:/path` URL with single slash (not triple slash) |
| 254 | FTP IPv6 dir list with PASV and `--disable-epsv` |
| 590 | HTTP POST with proxy Negotiate and NTLM authentication |
| 1217 | FTP with rubbish in PWD 257-response before directory path |
| 1224 | FTP fetch file from root directory with double slash in URL |
| 1225 | FTP fetch two files using absolute paths with multiple CWD commands |
| 1226 | FTP fetch file from root directory with `singlecwd` method |

## Work Needed

1. **file:/ single slash** (203): `file:/path` (one slash) is equivalent to `file:///path` — parse correctly.
2. **FTP IPv6 PASV** (254): When `--disable-epsv` is used with IPv6, fall back to PASV correctly.
3. **Negotiate + NTLM proxy** (590): Support proxy auth with Negotiate falling back to NTLM for POST requests.
4. **PWD response parsing** (1217, 1152): Handle malformed PWD responses with extra text before the `"directory"` path. Also handle uneven/unmatched quotes.
5. **Root directory absolute paths** (1224, 1225, 1226): FTP URLs like `ftp://host//file` (double slash = absolute from root) and `--ftp-method singlecwd` need proper CWD handling.

## Exit Criteria

All 7 tests pass: `runtests.pl 203 254 590 1217 1224 1225 1226`
