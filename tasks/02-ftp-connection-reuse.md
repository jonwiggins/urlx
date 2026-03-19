# Task 02: FTP Connection Reuse Across Multiple URLs

## Summary

When fetching multiple FTP URLs from the same server, urlx sends `QUIT` and opens a new connection (`USER`/`PASS`/`PWD`/`CWD`) for each URL. curl reuses the existing FTP control connection, only sending `CWD /` to reset the working directory before navigating to the next file. This is a single architectural fix affecting 27 tests.

## Failing Tests (27)

| Test | Description |
|------|-------------|
| 146 | persistent FTP with different paths |
| 149 | FTP with multiple uploads |
| 210 | Get two FTP files from the same remote dir: no second CWD |
| 211 | Get two FTP files with no remote EPSV support |
| 212 | Get two FTP files with no remote EPRT support |
| 215 | Get two FTP dir listings from the same remote dir: no second CWD |
| 216 | FTP upload two files to the same dir |
| 247 | FTP upload time condition evaluates TRUE => skip upload |
| 248 | FTP upload time condition evaluates FALSE => upload anyway |
| 254 | FTP IPv6 dir list PASV and --disable-epsv |
| 280 | FTP --ftp-alternative-to-user on USER failure |
| 295 | FTP ACCT request without --ftp-account |
| 340 | FTP using %00 in path with singlecwd |
| 407 | Get two FTPS files from the same remote dir: no second CWD |
| 698 | FTP with ACCT and connection reuse |
| 754 | FTP list with quote ops |
| 975 | HTTP with auth redirected to FTP allowing auth to continue |
| 1010 | FTP dir list nocwd |
| 1096 | Two FTP downloads, with failed RETR but reused control connection |
| 1102 | FTP OS/400 server name format check |
| 1103 | FTP non-OS/400 server |
| 1149 | FTP dir list multicwd then again nocwd |
| 1217 | FTP with rubbish before name in 257-response |
| 1219 | FTP with no user+password required (230 response) |
| 1224 | FTP fetch a file from the root directory |
| 1225 | FTP fetch two files using absolute paths |
| 1226 | FTP fetch a file from the root directory with singlecwd |

## Failure Pattern

All tests show the same pattern — extra `USER`/`PASS`/`PWD`/`CWD` commands where only `CWD` was expected:

```diff
 RETR 210[CR][LF]
+USER anonymous[CR][LF]
+PASS ftp@example.com[CR][LF]
+PWD[CR][LF]
+CWD a[CR][LF]
+CWD path[CR][LF]
 EPSV[CR][LF]
+TYPE I[CR][LF]
 SIZE 210[CR][LF]
 RETR 210[CR][LF]
 QUIT[CR][LF]
```

Expected (curl behavior): after the first file transfer, send `CWD /` to reset to root, then navigate to the next file's directory.

## What Needs to Change

### Key File: `crates/liburlx/src/protocol/ftp.rs`

1. **Connection pooling**: After completing an FTP transfer, do NOT send `QUIT` and drop the connection. Instead, keep the control connection alive in the connection pool keyed by `(host, port, user, pass)`.

2. **Connection reuse detection**: When starting a new FTP transfer, check the pool for an existing control connection to the same server with the same credentials.

3. **Directory reset on reuse**: When reusing a connection, send `CWD /` to reset to root directory, then navigate with `CWD` commands as needed. Do NOT re-authenticate (`USER`/`PASS`/`PWD`).

4. **TYPE command skip**: If the TYPE (I or A) is the same as the previous transfer on this connection, don't re-send it.

### Also check: `crates/liburlx/src/pool.rs`

The connection pool may need to support FTP control connections in addition to HTTP/TCP connections. Each pooled FTP connection should track its current state (authenticated, current directory, TYPE setting).

### Edge cases to handle:
- Failed RETR on first URL should still allow reuse for second URL (test 1096)
- FTPS connections must also be reusable (test 407)
- Different FTP methods (multicwd vs nocwd vs singlecwd) on reuse (test 1149)
- Server returning 230 without needing USER/PASS (test 1219)
- OS/400 format PWD responses like `257 "/QSYS.LIB"` (test 1102)

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  146 149 210 211 212 215 216 247 248 254 280 295 340 407 698 754 975 \
  1010 1096 1102 1103 1149 1217 1219 1224 1225 1226
```

All 27 tests must report OK. Run tests 100-130 to verify no FTP regressions.
