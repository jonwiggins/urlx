# Task 09: FTP Protocol Miscellaneous Fixes

## Summary
Fix scattered FTP protocol issues: bad PASV/EPSV handling, time conditions for upload, active mode (PORT/EPRT), path methods (nocwd/singlecwd), FTP over HTTP proxy, quote commands, and error handling.

## Estimated Effort
4-5 days

## Tests to Pass (42)
- **FTP over HTTP proxy (10):** 79, 208, 299, 714, 715, 1059, 1077, 1092, 1098, 1106
- **FTP misc (13):** 237, 238, 247, 248, 280, 295, 713, 793, 1057, 1102, 1103, 1219, 1233
- **FTP connection reuse — see Task 03 (11):** 146, 149, 210, 211, 212, 215, 216, 698, 1010, 1096, 1149
- **FTP paths (2):** 244, 340
- **FTP quote (2):** 227, 754
- **FTP resume (4):** 112, 1036, 1038, 1039

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 79 112 208 227 237 238 244 247 248 254 280 295 299 340 713 714 715 754 793 1036 1038 1039 1050 1057 1059 1077 1092 1098 1102 1103 1106 1206 1207 1208 1219 1224 1225 1226 1227 1233
# Most tests should report OK (excluding FTP connection reuse which is Task 03)
```

## FTP over HTTP Proxy

### 1. Non-CONNECT FTP proxy (tests 79, 208, 299, 1077, 1092, 1098, 1106)
When an HTTP proxy is set and the URL is `ftp://`, curl sends the FTP URL as an HTTP GET to the proxy:
```
GET ftp://ftp.example.com/file HTTP/1.1
Host: ftp.example.com
```
The proxy handles the FTP transfer and returns the result as HTTP.

**Current issue:** urlx connects directly via FTP instead of proxying.
**Fix:** In `easy.rs` dispatch, when scheme is `ftp` and an HTTP proxy is set (not CONNECT), send as an HTTP request with the full FTP URL as the request target.

### 2. FTP over CONNECT tunnel (tests 714, 715)
With `--proxytunnel`, FTP should use CONNECT to establish a tunnel, then run FTP protocol inside it.
**Fix:** Establish CONNECT tunnel to FTP host:port, then run FTP protocol over the tunneled connection.

### 3. ftp_proxy environment variable (test 1106)
Check `ftp_proxy` / `FTP_PROXY` env vars for FTP URLs (similar to `http_proxy`).

## FTP Error Handling

### 4. Bad PASV/EPSV response (tests 237, 238)
When EPSV returns a malformed response, fall back to PASV. When PASV also fails, return appropriate error.
**File:** `crates/liburlx/src/protocol/ftp.rs`

### 5. --ftp-alternative-to-user (test 280)
When USER fails with specific error, send the `--ftp-alternative-to-user` command instead.
**File:** `crates/liburlx/src/protocol/ftp.rs`

### 6. ACCT without --ftp-account (test 295)
When server requires ACCT (332 response to PASS), fail with appropriate error if no account is configured.

### 7. PORT/EPRT error handling (tests 1206, 1207, 1208)
- 425 "Can't open data connection" after PORT
- 421 service timeout during data transfer
- No data connection established

## FTP Path Methods

### 8. --ftp-method nocwd (test 244)
Send full path in RETR command without CWD: `RETR /path/to/file`
**File:** `crates/liburlx/src/protocol/ftp.rs` — FtpMethod::NoCwd handling

### 9. --ftp-method singlecwd with %00 (test 340)
URL encoding edge cases in FTP paths with null bytes.

### 10. Absolute FTP paths (tests 1224, 1225, 1226, 1227)
`ftp://host//path` (double slash) means absolute path from root. `ftp://host/path` means relative to home.

## FTP Time Conditions

### 11. MDTM time condition for upload (tests 247, 248)
Before uploading, check remote file modification time with MDTM. If the condition isn't met, skip upload.

## FTP Quote Commands

### 12. Pre/post quote commands (tests 227, 754)
`-Q "command"` sends before transfer, `-Q "-command"` sends after transfer, `-Q "*command"` ignores failure.
**File:** `crates/liburlx/src/protocol/ftp.rs` — quote command handling

## FTP Resume

### 13. APPE vs STOR for resume (tests 112, 1036, 1038, 1039)
- `-C -` with upload: use APPE (append) instead of STOR
- Resume from EOF: handle correctly
- REST with specific offset

## Key Files
- `crates/liburlx/src/protocol/ftp.rs` — Main FTP implementation
- `crates/liburlx/src/easy.rs` — FTP proxy dispatch, FTP config
- `crates/urlx-cli/src/args.rs` — FTP flags (--ftp-method, --ftp-account, etc.)

## Notes
- FTP over HTTP proxy is architecturally significant — it routes FTP URLs through the HTTP request path
- FTP connection reuse is in Task 03 — don't duplicate that work here
- Active mode (PORT/EPRT) requires opening a listener socket — complex networking
- OS/400 tests (1102, 1103) require SYST command detection and specialized behavior
