# Task 04: FTP Protocol Miscellaneous Fixes

## Summary

Fix scattered FTP protocol issues: upload resume (APPE vs STOR), EPSV-to-PASV fallback, EPRT error handling, byte ranges, --ftp-method (nocwd/singlecwd), quote commands, time conditions for upload, and bad PASV responses.

## Failing Tests (20)

| Test | Description | Root Cause |
|------|-------------|------------|
| 112 | FTP PASV upload resume | Uses STOR instead of APPE for resume |
| 161 | FTP RETR PASV | Protocol sequence wrong |
| 227 | FTP with quote ops | -Q quote commands not working |
| 237 | FTP getting bad host in 227-response to PASV | Not falling back on bad PASV |
| 238 | FTP getting bad port in response to EPSV | Wrong exit code (7 vs 28) |
| 973 | HTTP with auth redirected to FTP w/o auth | Cross-protocol redirect to FTP |
| 1028 | HTTP Location: redirect to FTP URL | Cross-protocol HTTP→FTP redirect |
| 1036 | FTP download resume from end of file | Wrong output when resuming at EOF |
| 1038 | FTP PASV upload resume from end of file | Wrong upload behavior at EOF |
| 1039 | FTP PASV upload resume from end of empty file | Resume from empty file |
| 1050 | FTP-IPv6 dir list, EPRT with specified IP | EPRT IPv6 formatting |
| 1055 | HTTP PUT Location: redirect to FTP URL | PUT redirect to FTP |
| 1057 | FTP retrieve a byte-range relative to end of file | Wrong REST offset |
| 1108 | FTP RETR PASV with PRET not supported | PRET fallback |
| 1120 | FTP with 421 timeout response | Not handling 421 properly |
| 1206 | FTP PORT and 425 on download | Quits after EPRT failure |
| 1207 | FTP PORT and 421 on download | Quits after 421 error |
| 1208 | FTP PORT download, no data conn and no transient negative reply | EPRT error handling |
| 1227 | FTP fetch a file from the root directory with nocwd | Sends relative path |
| 1233 | FTP failing to connect to EPSV port, switching to PASV | No EPSV→PASV fallback |

## Key Changes

### 1. Upload resume: APPE command (`crates/liburlx/src/protocol/ftp.rs`)
When resuming an upload (`-C offset`), use `APPE` (append) instead of `STOR` (store). Only use `REST` + `STOR` for download resume.

### 2. EPSV-to-PASV fallback
When EPSV fails (connection refused, timeout, bad port), fall back to PASV instead of quitting. Track per-connection whether EPSV is supported.

### 3. EPRT/PORT error handling
When EPRT fails, fall back to PORT instead of disconnecting. When PORT/EPRT gets a 425 or 421 response, handle gracefully.

### 4. Nocwd mode (`--ftp-method nocwd`)
In nocwd mode, send the full absolute path directly (e.g., `RETR /path/to/file`) without any CWD commands. Currently sends relative path.

### 5. Quote commands (-Q)
Implement `--quote` (pre-transfer), `--quote -` (post-transfer) for sending raw FTP commands.

### 6. Cross-protocol redirect (HTTP → FTP)
When HTTP redirects to an `ftp://` URL, follow the redirect and start an FTP transfer. Tests 973, 1028, 1055.

### 7. Bad PASV/EPSV responses
Parse PASV 227 responses robustly. If the host in the response doesn't match, use the control connection's IP instead.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  112 161 227 237 238 973 1028 1036 1038 1039 1050 1055 1057 \
  1108 1120 1206 1207 1208 1227 1233
```

All 20 tests must report OK. No regressions on FTP tests 100-130.
