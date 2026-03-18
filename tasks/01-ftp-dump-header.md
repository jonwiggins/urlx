# Task 01: FTP Dump-Header Support

## Summary
Implement `-D` (dump-header) support for FTP transfers. Currently, urlx only outputs HTTP headers to the dump-header file. curl outputs FTP server response lines (220 banner, 331, 230, 257 status codes, etc.) as if they were HTTP headers.

## Estimated Effort
4-8 hours

## Tests to Pass (24)
146, 149 (also need FTP reuse — partial), 1349, 1350, 1351, 1352, 1353, 1354, 1357, 1358, 1359, 1360, 1361, 1362, 1379, 1380, 1381, 1382, 1383, 1384, 1387, 1388, 1389, 1390, 1391, 1392

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 1349 1350 1351 1352 1353 1354 1357 1358 1359 1360 1361 1362 1379 1380 1381 1382 1383 1384 1387 1388 1389 1390 1391 1392
# All 24 tests should report OK
```

## What Needs to Change

### 1. Collect FTP server responses as "headers"
**File:** `crates/liburlx/src/protocol/ftp.rs`

The FTP `perform()` function exchanges commands with the server (USER, PASS, PWD, CWD, EPSV, TYPE, SIZE, RETR, etc.) and gets responses like `220 FTP server ready`. These response lines need to be collected into the `Response` object's raw header bytes.

**Approach:**
- Add a `Vec<u8>` accumulator for FTP response lines throughout the protocol flow
- After each `read_response()` call, append the raw response text (e.g., `"220 FTP server ready\r\n"`) to this accumulator
- When creating the final `Response` object, set these accumulated bytes as `raw_headers`

### 2. Format FTP responses for dump-header
**File:** `crates/urlx-cli/src/transfer.rs`

The CLI's dump-header path (`-D`) currently calls `format_headers()` which expects HTTP status lines. For FTP responses, the raw bytes should be written directly (they're already line-formatted).

**Approach:**
- When writing dump-header for FTP, use the raw header bytes directly
- The format should be one FTP response line per header line, e.g.:
  ```
  220 FTP server ready\r\n
  331 User name okay, need password\r\n
  230 User logged in\r\n
  257 "/" is current directory\r\n
  ...
  ```

### 3. Handle multi-line FTP responses
FTP responses can be multi-line (e.g., `220-Welcome\r\n220 server ready\r\n`). These should be captured as-is.

## Key Files
- `crates/liburlx/src/protocol/ftp.rs` — Collect responses during protocol flow
- `crates/liburlx/src/protocol/http/response.rs` — May need to ensure raw_headers works for non-HTTP
- `crates/urlx-cli/src/transfer.rs` — Write FTP headers to dump-header file
- `crates/urlx-cli/src/output.rs` — May need FTP-specific formatting

## Verification
Run a sample test to check output format:
```bash
perl runtests.pl -a -m=30 -c /path/to/urlx -vc /usr/bin/curl 1349 2>&1 | tail -20
```
The test expects FTP response lines in the dump-header file matching the server's actual responses.

## Notes
- Do NOT change the FTP protocol flow itself — only collect the response text
- The response accumulator should capture both the initial greeting (220) and all subsequent command responses
- For FTPS tests (1379-1392), the same mechanism applies after the TLS handshake
