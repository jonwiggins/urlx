# Task 08: CLI Write-out Variables, Config Files, and Variable Expansion

## Summary
Fix remaining `--write-out` variables, `-K` config file handling, and `--variable`/`--expand-*` expansion edge cases.

## Estimated Effort
2-3 days

## Tests to Pass (27)
- **Write-out (9):** 417, 421, 423, 424, 435, 978, 1188, 1340, 1341
- **Config files (6):** 430, 431, 432, 433, 436, 459
- **Variables/expand (12):** 428, 429, 448, 450, 451, 452, 453, 454, 455, 456, 458, 462

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 417 421 423 424 428 429 430 431 432 433 435 436 448 450 451 452 453 454 455 456 458 459 462 978 1188 1340 1341
# All 27 tests should report OK
```

## Write-out Variable Fixes

### 1. %{certs} — TLS certificate chain (test 417)
Output the server's TLS certificate chain in PEM format. Requires extracting certificate info from the TLS connection.
**File:** `crates/urlx-cli/src/output.rs`, `crates/liburlx/src/tls.rs`

### 2. %{header_json} — All headers as JSON (test 421)
Format all response headers as a JSON object. Duplicate header names become JSON arrays.
```json
{"content-type":["text/html"],"set-cookie":["a=1","b=2"]}
```
**File:** `crates/urlx-cli/src/output.rs`

### 3. %{url.*} and %{urle.*} — URL components (tests 423, 424)
These are already partially implemented. Verify they match curl's output exactly:
- `%{url.scheme}`, `%{url.host}`, `%{url.port}`, `%{url.path}`, `%{url.query}`, `%{url.user}`, `%{url.password}`, `%{url.fragment}`
- `%{urle.*}` — URL-encoded versions
**File:** `crates/urlx-cli/src/output.rs`

### 4. %{local_ip}, %{local_port}, %{remote_ip}, %{remote_port} (test 435)
Currently hardcoded or resolved at output time. Need actual connection info from the TCP stream.
**File:** `crates/liburlx/src/protocol/http/response.rs` (TransferInfo), `crates/liburlx/src/easy.rs`

### 5. --stderr routing for -w output (test 978)
When `--stderr <file>` is set, `-w` output should go to that file (not stdout).
**File:** `crates/urlx-cli/src/transfer.rs`

### 6. %{onerror}, %{urlnum}, %{exitcode}, %{errormsg} (test 1188)
- `%{onerror}` — only output the rest of the format string if an error occurred
- `%{urlnum}` — 0-based index of the current URL in multi-URL mode
- `%{exitcode}` and `%{errormsg}` should use actual values (currently hardcoded)
**File:** `crates/urlx-cli/src/output.rs`

### 7. %{filename_effective} with -J (tests 1340, 1341)
When `-J` (Content-Disposition filename) is used, `%{filename_effective}` should return the actual filename used.
**File:** `crates/urlx-cli/src/output.rs`, `crates/urlx-cli/src/transfer.rs`

## Config File (-K) Fixes

### 8. --next in config files (tests 430, 431, 432)
Config files should support `--next` to separate URL groups, with proper option isolation.
**File:** `crates/urlx-cli/src/args.rs`

### 9. XDG_CONFIG_HOME / CURL_HOME discovery (tests 433, 436)
Look for `.curlrc` in `$CURL_HOME`, `$XDG_CONFIG_HOME/.config`, and `$HOME`.
**File:** `crates/urlx-cli/src/args.rs`

### 10. Whitespace in config arguments (test 459)
Config file parsing should handle values with spaces (quoted and unquoted).
**File:** `crates/urlx-cli/src/args.rs`

## Variable/Expand Fixes

### 11. Environment variable expansion in -K (tests 428, 429, 448, 462)
Config files support `{{env:VAR}}` for environment variable expansion.
**File:** `crates/urlx-cli/src/args.rs`

### 12. --variable with file loading + functions (test 450)
`--variable name@file` loads from file, `--variable name%stdin` loads from stdin.
Functions: `{{name:trim}}`, `{{name:url}}`, `{{name:b64}}`, `{{name:json}}`.
**File:** `crates/urlx-cli/src/args.rs`

### 13. Error handling for invalid functions (tests 452, 454)
`{{name:invalid_function}}` should return exit code 2 with an error message.
**File:** `crates/urlx-cli/src/args.rs`

### 14. Null bytes in variable values (tests 451, 453, 456)
Variables can contain null bytes. `{{name:json}}` should encode them as `\u0000`.
**File:** `crates/urlx-cli/src/args.rs`

### 15. base64 decode function (test 455)
`{{name:b64d}}` — base64 decode the variable value.
**File:** `crates/urlx-cli/src/args.rs`

### 16. --expand-output (test 458)
`--expand-output {{var}}` expands variables in the output filename.
**File:** `crates/urlx-cli/src/args.rs`

## Key Files
- `crates/urlx-cli/src/output.rs` — format_write_out() function
- `crates/urlx-cli/src/args.rs` — Config file parsing, variable expansion
- `crates/urlx-cli/src/transfer.rs` — --stderr routing, filename tracking
- `crates/liburlx/src/protocol/http/response.rs` — TransferInfo struct
- `crates/liburlx/src/tls.rs` — Certificate extraction for %{certs}

## Notes
- %{header_json} must handle duplicate header names by creating JSON arrays
- Config file parsing is complex — test each scenario individually
- Variable expansion happens BEFORE argument parsing (affects URLs, data, headers)
- Null byte handling requires careful use of `&[u8]` instead of `&str` in some paths
