# Task 10: Long Tail — Miscellaneous Protocol and CLI Fixes

## Summary
Catch-all task for the remaining ~100 scattered fixes that don't fit into the other architectural categories. Each is a small, independent fix.

## Estimated Effort
5-8 days (many small independent fixes)

## Tests to Pass (~100)
Grouped by sub-category:

### Permanently Skippable (19 tests — 0 effort)
**Tests:** 745, 971, 1013, 1014, 1022, 1023, 1026, 1027, 1119, 1135, 1139, 1140, 1165, 1167, 1173, 1177, 1185, 1222, 1400
These test curl source code consistency, man pages, symbols, curl-config, --manual, --libcurl codegen. Impossible for urlx.

### SFTP/SCP (17 tests)
**Tests:** 609, 613, 614, 618, 619, 620, 621, 623, 625, 630, 631, 632, 635, 637, 638, 639, 656
- SFTP quote commands: mkdir, chmod, rename, `*`-prefixed accept-fail
- Multi-URL SSH connection reuse
- SFTP byte ranges (negative ranges)
- --ftp-create-dirs for SFTP
- Host key validation edge cases
- SCP upload failure error code
**File:** `crates/liburlx/src/protocol/ssh.rs`

### MQTT (7 tests)
**Tests:** 1132, 1193, 1194, 1195, 1196, 1198, 1199
- CONNACK error handling (bad remaining length)
- Large payload publish (2k)
- SUBSCRIBE with out-of-order PUBLISH/SUBACK
- Empty payload
**File:** `crates/liburlx/src/protocol/mqtt.rs`

### HTTP Formpost (7 tests)
**Tests:** 277, 1133, 1158, 1186, 1189, 1293, 1315
- Content-Disposition "attachment" vs "form-data"
- Filename escaping (comma, semicolon, quotes)
- --form-escape backslash mode
- Multi-file single -F field
**File:** `crates/liburlx/src/protocol/http/multipart.rs`

### HTTP PUT Edge Cases (7 tests)
**Tests:** 357, 1055, 1064, 1069, 1073, 1075, 1131
- Expect 100-continue with 417 rejection
- PUT redirect to FTP
- Chunked PUT + redirect
- HTTP/1.0 PUT from stdin
**File:** `crates/liburlx/src/protocol/http/h1.rs`, `crates/liburlx/src/easy.rs`

### HTTP POST Edge Cases (6 tests)
**Tests:** 158, 386, 463, 1015, 1070, 1221
- Formpost with only 100-continue
- --json + --next isolation
- -d @file with binary data
- --data-urlencode
**File:** `crates/urlx-cli/src/args.rs`, `crates/liburlx/src/protocol/http/h1.rs`

### HTTP Chunked/TE (6 tests)
**Tests:** 319, 373, 457, 1125, 1171, 1277
- --raw with chunked passthrough edge cases
- Binary zeros in chunked data
- --max-filesize with chunked
- --tr-encoding
**File:** `crates/liburlx/src/protocol/http/h1.rs`

### IMAP Protocol Gaps (9 tests)
**Tests:** 647, 795, 804, 815, 816, 841, 846, 896, 897
- APPEND with multipart MIME
- SELECT reuse
- STORE/EXPUNGE custom commands
- PREAUTH handling
**File:** `crates/liburlx/src/protocol/imap.rs`

### Globbing (7 tests)
**Tests:** 75, 471, 760, 761, 1240, 1290, 1328
- Bad range error handling
- Too many glob patterns
- Literal brackets in URL
**File:** `crates/liburlx/src/glob.rs`

### SMTP MIME (4 tests)
**Tests:** 646, 648, 649, 1187
- Multipart MIME upload for SMTP
**File:** `crates/liburlx/src/protocol/smtp.rs`

### Misc CLI (17 tests)
**Tests:** 338, 339, 369, 379, 415, 422, 469, 470, 762, 899, 1020, 1074, 1117, 1148, 1204, 1231, 1268
Various: --etag edge cases, --remove-on-error+--no-clobber, Unicode warnings, progress bar, dotdot paths, filename warnings, etc.

### Other Small Categories (~15 tests)
- HTTP compression (223, 230, 418)
- TLS/HTTPS (306, 313, 560)
- POP3 protocol (852, 855, 891)
- Content-Disposition -J (1311, 1370, 1371)
- --resolve (1317, 1318, 1322)
- Protocol over proxy tunnel (1319, 1320, 1321)
- Netrc (478), SOCKS (719), SMTP misc (941), NO_PROXY (1265)

## Approach
1. Start with the permanently skippable tests (document as skipped, +19 to pass count)
2. Then tackle sub-categories in order of test count
3. Each sub-category is independent — can be worked in any order
4. Run individual tests to understand exact failures before fixing

## Key Files
All source files are potentially affected. Focus on:
- `crates/liburlx/src/protocol/` — Protocol-specific fixes
- `crates/urlx-cli/src/` — CLI flag handling
- `crates/liburlx/src/easy.rs` — Transfer orchestration
