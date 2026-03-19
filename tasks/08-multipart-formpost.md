# Task 08: Multipart Formpost Fixes

## Summary

Fix HTTP multipart form upload (`-F`) issues: filename escaping (double-quotes, commas, semicolons, backslashes), multi-file upload format, custom Content-Type boundary handling, and Expect: 100-continue with multipart.

## Failing Tests (9)

| Test | Description | Root Cause |
|------|-------------|------------|
| 158 | HTTP multipart formpost with only a 100 reply | Body sent without waiting for 100-continue response |
| 277 | HTTP RFC1867-type formposting with custom Content-Type | Boundary merging with user Content-Type |
| 1133 | HTTP formposting with filename/data contains ',', ';', '"' | Special chars in filename not escaped |
| 1158 | HTTP formposting with filename containing '"' | Double-quote in filename |
| 1186 | Multipart formposting with backslash-escaping filename containing '"' | Backslash-escaped quotes in filename |
| 1187 | SMTP multipart with filename escaping | Filename escaping in SMTP context |
| 1189 | Multipart formposting with backslash-escaping of name= and filename= | Both name and filename escaping |
| 1293 | Multipart formpost to two URLs, the first failing | Error handling on first URL, continue to second |
| 1315 | HTTP formposting -F with three files, one with explicit type | Multi-file upload Content-Type |

## Key Changes

### 1. Filename escaping in Content-Disposition (`crates/liburlx/src/protocol/http.rs` or multipart module)

curl uses backslash-escaping for special characters in `Content-Disposition` filename:
- `"` → `\"`
- `\` → `\\`
- Commas and semicolons are kept as-is in the quoted filename

Example: `Content-Disposition: form-data; name="file"; filename="file\"with\"quotes"`

### 2. Custom Content-Type boundary merging (test 277)
When user specifies `-H "Content-Type: multipart/form-data"` without a boundary, curl generates the boundary and appends it. When user specifies a full `Content-Type` with boundary, use that boundary.

### 3. Expect: 100-continue for multipart (test 158)
When sending multipart POST with `Expect: 100-continue`, wait for the 100 response before sending the body. If the server responds with a final status (like 200) instead of 100, proceed accordingly.

### 4. Multi-file upload format (test 1315)
When `-F "field=@file1,file2;type=text/plain"` specifies multiple files with an explicit type, format the multipart part correctly.

### 5. Error continuation (test 1293)
When uploading to two URLs and the first fails, continue to the second URL.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  158 277 1133 1158 1186 1187 1189 1293 1315
```

All 9 tests must report OK. No regressions on formpost tests 9, 38, 39.
