# Task 10: Content and Transfer Encoding Fixes

## Summary

Fix content encoding (deflate, gzip, multiply-compressed), raw mode passthrough, chunked transfer with --max-filesize, TE header ordering, and JSON Unicode encoding.

## Failing Tests (9)

| Test | Description | Root Cause |
|------|-------------|------------|
| 223 | HTTP GET deflate compressed content with broken deflate header | Broken deflate stream not handled (raw deflate without zlib header) |
| 230 | HTTP GET multiply compressed content | Double-compressed content (gzip inside gzip) not decompressed |
| 268 | JSON encoding of Unicode string | Unicode in --json not properly encoded |
| 319 | HTTP GET gobbledigook transfer-encoded data in raw mode | --raw should pass through transfer-encoding without decoding |
| 418 | Response with multiple Transfer-Encoding headers | Wrong stderr warning message |
| 457 | chunked Transfer-Encoding with --max-filesize | --max-filesize not enforced during chunked transfer |
| 1125 | HTTP GET transfer-encoding with custom Connection: | TE header placed after Connection instead of before |
| 1171 | HTTP GET transfer-encoding with blanked Connection: | Same TE/Connection ordering issue |
| 1277 | HTTP GET with both content and transfer encoding | Accept-Encoding after Connection instead of before |

## Key Changes

### 1. Raw deflate handling (`crates/liburlx/src/filter.rs` or decompression module)
Test 223: curl handles "broken" deflate streams by trying raw deflate (no zlib header) when standard zlib decompression fails. Implement fallback to raw deflate.

### 2. Multiply compressed content
Test 230: When `Content-Encoding: gzip, gzip`, decompress twice. Support stacked content encodings.

### 3. --raw mode
Test 319: When `--raw` is specified, do NOT decode transfer-encoding or content-encoding. Pass through raw bytes.

### 4. --max-filesize with chunked transfer
Test 457: Enforce `--max-filesize` during chunked transfer by tracking bytes received. If exceeded, abort with exit code 63.

### 5. Header ordering (TE, Accept-Encoding, Connection)
Tests 1125, 1171, 1277: The expected header order is:
```
TE: gzip
Accept-Encoding: <value>
Connection: TE
```
Not:
```
TE: gzip
Connection: TE
Accept-Encoding: <value>
```

### 6. JSON Unicode (test 268)
When `--json` sends data containing Unicode characters, ensure proper UTF-8 encoding.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  223 230 268 319 418 457 1125 1171 1277
```

All 9 tests must report OK.
