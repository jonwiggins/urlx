# Task 05: SFTP/SCP Protocol Fixes

## Summary

Fix SFTP and SCP edge cases: quote commands (-Q for mkdir, chmod, rename), multi-file transfer with connection reuse, directory listing format, byte ranges, host key verification exit codes, and error code mapping.

## Failing Tests (17)

| Test | Description | Root Cause |
|------|-------------|------------|
| 609 | SFTP post-quote mkdir failure | -Q "mkdir" not implemented |
| 613 | SFTP directory retrieval | Wrong listing format |
| 614 | SFTP pre-quote chmod | -Q "chmod" not implemented |
| 618 | SFTP retrieval of two files | Connection not reused for second file |
| 619 | SCP retrieval of two files | Connection not reused for second file |
| 620 | SFTP retrieval of missing file followed by good file | Error on first, continue to second |
| 621 | SCP retrieval of missing file followed by good file | Error on first, continue to second |
| 623 | SCP upload failure | Wrong exit code on upload error |
| 625 | SFTP put with --ftp-create-dirs twice | --ftp-create-dirs not creating dirs for SFTP |
| 630 | SFTP incorrect host key | Wrong exit code (should be 51) |
| 631 | SCP incorrect host key | Wrong exit code (should be 51) |
| 632 | SFTP syntactically invalid host key | Wrong exit code |
| 635 | SFTP retrieval with byte range relative to end of file | Range not applied |
| 637 | SFTP retrieval with invalid X- range | Wrong exit code |
| 638 | SFTP post-quote rename * asterisk accept-fail | -Q "rename" not implemented |
| 639 | SFTP post-quote rename * asterisk accept-fail | -Q rename with accept-fail |
| 656 | SFTP retrieval with nonexistent private key file | Wrong exit code |

## Key Changes

### 1. Quote commands (`crates/liburlx/src/protocol/sftp.rs`)
Implement `--quote`/`-Q` support for SFTP with these commands:
- `mkdir <path>` — create directory
- `chmod <mode> <path>` — change permissions
- `rename <old> <new>` — rename file
- Support pre-quote (before transfer) and post-quote (after transfer)
- Support `*` prefix for "accept failure" (don't abort on error)

### 2. Multi-file connection reuse
When transferring multiple files via SFTP/SCP, reuse the SSH connection for subsequent transfers instead of opening a new connection each time.

### 3. Host key verification exit codes
Map SSH host key verification failures to curl exit code 51 (`CURLE_PEER_FAILED_VERIFICATION`).

### 4. Byte range support for SFTP
Support `-r start-end` byte ranges including relative-to-end ranges (`-r -500`).

### 5. Error code mapping
- Upload failure → exit code 25 (`CURLE_UPLOAD_FAILED`)
- Missing private key → exit code 58 (`CURLE_SSL_CERTPROBLEM`)
- Invalid range → exit code 36 (`CURLE_BAD_DOWNLOAD_RESUME`)

### 6. --ftp-create-dirs for SFTP
When `--ftp-create-dirs` is specified, create intermediate directories before SFTP upload.

### 7. Directory listing format
SFTP directory listings should match curl's format.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  609 613 614 618 619 620 621 623 625 630 631 632 635 637 638 639 656
```

All 17 tests must report OK. No regressions on SSH tests 600-608.
