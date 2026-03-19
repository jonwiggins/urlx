# Task 07: SMTP MIME, IMAP APPEND, and Email over HTTP Proxy

## Status: Not Started

## Problem

SMTP multipart MIME uploads fail, IMAP APPEND with multipart doesn't work, and email protocols (SMTP, IMAP, POP3) cannot be tunneled through HTTP CONNECT proxies. SMTP/NTLM auth cancellation hangs instead of timing out.

## Tests (9)

| Test | Description |
|------|-------------|
| 609 | SFTP post-quote mkdir failure — expects error code 21 |
| 646 | IMAP APPEND multipart message using `-F` flags (MIME API) |
| 647 | SMTP multipart message with transfer content encoders (quoted-printable, base64) |
| 648 | SMTP multipart with 7-bit encoder applied to binary file (should fail) |
| 649 | HTTP multipart form-data with custom Content-Type header parameter |
| 669 | SMTP edge case (additional SMTP protocol test) |
| 1319 | POP3 RETR tunneled through HTTP CONNECT proxy |
| 1320 | SMTP send tunneled through HTTP CONNECT proxy |
| 1321 | IMAP FETCH tunneled through HTTP CONNECT proxy |

## Work Needed

1. **IMAP APPEND with MIME** (646): Support `-F` form fields for IMAP APPEND, constructing a multipart MIME message for upload.
2. **SMTP MIME encoders** (647, 648): Support `--form-string` with transfer encoding (`quoted-printable`, `base64`, `7bit`). 7-bit encoding applied to binary should fail.
3. **Multipart Content-Type** (649): Custom Content-Type header parameters on multipart form-data (e.g., charset).
4. **Email over HTTP CONNECT** (1319, 1320, 1321): Tunnel POP3, SMTP, and IMAP connections through an HTTP CONNECT proxy. Requires establishing the CONNECT tunnel first, then running the email protocol inside it.
5. **SFTP quote failure** (609): SFTP post-quote `mkdir` that fails should return exit code 21.
6. **SMTP edge case** (669): Additional SMTP protocol conformance fix.

## Exit Criteria

All 9 tests pass: `runtests.pl 609 646 647 648 649 669 1319 1320 1321`
