# Task 07: Email Protocol Fixes (IMAP, POP3, SMTP)

## Summary

Fix IMAP, POP3, and SMTP protocol issues: IMAP APPEND/STORE/SEARCH commands, custom requests, PREAUTH handling, POP3 invalid message handling, SMTP MIME multipart structure, and auth edge cases.

## Failing Tests (16)

| Test | Description | Root Cause |
|------|-------------|------------|
| 646 | SMTP multipart using mime API | Wrong MIME structure (Content-Disposition: form-data instead of attachment) |
| 647 | IMAP APPEND multipart using mime API | Wrong MIME upload format |
| 648 | SMTP multipart with transfer content encoders | Wrong MIME encoding |
| 649 | SMTP multipart with 7-bit encoder error | Wrong error handling |
| 795 | HTTP with credentials redirects to IMAP | Cross-protocol redirect to IMAP |
| 804 | IMAP does not perform SELECT if reusing the same mailbox | SELECT sent when not needed |
| 815 | IMAP STORE - delete message (CUSTOMREQUEST) | Custom IMAP command not working |
| 816 | IMAP STORE - delete message with confirmation (CUSTOMREQUEST) | Custom IMAP command |
| 841 | IMAP custom request does not check continuation data | Custom request + continuation |
| 846 | IMAP PREAUTH response | Not handling PREAUTH (skip LOGIN) |
| 852 | POP3 LIST invalid message | Wrong exit code for invalid message ID |
| 855 | POP3 RETR invalid message | Wrong protocol for invalid message |
| 896 | IMAP with --login-options 'AUTH=dummy' (failing) | Wrong exit code on auth failure |
| 897 | IMAP and envelope meta data after body transfer | Meta data output wrong |
| 899 | URL with credentials redirects to URL with different credentials | Credential handling on redirect |
| 941 | SMTP with --crlf | Line ending conversion wrong |

## Key Changes

### 1. SMTP MIME structure (`crates/liburlx/src/protocol/smtp.rs`)
When building MIME multipart for SMTP, use `Content-Disposition: attachment` not `Content-Disposition: form-data`. HTTP formpost uses `form-data`; email attachments use `attachment` or `inline`.

### 2. IMAP custom requests (`crates/liburlx/src/protocol/imap.rs`)
Support `-X` custom commands for IMAP (STORE, SEARCH, EXAMINE, etc.). The custom command replaces the default FETCH command in the IMAP sequence.

### 3. IMAP PREAUTH (`crates/liburlx/src/protocol/imap.rs`)
If the server greeting is `* PREAUTH`, skip the LOGIN/AUTHENTICATE step entirely. The session is already authenticated.

### 4. IMAP mailbox SELECT reuse
When the previously-selected mailbox is the same as the requested one, skip the SELECT command.

### 5. POP3 error handling
- `LIST` with invalid message ID should return exit code 56 (CURLE_RECV_ERROR)
- `RETR` with invalid message should return proper error

### 6. SMTP --crlf
When `--crlf` is specified, convert bare LF to CRLF in the upload data before sending.

### 7. Cross-protocol redirect to IMAP (test 795)
When HTTP redirects to `imap://`, follow the redirect and start an IMAP transfer.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  646 647 648 649 795 804 815 816 841 846 852 855 896 897 899 941
```

All 16 tests must report OK. No regressions on email tests 800-900 that currently pass.
