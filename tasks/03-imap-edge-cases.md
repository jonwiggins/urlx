# Task 03: IMAP Protocol Edge Cases

## Status: Not Started

## Problem

Core IMAP operations work, but several edge cases fail: STORE/CLOSE/EXPUNGE custom commands, IMAP FETCH with special auth options, quoted passwords with special characters, UID parameters, and APPEND uploads with multipart MIME.

## Tests (7)

| Test | Description |
|------|-------------|
| 795 | HTTP 302 redirect from HTTP to IMAP with `--location` |
| 800 | IMAP FETCH with quoted password containing special characters |
| 815 | IMAP STORE to mark message deleted + CLOSE using `-X` custom request |
| 816 | IMAP STORE to mark message deleted + EXPUNGE using `-X` custom request |
| 847 | IMAP FETCH with UID parameter and quoted password with special chars |
| 897 | IMAP FETCH with MAILINDEX and SECTION parameters, storing headers to file |
| 1221 | HTTP POST with `--url-query` and `--data-urlencode` combining query and body |

## Work Needed

1. **Cross-protocol redirect** (795): Support redirecting from HTTP 302 to an `imap://` URL when `--location` is used.
2. **Quoted passwords** (800, 847): Handle IMAP credentials with special characters (quotes, backslashes) in the URL or `-u` flag.
3. **STORE + CLOSE/EXPUNGE** (815, 816): Support `-X "STORE ... +FLAGS \Deleted"` followed by CLOSE or EXPUNGE as a compound custom command.
4. **UID FETCH** (847): Support UID parameter in IMAP URL for fetching specific messages by UID.
5. **MAILINDEX + SECTION** (897): Support RFC 5092 URL components (`;MAILINDEX=` and `;SECTION=`) for fetching specific message parts.
6. **--url-query** (1221): Implement `--url-query` flag to append query parameters to URL separately from body data.

## Exit Criteria

All 7 tests pass: `runtests.pl 795 800 815 816 847 897 1221`
