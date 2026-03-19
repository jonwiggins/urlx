# Task 12: Source Analysis Tests — Permanent Skips

## Status: Complete

## Problem

16 tests verify curl's own source code structure, build system, man pages, and symbol consistency. These are not applicable to urlx since we have a completely different codebase.

## Tests (16)

| Test | Description | Skip Reason |
|------|-------------|-------------|
| 745 | Verify typecheck-gcc and curl.h are in sync | curl source analysis |
| 1013 | Compare `curl --version` with `curl-config --protocols` | curl-config not applicable |
| 1014 | Compare `curl --version` with `curl-config --features` | curl-config not applicable |
| 1022 | Compare `curl --version` with `curl-config --version` | curl-config not applicable |
| 1023 | Compare `curl --version` with `curl-config --vernum` | curl-config not applicable |
| 1026 | `curl --manual` flag output | urlx doesn't embed manual |
| 1027 | `curl --help` flag output matching | Different help text format |
| 1119 | Verify symbols-in-versions and headers in sync | curl source analysis |
| 1135 | Verify CURL_EXTERN function order | curl source analysis |
| 1139 | Verify all libcurl options have man pages | curl source analysis |
| 1165 | Verify CURL_DISABLE values in configure.ac | curl source analysis |
| 1167 | Verify curl prefix of public symbols | curl source analysis |
| 1173 | Man page syntax checks | curl documentation |
| 1177 | Verify CURL_VERSION_* constants sync | curl source analysis |
| 1185 | checksrc source code style validation | curl source analysis |
| 1222 | Verify deprecation statuses across codebase | curl source analysis |

## Work Needed

Add these test numbers to a skip list in `scripts/run-curl-tests.sh` or document them as permanently excluded. No code changes needed — these tests verify curl's source code, not CLI behavior.

## Exit Criteria

All 16 tests documented as permanently skipped with rationale. Running the test suite should exclude them automatically.
