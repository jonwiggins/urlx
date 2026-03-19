# Task 15: Build/Meta Tests — Permanently Skip

## Summary

These 19 tests verify curl's source code, man pages, symbol tables, and build infrastructure. They are NOT behavioral tests — they check properties of curl's repository that don't apply to urlx. They should be permanently skipped by adding them to the test suite's DISABLED list or by documenting them as expected skips.

## Tests to Skip (19)

| Test | Description | Why Skip |
|------|-------------|----------|
| 745 | Verify typecheck-gcc and curl.h are in sync | Checks curl's C header, not urlx |
| 971 | Verify options-in-versions and docs/cmdline-opts are in sync | Checks curl documentation files |
| 1013 | Compare curl --version with curl-config --protocols | curl-config doesn't exist for urlx |
| 1014 | Compare curl --version with curl-config --features | curl-config doesn't exist for urlx |
| 1022 | Compare curl --version with curl-config --version | curl-config doesn't exist for urlx |
| 1023 | Compare curl --version with curl-config --vernum | curl-config doesn't exist for urlx |
| 1026 | curl --manual | urlx doesn't embed a manual page |
| 1027 | curl --help | Help output format differs (acceptable) |
| 1119 | Verify symbols-in-versions and headers are in sync | Checks curl's symbol versioning files |
| 1135 | Verify CURL_EXTERN order | Checks curl's C header ordering |
| 1139 | Verify all libcurl options have man pages | Checks curl's man page completeness |
| 1140 | Verify nroff of man pages | Checks curl's man page formatting |
| 1165 | Verify configure.ac and source code CURL_DISABLE_-sync | Checks curl's build config |
| 1167 | Verify curl prefix of public symbols in header files | Checks curl's C symbol naming |
| 1173 | Man page syntax checks | Checks curl's man page syntax |
| 1177 | Verify feature names and CURL_VERSION_* sync | Checks curl's version defines |
| 1185 | checksrc | Runs curl's C source code style checker |
| 1222 | Verify deprecation statuses and versions | Checks curl's deprecation metadata |
| 1400 | --libcurl for simple HTTP GET | Generates C source code (curl-specific feature) |

## What to Do

Add these test numbers to the DISABLED file for the test runner, or handle them in the test wrapper script (`scripts/urlx-as-curl`).

**Option A**: Add to `vendor/curl-build/tests/data/DISABLED`:
```
745
971
1013
1014
1022
1023
1026
1027
1119
1135
1139
1140
1165
1167
1173
1177
1185
1222
1400
```

**Option B**: Add skip logic in `scripts/run-curl-tests.sh` that automatically excludes these test numbers.

## Acceptance Criteria

All 19 tests should show as SKIPPED (not FAILED) when running the test suite.
