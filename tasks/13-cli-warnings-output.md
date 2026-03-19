# Task 13: CLI Behavior, Warnings, and Output Fixes

## Summary

Fix CLI-level issues: wrong exit codes, missing/wrong warning messages, --write-out variables, stdin URL reading, globbing, progress bar, --next interaction, and various flag behaviors. This is a collection of independent small fixes.

## Failing Tests (43)

### Exit Code Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 313 | CRL test | Wrong exit code for certificate revocation |
| 460 | try --expand without an argument | Missing/wrong error for --expand with no arg |
| 497 | Reject too large accumulated HTTP response headers | Not rejecting oversized headers |
| 1069 | HTTP 1.0 PUT from stdin with no content length | Wrong exit code |

### Warning/Stderr Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 415 | HTTP response with control code then negative Content-Length | Wrong handling of negative CL |
| 422 | use --next with missing URL before it | Wrong warning for --next without URL |
| 469 | warn about Unicode quote character | Missing warning for Unicode quotes in args |
| 470 | warn about Unicode quote character read from config file | Missing warning in config files |
| 481 | --no-clobber with --continue-at | Missing incompatibility warning |
| 482 | --remove-on-error with --continue-at | Missing incompatibility warning |
| 484 | Use --etag-compare and -save with more than one URL | Missing multi-URL warning |
| 485 | Use --etag-compare/save with more than one URL, URLs first | Same warning, different order |
| 760 | more cmdline options than URLs and --next | Wrong handling of option/URL count mismatch |
| 761 | too many {} globs | Missing error for excessive glob expansion |

### Write-out and Output Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 417 | --write-out with %{certs} | %{certs} variable not implemented |
| 1148 | progress-bar | Progress bar format doesn't match curl |
| 1268 | filename argument looks like a flag | Missing warning when filename starts with `-` |
| 1370 | HTTP GET -o fname -J and Content-Disposition, -D file | -J + -D interaction |
| 1371 | HTTP GET -o fname -J and Content-Disposition, -D stdout | -J + -D to stdout |

### Request Building Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 48 | HTTP with -d and -G and -I | -d + -G + -I: should be HEAD with data in query string |
| 306 | HTTPS GET, receive no headers only data! | HTTPS response with no headers |
| 357 | HTTP PUT with Expect: 100-continue and 417 response | 417 not handled properly |
| 386 | --json + --next | Headers from --json leaking to --next request |
| 461 | disable Host: when specified as lower case | `-H "host:"` should suppress Host header |
| 463 | HTTP with -d @file with file containing CR, LF and null byte | Binary data in -d @file |
| 471 | HTTP reject HTTP/1.1 to HTTP/2 switch on same connection | Upgrade: h2c rejection |

### URL/Stdin/Glob Input Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 203 | file:/path URL with a single slash | Single-slash file:/ URL handling |
| 487 | Variable using 64dec with bad base64 | --variable with 64dec function on bad input |
| 488 | Download two URLs provided on stdin | Reading URLs from stdin not working |
| 489 | Download two URLs provided in a file | Reading URLs from file not working |
| 490 | Two globbed HTTP PUTs | Globbed PUT with upload files |
| 491 | Two globbed HTTP PUTs, the second upload file is missing | Error on missing upload file |
| 492 | Two globbed HTTP PUTs to two globbed URLs | Double glob expansion |
| 1015 | --data-urlencode | URL encoding of data |
| 1020 | -Y range on a file:// URL to stdout | Speed limit on file:// |
| 1117 | HTTP with invalid range then another URL | Continue after range error |
| 1221 | --url-query with --data-urlencode | URL encoding in query params |
| 1292 | Replaced internal headers with a blank one | Blanking internal headers |
| 1328 | HTTP GET a globbed range with -f | Glob + --fail interaction |

### Misc CLI Issues
| Test | Description | Root Cause |
|------|-------------|------------|
| 369 | --etag-save with bad path then working transfer | Error recovery after bad etag path |
| 379 | --remove-on-error with --no-clobber and an added number | File numbering with --no-clobber |
| 762 | HTTP GET with --remote-time with file date from 1940 | Old file dates |
| 1147 | -H headers from a file | Loading headers from @file |

## Key Changes

### 1. URL from stdin/file (`crates/urlx-cli/src/args.rs` or input handling)
Support reading URLs from stdin (`--url -`) and from file (`--url @file`). Each line is one URL.

### 2. Warning messages (`crates/urlx-cli/src/main.rs`)
Add curl-compatible warnings for:
- Unicode quote characters in arguments and config files
- `--no-clobber` + `--continue-at` incompatibility
- `--remove-on-error` + `--continue-at` incompatibility
- `--etag-compare/save` with multiple URLs
- Filename arguments that look like flags (`-q`)

### 3. --next header isolation
Headers, methods, and options set before `--next` must NOT leak to requests after `--next`. Each `--next` boundary resets per-request options.

### 4. --write-out %{certs}
Implement the `%{certs}` variable showing certificate chain information.

### 5. -d + -G + -I interaction
When all three flags are used: `-G` moves `-d` data to query string, `-I` makes it HEAD.

### 6. Glob expansion limits
Set a maximum on glob expansion (curl's limit is 100 expansions). Error with appropriate message.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  48 203 306 313 357 369 379 386 415 417 422 460 461 463 469 470 471 \
  481 482 484 485 487 488 489 490 491 492 497 760 761 762 \
  1015 1020 1069 1117 1147 1148 1221 1268 1292 1328 1370 1371
```

All 43 tests must report OK.
