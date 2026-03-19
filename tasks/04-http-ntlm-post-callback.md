# Task 04: HTTP NTLM Authentication with POST

## Status: Not Started

## Problem

NTLM authentication works for simple GET requests, but fails for POST requests (especially through proxies), very long usernames, and Negotiate+NTLM combined authentication. The core issue is that NTLM multi-step auth (Type 1 → 401 → Type 3) doesn't properly handle request bodies during the negotiation.

## Tests (7)

| Test | Description |
|------|-------------|
| 547 | HTTP POST with proxy NTLM authentication (Type 1/Type 3 negotiation) |
| 548 | HTTP POST with proxy NTLM auth using multi interface |
| 555 | Simple HTTPS GET with multi interface (requires libtest tool — may need skip) |
| 560 | HTTP POST with Negotiate and NTLM WWW-Authentication |
| 694 | HTTP NTLM with very long username (1100+ characters) |
| 775 | HTTP NTLM auth with excessively long NTLMv2 response — expects error 100 |
| 895 | IMAP FETCH with quoted username containing special chars and `AUTH=*` option |

## Work Needed

1. **POST body during NTLM negotiation** (547, 548): During the initial Type 1 request, send `Content-Length: 0` (not the actual body). Only send the real POST body after the Type 3 auth succeeds.
2. **Negotiate + NTLM** (560): Support `WWW-Authenticate: Negotiate` falling back to NTLM when Negotiate fails. Handle the dual-auth flow correctly with POST bodies.
3. **Long NTLM usernames** (694): Handle NTLM usernames longer than typical buffer sizes (1100+ chars). Domain\username splitting must work with long strings.
4. **NTLM response overflow** (775): When NTLMv2 response exceeds expected size, return error code 100 instead of crashing or hanging.
5. **IMAP AUTH=*** (895): Support `AUTH=*` login option in IMAP URLs to try all available auth mechanisms.
6. **Multi interface** (548, 555): These use the multi (non-blocking) interface. Test 555 requires a libtest tool and may need to be skipped.

## Exit Criteria

All 7 tests pass (or 555 documented as skip if it requires libtest): `runtests.pl 547 548 555 560 694 775 895`
