# Task 05: HTTP Proxy Authentication (NTLM, Digest, AnyAuth)

## Summary
Fix HTTP proxy authentication for NTLM multi-step negotiation, Digest challenge-response, and --proxy-anyauth mechanism selection. Includes both CONNECT tunnel and non-CONNECT proxy paths.

## Estimated Effort
4-6 days

## Tests to Pass (28)
- **Proxy NTLM (8):** 169, 243, 547, 548, 555, 590, 694, 1021
- **Proxy Digest (10):** 168, 206, 258, 259, 335, 718, 1001, 1002, 1060, 1061
- **Proxy CONNECT (8):** 217, 275, 287, 749, 1078, 1230, 1287, 1288
- **Proxy Misc (2):** 974, 1004

Note: Tests 547, 548, 555 use `<tool>` (C test programs) and may not be applicable to CLI testing.

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 168 169 206 217 243 258 259 275 287 335 590 694 718 749 974 1001 1002 1004 1021 1060 1061 1078 1230 1287 1288
# All non-libtool tests should report OK
```

## What Needs to Change

### 1. Non-CONNECT Proxy Digest 407 Handler
**File:** `crates/liburlx/src/easy.rs` (~line 3185)

The 407 handler in `perform_transfer` only handles `ProxyAuthMethod::Ntlm`. Add a `ProxyAuthMethod::Digest` branch:

```rust
ProxyAuthMethod::Digest => {
    let proxy_auth_header = response.header("proxy-authenticate");
    if let Some(auth_header) = proxy_auth_header {
        let challenge = DigestChallenge::parse(auth_header)?;
        let uri = format!("{}:{}", target_host, target_port);
        let cnonce = generate_cnonce();
        let auth_value = challenge.respond(&user, &pass, method, &uri, 1, &cnonce);
        // Add Proxy-Authorization header and retry
        request_headers.push(("Proxy-Authorization".to_string(), auth_value));
        // Re-send the request
    }
}
```

### 2. Proxy NTLM Type 1 → Type 3 Completion
**File:** `crates/liburlx/src/easy.rs` (~line 3200)

The current NTLM proxy handler sends Type 1 but doesn't complete the Type 3 exchange. The flow should be:

1. First request: send with `Proxy-Authorization: NTLM <Type1>`
2. Get 407 response with `Proxy-Authenticate: NTLM <Type2>`
3. Parse Type 2 challenge
4. Send retry with `Proxy-Authorization: NTLM <Type3>`
5. Get 200 (or actual server response)

**Current issue:** Step 2-4 may not be happening correctly. The retry logic needs to extract the Type 2 from the 407 response and generate Type 3.

### 3. --proxy-anyauth Implementation
**File:** `crates/urlx-cli/src/args.rs`, `crates/liburlx/src/easy.rs`

Add `ProxyAuthMethod::Any` variant:
1. First request: no Proxy-Authorization header
2. On 407: parse `Proxy-Authenticate` header
3. Select strongest: NTLM > Digest > Basic
4. Retry with selected method

### 4. CONNECT Tunnel Improvements
**File:** `crates/liburlx/src/easy.rs` (~line 4700-5000)

- **Test 217:** CONNECT returns 405 → return error 56 with proxy-related message
- **Test 749:** CONNECT returns non-HTTP → return error 43 (already fixed, verify)
- **Test 275:** CONNECT tunnel reuse for multiple URLs through same proxy
- **Test 287:** Custom User-Agent in CONNECT request (already sent, may be ordering)
- **Test 1078:** HTTP/1.0 CONNECT (use `proxy_http_10` flag)
- **Test 1230:** CONNECT with IPv6 target address (bracket handling)
- **Test 1287:** Ignore Transfer-Encoding and Content-Length in CONNECT 200 response
- **Test 1288:** Suppress CONNECT response headers from output

### 5. Dual Auth (Proxy + Server)
**File:** `crates/liburlx/src/easy.rs`

Tests 169 and 335 use proxy Digest/NTLM AND server Digest auth. The flow:
1. Send request → get 407 from proxy
2. Retry with proxy auth → get 401 from server
3. Retry with server auth → get 200

The current code may not chain these two auth loops correctly.

### 6. Body Handling During Proxy Auth
When proxy returns 407 during a POST request:
- Type 1 probe: send with `Content-Length: 0` (already implemented)
- Type 3 retry: send the actual body

For CONNECT tunnel: the body is irrelevant (CONNECT has no body).

## Key Files
- `crates/liburlx/src/easy.rs` — Proxy auth flow in `perform_transfer()` and `establish_connect_tunnel()`
- `crates/liburlx/src/auth/digest.rs` — Digest challenge parsing and response generation
- `crates/liburlx/src/auth/ntlm.rs` — NTLM Type 1/2/3 messages
- `crates/liburlx/src/auth/mod.rs` — ProxyAuthMethod enum
- `crates/urlx-cli/src/args.rs` — --proxy-anyauth flag

## Notes
- The CONNECT body draining after 407 is already implemented (Content-Length and chunked)
- Tests 547, 548, 555 use libtest (C programs) — verify if they're CLI-testable
- Test 590: server offers "Negotiate, NTLM" — should pick NTLM (we don't support Negotiate/SPNEGO)
- Test 694: NTLM info callback tracking — may need NTLM state info in response
- CONNECT tunnel auth is separate from non-CONNECT proxy auth — both need to work
