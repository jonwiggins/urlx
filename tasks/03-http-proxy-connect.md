# Task 03: HTTP Proxy Auth + CONNECT Tunnel

## Summary

Fix HTTP proxy authentication and CONNECT tunnel issues. Multiple sub-problems:

1. **FTP-over-HTTP-proxy**: FTP transfers through HTTP proxies time out (exit code 28) because the CONNECT tunnel or proxy GET relay is not properly implemented for FTP URLs.
2. **Proxy NTLM auth**: NTLM multi-step authentication through proxy has header ordering issues (same as Task 01).
3. **Proxy Digest auth**: Digest challenge-response through proxy produces wrong hash values.
4. **CONNECT tunnel reuse**: When tunneling two URLs through the same proxy to the same host, the tunnel should be reused.
5. **SOCKS proxy**: SOCKS5h with IPv6 and --connect-to produce crashes.
6. **Email-over-proxy**: POP3, SMTP, IMAP through HTTP CONNECT proxy.

## Failing Tests (36)

| Test | Description |
|------|-------------|
| 79 | FTP over HTTP proxy (timeout 28) |
| 167 | HTTP proxy-Basic to site-Digest |
| 168 | HTTP proxy-Digest to site-Digest |
| 169 | HTTP proxy-NTLM to site-Digest |
| 206 | HTTP proxy CONNECT auth Digest |
| 208 | HTTP PUT to FTP URL over HTTP proxy (timeout 28) |
| 275 | HTTP CONNECT proxytunnel two URLs same host |
| 299 | FTP over HTTP proxy user:pass not in URL (timeout 28) |
| 335 | HTTP proxy Digest + site Digest with creds in URLs |
| 547 | HTTP proxy auth NTLM with POST data from read callback |
| 548 | HTTP proxy auth NTLM with POST data from POSTFIELDS |
| 555 | HTTP proxy auth NTLM with POST data multi-if |
| 560 | simple HTTPS GET with multi interface |
| 590 | HTTP proxy offers Negotiate+NTLM, use only NTLM |
| 713 | FTP with socks5:// proxy + --connect-to (crash, exit 3) |
| 714 | FTP with http:// proxy + --connect-to |
| 715 | FTP with --preproxy, --proxy + --connect-to |
| 719 | HTTP GET with IPv6 via SOCKS5h |
| 1021 | HTTP proxy CONNECT any proxyauth, NTLM + close |
| 1059 | HTTP CONNECT proxytunnel to unsupported FTP URL (timeout 28) |
| 1060 | HTTP proxy CONNECT auth Digest, large headers and data |
| 1061 | HTTP proxy CONNECT auth Digest, large headers and chunked data |
| 1077 | FTP over HTTP proxy downgrade to HTTP 1.0 (timeout 28) |
| 1078 | HTTP 1.0 CONNECT proxytunnel downgrade GET |
| 1087 | HTTP proxy --anyauth + Location: to new host |
| 1088 | HTTP proxy --anyauth + Location: using location-trusted |
| 1092 | FTP type=i over HTTP proxy (timeout 28) |
| 1098 | FTP RETR twice over proxy confirming persistent connection |
| 1106 | FTP with ftp_proxy environment variable (timeout 28) |
| 1215 | HTTP with server NTLM auth using a proxy |
| 1230 | HTTP CONNECT to IPv6 numerical address |
| 1265 | NO_PROXY with IPv6 numerical address (crash, exit 3) |
| 1319 | POP3 fetch tunneled through HTTP proxy |
| 1320 | SMTP send tunneled through HTTP proxy |
| 1321 | IMAP FETCH tunneled through HTTP proxy |
| 1331 | HTTP --proxy-anyauth and 407 with cookies |

## Failure Patterns

### FTP-over-proxy (timeout): Tests 79, 208, 299, 1059, 1077, 1092, 1106
These all exit with code 28 (timeout). The proxy CONNECT or relay mechanism doesn't properly forward data for FTP protocol.

### Proxy Digest auth: Tests 168, 206, 335, 1060, 1061
Wrong `Proxy-Authorization: Digest response=...` hash value.

### Proxy NTLM auth: Tests 169, 547, 548, 555, 590, 1021, 1215
`Proxy-Authorization: NTLM` header placed after other headers instead of before User-Agent.

### IPv6/SOCKS crash: Tests 713, 719, 1230, 1265
Crashes (exit code 3) when handling IPv6 addresses in proxy contexts.

## What Needs to Change

### 1. FTP-over-HTTP-proxy relay (`crates/liburlx/src/proxy/http.rs`)
For non-CONNECT FTP-over-proxy (e.g., `curl -x http://proxy ftp://host/file`), curl sends a normal HTTP GET to the proxy with the full FTP URL. The proxy fetches the FTP file and returns it as HTTP. urlx needs to format the request correctly and handle the HTTP response.

### 2. CONNECT tunnel for non-HTTP protocols (`crates/liburlx/src/proxy/http.rs`)
For `CONNECT` tunneling of FTP/POP3/SMTP/IMAP through HTTP proxy, after the tunnel is established, the raw protocol bytes must be forwarded. The tunnel establishment and data forwarding need to work for all protocols, not just HTTPS.

### 3. Proxy auth header ordering
Same fix as Task 01 but for `Proxy-Authorization:` — must come before `User-Agent:`.

### 4. IPv6 handling in proxy
Fix IPv6 literal address handling in CONNECT requests (must use `[::1]:port` format) and NO_PROXY matching for IPv6 addresses.

### 5. SOCKS5h with --connect-to
Fix crash when combining SOCKS5h proxy with --connect-to for FTP connections.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  79 167 168 169 206 208 275 299 335 547 548 555 560 590 \
  713 714 715 719 1021 1059 1060 1061 1077 1078 1087 1088 \
  1092 1098 1106 1215 1230 1265 1319 1320 1321 1331
```

All 36 tests must report OK. No regressions on proxy tests 5, 16, 94, 95.
