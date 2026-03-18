# Task 03: FTP Connection Reuse Across Multiple URLs

## Summary
When fetching multiple FTP URLs from the same server, urlx sends QUIT+reconnect (USER/PASS/PWD) for each URL. curl reuses the control connection, sending only CWD to change directories. This affects all multi-URL FTP tests.

## Estimated Effort
2-3 days

## Tests to Pass (11)
146, 149, 210, 211, 212, 215, 216, 698, 1010, 1096, 1149

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 146 149 210 211 212 215 216 698 1010 1096 1149
# All 11 tests should report OK
```

## Current Problem

Test 146 shows:
```
Expected:                    Actual:
USER anonymous               USER anonymous
PASS ftp@example.com         PASS ftp@example.com
PWD                          PWD
EPSV                         EPSV
TYPE I                       TYPE I
SIZE 146                     SIZE 146
RETR 146                     RETR 146
CWD /          ←──────→      QUIT              ← Wrong!
EPSV                         USER anonymous     ← Reconnects!
SIZE 146                     PASS ftp@example.com
RETR 146                     PWD
QUIT                         EPSV
                             TYPE I
                             SIZE 146
                             RETR 146
```

## Architecture

### Option A: FTP Session in Easy Handle (Recommended)

Store the FTP control connection as a reusable session in the `Easy` handle:

```rust
// In easy.rs
pub struct Easy {
    // ... existing fields ...
    ftp_session: Option<FtpSession>,
}
```

```rust
// In ftp.rs
pub struct FtpSession {
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    host: String,
    port: u16,
    user: String,
    current_dir: String,
}
```

### Option B: Session Parameter (Simpler)

Pass `&mut Option<FtpSession>` through the call chain:
`perform_async()` → `perform_transfer()` → `do_single_request()` → `ftp::perform()`

## What Needs to Change

### 1. Create FtpSession struct
**File:** `crates/liburlx/src/protocol/ftp.rs`

```rust
pub struct FtpSession {
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    host: String,
    port: u16,
    user: String,
    current_dir: String,
    features: FtpFeatures,
    use_epsv: bool,
}
```

### 2. Split `perform()` into connect + execute
**File:** `crates/liburlx/src/protocol/ftp.rs`

Currently `perform()` does everything: connect, login, navigate, transfer, quit. Split into:

- `connect_and_login()` → creates a new FtpSession
- `execute_transfer(session, ...)` → uses existing session, navigates + transfers
- `perform()` → orchestrates: reuse session if available, else connect

On reuse:
1. Check if `session.host == target_host && session.port == target_port && session.user == user`
2. If match: send `CWD /` to reset to root, then navigate to target path
3. If no match: QUIT old session, create new one

### 3. Store session in Easy handle
**File:** `crates/liburlx/src/easy.rs`

Add `ftp_session: Option<FtpSession>` field. Pass `&mut self.ftp_session` through `perform_async()`.

The challenge: `perform_async()` calls `perform_transfer()` which is a free function. The session needs to be threaded through as a parameter. Since `perform_transfer` and `do_single_request` already have many parameters, consider:
- Adding it as another parameter (ugly but consistent)
- Wrapping it in an `Arc<Mutex<>>` (needed since the future might be `Send`)

### 4. Handle the multi-URL path in CLI
**File:** `crates/urlx-cli/src/transfer.rs`

The `run_multi()` function calls `rt.block_on(easy.perform_async())` in a loop. Since it reuses the same `easy` handle, the FTP session stored in `easy.ftp_session` will naturally persist across calls. The only change needed: don't call `easy.ftp_session.take()` between URLs.

After all URLs are processed, explicitly QUIT:
```rust
if let Some(session) = easy.ftp_session.take() {
    rt.block_on(session.quit());
}
```

### 5. CWD path management
When reusing a connection, the FTP server remembers the current directory. The reuse path needs to:
1. Send `CWD /` to reset to root
2. Then send `CWD <target_dir>` for the new URL's path
3. Skip `CWD /` + `CWD <dir>` if the target is in the same directory as the previous request

Test 210: Two files from the SAME directory → no CWD needed (just EPSV + RETR for second file)
Test 146: Two files from DIFFERENT paths → CWD / then navigate

## Key Files
- `crates/liburlx/src/protocol/ftp.rs` — FtpSession struct, split perform()
- `crates/liburlx/src/easy.rs` — Store session, pass through call chain
- `crates/urlx-cli/src/transfer.rs` — QUIT after all URLs

## Notes
- Test 211: Uses PASV (not EPSV) — session must track `use_epsv` state
- Test 212: Uses PORT (active mode) — session must track active/passive
- Test 698: Connection reuse with cookie jar interaction
- Test 1010: Connection reuse with HTTP/2 (separate test, may not apply to FTP)
- Test 1096: --ftp-method nocwd with connection reuse
- Test 1149: LIST then nocwd LIST — mixed FTP methods across URLs
- QUIT should only be sent when the session is explicitly closed, not between URLs
