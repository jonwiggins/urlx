# Task 02: STARTTLS for All Protocols (FTPS, SMTP, IMAP, POP3)

## Summary
Implement STARTTLS — upgrading a plain TCP connection to TLS mid-stream after initial protocol negotiation. This is needed for FTPS (AUTH TLS), SMTP (STARTTLS command), IMAP (STARTTLS command), and POP3 (STLS command). Implicit TLS (`smtps://`, `imaps://`, `pop3s://`) already works.

## Estimated Effort
3-5 days

## Tests to Pass (16)
- **FTPS:** 400, 401, 402, 403, 406, 407, 408, 409, 1112
- **SMTP:** 980, 981, 982
- **IMAP:** 983, 984
- **POP3:** 985, 986

## Acceptance Criteria
```bash
cd vendor/curl-build/tests && perl runtests.pl -a -m=30 -c $PWD/../../../target/release/urlx -vc /usr/bin/curl 400 401 402 403 406 407 408 409 980 981 982 983 984 985 986 1112
# All 16 tests should report OK
```

## Architecture: MaybeTls Stream

The core challenge is that after STARTTLS, the connection changes from `TcpStream` to `TlsStream<TcpStream>`. Rust's type system requires a unified type to handle both.

### Option A: Enum Wrapper (Recommended)
```rust
// In crates/liburlx/src/tls.rs or a new module
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for MaybeTlsStream { /* delegate */ }
impl AsyncWrite for MaybeTlsStream { /* delegate */ }
```

This avoids `Box<dyn>` overhead and keeps types concrete. Implement `AsyncRead` + `AsyncWrite` by delegating to the inner variant.

### Option B: Box<dyn> (Already used for implicit TLS)
The implicit TLS implementation already uses `Box<dyn AsyncRead/AsyncWrite>`. Extend this to support upgrading by replacing the inner stream.

## What Needs to Change

### 1. FTPS (AUTH TLS) — Most Complex
**File:** `crates/liburlx/src/protocol/ftp.rs`

FTPS STARTTLS flow:
1. Connect plain TCP
2. Read 220 greeting
3. Send `AUTH TLS`
4. Receive `234 AUTH TLS successful`
5. **Upgrade control connection to TLS** ← key step
6. Send `PBSZ 0`, receive `200`
7. Send `PROT P`, receive `200`
8. Continue normal FTP flow (USER, PASS, etc.) over TLS
9. **Data connections also need TLS wrapping** after PROT P

Current state: FTP sends AUTH TLS and gets 234, but then the TLS handshake on the control connection fails or isn't attempted. The code at `ftp.rs` around the STARTTLS handling needs to:
- Take ownership of the `TcpStream`
- Perform TLS handshake using `TlsConnector`
- Replace the reader/writer with TLS-wrapped versions
- For data connections: wrap each new data connection in TLS after PROT P

**Data connection TLS:**
- After `PROT P`, every data connection (EPSV/PASV → connect → TLS handshake) must be TLS-wrapped
- The data connection TLS should use the same `TlsConfig` but without ALPN negotiation

### 2. SMTP STARTTLS
**File:** `crates/liburlx/src/protocol/smtp.rs`

SMTP STARTTLS flow:
1. Connect, read greeting
2. Send `EHLO`
3. Server advertises `STARTTLS` in capabilities
4. Send `STARTTLS`
5. Receive `220 Ready to start TLS`
6. **Upgrade to TLS**
7. Send `EHLO` again (re-negotiate capabilities over TLS)
8. Continue with AUTH, MAIL FROM, etc.

**Implementation:**
- After step 5, reassemble the split reader/writer back into the original TcpStream
- Call `TlsConnector::connect(tcp, hostname)`
- Re-split and re-wrap in BufReader
- The existing auth/send logic continues unchanged

### 3. IMAP STARTTLS
**File:** `crates/liburlx/src/protocol/imap.rs`

IMAP STARTTLS flow:
1. Connect, read greeting
2. Send `A001 CAPABILITY`
3. Server lists `STARTTLS` in capabilities
4. Send `A002 STARTTLS`
5. Receive `A002 OK`
6. **Upgrade to TLS**
7. Send `A003 CAPABILITY` again
8. Continue with AUTH, SELECT, etc.

### 4. POP3 STARTTLS (STLS)
**File:** `crates/liburlx/src/protocol/pop3.rs`

POP3 STLS flow:
1. Connect, read greeting
2. Send `CAPA`
3. Server lists `STLS` capability
4. Send `STLS`
5. Receive `+OK Begin TLS negotiation`
6. **Upgrade to TLS**
7. Send `CAPA` again
8. Continue with AUTH, RETR, etc.

## Stream Reassembly for TLS Upgrade

The critical technical challenge: after `tokio::io::split(tcp)`, the reader and writer halves can be reassembled back into the original stream using `reader.into_inner()` (for BufReader) and then the `unsplit()` method:

```rust
// Current: split stream
let (reader, writer) = tokio::io::split(tcp);
let mut reader = BufReader::new(reader);

// To upgrade: reassemble
let read_half = reader.into_inner(); // unwrap BufReader
let tcp = read_half.unsplit(writer); // reassemble TcpStream

// TLS handshake
let connector = TlsConnector::new(tls_config)?;
let (tls_stream, _) = connector.connect(tcp, &host).await?;

// Re-split
let (new_reader, new_writer) = tokio::io::split(tls_stream);
let mut reader = BufReader::new(new_reader);
let mut writer = new_writer;
```

**Note:** This requires that all buffered data in BufReader has been consumed before reassembly. Ensure no unread data remains in the buffer.

## Key Files
- `crates/liburlx/src/tls.rs` — TLS connector (already has `connect()` method)
- `crates/liburlx/src/protocol/ftp.rs` — FTPS AUTH TLS + data channel TLS
- `crates/liburlx/src/protocol/smtp.rs` — SMTP STARTTLS
- `crates/liburlx/src/protocol/imap.rs` — IMAP STARTTLS
- `crates/liburlx/src/protocol/pop3.rs` — POP3 STLS
- `crates/liburlx/src/easy.rs` — Pass `tls_config` to protocol handlers (already done for implicit TLS)

## Notes
- Tests 984-986 test "STARTTLS required but server doesn't advertise it" — should return error 64 (CURLE_USE_SSL_FAILED)
- Tests 980-982 test pipelined STARTTLS where the server sends capability response and STARTTLS OK in one TCP packet
- FTPS data channel TLS (PROT P) is the hardest part — each data connection is a new TCP connection that needs its own TLS handshake
- The `tokio::io::split` halves can be `unsplit()` — this is the key to upgrading mid-stream
