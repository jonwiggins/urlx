//! Regression tests for recently fixed WebSocket curl-compatibility bugs.
//!
//! Each test pins one fix against curl's reference behavior (lib/ws.c and
//! lib/http.c): handshake header emission (auto-auth marker rewriting,
//! user-supplied upgrade headers, Connection merging), connect timeouts,
//! HTTP CONNECT proxy tunneling, curl's fragmented-send quirk for
//! `flags == 0`, EOF-mid-frame semantics, the raw 7-bit control-frame
//! length check, and Easy connect-only bookkeeping.
//!
//! Conventions follow `ws_e2e.rs`: async tests use `#[tokio::test]` with
//! tokio mock servers; Easy tests are sync (`Easy::perform` spawns its own
//! runtime) and use std-thread servers. Every await is wrapped in a timeout
//! so a bug cannot hang CI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

use std::time::Duration;

use liburlx::protocol::ws::{connect_stream, transfer, ws_flags, WsConnectOptions, WsConnection};
use liburlx::{Error, TlsConfig, Url};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Upper bound on every await so a bug cannot hang CI.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A minimal 101 upgrade response (curl's test servers do not send a valid
/// `Sec-WebSocket-Accept` either; curl skips validating it).
const HANDSHAKE_101: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n\
    Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs=\r\n\r\n";

// --- Helpers ---

/// Await `fut` with the standard test timeout.
async fn within<T, F: std::future::Future<Output = T>>(fut: F) -> T {
    tokio::time::timeout(TIMEOUT, fut).await.expect("test future timed out")
}

/// URL for the mock server on `port`.
fn test_url(port: u16) -> Url {
    Url::parse(&format!("ws://127.0.0.1:{port}/test")).unwrap()
}

/// Read one HTTP request (upgrade or CONNECT) through the terminating blank
/// line so no request bytes are mistaken for later data.
async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(TIMEOUT, stream.read(&mut byte))
            .await
            .expect("request read timed out")
            .unwrap();
        assert!(n > 0, "client closed before completing the request");
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    request
}

/// Spawn a one-connection mock server. The upgrade request is consumed
/// before `script` receives the socket; dropping the socket ends the
/// connection. Returns the listening port and the script's output handle.
async fn spawn_server<F, Fut, T>(script: F) -> (u16, tokio::task::JoinHandle<T>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _addr) = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .expect("accept timed out")
            .unwrap();
        let _request = read_request(&mut stream).await;
        script(stream).await
    });
    (port, handle)
}

/// Spawn a one-connection server that captures the client's upgrade request,
/// replies with a plain 101, and returns the captured request bytes.
async fn spawn_capture_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _addr) = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .expect("accept timed out")
            .unwrap();
        let request = read_request(&mut stream).await;
        stream.write_all(HANDSHAKE_101).await.unwrap();
        request
    });
    (port, handle)
}

/// XOR `payload` in place with a 4-byte client mask key.
fn unmask(mask: [u8; 4], payload: &mut [u8]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

/// Build an unmasked server-to-client frame.
fn server_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![first_byte];
    match payload.len() {
        n if n < 126 => buf.push(u8::try_from(n).unwrap()),
        n if n <= 65535 => {
            buf.push(126);
            buf.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
        }
        n => {
            buf.push(127);
            buf.extend_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        }
    }
    buf.extend_from_slice(payload);
    buf
}

/// Read one masked client frame server-side: `(first_byte, unmasked payload)`.
async fn read_client_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[1] & 0x80, 0x80, "client frames must be masked (RFC 6455)");
    let mut len = u64::from(header[1] & 0x7F);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await.unwrap();
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await.unwrap();
        len = u64::from_be_bytes(ext);
    }
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await.unwrap();
    let mut payload = vec![0u8; usize::try_from(len).unwrap()];
    stream.read_exact(&mut payload).await.unwrap();
    unmask(mask, &mut payload);
    (header[0], payload)
}

/// Open a `WsConnection` to the mock server on `port` with default options.
async fn ws_connection(port: u16) -> WsConnection {
    let (response, stream) = within(connect_stream(
        &test_url(port),
        &[],
        &TlsConfig::default(),
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);
    WsConnection::new(stream, response, 0)
}

/// Destructure an `Error::Transfer` into its code and message.
fn transfer_error(err: &Error) -> (u32, &str) {
    match err {
        Error::Transfer { code, message } => (*code, message.as_str()),
        other => unreachable!("expected Error::Transfer, got: {other:?}"),
    }
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// --- Handshake: the internal auto-auth marker never reaches the wire ---

#[tokio::test]
async fn auth_marker_rewritten() {
    let (port, server) = spawn_capture_server().await;

    let headers = [("_auto_Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string())];
    let (response, _stream) = within(connect_stream(
        &test_url(port),
        &headers,
        &TlsConfig::default(),
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);

    let request = String::from_utf8(within(server).await.unwrap()).unwrap();
    assert!(
        request.contains("\r\nAuthorization: Basic dXNlcjpwYXNz\r\n"),
        "auto-generated credentials must be sent as a real Authorization \
         header:\n{request}"
    );
    assert!(
        !request.contains("_auto_Authorization"),
        "the internal marker name must never reach the wire:\n{request}"
    );
}

// --- Handshake: user-supplied upgrade headers override the generated ones ---

#[tokio::test]
async fn user_handshake_header_overrides() {
    let (port, server) = spawn_capture_server().await;

    let headers = [
        ("Sec-WebSocket-Key".to_string(), "dGhlIHNhbXBsZSBub25jZQ==".to_string()),
        ("Upgrade".to_string(), "custom-proto".to_string()),
        ("Sec-WebSocket-Version".to_string(), "14".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ];
    let (response, _stream) = within(connect_stream(
        &test_url(port),
        &headers,
        &TlsConfig::default(),
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);

    let request = String::from_utf8(within(server).await.unwrap()).unwrap();

    // The pinned key is used verbatim and no second key is generated.
    assert!(
        request.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"),
        "the user-pinned key must be sent verbatim:\n{request}"
    );
    assert_eq!(
        count_occurrences(&request, "Sec-WebSocket-Key:"),
        1,
        "exactly one Sec-WebSocket-Key line:\n{request}"
    );

    // Custom Upgrade replaces the generated `Upgrade: websocket`.
    assert!(
        request.contains("\r\nUpgrade: custom-proto\r\n"),
        "custom Upgrade value must be sent:\n{request}"
    );
    assert_eq!(
        count_occurrences(&request, "\r\nUpgrade:"),
        1,
        "exactly one Upgrade line:\n{request}"
    );

    // Custom version replaces the generated `Sec-WebSocket-Version: 13`.
    assert!(
        request.contains("\r\nSec-WebSocket-Version: 14\r\n"),
        "custom Sec-WebSocket-Version must be sent:\n{request}"
    );
    assert_eq!(
        count_occurrences(&request, "Sec-WebSocket-Version:"),
        1,
        "exactly one Sec-WebSocket-Version line:\n{request}"
    );

    // curl merges a custom Connection value with Upgrade and emits it last
    // (curl compat: http_add_connection_hd in lib/http.c).
    assert!(
        request.ends_with("Connection: keep-alive, Upgrade\r\n\r\n"),
        "the request must end with the merged Connection header:\n{request}"
    );
    assert_eq!(
        request.matches("Connection:").count(),
        1,
        "exactly one Connection header (curl merges the custom value)"
    );
}

// --- Handshake: --connect-timeout covers the TCP connect ---

#[tokio::test]
async fn connect_timeout_applies() {
    // 10.255.255.1:81 is a blackhole for the SYN on typical networks: the
    // connect attempt hangs until the configured timeout fires.
    let url = Url::parse("ws://10.255.255.1:81/").unwrap();
    let options = WsConnectOptions {
        connect_timeout: Some(Duration::from_millis(300)),
        ..WsConnectOptions::default()
    };

    let start = std::time::Instant::now();
    let result = within(connect_stream(&url, &[], &TlsConfig::default(), &options)).await;
    let elapsed = start.elapsed();
    let Err(err) = result else { unreachable!("connect to a blackhole address must not succeed") };

    assert!(matches!(err, Error::Timeout(_)), "expected Error::Timeout, got: {err:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "300ms connect timeout must fire well under 10s, took {elapsed:?}"
    );
}

// --- Handshake: HTTP CONNECT proxy tunnel with proxy auth ---

#[tokio::test]
async fn http_connect_proxy_tunnel() {
    // Reserve a target port with nothing listening on it: all traffic must
    // flow through the proxy, never to the target directly.
    let fake_target_port = {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        reserved.local_addr().unwrap().port()
    };

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (mut stream, _addr) = tokio::time::timeout(TIMEOUT, proxy_listener.accept())
            .await
            .expect("proxy accept timed out")
            .unwrap();
        // (a) The CONNECT request for the tunnel.
        let connect_request = read_request(&mut stream).await;
        // (b) Grant the tunnel.
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
        // (c) Act as the WebSocket server on the same socket.
        let _upgrade = read_request(&mut stream).await;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HANDSHAKE_101);
        bytes.extend_from_slice(&server_frame(0x81, b"via-proxy"));
        stream.write_all(&bytes).await.unwrap();
        connect_request
    });

    let url = Url::parse(&format!("ws://127.0.0.1:{fake_target_port}/")).unwrap();
    let proxy_url = Url::parse(&format!("http://127.0.0.1:{proxy_port}")).unwrap();
    let options = WsConnectOptions {
        proxy: Some(&proxy_url),
        proxy_auth: Some(("u", "p")),
        connect_timeout: None,
    };

    let (response, stream) =
        within(connect_stream(&url, &[], &TlsConfig::default(), &options)).await.unwrap();
    assert_eq!(response.status(), 101);

    let mut conn = WsConnection::new(stream, response, 0);
    let mut buf = [0u8; 64];
    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("tunneled frame");
    assert_eq!(&buf[..n], b"via-proxy");
    assert_eq!(meta.flags, ws_flags::TEXT);

    let connect_request = String::from_utf8(within(server).await.unwrap()).unwrap();
    assert!(
        connect_request.starts_with(&format!("CONNECT 127.0.0.1:{fake_target_port} HTTP/1.1\r\n")),
        "tunnel must target the origin host:port:\n{connect_request}"
    );
    // base64("u:p") == "dTpw".
    assert!(
        connect_request.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
        "proxy credentials must be sent on the CONNECT:\n{connect_request}"
    );
}

// --- Send: curl's contfragment quirk for flags == 0 ---

#[tokio::test]
async fn send_cont_flags_zero_curl_quirk() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        let first = read_client_frame(&mut stream).await;
        let second = read_client_frame(&mut stream).await;
        let third = read_client_frame(&mut stream).await;
        (first, second, third)
    })
    .await;

    let mut conn = ws_connection(port).await;
    assert_eq!(within(conn.send(b"a", ws_flags::TEXT | ws_flags::CONT)).await.unwrap(), 1);
    assert_eq!(within(conn.send(b"b", 0)).await.unwrap(), 1);
    // curl's ws_frame_flags2firstbyte() leaves its contfragment state
    // unchanged for flags == 0, so another flags-0 send emits another final
    // continuation instead of failing — intentional curl fidelity.
    assert_eq!(within(conn.send(b"c", 0)).await.unwrap(), 1);

    let ((first_byte, first_payload), (second_byte, second_payload), (third_byte, third_payload)) =
        within(server).await.unwrap();
    assert_eq!(first_byte, 0x01, "TEXT|CONT starts a fragmented message (no FIN)");
    assert_eq!(first_payload, b"a");
    assert_eq!(second_byte, 0x80, "flags 0 mid-fragmentation sends a FIN continuation");
    assert_eq!(second_payload, b"b");
    assert_eq!(
        third_byte, 0x80,
        "contfragment state must be unchanged by a flags-0 send (curl quirk)"
    );
    assert_eq!(third_payload, b"c");
}

// --- Recv: EOF mid-frame is a clean close, not an error ---

/// A 101 handshake followed by a TEXT frame declaring 10 payload bytes but
/// delivering only 3 before the connection closes.
fn truncated_frame_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HANDSHAKE_101);
    bytes.extend_from_slice(&[0x81, 0x0A]); // FIN TEXT, declared length 10
    bytes.extend_from_slice(b"abc"); // only 3 of the 10 payload bytes
    bytes
}

#[tokio::test]
async fn eof_mid_frame_is_clean_close() {
    // WsConnection::recv: the available bytes are delivered first, then the
    // EOF surfaces as Ok(None) — curl treats any EOF as the normal end of
    // the websocket data.
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(&truncated_frame_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    })
    .await;

    let mut conn = ws_connection(port).await;
    let mut buf = [0u8; 64];
    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("partial payload first");
    assert_eq!(&buf[..n], b"abc");
    assert_eq!(meta.flags, ws_flags::TEXT);
    assert_eq!((meta.len, meta.offset, meta.bytesleft), (3, 0, 7));

    assert!(
        within(conn.recv(&mut buf)).await.unwrap().is_none(),
        "EOF mid-frame must be a clean close, not an error"
    );
    within(server).await.unwrap();

    // transfer() over the same wire bytes: Ok with the 3 bytes as body.
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(&truncated_frame_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    })
    .await;

    let response = within(transfer(
        &test_url(port),
        &[],
        &TlsConfig::default(),
        None,
        None,
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);
    assert_eq!(response.body(), b"abc");
    within(server).await.unwrap();
}

// --- Recv: control frames must use the 7-bit length form ---

#[tokio::test]
async fn control_frame_extended_length_rejected() {
    // PING declaring its 5-byte payload via the 16-bit extended-length form.
    // curl validates the raw 7-bit length byte (126 > 125) before decoding
    // the extension, so this is rejected even though 5 <= 125.
    let (port, _server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(&[0x89, 0x7E, 0x00, 0x05]).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        // Hold the socket open so the failure is the validation, not EOF.
        let mut sink = [0u8; 16];
        let _ = stream.read(&mut sink).await;
    })
    .await;

    let mut conn = ws_connection(port).await;
    let mut buf = [0u8; 64];
    let err = within(conn.recv(&mut buf)).await.unwrap_err();
    assert!(err.to_string().contains("control frame payload"), "got: {err}");
}

// --- Easy connect-only (sync; servers on std threads) ---

/// Read the upgrade request from a std stream through the blank line.
fn read_upgrade_request_sync(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read as _;
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).unwrap();
        assert!(n > 0, "client closed before completing the upgrade request");
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    request
}

#[test]
fn refused_upgrade_records_response() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        read_upgrade_request_sync(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("ws://127.0.0.1:{port}/")).unwrap();
    easy.set_connect_only(2);

    let err = easy.perform().unwrap_err();
    assert_eq!(transfer_error(&err).0, 22, "CURLE_HTTP_RETURNED_ERROR");

    // The refused handshake response must still be recorded so
    // CURLINFO_RESPONSE_CODE reflects the 200 (curl compat: test 2303).
    let last = easy.last_response().expect("refused upgrade must record the response");
    assert_eq!(last.status(), 200);

    server.join().unwrap();
}

#[test]
fn stale_connection_cleared_after_failed_perform() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        read_upgrade_request_sync(&mut stream);
        stream.write_all(HANDSHAKE_101).unwrap();
        // Hold the connection open until the client abandons it.
        let mut sink = [0u8; 64];
        let _ = stream.read(&mut sink);
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("ws://127.0.0.1:{port}/")).unwrap();
    easy.set_connect_only(2);
    let response = easy.perform().unwrap();
    assert_eq!(response.status(), 101);

    // Re-perform against a port with nothing listening: the perform fails,
    // and it must also drop the previously retained connection.
    let closed_port = {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        reserved.local_addr().unwrap().port()
    };
    easy.url(&format!("ws://127.0.0.1:{closed_port}/")).unwrap();
    easy.perform().unwrap_err();

    // The old (still open server-side!) connection must not be reachable.
    let err = easy.ws_send(b"x", ws_flags::TEXT).unwrap_err();
    assert_eq!(
        transfer_error(&err).0,
        55,
        "CURLE_SEND_ERROR: ws_send must not reuse the superseded connection"
    );

    drop(easy);
    server.join().unwrap();
}
