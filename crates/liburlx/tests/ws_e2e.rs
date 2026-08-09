//! End-to-end WebSocket connection tests.
//!
//! Exercises `connect_stream`, `transfer`, `WsConnection` send/recv, and the
//! Easy connect-only API against real TCP mock servers, modeled on curl's
//! WebSocket test scenarios (tests 2300-2304 and the 2700 series).
//!
//! The async `WsConnection` tests use `#[tokio::test]` with tokio mock
//! servers. The Easy tests are sync (`Easy::perform` spawns its own runtime)
//! and use std-thread servers instead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results,
    clippy::significant_drop_tightening
)]

use std::time::Duration;

use liburlx::protocol::ws::{
    connect_stream, transfer, ws_flags, ws_options, Message, WsConnectOptions, WsConnection,
};
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

/// Read the client's upgrade request through the terminating blank line so
/// no request bytes are mistaken for frame data.
async fn read_upgrade_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(TIMEOUT, stream.read(&mut byte))
            .await
            .expect("upgrade request read timed out")
            .unwrap();
        assert!(n > 0, "client closed before completing the upgrade request");
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
        let _request = read_upgrade_request(&mut stream).await;
        script(stream).await
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

/// Run a curl-style transfer against the mock server on `port`.
async fn run_transfer(port: u16, upload: Option<&[u8]>) -> Result<liburlx::Response, Error> {
    within(transfer(
        &test_url(port),
        &[],
        &TlsConfig::default(),
        upload,
        None,
        &WsConnectOptions::default(),
    ))
    .await
}

/// Open a `WsConnection` to the mock server on `port`.
async fn ws_connection(port: u16, options: u32) -> WsConnection {
    let (response, stream) = within(connect_stream(
        &test_url(port),
        &[],
        &TlsConfig::default(),
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);
    WsConnection::new(stream, response, options)
}

/// Destructure an `Error::Transfer` into its code and message.
fn transfer_error(err: &Error) -> (u32, &str) {
    match err {
        Error::Transfer { code, message } => (*code, message.as_str()),
        other => unreachable!("expected Error::Transfer, got: {other:?}"),
    }
}

// --- transfer(): curl test 2700 analog (frame types) ---

#[tokio::test]
async fn transfer_collects_frame_payloads_and_auto_pongs_ping() {
    let (port, server) = spawn_server(|mut stream| async move {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HANDSHAKE_101);
        bytes.extend_from_slice(&server_frame(0x81, b"txt")); // TEXT
        bytes.extend_from_slice(&server_frame(0x82, b"bin")); // BINARY
        bytes.extend_from_slice(&server_frame(0x89, b"ping")); // PING
        bytes.extend_from_slice(&server_frame(0x8A, b"pong")); // PONG
        bytes.extend_from_slice(&server_frame(0x88, b"\x03\xe8close")); // CLOSE 1000
        stream.write_all(&bytes).await.unwrap();
        // The client must answer the PING with a masked PONG before we
        // close the connection.
        read_client_frame(&mut stream).await
    })
    .await;

    let response = run_transfer(port, None).await.unwrap();
    assert_eq!(response.status(), 101);

    // TEXT + BINARY + PONG + CLOSE payloads flow to the body; the PING is
    // auto-ponged and never surfaced; the CLOSE payload keeps its 2-byte
    // status code (curl compat: test 2700 stdout).
    let mut expected = Vec::new();
    expected.extend_from_slice(b"txt");
    expected.extend_from_slice(b"bin");
    expected.extend_from_slice(b"pong");
    expected.extend_from_slice(b"\x03\xe8close");
    assert_eq!(response.body(), expected.as_slice());

    let (first_byte, payload) = within(server).await.unwrap();
    assert_eq!(first_byte, 0x8A, "auto-reply must be an unfragmented PONG");
    assert_eq!(payload, b"ping", "auto-PONG must echo the PING payload");
}

// --- transfer(): curl test 2300 analog (close without frames) ---

#[tokio::test]
async fn transfer_close_after_upgrade_is_empty_reply() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.shutdown().await.unwrap();
    })
    .await;

    let err = run_transfer(port, None).await.unwrap_err();
    let (code, message) = transfer_error(&err);
    assert_eq!(code, 52, "CURLE_GOT_NOTHING");
    assert_eq!(message, "Empty reply from server");
    within(server).await.unwrap();
}

// --- transfer(): curl test 2303 analog (200 instead of 101) ---

#[tokio::test]
async fn transfer_refused_upgrade_reports_http_error() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 Oblivious\r\n\
                  Server: test-server/fake\r\n\
                  Content-Length: 6\r\n\r\nhello\n",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    })
    .await;

    let err = run_transfer(port, None).await.unwrap_err();
    let (code, message) = transfer_error(&err);
    assert_eq!(code, 22, "CURLE_HTTP_RETURNED_ERROR");
    assert!(message.contains("Refused WebSocket upgrade: 200"), "unexpected message: {message}");
    within(server).await.unwrap();
}

// --- transfer(): upload data sent as one masked BINARY frame ---

#[tokio::test]
async fn transfer_upload_sends_masked_binary_frame() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        let frame = read_client_frame(&mut stream).await;
        // Send one frame so the transfer does not fail with 52, then close.
        stream.write_all(&server_frame(0x81, b"ok")).await.unwrap();
        frame
    })
    .await;

    let response = run_transfer(port, Some(b"upload-payload")).await.unwrap();
    assert_eq!(response.body(), b"ok");

    let (first_byte, payload) = within(server).await.unwrap();
    assert_eq!(first_byte, 0x82, "upload must go out as an unfragmented BINARY frame");
    assert_eq!(payload, b"upload-payload");
}

// --- WsConnection: fragmentation (curl tests 2719/2720 analogs) ---

#[tokio::test]
async fn recv_reports_fragment_flags_and_recv_message_reassembles() {
    let (port, server) = spawn_server(|mut stream| async move {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HANDSHAKE_101);
        // Message 1: TEXT in five fragments, with empty first, middle, and
        // last fragments (curl test 2720 exercises empty fragments).
        bytes.extend_from_slice(&server_frame(0x01, b"")); // TEXT, no FIN
        bytes.extend_from_slice(&server_frame(0x00, b"Hello")); // CONT
        bytes.extend_from_slice(&server_frame(0x00, b"")); // empty CONT
        bytes.extend_from_slice(&server_frame(0x00, b" World")); // CONT
        bytes.extend_from_slice(&server_frame(0x80, b"")); // final CONT, empty
                                                           // Message 2: TEXT in three fragments for recv_message reassembly.
        bytes.extend_from_slice(&server_frame(0x01, b"foo"));
        bytes.extend_from_slice(&server_frame(0x00, b"bar"));
        bytes.extend_from_slice(&server_frame(0x80, b"baz"));
        stream.write_all(&bytes).await.unwrap();
    })
    .await;

    let mut conn = ws_connection(port, 0).await;
    let mut buf = [0u8; 256];

    // Non-final fragments carry TEXT|CONT; the final fragment TEXT alone.
    let expectations: &[(&[u8], u32)] = &[
        (b"", ws_flags::TEXT | ws_flags::CONT),
        (b"Hello", ws_flags::TEXT | ws_flags::CONT),
        (b"", ws_flags::TEXT | ws_flags::CONT),
        (b" World", ws_flags::TEXT | ws_flags::CONT),
        (b"", ws_flags::TEXT),
    ];
    for (expected_payload, expected_flags) in expectations {
        let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("frame expected");
        assert_eq!(&buf[..n], *expected_payload);
        assert_eq!(meta.flags, *expected_flags, "payload {expected_payload:?}");
        assert_eq!(meta.len, expected_payload.len());
        assert_eq!(meta.offset, 0);
        assert_eq!(meta.bytesleft, 0);
    }

    // Message 2 reassembles into the concatenated text.
    let message = within(conn.recv_message()).await.unwrap();
    assert_eq!(message, Message::Text("foobarbaz".to_string()));

    within(server).await.unwrap();
}

// --- WsConnection: invalid inbound frames (curl tests 2701-2706, 2713-2718, 2722 analogs) ---

/// Connect, feed `bad` after the 101, and return the resulting recv error.
/// The server holds its socket open so the failure is the frame validation,
/// never a surprise EOF.
async fn recv_rejects(bad: &'static [u8]) -> Error {
    let (port, _server) = spawn_server(move |mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(bad).await.unwrap();
        let mut sink = [0u8; 16];
        let _ = stream.read(&mut sink).await;
    })
    .await;

    let mut conn = ws_connection(port, 0).await;
    let mut buf = [0u8; 64];
    within(conn.recv(&mut buf)).await.unwrap_err()
}

#[tokio::test]
async fn recv_rejects_reserved_opcode() {
    // Opcode 0x3 is reserved (curl test 2704 analog).
    let err = recv_rejects(&[0x83, 0x00]).await;
    assert!(err.to_string().contains("invalid opcode"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_rsv_bits() {
    // RSV1 set without a negotiated extension (curl test 2705 analog).
    let err = recv_rejects(&[0xC1, 0x00]).await;
    assert!(err.to_string().contains("reserved bits"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_masked_server_frame() {
    // Server-to-client frames must not be masked.
    let err = recv_rejects(&[0x81, 0x83]).await;
    assert!(err.to_string().contains("masked frame"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_oversized_control_frame() {
    // PING with a declared 126-byte payload (curl test 2702 analog).
    let err = recv_rejects(&[0x89, 0x7E, 0x00, 0x7E]).await;
    assert!(err.to_string().contains("control frame payload"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_fragmented_control_frame() {
    // PING without FIN (curl test 2703 analog).
    let err = recv_rejects(&[0x09, 0x00]).await;
    assert!(err.to_string().contains("fragmented control frame"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_stray_continuation() {
    // CONT with no fragmented message in progress (curl test 2706 analog).
    let err = recv_rejects(&[0x00, 0x01, b'x']).await;
    assert!(err.to_string().contains("no ongoing fragmented message"), "got: {err}");
}

#[tokio::test]
async fn recv_rejects_new_message_mid_fragment() {
    // A new TEXT frame while a fragmented message is open (2707 analog).
    let (port, _server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(&server_frame(0x01, b"a")).await.unwrap(); // TEXT, no FIN
        stream.write_all(&server_frame(0x81, b"b")).await.unwrap(); // new final TEXT
        let mut sink = [0u8; 16];
        let _ = stream.read(&mut sink).await;
    })
    .await;

    let mut conn = ws_connection(port, 0).await;
    let mut buf = [0u8; 64];
    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("first fragment");
    assert_eq!(&buf[..n], b"a");
    assert_eq!(meta.flags, ws_flags::TEXT | ws_flags::CONT);

    let err = within(conn.recv(&mut buf)).await.unwrap_err();
    assert!(err.to_string().contains("interrupted by new message"), "got: {err}");
}

// --- WsConnection: unsolicited PONG + zero-length frames (2710 analog) ---

#[tokio::test]
async fn recv_surfaces_unsolicited_pong_and_zero_length_frames() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(&server_frame(0x8A, b"tag")).await.unwrap(); // PONG
        stream.write_all(&server_frame(0x81, b"")).await.unwrap(); // empty TEXT
    })
    .await;

    let mut conn = ws_connection(port, 0).await;
    let mut buf = [0u8; 64];

    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("PONG expected");
    assert_eq!(&buf[..n], b"tag");
    assert_eq!(meta.flags, ws_flags::PONG);

    // A zero-length frame yields exactly one zero-length chunk.
    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("empty TEXT expected");
    assert_eq!(n, 0);
    assert_eq!(meta.flags, ws_flags::TEXT);
    assert_eq!((meta.len, meta.offset, meta.bytesleft), (0, 0, 0));

    // Server closed: clean end of connection.
    assert!(within(conn.recv(&mut buf)).await.unwrap().is_none());
    assert_eq!(conn.frames_received(), 2);

    within(server).await.unwrap();
}

// --- WsConnection: NO_AUTO_PONG option ---

#[tokio::test]
async fn no_auto_pong_surfaces_ping_and_sends_no_pong() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(&server_frame(0x89, b"hi")).await.unwrap(); // PING
                                                                     // The next client frame must be the TEXT the test sends afterwards:
                                                                     // TCP ordering proves no PONG was emitted before it.
        read_client_frame(&mut stream).await
    })
    .await;

    let mut conn = ws_connection(port, ws_options::NO_AUTO_PONG).await;
    let mut buf = [0u8; 64];

    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("PING expected");
    assert_eq!(&buf[..n], b"hi");
    assert_eq!(meta.flags, ws_flags::PING, "PING must be surfaced when auto-pong is off");

    within(conn.send(b"done", ws_flags::TEXT)).await.unwrap();

    let (first_byte, payload) = within(server).await.unwrap();
    assert_eq!(first_byte, 0x81, "no PONG may precede the client TEXT frame");
    assert_eq!(payload, b"done");
}

// --- WsConnection: chunked delivery of a large frame ---

#[tokio::test]
async fn recv_delivers_large_frame_in_chunks_with_meta() {
    let payload: Vec<u8> = (0..200u8).collect();
    let frame = server_frame(0x82, &payload);
    let (port, server) = spawn_server(move |mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        stream.write_all(&frame).await.unwrap();
    })
    .await;

    let mut conn = ws_connection(port, 0).await;
    let mut buf = [0u8; 64];
    let mut reassembled = Vec::new();
    let expected_meta = [(64, 0, 136), (64, 64, 72), (64, 128, 8), (8, 192, 0)];
    for (expected_len, expected_offset, expected_bytesleft) in expected_meta {
        let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("chunk expected");
        assert_eq!(n, expected_len);
        assert_eq!(meta.len, expected_len);
        assert_eq!(meta.offset, expected_offset);
        assert_eq!(meta.bytesleft, expected_bytesleft);
        assert_eq!(meta.flags, ws_flags::BINARY, "every chunk carries the frame flags");
        reassembled.extend_from_slice(&buf[..n]);
    }
    assert_eq!(reassembled, payload);

    // last_meta reflects the final chunk.
    assert_eq!(conn.last_meta().offset, 192);
    assert_eq!(conn.last_meta().bytesleft, 0);

    within(server).await.unwrap();
}

// --- WsConnection: send flag validation + fragmented send ---

#[tokio::test]
async fn send_validates_flags_and_fragments_messages() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream.write_all(HANDSHAKE_101).await.unwrap();
        let first = read_client_frame(&mut stream).await;
        let second = read_client_frame(&mut stream).await;
        (first, second)
    })
    .await;

    let mut conn = ws_connection(port, 0).await;

    // Control frame with CONT: invalid flag combination.
    let err = within(conn.send(b"x", ws_flags::PING | ws_flags::CONT)).await.unwrap_err();
    assert_eq!(transfer_error(&err).0, 43, "CURLE_BAD_FUNCTION_ARGUMENT");

    // Control payload over 125 bytes.
    let err = within(conn.send(&[0u8; 126], ws_flags::PING)).await.unwrap_err();
    assert_eq!(transfer_error(&err).0, 100, "CURLE_TOO_LARGE");

    // Flags 0 outside a fragmented send.
    let err = within(conn.send(b"x", 0)).await.unwrap_err();
    assert_eq!(transfer_error(&err).0, 43, "CURLE_BAD_FUNCTION_ARGUMENT");

    // Fragmented send: TEXT|CONT starts the message, final TEXT ends it.
    assert_eq!(within(conn.send(b"Hello", ws_flags::TEXT | ws_flags::CONT)).await.unwrap(), 5);
    assert_eq!(within(conn.send(b"World", ws_flags::TEXT)).await.unwrap(), 5);

    let ((first_byte, first_payload), (second_byte, second_payload)) =
        within(server).await.unwrap();
    assert_eq!(first_byte, 0x01, "first fragment: TEXT without FIN");
    assert_eq!(first_payload, b"Hello");
    assert_eq!(second_byte, 0x80, "final fragment: FIN continuation");
    assert_eq!(second_payload, b"World");
}

// --- connect_stream: frames arriving in the same packet as the 101 ---

#[tokio::test]
async fn connect_stream_leaves_frame_bytes_after_pipelined_101() {
    let (port, server) = spawn_server(|mut stream| async move {
        // Headers and the first frame in ONE write: the handshake parser
        // must not consume any frame bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HANDSHAKE_101);
        bytes.extend_from_slice(&server_frame(0x81, b"hi"));
        stream.write_all(&bytes).await.unwrap();
        let mut sink = [0u8; 16];
        let _ = stream.read(&mut sink).await;
    })
    .await;

    let (response, stream) = within(connect_stream(
        &test_url(port),
        &[],
        &TlsConfig::default(),
        &WsConnectOptions::default(),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 101);

    let mut conn = WsConnection::new(stream, response, 0);
    assert_eq!(conn.response().status(), 101);

    let mut buf = [0u8; 64];
    let (n, meta) = within(conn.recv(&mut buf)).await.unwrap().expect("pipelined frame");
    assert_eq!(&buf[..n], b"hi");
    assert_eq!(meta.flags, ws_flags::TEXT);

    drop(conn);
    within(server).await.unwrap();
}

// --- transfer(): 101 response headers preserved ---

#[tokio::test]
async fn transfer_preserves_response_status_and_headers() {
    let (port, server) = spawn_server(|mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Server: ws-mock/1\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs=\r\n\r\n",
            )
            .await
            .unwrap();
        stream.write_all(&server_frame(0x81, b"x")).await.unwrap();
    })
    .await;

    let response = run_transfer(port, None).await.unwrap();
    assert_eq!(response.status(), 101);
    assert_eq!(response.header("server"), Some("ws-mock/1"));
    assert_eq!(response.header("upgrade"), Some("websocket"));
    assert_eq!(response.body(), b"x");

    within(server).await.unwrap();
}

// --- Easy connect-only API (sync; server on a std thread) ---

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

/// Read one masked client frame from a std stream: `(first_byte, payload)`.
fn read_client_frame_sync(stream: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
    use std::io::Read as _;
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[1] & 0x80, 0x80, "client frames must be masked (RFC 6455)");
    let mut len = u64::from(header[1] & 0x7F);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).unwrap();
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).unwrap();
        len = u64::from_be_bytes(ext);
    }
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).unwrap();
    let mut payload = vec![0u8; usize::try_from(len).unwrap()];
    stream.read_exact(&mut payload).unwrap();
    unmask(mask, &mut payload);
    (header[0], payload)
}

#[test]
fn easy_connect_only_ws_round_trip() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        read_upgrade_request_sync(&mut stream);
        stream.write_all(HANDSHAKE_101).unwrap();
        let frame = read_client_frame_sync(&mut stream);
        stream.write_all(&server_frame(0x81, b"world")).unwrap();
        // Dropping the stream closes the connection.
        frame
    });

    let mut easy = liburlx::Easy::new();
    easy.url(&format!("ws://127.0.0.1:{port}/chat")).unwrap();
    easy.set_connect_only(2);
    let response = easy.perform().unwrap();
    assert_eq!(response.status(), 101);

    assert_eq!(easy.ws_send(b"hello", ws_flags::TEXT).unwrap(), 5);

    let mut buf = [0u8; 64];
    let (n, meta) = easy.ws_recv(&mut buf).unwrap().expect("server frame expected");
    assert_eq!(&buf[..n], b"world");
    assert_eq!(meta.flags, ws_flags::TEXT);
    assert_eq!((meta.len, meta.offset, meta.bytesleft), (5, 0, 0));

    // ws_meta reports the same chunk metadata.
    let stored = easy.ws_meta().expect("meta after ws_recv");
    assert_eq!(stored.flags, meta.flags);
    assert_eq!(stored.len, meta.len);
    assert_eq!(stored.offset, meta.offset);
    assert_eq!(stored.bytesleft, meta.bytesleft);

    // Server closed after its reply: clean end of connection.
    assert!(easy.ws_recv(&mut buf).unwrap().is_none());

    let (first_byte, payload) = server.join().unwrap();
    assert_eq!(first_byte, 0x81, "client TEXT frame expected");
    assert_eq!(payload, b"hello");
}

#[test]
fn easy_ws_send_without_connection_fails() {
    let mut easy = liburlx::Easy::new();
    // curl_ws_send without a connection fails with CURLE_SEND_ERROR (55);
    // curl_ws_recv fails with CURLE_UNSUPPORTED_PROTOCOL (1).
    let err = easy.ws_send(b"x", ws_flags::TEXT).unwrap_err();
    assert_eq!(transfer_error(&err).0, 55, "CURLE_SEND_ERROR");

    let mut buf = [0u8; 8];
    let err = easy.ws_recv(&mut buf).unwrap_err();
    assert_eq!(transfer_error(&err).0, 1, "CURLE_UNSUPPORTED_PROTOCOL");
}

#[test]
fn easy_connect_only_mode_one_fails_not_built_in() {
    // Mode 1 (raw connect-only) is unsupported even for ws URLs; the check
    // happens before any connection so no server is needed.
    let mut easy = liburlx::Easy::new();
    easy.url("ws://127.0.0.1:1/").unwrap();
    easy.set_connect_only(1);
    let err = easy.perform().unwrap_err();
    assert_eq!(transfer_error(&err).0, 4, "CURLE_NOT_BUILT_IN");
}

#[test]
fn easy_connect_only_ws_mode_on_http_url_fails_not_built_in() {
    let mut easy = liburlx::Easy::new();
    easy.url("http://127.0.0.1:1/").unwrap();
    easy.set_connect_only(2);
    let err = easy.perform().unwrap_err();
    assert_eq!(transfer_error(&err).0, 4, "CURLE_NOT_BUILT_IN");
}
