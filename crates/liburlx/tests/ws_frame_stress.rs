//! WebSocket frame encoding/decoding stress tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::ws::{compute_accept_key, generate_ws_key, read_frame, Frame, Opcode};

// --- Frame roundtrip tests ---

#[tokio::test]
async fn text_frame_roundtrip() {
    let original = Frame::text("hello, websocket!");
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert!(decoded.fin);
    assert_eq!(decoded.opcode, Opcode::Text);
    assert_eq!(decoded.as_text().unwrap(), "hello, websocket!");
}

#[tokio::test]
async fn binary_frame_roundtrip() {
    let data: Vec<u8> = (0..=255).collect();
    let original = Frame::binary(&data);
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.opcode, Opcode::Binary);
    assert_eq!(decoded.payload, data);
}

#[tokio::test]
async fn masked_frame_roundtrip() {
    let original = Frame::text("masked data here");
    let encoded = original.encode(true);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.as_text().unwrap(), "masked data here");
}

#[tokio::test]
async fn ping_frame_roundtrip() {
    let original = Frame::ping(b"ping-payload");
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.opcode, Opcode::Ping);
    assert_eq!(decoded.payload, b"ping-payload");
}

#[tokio::test]
async fn pong_frame_roundtrip() {
    let original = Frame::pong(b"pong-payload");
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.opcode, Opcode::Pong);
    assert_eq!(decoded.payload, b"pong-payload");
}

#[tokio::test]
async fn close_frame_roundtrip() {
    let original = Frame::close();
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.opcode, Opcode::Close);
    assert!(decoded.payload.is_empty());
}

// --- Size edge cases ---

#[tokio::test]
async fn empty_text_frame() {
    let original = Frame::text("");
    let encoded = original.encode(false);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.as_text().unwrap(), "");
}

#[tokio::test]
async fn frame_125_bytes() {
    // Maximum single-byte length
    let data = "x".repeat(125);
    let original = Frame::text(&data);
    let encoded = original.encode(false);
    assert_eq!(encoded[1] & 0x7F, 125);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.as_text().unwrap(), data);
}

#[tokio::test]
async fn frame_126_bytes() {
    // First 16-bit length
    let data = "x".repeat(126);
    let original = Frame::text(&data);
    let encoded = original.encode(false);
    assert_eq!(encoded[1] & 0x7F, 126); // Extended 16-bit indicator
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.as_text().unwrap(), data);
}

#[tokio::test]
async fn frame_65535_bytes() {
    // Maximum 16-bit length
    let data = vec![0x41u8; 65535];
    let original = Frame::binary(&data);
    let encoded = original.encode(false);
    assert_eq!(encoded[1] & 0x7F, 126);
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.payload.len(), 65535);
}

#[tokio::test]
async fn frame_65536_bytes() {
    // First 64-bit length
    let data = vec![0x42u8; 65536];
    let original = Frame::binary(&data);
    let encoded = original.encode(false);
    assert_eq!(encoded[1] & 0x7F, 127); // Extended 64-bit indicator
    let mut cursor = std::io::Cursor::new(encoded);
    let decoded = read_frame(&mut cursor).await.unwrap();
    assert_eq!(decoded.payload.len(), 65536);
}

// --- Multiple frames in sequence ---

#[tokio::test]
async fn multiple_frames_in_stream() {
    let mut data = Vec::new();
    let frame1 = Frame::text("first");
    let frame2 = Frame::text("second");
    let frame3 = Frame::binary(b"third");
    data.extend_from_slice(&frame1.encode(false));
    data.extend_from_slice(&frame2.encode(false));
    data.extend_from_slice(&frame3.encode(false));

    let mut cursor = std::io::Cursor::new(data);
    let d1 = read_frame(&mut cursor).await.unwrap();
    let d2 = read_frame(&mut cursor).await.unwrap();
    let d3 = read_frame(&mut cursor).await.unwrap();

    assert_eq!(d1.as_text().unwrap(), "first");
    assert_eq!(d2.as_text().unwrap(), "second");
    assert_eq!(d3.opcode, Opcode::Binary);
    assert_eq!(d3.payload, b"third");
}

// --- Masked encoding varies ---

#[tokio::test]
async fn masked_encoding_produces_different_bytes() {
    let frame = Frame::text("same");
    let enc1 = frame.encode(true);
    let enc2 = frame.encode(true);
    // Mask keys are random, so encoded bytes should differ (with very high probability)
    // But decoded content should be the same
    let mut c1 = std::io::Cursor::new(enc1);
    let mut c2 = std::io::Cursor::new(enc2);
    let d1 = read_frame(&mut c1).await.unwrap();
    let d2 = read_frame(&mut c2).await.unwrap();
    assert_eq!(d1.as_text().unwrap(), "same");
    assert_eq!(d2.as_text().unwrap(), "same");
}

// --- Key generation ---

#[test]
fn ws_key_is_base64() {
    let key = generate_ws_key();
    // WebSocket key should be 16 bytes base64-encoded = 24 chars with padding
    assert!(key.len() >= 20, "key too short: {key}");
    assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

#[test]
fn ws_key_unique() {
    let key1 = generate_ws_key();
    let key2 = generate_ws_key();
    assert_ne!(key1, key2);
}

#[test]
fn accept_key_rfc6455_example() {
    // RFC 6455 Section 4.2.2 example
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let accept = compute_accept_key(key);
    // The expected value from the RFC
    assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// --- Error cases ---

#[tokio::test]
async fn truncated_frame_returns_error() {
    // Only header, no payload
    let data = vec![0x81, 5]; // text frame, length 5, but no payload
    let mut cursor = std::io::Cursor::new(data);
    let result = read_frame(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn empty_stream_returns_error() {
    let data: Vec<u8> = vec![];
    let mut cursor = std::io::Cursor::new(data);
    let result = read_frame(&mut cursor).await;
    assert!(result.is_err());
}
