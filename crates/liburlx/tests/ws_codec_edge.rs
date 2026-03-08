//! WebSocket codec edge case tests.
//!
//! Tests frame construction, encoding, text/binary types, close/ping/pong
//! frames, UTF-8 validation, and key generation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::ws::{compute_accept_key, generate_ws_key, Frame, Opcode};

// --- Frame construction ---

#[test]
fn text_frame_has_correct_opcode() {
    let frame = Frame::text("hello");
    assert!(frame.fin);
    assert!(matches!(frame.opcode, Opcode::Text));
    assert_eq!(frame.payload, b"hello");
}

#[test]
fn binary_frame_has_correct_opcode() {
    let frame = Frame::binary(&[1, 2, 3]);
    assert!(frame.fin);
    assert!(matches!(frame.opcode, Opcode::Binary));
    assert_eq!(frame.payload, &[1, 2, 3]);
}

#[test]
fn close_frame_is_empty() {
    let frame = Frame::close();
    assert!(frame.fin);
    assert!(matches!(frame.opcode, Opcode::Close));
    assert!(frame.payload.is_empty());
}

#[test]
fn ping_frame_with_data() {
    let frame = Frame::ping(b"heartbeat");
    assert!(frame.fin);
    assert!(matches!(frame.opcode, Opcode::Ping));
    assert_eq!(frame.payload, b"heartbeat");
}

#[test]
fn pong_frame_with_data() {
    let frame = Frame::pong(b"heartbeat");
    assert!(frame.fin);
    assert!(matches!(frame.opcode, Opcode::Pong));
    assert_eq!(frame.payload, b"heartbeat");
}

#[test]
fn ping_frame_empty() {
    let frame = Frame::ping(b"");
    assert!(matches!(frame.opcode, Opcode::Ping));
    assert!(frame.payload.is_empty());
}

#[test]
fn pong_frame_empty() {
    let frame = Frame::pong(b"");
    assert!(matches!(frame.opcode, Opcode::Pong));
    assert!(frame.payload.is_empty());
}

// --- as_text ---

#[test]
fn text_frame_as_text_valid() {
    let frame = Frame::text("Hello, World!");
    assert_eq!(frame.as_text().unwrap(), "Hello, World!");
}

#[test]
fn text_frame_as_text_unicode() {
    let frame = Frame::text("Hello world");
    assert_eq!(frame.as_text().unwrap(), "Hello world");
}

#[test]
fn binary_frame_as_text_invalid_utf8() {
    let frame = Frame::binary(&[0xFF, 0xFE, 0xFD]);
    assert!(frame.as_text().is_err());
}

#[test]
fn text_frame_as_text_empty() {
    let frame = Frame::text("");
    assert_eq!(frame.as_text().unwrap(), "");
}

// --- Encoding ---

#[test]
fn encoded_frame_starts_with_opcode_byte() {
    let frame = Frame::text("hi");
    // unmasked for easier testing
    let encoded = frame.encode(false);
    // First byte: FIN=1 + opcode=0x01 = 0x81
    assert_eq!(encoded[0], 0x81);
}

#[test]
fn encoded_unmasked_has_correct_length_byte() {
    let frame = Frame::text("hi");
    let encoded = frame.encode(false);
    // Second byte: mask=0, length=2
    assert_eq!(encoded[1], 2);
}

#[test]
fn encoded_unmasked_payload_follows() {
    let frame = Frame::text("hi");
    let encoded = frame.encode(false);
    assert_eq!(&encoded[2..], b"hi");
}

#[test]
fn encoded_masked_has_mask_bit() {
    let frame = Frame::text("hi");
    let encoded = frame.encode(true);
    // Second byte should have mask bit set (0x80)
    assert_eq!(encoded[1] & 0x80, 0x80);
}

#[test]
fn encoded_masked_has_four_byte_mask_key() {
    let frame = Frame::text("hi");
    let encoded = frame.encode(true);
    // Length byte: 0x82 (mask=1, len=2)
    let len = (encoded[1] & 0x7F) as usize;
    assert_eq!(len, 2);
    // Mask key is 4 bytes at offset 2
    // Masked payload is 2 bytes at offset 6
    assert_eq!(encoded.len(), 2 + 4 + 2); // header + mask + payload
}

#[test]
fn encoded_close_frame_is_minimal() {
    let frame = Frame::close();
    let encoded = frame.encode(false);
    assert_eq!(encoded[0], 0x88); // FIN=1 + opcode=0x08
    assert_eq!(encoded[1], 0); // no payload
    assert_eq!(encoded.len(), 2);
}

#[test]
fn encoded_binary_frame_opcode() {
    let frame = Frame::binary(b"data");
    let encoded = frame.encode(false);
    assert_eq!(encoded[0], 0x82); // FIN=1 + opcode=0x02
}

#[test]
fn encoded_ping_frame_opcode() {
    let frame = Frame::ping(b"");
    let encoded = frame.encode(false);
    assert_eq!(encoded[0], 0x89); // FIN=1 + opcode=0x09
}

#[test]
fn encoded_pong_frame_opcode() {
    let frame = Frame::pong(b"");
    let encoded = frame.encode(false);
    assert_eq!(encoded[0], 0x8A); // FIN=1 + opcode=0x0A
}

// --- Medium-sized payload (126-byte extended length) ---

#[test]
fn encoded_medium_payload_uses_16bit_length() {
    let data = vec![b'x'; 200];
    let frame = Frame::binary(&data);
    let encoded = frame.encode(false);
    // Second byte should be 126 (indicating 16-bit length follows)
    assert_eq!(encoded[1], 126);
    // Next 2 bytes are big-endian length
    let len = u16::from_be_bytes([encoded[2], encoded[3]]);
    assert_eq!(len, 200);
}

// --- Large payload (64-bit extended length) ---

#[test]
fn encoded_large_payload_uses_64bit_length() {
    let data = vec![b'x'; 70_000];
    let frame = Frame::binary(&data);
    let encoded = frame.encode(false);
    // Second byte should be 127 (indicating 64-bit length follows)
    assert_eq!(encoded[1], 127);
    // Next 8 bytes are big-endian length
    let len_bytes: [u8; 8] = encoded[2..10].try_into().unwrap();
    let len = u64::from_be_bytes(len_bytes);
    assert_eq!(len, 70_000);
}

// --- Key generation ---

#[test]
fn generate_ws_key_is_base64() {
    let key = generate_ws_key();
    // WebSocket key should be 16 bytes base64-encoded = 24 chars with padding
    assert!(!key.is_empty());
    // Should be valid base64
    assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

#[test]
fn generate_ws_key_different_each_time() {
    let key1 = generate_ws_key();
    let key2 = generate_ws_key();
    // Keys should be different (extremely unlikely to collide)
    assert_ne!(key1, key2);
}

// --- Accept key computation ---

#[test]
fn compute_accept_key_rfc6455_example() {
    // RFC 6455 example
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let accept = compute_accept_key(key);
    assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn compute_accept_key_deterministic() {
    let key = "testkey123==";
    let accept1 = compute_accept_key(key);
    let accept2 = compute_accept_key(key);
    assert_eq!(accept1, accept2);
}

#[test]
fn compute_accept_key_different_inputs() {
    let accept1 = compute_accept_key("key1==");
    let accept2 = compute_accept_key("key2==");
    assert_ne!(accept1, accept2);
}

// --- Opcode debug ---

#[test]
fn opcode_debug_format() {
    assert!(format!("{:?}", Opcode::Text).contains("Text"));
    assert!(format!("{:?}", Opcode::Binary).contains("Binary"));
    assert!(format!("{:?}", Opcode::Close).contains("Close"));
    assert!(format!("{:?}", Opcode::Ping).contains("Ping"));
    assert!(format!("{:?}", Opcode::Pong).contains("Pong"));
    assert!(format!("{:?}", Opcode::Continuation).contains("Continuation"));
}
