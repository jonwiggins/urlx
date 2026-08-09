//! Deterministic WebSocket entropy tests (`CURL_ENTROPY` /
//! `CURL_WS_FORCE_ZERO_MASK`).
//!
//! This file must stay a separate integration test with exactly ONE test:
//! the entropy variables seed process-global once-latched state in liburlx,
//! so any other test in the same binary would observe (or disturb) the
//! deterministic sequence.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_results)]

use std::collections::HashMap;

use liburlx::protocol::ws::{generate_ws_key, ws_flags, WsConnection};
use liburlx::Response;
use tokio::io::AsyncReadExt;

#[test]
fn curl_entropy_pins_ws_key_and_frame_masks() {
    // Must happen before any key/mask generation: the seed is latched on
    // first use (curl compat: lib/rand.c static randseed).
    std::env::set_var("CURL_ENTROPY", "12345678");

    // Draws 1-4 (16 key bytes): the deterministic Sec-WebSocket-Key that
    // curl test 2300 pins for CURL_ENTROPY=12345678.
    assert_eq!(generate_ws_key(), "NDMyMTUzMjE2MzIxNzMyMQ==");

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (client, mut server) = tokio::io::duplex(4096);
        let response = Response::new(101, HashMap::new(), Vec::new(), "ws://test/".to_string());
        let mut conn = WsConnection::new(Box::new(client), response, 0);

        // Draw 5: the first frame mask after the key. Seed 0x31323334
        // ("1234" big-endian) has advanced four times; the fifth value
        // 0x31323338 serializes LSB-first as b"8321".
        assert_eq!(conn.send(b"hey", ws_flags::TEXT).await.unwrap(), 3);
        let mut wire = [0u8; 9];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[0], 0x81, "FIN + TEXT");
        assert_eq!(wire[1], 0x80 | 3, "mask bit + length 3");
        assert_eq!(&wire[2..6], b"8321", "deterministic mask key (fifth draw)");
        let mut payload = [wire[6], wire[7], wire[8]];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= wire[2 + (i % 4)];
        }
        assert_eq!(&payload, b"hey", "payload must be XOR-masked with the key");

        // CURL_WS_FORCE_ZERO_MASK zeroes the mask bytes but keeps the mask
        // bit set (curl compat: tests 2700+), so the payload rides the wire
        // verbatim.
        std::env::set_var("CURL_WS_FORCE_ZERO_MASK", "1");
        assert_eq!(conn.send(b"zero", ws_flags::BINARY).await.unwrap(), 4);
        let mut wire = [0u8; 10];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[0], 0x82, "FIN + BINARY");
        assert_eq!(wire[1], 0x80 | 4, "mask bit still set with a zero mask");
        assert_eq!(&wire[2..6], &[0, 0, 0, 0], "four zero mask bytes");
        assert_eq!(&wire[6..], b"zero", "zero mask leaves the payload unchanged");
    });
}
