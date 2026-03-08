//! Property-based tests for the WebSocket frame codec.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use liburlx::protocol::ws::{read_frame, Frame, Opcode};

proptest! {
    /// Any text frame roundtrips through encode → decode.
    #[test]
    fn text_frame_roundtrip(text in "[a-zA-Z0-9 ]{0,200}") {
        let frame = Frame::text(&text);
        let encoded = frame.encode(false);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        prop_assert_eq!(decoded.as_text().unwrap(), text.as_str());
        prop_assert_eq!(decoded.opcode, Opcode::Text);
        prop_assert!(decoded.fin);
    }

    /// Any binary frame roundtrips through encode → decode.
    #[test]
    fn binary_frame_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..500)) {
        let frame = Frame::binary(&data);
        let encoded = frame.encode(false);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        prop_assert_eq!(&decoded.payload, &data);
        prop_assert_eq!(decoded.opcode, Opcode::Binary);
    }

    /// Masked frames decode to the same payload as unmasked.
    #[test]
    fn masked_unmasked_same_payload(text in "[a-zA-Z0-9]{1,100}") {
        let frame = Frame::text(&text);
        let unmasked = frame.encode(false);
        let masked = frame.encode(true);

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (d_un, d_ma) = rt.block_on(async {
            let mut c1 = std::io::Cursor::new(unmasked);
            let mut c2 = std::io::Cursor::new(masked);
            let d1 = read_frame(&mut c1).await.unwrap();
            let d2 = read_frame(&mut c2).await.unwrap();
            (d1, d2)
        });

        prop_assert_eq!(d_un.as_text().unwrap(), d_ma.as_text().unwrap());
    }

    /// Frame length encoding always matches the payload size.
    #[test]
    fn encoded_length_consistent(len in 0usize..2000) {
        let data = vec![0x41u8; len];
        let frame = Frame::binary(&data);
        let encoded = frame.encode(false);

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        prop_assert_eq!(decoded.payload.len(), len);
    }

    /// Ping frames preserve arbitrary payload.
    #[test]
    fn ping_payload_preserved(data in proptest::collection::vec(any::<u8>(), 0..125)) {
        let frame = Frame::ping(&data);
        let encoded = frame.encode(false);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        prop_assert_eq!(&decoded.payload, &data);
        prop_assert_eq!(decoded.opcode, Opcode::Ping);
    }

    /// Pong frames preserve arbitrary payload.
    #[test]
    fn pong_payload_preserved(data in proptest::collection::vec(any::<u8>(), 0..125)) {
        let frame = Frame::pong(&data);
        let encoded = frame.encode(false);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        prop_assert_eq!(&decoded.payload, &data);
        prop_assert_eq!(decoded.opcode, Opcode::Pong);
    }
}
