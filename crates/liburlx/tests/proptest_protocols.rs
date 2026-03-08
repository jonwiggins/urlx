//! Property-based tests for SMTP, POP3, IMAP, and MQTT protocol codecs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use tokio::io::BufReader;

// --- SMTP property tests ---

proptest! {
    #[test]
    fn smtp_response_code_categories(code in 200u16..600) {
        let data = format!("{code} Test message\r\n");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut reader = BufReader::new(std::io::Cursor::new(data.into_bytes()));
            liburlx::protocol::smtp::read_response(&mut reader).await
        });
        if let Ok(resp) = result {
            prop_assert_eq!(resp.code, code);
            if (200..300).contains(&code) {
                prop_assert!(resp.is_ok());
                prop_assert!(!resp.is_intermediate());
            } else if (300..400).contains(&code) {
                prop_assert!(resp.is_intermediate());
                prop_assert!(!resp.is_ok());
            } else {
                prop_assert!(!resp.is_ok());
                prop_assert!(!resp.is_intermediate());
            }
        }
    }

    #[test]
    fn smtp_send_command_appends_crlf(cmd in "[A-Z]{4,10}( [a-z@.<>]{1,30})?") {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let buf = rt.block_on(async {
            let mut buf = Vec::new();
            liburlx::protocol::smtp::send_command(&mut buf, &cmd).await.unwrap();
            buf
        });
        let expected = format!("{cmd}\r\n");
        prop_assert_eq!(buf, expected.as_bytes());
    }
}

// --- POP3 property tests ---

proptest! {
    #[test]
    fn pop3_ok_response_parsed(msg in "[a-zA-Z0-9 ]{0,50}") {
        let data = format!("+OK {msg}\r\n");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut reader = BufReader::new(std::io::Cursor::new(data.into_bytes()));
            liburlx::protocol::pop3::read_response(&mut reader).await
        });
        let resp = result.unwrap();
        prop_assert!(resp.ok);
    }

    #[test]
    fn pop3_err_response_parsed(msg in "[a-zA-Z0-9 ]{0,50}") {
        let data = format!("-ERR {msg}\r\n");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut reader = BufReader::new(std::io::Cursor::new(data.into_bytes()));
            liburlx::protocol::pop3::read_response(&mut reader).await
        });
        let resp = result.unwrap();
        prop_assert!(!resp.ok);
    }

    #[test]
    fn pop3_send_command_appends_crlf(cmd in "[A-Z]{3,6}( [a-z0-9]{1,20})?") {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let buf = rt.block_on(async {
            let mut buf = Vec::new();
            liburlx::protocol::pop3::send_command(&mut buf, &cmd).await.unwrap();
            buf
        });
        let expected = format!("{cmd}\r\n");
        prop_assert_eq!(buf, expected.as_bytes());
    }
}

// --- IMAP property tests ---

proptest! {
    #[test]
    fn imap_ok_status_case_insensitive(tag in "A[0-9]{3}") {
        for status in ["OK", "ok", "Ok", "oK"] {
            let resp = liburlx::protocol::imap::ImapResponse {
                tag: tag.clone(),
                status: status.to_string(),
                message: "done".to_string(),
                data: Vec::new(),
            };
            prop_assert!(resp.is_ok(), "status '{}' should be OK", status);
        }
    }

    #[test]
    fn imap_non_ok_status(status in "(NO|BAD|PREAUTH|BYE)") {
        let resp = liburlx::protocol::imap::ImapResponse {
            tag: "A001".to_string(),
            status,
            message: "test".to_string(),
            data: Vec::new(),
        };
        prop_assert!(!resp.is_ok());
    }

    #[test]
    fn imap_response_preserves_data(n in 0usize..20) {
        let data: Vec<String> = (0..n).map(|i| format!("* {i} EXISTS")).collect();
        let resp = liburlx::protocol::imap::ImapResponse {
            tag: "A001".to_string(),
            status: "OK".to_string(),
            message: "done".to_string(),
            data,
        };
        prop_assert_eq!(resp.data.len(), n);
    }
}

// --- MQTT property tests ---

proptest! {
    #[test]
    fn mqtt_packet_type_roundtrip(val in prop::sample::select(vec![1u8, 2, 3, 4, 8, 9, 14])) {
        let pt = match val {
            1 => liburlx::protocol::mqtt::PacketType::Connect,
            2 => liburlx::protocol::mqtt::PacketType::Connack,
            3 => liburlx::protocol::mqtt::PacketType::Publish,
            4 => liburlx::protocol::mqtt::PacketType::Puback,
            8 => liburlx::protocol::mqtt::PacketType::Subscribe,
            9 => liburlx::protocol::mqtt::PacketType::Suback,
            14 => liburlx::protocol::mqtt::PacketType::Disconnect,
            _ => unreachable!(),
        };
        prop_assert_eq!(pt as u8, val);
    }

    #[test]
    fn mqtt_packet_type_debug_contains_name(val in prop::sample::select(vec![1u8, 2, 3, 4, 8, 9, 14])) {
        let (pt, name) = match val {
            1 => (liburlx::protocol::mqtt::PacketType::Connect, "Connect"),
            2 => (liburlx::protocol::mqtt::PacketType::Connack, "Connack"),
            3 => (liburlx::protocol::mqtt::PacketType::Publish, "Publish"),
            4 => (liburlx::protocol::mqtt::PacketType::Puback, "Puback"),
            8 => (liburlx::protocol::mqtt::PacketType::Subscribe, "Subscribe"),
            9 => (liburlx::protocol::mqtt::PacketType::Suback, "Suback"),
            14 => (liburlx::protocol::mqtt::PacketType::Disconnect, "Disconnect"),
            _ => unreachable!(),
        };
        let debug = format!("{pt:?}");
        prop_assert!(debug.contains(name));
    }
}
