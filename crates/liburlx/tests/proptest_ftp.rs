//! Property-based tests for FTP protocol parsing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use tokio::io::BufReader;

use liburlx::protocol::ftp::{parse_epsv_response, parse_pasv_response, read_response};

proptest! {
    /// PASV response with valid 6-tuple always parses to correct host and port.
    #[test]
    fn pasv_valid_six_tuple(
        h1 in 0u16..256,
        h2 in 0u16..256,
        h3 in 0u16..256,
        h4 in 0u16..256,
        p1 in 0u16..256,
        p2 in 0u16..256,
    ) {
        let msg = format!("Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})");
        let (host, port) = parse_pasv_response(&msg).unwrap();
        let expected_host = format!("{h1}.{h2}.{h3}.{h4}");
        let expected_port = p1 * 256 + p2;
        prop_assert_eq!(host, expected_host);
        prop_assert_eq!(port, expected_port);
    }

    /// EPSV response with valid port always parses correctly.
    #[test]
    fn epsv_valid_port(port in 1u16..=65535) {
        let msg = format!("Entering Extended Passive Mode (|||{port}|)");
        let parsed = parse_epsv_response(&msg).unwrap();
        prop_assert_eq!(parsed, port);
    }

    /// FTP response code categories are mutually exclusive.
    #[test]
    fn response_categories_exclusive(code in 100u16..600) {
        let msg = format!("{code} Test message\r\n");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let resp = rt.block_on(async {
            let mut reader = BufReader::new(std::io::Cursor::new(msg.into_bytes()));
            read_response(&mut reader).await.unwrap()
        });

        prop_assert_eq!(resp.code, code);

        let is_preliminary = resp.is_preliminary();
        let is_complete = resp.is_complete();
        let is_intermediate = resp.is_intermediate();

        // At most one should be true (for 4xx/5xx, none are true)
        let count = usize::from(is_preliminary) + usize::from(is_complete) + usize::from(is_intermediate);
        prop_assert!(count <= 1, "categories not exclusive for code {code}");

        // Verify correct category
        match code {
            100..=199 => prop_assert!(is_preliminary),
            200..=299 => prop_assert!(is_complete),
            300..=399 => prop_assert!(is_intermediate),
            _ => prop_assert_eq!(count, 0, "4xx/5xx should have no category"),
        }
    }

    /// Any valid 3-digit code with a single-line message can be read.
    #[test]
    fn any_three_digit_code_readable(code in 100u16..1000, msg in "[a-zA-Z0-9 ]{1,50}") {
        let raw = format!("{code} {msg}\r\n");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let resp = rt.block_on(async {
            let mut reader = BufReader::new(std::io::Cursor::new(raw.into_bytes()));
            read_response(&mut reader).await.unwrap()
        });
        prop_assert_eq!(resp.code, code);
        prop_assert_eq!(resp.message, msg);
    }
}
