//! SMTP protocol edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::io::BufReader;

use liburlx::protocol::smtp::{read_response, send_command};

// --- Response reading ---

#[tokio::test]
async fn read_220_greeting() {
    let data = b"220 smtp.example.com ESMTP ready\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 220);
    assert!(resp.is_ok());
    assert!(resp.message.contains("ESMTP"));
}

#[tokio::test]
async fn read_250_ehlo_multiline() {
    let data = b"250-smtp.example.com\r\n250-SIZE 35882577\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 250);
    assert!(resp.is_ok());
    assert!(resp.message.contains("AUTH PLAIN LOGIN"));
}

#[tokio::test]
async fn read_354_data_intermediate() {
    let data = b"354 End data with <CR><LF>.<CR><LF>\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 354);
    assert!(resp.is_intermediate());
    assert!(!resp.is_ok());
}

#[tokio::test]
async fn read_535_auth_failure() {
    let data = b"535 Authentication failed\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 535);
    assert!(!resp.is_ok());
    assert!(!resp.is_intermediate());
}

#[tokio::test]
async fn read_421_service_unavailable() {
    let data = b"421 Service not available, closing transmission channel\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 421);
}

#[tokio::test]
async fn read_empty_stream_error() {
    let data = b"";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let result = read_response(&mut reader).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn read_multiple_responses_sequential() {
    let data = b"220 Ready\r\n250 OK\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));

    let r1 = read_response(&mut reader).await.unwrap();
    assert_eq!(r1.code, 220);

    let r2 = read_response(&mut reader).await.unwrap();
    assert_eq!(r2.code, 250);
}

// --- Response status categories ---

#[tokio::test]
async fn response_2xx_is_ok() {
    for code in [200, 211, 220, 221, 250, 251, 252] {
        let data = format!("{code} Test\r\n");
        let mut reader = BufReader::new(std::io::Cursor::new(data.into_bytes()));
        let resp = read_response(&mut reader).await.unwrap();
        assert!(resp.is_ok(), "code {code} should be ok");
        assert!(!resp.is_intermediate(), "code {code} should not be intermediate");
    }
}

#[tokio::test]
async fn response_3xx_is_intermediate() {
    for code in [334, 354] {
        let data = format!("{code} Test\r\n");
        let mut reader = BufReader::new(std::io::Cursor::new(data.into_bytes()));
        let resp = read_response(&mut reader).await.unwrap();
        assert!(resp.is_intermediate(), "code {code} should be intermediate");
        assert!(!resp.is_ok(), "code {code} should not be ok");
    }
}

// --- send_command ---

#[tokio::test]
async fn send_ehlo_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "EHLO localhost").await.unwrap();
    assert_eq!(buf, b"EHLO localhost\r\n");
}

#[tokio::test]
async fn send_mail_from_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "MAIL FROM:<sender@example.com>").await.unwrap();
    assert_eq!(buf, b"MAIL FROM:<sender@example.com>\r\n");
}

#[tokio::test]
async fn send_data_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "DATA").await.unwrap();
    assert_eq!(buf, b"DATA\r\n");
}

#[tokio::test]
async fn send_quit_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "QUIT").await.unwrap();
    assert_eq!(buf, b"QUIT\r\n");
}
