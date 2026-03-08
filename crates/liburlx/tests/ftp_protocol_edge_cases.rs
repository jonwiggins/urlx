//! FTP protocol parsing edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::io::BufReader;

use liburlx::protocol::ftp::{
    parse_epsv_response, parse_pasv_response, read_response, send_command,
};

// --- PASV response parsing ---

#[test]
fn pasv_standard_format() {
    let msg = "Entering Passive Mode (192,168,1,1,4,1)";
    let (host, port) = parse_pasv_response(msg).unwrap();
    assert_eq!(host, "192.168.1.1");
    assert_eq!(port, 1025); // 4*256 + 1
}

#[test]
fn pasv_port_zero() {
    let msg = "Entering Passive Mode (10,0,0,1,0,21)";
    let (host, port) = parse_pasv_response(msg).unwrap();
    assert_eq!(host, "10.0.0.1");
    assert_eq!(port, 21);
}

#[test]
fn pasv_high_port() {
    let msg = "Entering Passive Mode (127,0,0,1,255,255)";
    let (host, port) = parse_pasv_response(msg).unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 65535);
}

#[test]
fn pasv_with_extra_text() {
    let msg = "227 Entering Passive Mode (1,2,3,4,5,6). Some extra stuff.";
    let (host, port) = parse_pasv_response(msg).unwrap();
    assert_eq!(host, "1.2.3.4");
    assert_eq!(port, 1286); // 5*256 + 6
}

#[test]
fn pasv_missing_parens() {
    let msg = "Entering Passive Mode 1,2,3,4,5,6";
    assert!(parse_pasv_response(msg).is_err());
}

#[test]
fn pasv_incomplete_numbers() {
    let msg = "Entering Passive Mode (1,2,3)";
    assert!(parse_pasv_response(msg).is_err());
}

#[test]
fn pasv_no_numbers() {
    let msg = "Entering Passive Mode ()";
    assert!(parse_pasv_response(msg).is_err());
}

// --- EPSV response parsing ---

#[test]
fn epsv_standard_format() {
    let msg = "Entering Extended Passive Mode (|||6446|)";
    let port = parse_epsv_response(msg).unwrap();
    assert_eq!(port, 6446);
}

#[test]
fn epsv_port_21() {
    let msg = "Entering Extended Passive Mode (|||21|)";
    let port = parse_epsv_response(msg).unwrap();
    assert_eq!(port, 21);
}

#[test]
fn epsv_high_port() {
    let msg = "(|||65535|)";
    let port = parse_epsv_response(msg).unwrap();
    assert_eq!(port, 65535);
}

#[test]
fn epsv_missing_delimiter() {
    let msg = "No delimiters here";
    assert!(parse_epsv_response(msg).is_err());
}

#[test]
fn epsv_missing_closing_delimiter() {
    let msg = "|||1234";
    assert!(parse_epsv_response(msg).is_err());
}

#[test]
fn epsv_non_numeric_port() {
    let msg = "|||abc|";
    assert!(parse_epsv_response(msg).is_err());
}

// --- FTP response reading ---

#[tokio::test]
async fn read_simple_220_greeting() {
    let data = b"220 Welcome to FTP server\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 220);
    assert_eq!(resp.message, "Welcome to FTP server");
}

#[tokio::test]
async fn read_multiline_response() {
    let data = b"220-Welcome\r\n220-to the\r\n220 FTP server\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 220);
    assert!(resp.message.contains("Welcome"));
    assert!(resp.message.contains("FTP server"));
}

#[tokio::test]
async fn read_331_user_ok() {
    let data = b"331 User name okay, need password\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 331);
    assert!(resp.is_intermediate());
}

#[tokio::test]
async fn read_230_login_ok() {
    let data = b"230 Login successful\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 230);
    assert!(resp.is_complete());
}

#[tokio::test]
async fn read_150_preliminary() {
    let data = b"150 Opening data connection\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 150);
    assert!(resp.is_preliminary());
}

#[tokio::test]
async fn read_530_not_logged_in() {
    let data = b"530 Not logged in\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 530);
    assert!(!resp.is_complete());
    assert!(!resp.is_preliminary());
    assert!(!resp.is_intermediate());
}

#[tokio::test]
async fn read_empty_connection_error() {
    let data = b"";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let result = read_response(&mut reader).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn read_multiple_responses_in_sequence() {
    let data = b"220 Welcome\r\n331 Password required\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));

    let resp1 = read_response(&mut reader).await.unwrap();
    assert_eq!(resp1.code, 220);

    let resp2 = read_response(&mut reader).await.unwrap();
    assert_eq!(resp2.code, 331);
}

// --- FTP response category checks ---

#[tokio::test]
async fn response_categories() {
    // 1xx = preliminary
    let data = b"125 Data connection already open\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(resp.is_preliminary());
    assert!(!resp.is_complete());
    assert!(!resp.is_intermediate());

    // 2xx = complete
    let data = b"250 Directory changed\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(!resp.is_preliminary());
    assert!(resp.is_complete());
    assert!(!resp.is_intermediate());

    // 3xx = intermediate
    let data = b"350 Ready for RNTO\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(!resp.is_preliminary());
    assert!(!resp.is_complete());
    assert!(resp.is_intermediate());
}

// --- send_command ---

#[tokio::test]
async fn send_command_appends_crlf() {
    let mut buf = Vec::new();
    send_command(&mut buf, "USER anonymous").await.unwrap();
    assert_eq!(buf, b"USER anonymous\r\n");
}

#[tokio::test]
async fn send_command_empty_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "").await.unwrap();
    assert_eq!(buf, b"\r\n");
}

#[tokio::test]
async fn send_command_with_spaces() {
    let mut buf = Vec::new();
    send_command(&mut buf, "RETR /path/to/file.txt").await.unwrap();
    assert_eq!(buf, b"RETR /path/to/file.txt\r\n");
}

// --- PASV with spaces around numbers ---

#[test]
fn pasv_with_spaces() {
    let msg = "Entering Passive Mode ( 192, 168, 1, 1, 4, 1 )";
    let (host, port) = parse_pasv_response(msg).unwrap();
    assert_eq!(host, "192.168.1.1");
    assert_eq!(port, 1025);
}

// --- Multiline response with blank continuation lines ---

#[tokio::test]
async fn multiline_response_with_text_between() {
    let data = b"220-Welcome to FTP\r\nPlease read the rules.\r\n220 Ready.\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert_eq!(resp.code, 220);
    assert!(resp.message.contains("Welcome to FTP"));
    assert!(resp.message.contains("Please read the rules."));
    assert!(resp.message.contains("Ready."));
}
