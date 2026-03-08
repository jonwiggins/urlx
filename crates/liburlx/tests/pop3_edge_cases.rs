//! POP3 protocol edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::io::BufReader;

use liburlx::protocol::pop3::{read_multiline, read_response, send_command};

// --- Response reading ---

#[tokio::test]
async fn read_ok_response() {
    let data = b"+OK POP3 server ready\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(resp.ok);
    assert!(resp.message.contains("POP3 server ready"));
}

#[tokio::test]
async fn read_err_response() {
    let data = b"-ERR authentication failed\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(!resp.ok);
    assert!(resp.message.contains("authentication failed"));
}

#[tokio::test]
async fn read_ok_with_stats() {
    let data = b"+OK 3 messages (1234 octets)\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(resp.ok);
    assert!(resp.message.contains("3 messages"));
}

#[tokio::test]
async fn read_empty_ok() {
    let data = b"+OK\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let resp = read_response(&mut reader).await.unwrap();
    assert!(resp.ok);
}

#[tokio::test]
async fn read_empty_stream_error() {
    let data = b"";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let result = read_response(&mut reader).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn read_sequential_responses() {
    let data = b"+OK Ready\r\n+OK User accepted\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let r1 = read_response(&mut reader).await.unwrap();
    assert!(r1.ok);
    let r2 = read_response(&mut reader).await.unwrap();
    assert!(r2.ok);
}

// --- Multiline reading ---

#[tokio::test]
async fn multiline_basic_list() {
    let data = b"+OK 3 messages\r\n1 120\r\n2 250\r\n3 340\r\n.\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    // Read the initial response line
    let _resp = read_response(&mut reader).await.unwrap();
    // Read the multiline data
    let lines = read_multiline(&mut reader).await.unwrap();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("1 120"));
    assert!(lines[2].contains("3 340"));
}

#[tokio::test]
async fn multiline_empty() {
    let data = b".\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let lines = read_multiline(&mut reader).await.unwrap();
    assert!(lines.is_empty());
}

#[tokio::test]
async fn multiline_with_dot_stuffing() {
    let data = b"Hello\r\n..This had a dot\r\n.\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let lines = read_multiline(&mut reader).await.unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "Hello");
    assert_eq!(lines[1], ".This had a dot");
}

#[tokio::test]
async fn multiline_single_line() {
    let data = b"Just one line\r\n.\r\n";
    let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
    let lines = read_multiline(&mut reader).await.unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], "Just one line");
}

// --- send_command ---

#[tokio::test]
async fn send_user_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "USER testuser").await.unwrap();
    assert_eq!(buf, b"USER testuser\r\n");
}

#[tokio::test]
async fn send_pass_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "PASS secret123").await.unwrap();
    assert_eq!(buf, b"PASS secret123\r\n");
}

#[tokio::test]
async fn send_list_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "LIST").await.unwrap();
    assert_eq!(buf, b"LIST\r\n");
}

#[tokio::test]
async fn send_retr_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "RETR 1").await.unwrap();
    assert_eq!(buf, b"RETR 1\r\n");
}

#[tokio::test]
async fn send_quit_command() {
    let mut buf = Vec::new();
    send_command(&mut buf, "QUIT").await.unwrap();
    assert_eq!(buf, b"QUIT\r\n");
}

// --- Pop3Response struct ---

#[test]
fn pop3_response_ok_field() {
    let resp = liburlx::protocol::pop3::Pop3Response { ok: true, message: "success".to_string() };
    assert!(resp.ok);
    assert_eq!(resp.message, "success");
}

#[test]
fn pop3_response_err_field() {
    let resp = liburlx::protocol::pop3::Pop3Response { ok: false, message: "failed".to_string() };
    assert!(!resp.ok);
}
