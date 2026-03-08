//! IMAP protocol edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::imap::ImapResponse;

// --- ImapResponse tests ---

#[test]
fn imap_response_ok_status() {
    let resp = ImapResponse {
        tag: "A001".to_string(),
        status: "OK".to_string(),
        message: "SELECT completed".to_string(),
        data: Vec::new(),
    };
    assert!(resp.is_ok());
}

#[test]
fn imap_response_ok_case_insensitive() {
    let resp = ImapResponse {
        tag: "A001".to_string(),
        status: "ok".to_string(),
        message: "done".to_string(),
        data: Vec::new(),
    };
    assert!(resp.is_ok());
}

#[test]
fn imap_response_no_status() {
    let resp = ImapResponse {
        tag: "A001".to_string(),
        status: "NO".to_string(),
        message: "Authentication failed".to_string(),
        data: Vec::new(),
    };
    assert!(!resp.is_ok());
}

#[test]
fn imap_response_bad_status() {
    let resp = ImapResponse {
        tag: "A001".to_string(),
        status: "BAD".to_string(),
        message: "Command error".to_string(),
        data: Vec::new(),
    };
    assert!(!resp.is_ok());
}

#[test]
fn imap_response_with_data() {
    let resp = ImapResponse {
        tag: "A002".to_string(),
        status: "OK".to_string(),
        message: "FETCH completed".to_string(),
        data: vec![
            "* 1 EXISTS".to_string(),
            "* 2 EXISTS".to_string(),
            "* FLAGS (\\Seen \\Answered)".to_string(),
        ],
    };
    assert!(resp.is_ok());
    assert_eq!(resp.data.len(), 3);
    assert!(resp.data[0].contains("EXISTS"));
}

#[test]
fn imap_response_debug() {
    let resp = ImapResponse {
        tag: "A001".to_string(),
        status: "OK".to_string(),
        message: "test".to_string(),
        data: Vec::new(),
    };
    let debug = format!("{resp:?}");
    assert!(debug.contains("A001"));
    assert!(debug.contains("OK"));
}
