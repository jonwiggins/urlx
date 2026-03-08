//! IMAP protocol handler.
//!
//! Implements a basic `IMAP4rev1` client (RFC 3501) for reading mailboxes.
//! Supports LOGIN, LIST, SELECT, and FETCH commands.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// An IMAP response from the server.
#[derive(Debug, Clone)]
pub struct ImapResponse {
    /// The tag that was used in the command (e.g., "A001").
    pub tag: String,
    /// The status: OK, NO, or BAD.
    pub status: String,
    /// The status text.
    pub message: String,
    /// Untagged response lines received before the tagged response.
    pub data: Vec<String>,
}

impl ImapResponse {
    /// Check if the response status is OK.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status.eq_ignore_ascii_case("OK")
    }
}

/// A simple tag counter for IMAP commands.
struct TagCounter {
    next: u32,
}

impl TagCounter {
    const fn new() -> Self {
        Self { next: 1 }
    }

    fn next_tag(&mut self) -> String {
        let tag = format!("A{:03}", self.next);
        self.next += 1;
        tag
    }
}

/// Read an IMAP response (untagged lines + tagged completion).
///
/// # Errors
///
/// Returns an error if the connection drops or the response is malformed.
async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    expected_tag: &str,
) -> Result<ImapResponse, Error> {
    let mut data = Vec::new();

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("IMAP read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("IMAP connection closed unexpectedly".to_string()));
        }

        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

        // Untagged response starts with "* "
        if let Some(untagged) = trimmed.strip_prefix("* ") {
            data.push(untagged.to_string());
            continue;
        }

        // Tagged response: "TAG STATUS message"
        if let Some(rest) = trimmed.strip_prefix(expected_tag) {
            let rest = rest.trim_start();
            let (status, message) = rest.split_once(' ').map_or_else(
                || (rest.to_string(), String::new()),
                |(s, m)| (s.to_string(), m.to_string()),
            );

            return Ok(ImapResponse { tag: expected_tag.to_string(), status, message, data });
        }

        // Continuation or other data
        data.push(trimmed.to_string());
    }
}

/// Send a tagged IMAP command.
///
/// # Errors
///
/// Returns an error if the write fails.
async fn send_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    tag: &str,
    command: &str,
) -> Result<(), Error> {
    let cmd = format!("{tag} {command}\r\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("IMAP flush error: {e}")))?;
    Ok(())
}

/// Read the untagged greeting sent by the server upon connection.
///
/// # Errors
///
/// Returns an error if the connection drops.
async fn read_greeting<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Result<String, Error> {
    let mut line = String::new();
    let bytes_read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Http(format!("IMAP greeting read error: {e}")))?;

    if bytes_read == 0 {
        return Err(Error::Http("IMAP connection closed before greeting".to_string()));
    }

    Ok(line.trim().to_string())
}

/// Fetch email from an IMAP server.
///
/// URL format: `imap://user:pass@host:port/mailbox/;UID=N`
///
/// If a UID is specified, fetches that specific message. Otherwise,
/// returns a listing of the mailbox.
///
/// # Errors
///
/// Returns an error if login fails, the mailbox doesn't exist, or the fetch fails.
#[allow(clippy::too_many_lines)]
pub async fn fetch(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url
        .credentials()
        .ok_or_else(|| Error::Http("IMAP requires credentials in the URL".to_string()))?;

    let path = url.path();
    // Parse mailbox and optional UID from path: /INBOX/;UID=123
    let (mailbox, uid) = parse_imap_path(path);

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);
    let mut tags = TagCounter::new();

    // Read greeting
    let greeting = read_greeting(&mut reader).await?;
    if !greeting.contains("OK") {
        return Err(Error::Http(format!("IMAP server rejected: {greeting}")));
    }

    // LOGIN
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, &format!("LOGIN {user} {pass}")).await?;
    let login_resp = read_response(&mut reader, &tag).await?;
    if !login_resp.is_ok() {
        return Err(Error::Http(format!(
            "IMAP LOGIN failed: {} {}",
            login_resp.status, login_resp.message
        )));
    }

    let mailbox_name = if mailbox.is_empty() { "INBOX" } else { &mailbox };

    // SELECT mailbox
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, &format!("SELECT {mailbox_name}")).await?;
    let select_resp = read_response(&mut reader, &tag).await?;
    if !select_resp.is_ok() {
        return Err(Error::Http(format!(
            "IMAP SELECT failed: {} {}",
            select_resp.status, select_resp.message
        )));
    }

    let tag = tags.next_tag();
    let body = if let Some(uid_num) = uid {
        // FETCH specific message by UID
        send_command(&mut writer, &tag, &format!("UID FETCH {uid_num} BODY[]")).await?;
        let fetch_resp = read_response(&mut reader, &tag).await?;
        if !fetch_resp.is_ok() {
            return Err(Error::Http(format!(
                "IMAP FETCH failed: {} {}",
                fetch_resp.status, fetch_resp.message
            )));
        }
        fetch_resp.data.join("\r\n").into_bytes()
    } else {
        // LIST messages in mailbox
        send_command(&mut writer, &tag, "FETCH 1:* (FLAGS INTERNALDATE ENVELOPE)").await?;
        let fetch_resp = read_response(&mut reader, &tag).await?;
        fetch_resp.data.join("\r\n").into_bytes()
    };

    // LOGOUT
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, "LOGOUT").await?;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

/// Parse an IMAP path into mailbox name and optional UID.
///
/// Examples:
/// - `/INBOX` → (`"INBOX"`, `None`)
/// - `/INBOX/;UID=123` → (`"INBOX"`, `Some(123)`)
/// - `/` → (`""`, `None`)
fn parse_imap_path(path: &str) -> (String, Option<u32>) {
    let path = path.trim_start_matches('/');

    if let Some((mailbox, params)) = path.split_once("/;") {
        let uid = params
            .strip_prefix("UID=")
            .or_else(|| params.strip_prefix("uid="))
            .and_then(|s| s.parse().ok());
        (mailbox.to_string(), uid)
    } else {
        (path.to_string(), None)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_imap_path_inbox() {
        let (mailbox, uid) = parse_imap_path("/INBOX");
        assert_eq!(mailbox, "INBOX");
        assert!(uid.is_none());
    }

    #[test]
    fn parse_imap_path_with_uid() {
        let (mailbox, uid) = parse_imap_path("/INBOX/;UID=42");
        assert_eq!(mailbox, "INBOX");
        assert_eq!(uid, Some(42));
    }

    #[test]
    fn parse_imap_path_root() {
        let (mailbox, uid) = parse_imap_path("/");
        assert_eq!(mailbox, "");
        assert!(uid.is_none());
    }

    #[test]
    fn tag_counter_increments() {
        let mut counter = TagCounter::new();
        assert_eq!(counter.next_tag(), "A001");
        assert_eq!(counter.next_tag(), "A002");
        assert_eq!(counter.next_tag(), "A003");
    }

    #[tokio::test]
    async fn read_greeting_basic() {
        let data = b"* OK IMAP4rev1 ready\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let greeting = read_greeting(&mut reader).await.unwrap();
        assert!(greeting.contains("OK"));
    }

    #[tokio::test]
    async fn read_tagged_response() {
        let data = b"* 1 EXISTS\r\n* 0 RECENT\r\nA001 OK SELECT completed\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader, "A001").await.unwrap();
        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 2);
        assert!(resp.data[0].contains("EXISTS"));
    }

    #[tokio::test]
    async fn read_tagged_response_no() {
        let data = b"A002 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader, "A002").await.unwrap();
        assert!(!resp.is_ok());
        assert_eq!(resp.status, "NO");
    }

    #[test]
    fn imap_response_is_ok() {
        let resp = ImapResponse {
            tag: "A001".to_string(),
            status: "OK".to_string(),
            message: "done".to_string(),
            data: vec![],
        };
        assert!(resp.is_ok());
    }
}
