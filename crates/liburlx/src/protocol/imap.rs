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
/// The server may send banner lines before the `* OK` greeting.
/// We keep reading until we find a line starting with `* OK` or `* PREAUTH`.
///
/// # Errors
///
/// Returns an error if the connection drops or no greeting is found.
async fn read_greeting<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Result<String, Error> {
    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("IMAP greeting read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("IMAP connection closed before greeting".to_string()));
        }

        let trimmed = line.trim();
        // The greeting is an untagged response: "* OK ..." or "* PREAUTH ..."
        if trimmed.starts_with("* OK") || trimmed.starts_with("* PREAUTH") {
            return Ok(trimmed.to_string());
        }
        // Skip non-greeting lines (server banners, etc.)
    }
}

/// Fetch email from an IMAP server.
///
/// URL format: `imap://user:pass@host:port/mailbox/;UID=N`
///
/// If a UID is specified, fetches that specific message. Otherwise,
/// returns a listing of the mailbox.
///
/// Credentials can come from the URL or be passed via `credentials` parameter
/// (from `-u` flag). URL credentials take priority.
///
/// # Errors
///
/// Returns an error if login fails, the mailbox doesn't exist, or the fetch fails.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn fetch(
    url: &crate::url::Url,
    credentials: Option<(&str, &str)>,
    custom_request: Option<&str>,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
) -> Result<Response, Error> {
    use base64::Engine;
    let (host, port) = url.host_and_port()?;
    let url_creds = url.credentials();
    let (user, pass) = url_creds
        .or(credentials)
        .ok_or_else(|| Error::Http("IMAP requires credentials".to_string()))?;

    let path = url.path();
    // Parse mailbox and optional params from path: /INBOX/;UID=123 or /INBOX/;MAILINDEX=1
    let (mailbox, params) = parse_imap_path(path);

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

    // CAPABILITY (curl always sends this first)
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, "CAPABILITY").await?;
    let cap_resp = read_response(&mut reader, &tag).await?;

    // Parse AUTH mechanisms from CAPABILITY response
    let mut server_auth_login = false;
    let mut server_sasl_ir = false;
    for line in &cap_resp.data {
        for token in line.split_whitespace() {
            if token.eq_ignore_ascii_case("AUTH=LOGIN") {
                server_auth_login = true;
            }
            if token.eq_ignore_ascii_case("SASL-IR") {
                server_sasl_ir = true;
            }
        }
    }

    // Authenticate: XOAUTH2 > AUTHENTICATE LOGIN > plain LOGIN
    if let Some(bearer) = oauth2_bearer {
        // XOAUTH2 authentication
        let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let tag = tags.next_tag();

        if sasl_ir && server_sasl_ir {
            send_command(&mut writer, &tag, &format!("AUTHENTICATE XOAUTH2 {encoded}")).await?;
        } else {
            send_command(&mut writer, &tag, "AUTHENTICATE XOAUTH2").await?;
            // Read continuation (+)
            let mut challenge_line = String::new();
            let _ = reader.read_line(&mut challenge_line).await;
            // Send encoded payload
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let auth_resp = read_response(&mut reader, &tag).await?;
        if !auth_resp.is_ok() {
            let ltag = tags.next_tag();
            send_command(&mut writer, &ltag, "LOGOUT").await?;
            return Err(Error::Transfer {
                code: 67,
                message: format!("IMAP XOAUTH2 failed: {} {}", auth_resp.status, auth_resp.message),
            });
        }
    } else if server_auth_login {
        // AUTHENTICATE LOGIN (SASL two-step)
        let tag = tags.next_tag();
        send_command(&mut writer, &tag, "AUTHENTICATE LOGIN").await?;
        // Server sends + challenge for username
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await;
        // Send base64-encoded username
        let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
        writer
            .write_all(format!("{user_b64}\r\n").as_bytes())
            .await
            .map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
        let _ = writer.flush().await;
        // Server sends + challenge for password
        let mut line2 = String::new();
        let _ = reader.read_line(&mut line2).await;
        // Send base64-encoded password
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());
        writer
            .write_all(format!("{pass_b64}\r\n").as_bytes())
            .await
            .map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
        let _ = writer.flush().await;
        let auth_resp = read_response(&mut reader, &tag).await?;
        if !auth_resp.is_ok() {
            let ltag = tags.next_tag();
            send_command(&mut writer, &ltag, "LOGOUT").await?;
            return Err(Error::Transfer {
                code: 67,
                message: format!(
                    "IMAP AUTHENTICATE LOGIN failed: {} {}",
                    auth_resp.status, auth_resp.message
                ),
            });
        }
    } else {
        // Plain LOGIN (not SASL)
        let tag = tags.next_tag();
        let quoted_user = imap_quote(user);
        let quoted_pass = imap_quote(pass);
        send_command(&mut writer, &tag, &format!("LOGIN {quoted_user} {quoted_pass}")).await?;
        let login_resp = read_response(&mut reader, &tag).await?;
        if !login_resp.is_ok() {
            let ltag = tags.next_tag();
            send_command(&mut writer, &ltag, "LOGOUT").await?;
            return Err(Error::Transfer {
                code: 67,
                message: format!("IMAP LOGIN failed: {} {}", login_resp.status, login_resp.message),
            });
        }
    }

    let mailbox_name = if mailbox.is_empty() { "INBOX" } else { &mailbox };

    // If custom request is set (e.g. -X EXAMINE), use that instead of SELECT
    let select_cmd = custom_request.unwrap_or("SELECT");

    // SELECT (or custom command like EXAMINE) mailbox
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, &format!("{select_cmd} {mailbox_name}")).await?;
    let select_resp = read_response(&mut reader, &tag).await?;
    if !select_resp.is_ok() {
        let ltag = tags.next_tag();
        send_command(&mut writer, &ltag, "LOGOUT").await?;
        return Err(Error::Http(format!(
            "IMAP {select_cmd} failed: {} {}",
            select_resp.status, select_resp.message
        )));
    }

    let tag = tags.next_tag();
    let body = if let Some(uid) = params.uid {
        // FETCH specific message by UID
        let section = params.section.as_deref().unwrap_or("BODY[]");
        send_command(&mut writer, &tag, &format!("UID FETCH {uid} {section}")).await?;
        let fetch_resp = read_response(&mut reader, &tag).await?;
        if !fetch_resp.is_ok() {
            return Err(Error::Http(format!(
                "IMAP FETCH failed: {} {}",
                fetch_resp.status, fetch_resp.message
            )));
        }
        fetch_resp.data.join("\r\n").into_bytes()
    } else if let Some(index) = params.mailindex {
        // FETCH by message number (MAILINDEX)
        let section = params.section.as_deref().unwrap_or("BODY[]");
        send_command(&mut writer, &tag, &format!("FETCH {index} {section}")).await?;
        let fetch_resp = read_response(&mut reader, &tag).await?;
        if !fetch_resp.is_ok() {
            return Err(Error::Http(format!(
                "IMAP FETCH failed: {} {}",
                fetch_resp.status, fetch_resp.message
            )));
        }
        fetch_resp.data.join("\r\n").into_bytes()
    } else {
        // No specific message - just do a search or list
        send_command(&mut writer, &tag, "FETCH 1:* (FLAGS INTERNALDATE ENVELOPE)").await?;
        let fetch_resp = read_response(&mut reader, &tag).await?;
        fetch_resp.data.join("\r\n").into_bytes()
    };

    // LOGOUT
    let tag = tags.next_tag();
    send_command(&mut writer, &tag, "LOGOUT").await?;
    let _ = read_response(&mut reader, &tag).await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

/// Quote an IMAP string value, escaping backslashes and double quotes.
fn imap_quote(s: &str) -> String {
    // If the string contains special characters, quote it
    if s.contains('"') || s.contains('\\') || s.contains(' ') || s.contains('{') {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Parsed IMAP URL parameters.
#[derive(Debug, Default)]
struct ImapParams {
    /// UID for UID FETCH.
    uid: Option<u32>,
    /// MAILINDEX for FETCH by message number.
    mailindex: Option<u32>,
    /// SECTION override (e.g., `BODY[TEXT]`).
    section: Option<String>,
}

/// Parse an IMAP path into mailbox name and parameters.
///
/// Examples:
/// - `/INBOX` → (`"INBOX"`, default params)
/// - `/INBOX/;UID=123` → (`"INBOX"`, uid=123)
/// - `/INBOX/;MAILINDEX=1` → (`"INBOX"`, mailindex=1)
/// - `/INBOX/;UID=1;SECTION=BODY[TEXT]` → with section
/// - `/` → (`""`, default params)
fn parse_imap_path(path: &str) -> (String, ImapParams) {
    let path = path.trim_start_matches('/');
    let mut params = ImapParams::default();

    if let Some((mailbox, param_str)) = path.split_once("/;") {
        // Parse semicolon-separated parameters
        for param in param_str.split(';') {
            if let Some(val) = param.strip_prefix("UID=").or_else(|| param.strip_prefix("uid=")) {
                params.uid = val.parse().ok();
            } else if let Some(val) =
                param.strip_prefix("MAILINDEX=").or_else(|| param.strip_prefix("mailindex="))
            {
                params.mailindex = val.parse().ok();
            } else if let Some(val) =
                param.strip_prefix("SECTION=").or_else(|| param.strip_prefix("section="))
            {
                params.section = Some(val.to_string());
            }
        }
        (mailbox.to_string(), params)
    } else {
        (path.to_string(), params)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_imap_path_inbox() {
        let (mailbox, params) = parse_imap_path("/INBOX");
        assert_eq!(mailbox, "INBOX");
        assert!(params.uid.is_none());
        assert!(params.mailindex.is_none());
    }

    #[test]
    fn parse_imap_path_with_uid() {
        let (mailbox, params) = parse_imap_path("/INBOX/;UID=42");
        assert_eq!(mailbox, "INBOX");
        assert_eq!(params.uid, Some(42));
    }

    #[test]
    fn parse_imap_path_with_mailindex() {
        let (mailbox, params) = parse_imap_path("/INBOX/;MAILINDEX=1");
        assert_eq!(mailbox, "INBOX");
        assert_eq!(params.mailindex, Some(1));
    }

    #[test]
    fn parse_imap_path_root() {
        let (mailbox, params) = parse_imap_path("/");
        assert_eq!(mailbox, "");
        assert!(params.uid.is_none());
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
