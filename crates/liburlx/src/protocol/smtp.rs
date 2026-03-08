//! SMTP protocol handler.
//!
//! Implements a basic SMTP client (RFC 5321) for sending email messages.
//! Supports EHLO/HELO greeting, MAIL FROM, RCPT TO, DATA commands,
//! and AUTH PLAIN/LOGIN authentication.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;

/// An SMTP response from the server.
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    /// The 3-digit status code.
    pub code: u16,
    /// The response text (may be multi-line).
    pub message: String,
}

impl SmtpResponse {
    /// Check if this is a positive completion (2xx).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// Check if this is a positive intermediate (3xx).
    #[must_use]
    pub const fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

/// Read an SMTP response (potentially multi-line) from the server.
///
/// Multi-line responses use `code-text` format; final line uses `code text`.
///
/// # Errors
///
/// Returns an error if the response is malformed or the connection drops.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<SmtpResponse, Error> {
    let mut full_message = String::new();
    let mut final_code: Option<u16> = None;

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("SMTP read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("SMTP connection closed unexpectedly".to_string()));
        }

        let line = line.trim_end_matches('\n').trim_end_matches('\r');

        if line.len() < 4 {
            full_message.push_str(line);
            full_message.push('\n');
            continue;
        }

        let code_str = &line[..3];
        let separator = line.as_bytes().get(3).copied();

        if let Ok(code) = code_str.parse::<u16>() {
            match separator {
                Some(b' ') => {
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    final_code = Some(code);
                    break;
                }
                Some(b'-') => {
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    full_message.push('\n');
                    if final_code.is_none() {
                        final_code = Some(code);
                    }
                }
                _ => {
                    full_message.push_str(line);
                    full_message.push('\n');
                }
            }
        } else {
            full_message.push_str(line);
            full_message.push('\n');
        }
    }

    let code =
        final_code.ok_or_else(|| Error::Http("SMTP response has no status code".to_string()))?;

    Ok(SmtpResponse { code, message: full_message })
}

/// Send an SMTP command.
///
/// # Errors
///
/// Returns an error if the write fails.
pub async fn send_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    command: &str,
) -> Result<(), Error> {
    let cmd = format!("{command}\r\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("SMTP write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMTP flush error: {e}")))?;
    Ok(())
}

/// Send an email via SMTP.
///
/// Connects to the SMTP server specified in the URL, authenticates if
/// credentials are present, and sends the provided message data.
///
/// # URL format
///
/// `smtp://host:port` — plain SMTP (port 25 default)
///
/// # Errors
///
/// Returns an error if connection, auth, or sending fails.
#[allow(clippy::too_many_lines)]
pub async fn send_mail(url: &crate::url::Url, mail_data: &[u8]) -> Result<(), Error> {
    let (host, port) = url.host_and_port()?;

    // Extract credentials and mail parameters from URL
    let credentials = url.credentials();

    // Connect to SMTP server
    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    // Read server greeting
    let greeting = read_response(&mut reader).await?;
    if !greeting.is_ok() {
        return Err(Error::Http(format!(
            "SMTP server rejected connection: {} {}",
            greeting.code, greeting.message
        )));
    }

    // Send EHLO
    send_command(&mut writer, &format!("EHLO {host}")).await?;
    let ehlo_resp = read_response(&mut reader).await?;
    if !ehlo_resp.is_ok() {
        // Fall back to HELO
        send_command(&mut writer, &format!("HELO {host}")).await?;
        let helo_resp = read_response(&mut reader).await?;
        if !helo_resp.is_ok() {
            return Err(Error::Http(format!(
                "SMTP HELO failed: {} {}",
                helo_resp.code, helo_resp.message
            )));
        }
    }

    // Authenticate if credentials provided
    if let Some((user, pass)) = credentials {
        // Use AUTH PLAIN
        use base64::Engine;
        let auth_string = format!("\0{user}\0{pass}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());
        send_command(&mut writer, &format!("AUTH PLAIN {encoded}")).await?;
        let auth_resp = read_response(&mut reader).await?;
        if !auth_resp.is_ok() {
            return Err(Error::Http(format!(
                "SMTP AUTH failed: {} {}",
                auth_resp.code, auth_resp.message
            )));
        }
    }

    // Parse mail_data to extract From/To from headers
    let mail_str = String::from_utf8_lossy(mail_data);
    let (from, to) = extract_mail_addresses(&mail_str);

    let from_addr =
        from.ok_or_else(|| Error::Http("no From address found in message".to_string()))?;
    let to_addr = to.ok_or_else(|| Error::Http("no To address found in message".to_string()))?;

    // MAIL FROM
    send_command(&mut writer, &format!("MAIL FROM:<{from_addr}>")).await?;
    let mail_resp = read_response(&mut reader).await?;
    if !mail_resp.is_ok() {
        return Err(Error::Http(format!(
            "SMTP MAIL FROM failed: {} {}",
            mail_resp.code, mail_resp.message
        )));
    }

    // RCPT TO
    send_command(&mut writer, &format!("RCPT TO:<{to_addr}>")).await?;
    let rcpt_resp = read_response(&mut reader).await?;
    if !rcpt_resp.is_ok() {
        return Err(Error::Http(format!(
            "SMTP RCPT TO failed: {} {}",
            rcpt_resp.code, rcpt_resp.message
        )));
    }

    // DATA
    send_command(&mut writer, "DATA").await?;
    let data_resp = read_response(&mut reader).await?;
    if !data_resp.is_intermediate() {
        return Err(Error::Http(format!(
            "SMTP DATA failed: {} {}",
            data_resp.code, data_resp.message
        )));
    }

    // Send message body, escaping leading dots
    for line in mail_str.lines() {
        if line.starts_with('.') {
            writer
                .write_all(b".")
                .await
                .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
        }
        writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
        writer
            .write_all(b"\r\n")
            .await
            .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
    }

    // End data with CRLF.CRLF
    send_command(&mut writer, ".").await?;
    let end_resp = read_response(&mut reader).await?;
    if !end_resp.is_ok() {
        return Err(Error::Http(format!(
            "SMTP message rejected: {} {}",
            end_resp.code, end_resp.message
        )));
    }

    // QUIT
    send_command(&mut writer, "QUIT").await?;

    Ok(())
}

/// Extract From and To addresses from email headers.
fn extract_mail_addresses(mail: &str) -> (Option<String>, Option<String>) {
    let mut from = None;
    let mut to = None;

    for line in mail.lines() {
        if line.is_empty() {
            break; // End of headers
        }
        if let Some(addr) = line.strip_prefix("From:").or_else(|| line.strip_prefix("from:")) {
            from = Some(extract_address(addr.trim()));
        } else if let Some(addr) = line.strip_prefix("To:").or_else(|| line.strip_prefix("to:")) {
            to = Some(extract_address(addr.trim()));
        }
    }

    (from, to)
}

/// Extract a bare email address from a header value.
///
/// Handles formats like:
/// - `user@example.com`
/// - `<user@example.com>`
/// - `"Name" <user@example.com>`
fn extract_address(value: &str) -> String {
    if let Some(start) = value.find('<') {
        if let Some(end) = value.find('>') {
            return value[start + 1..end].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_simple_response() {
        let data = b"220 mail.example.com ESMTP\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.message, "mail.example.com ESMTP");
    }

    #[tokio::test]
    async fn read_multiline_response() {
        let data = b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 AUTH PLAIN LOGIN\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 250);
        assert!(resp.message.contains("mail.example.com"));
        assert!(resp.message.contains("AUTH PLAIN LOGIN"));
    }

    #[tokio::test]
    async fn read_response_connection_closed() {
        let data = b"";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let result = read_response(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn smtp_response_status_ok() {
        let resp = SmtpResponse { code: 250, message: String::new() };
        assert!(resp.is_ok());
        assert!(!resp.is_intermediate());
    }

    #[test]
    fn smtp_response_status_intermediate() {
        let resp = SmtpResponse { code: 354, message: String::new() };
        assert!(resp.is_intermediate());
        assert!(!resp.is_ok());
    }

    #[test]
    fn extract_address_bare() {
        assert_eq!(extract_address("user@example.com"), "user@example.com");
    }

    #[test]
    fn extract_address_angle_brackets() {
        assert_eq!(extract_address("<user@example.com>"), "user@example.com");
    }

    #[test]
    fn extract_address_display_name() {
        assert_eq!(extract_address("\"John Doe\" <john@example.com>"), "john@example.com");
    }

    #[test]
    fn extract_from_to_headers() {
        let mail = "From: sender@example.com\r\nTo: receiver@example.com\r\n\r\nBody";
        let (from, to) = extract_mail_addresses(mail);
        assert_eq!(from.unwrap(), "sender@example.com");
        assert_eq!(to.unwrap(), "receiver@example.com");
    }

    #[test]
    fn extract_from_to_with_angle_brackets() {
        let mail = "From: <sender@example.com>\r\nTo: \"Bob\" <bob@example.com>\r\n\r\n";
        let (from, to) = extract_mail_addresses(mail);
        assert_eq!(from.unwrap(), "sender@example.com");
        assert_eq!(to.unwrap(), "bob@example.com");
    }

    #[test]
    fn extract_no_from() {
        let mail = "To: receiver@example.com\r\n\r\nBody";
        let (from, _to) = extract_mail_addresses(mail);
        assert!(from.is_none());
    }
}
