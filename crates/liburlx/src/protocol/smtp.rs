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
/// If `mail_from` or `mail_rcpt` are provided, they override the addresses
/// parsed from the message headers. This matches curl's `CURLOPT_MAIL_FROM`
/// and `CURLOPT_MAIL_RCPT` behavior.
///
/// # URL format
///
/// `smtp://host:port` — plain SMTP (port 25 default)
///
/// # Errors
///
/// Returns an error if connection, auth, or sending fails.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn send_mail(
    url: &crate::url::Url,
    mail_data: &[u8],
    mail_from: Option<&str>,
    mail_rcpt: &[String],
    mail_auth: Option<&str>,
    sasl_authzid: Option<&str>,
    sasl_ir: bool,
    ext_credentials: Option<(&str, &str)>,
    custom_request: Option<&str>,
    oauth2_bearer: Option<&str>,
) -> Result<crate::protocol::http::response::Response, Error> {
    let (host, port) = url.host_and_port()?;

    // Extract credentials from URL or external parameter (-u flag)
    let credentials = url.credentials().or(ext_credentials);

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

    // Send EHLO — curl uses the URL path (without leading /) as the EHLO argument.
    // For smtp://host:port/900, EHLO argument is "900".
    // If no path, fall back to the host.
    let ehlo_arg = {
        let p = url.path().trim_start_matches('/');
        if p.is_empty() {
            host.clone()
        } else {
            p.to_string()
        }
    };
    send_command(&mut writer, &format!("EHLO {ehlo_arg}")).await?;
    let ehlo_resp = read_response(&mut reader).await?;

    // Parse EHLO capabilities to find supported AUTH mechanisms
    let mut server_auth_mechanisms: Vec<String> = Vec::new();
    if ehlo_resp.is_ok() {
        // EHLO response message may contain "AUTH PLAIN LOGIN" etc.
        let ehlo_text = format!("{} {}", ehlo_resp.code, ehlo_resp.message);
        for word in ehlo_text.split_whitespace() {
            let upper = word.to_uppercase();
            if matches!(upper.as_str(), "PLAIN" | "LOGIN" | "CRAM-MD5" | "NTLM" | "XOAUTH2") {
                server_auth_mechanisms.push(upper);
            }
        }
    } else {
        // Fall back to HELO
        send_command(&mut writer, &format!("HELO {ehlo_arg}")).await?;
        let helo_resp = read_response(&mut reader).await?;
        if !helo_resp.is_ok() {
            return Err(Error::Http(format!(
                "SMTP HELO failed: {} {}",
                helo_resp.code, helo_resp.message
            )));
        }
    }

    // XOAUTH2 takes priority when bearer token is present
    if let Some(bearer) = oauth2_bearer {
        use base64::Engine;
        if let Some((user, _)) = credentials {
            let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

            if sasl_ir {
                send_command(&mut writer, &format!("AUTH XOAUTH2 {encoded}")).await?;
            } else {
                send_command(&mut writer, "AUTH XOAUTH2").await?;
                let continue_resp = read_response(&mut reader).await?;
                if continue_resp.code != 334 {
                    send_command(&mut writer, "QUIT").await?;
                    let _ = read_response(&mut reader).await;
                    return Err(Error::Http(format!(
                        "SMTP AUTH XOAUTH2 expected 334, got: {} {}",
                        continue_resp.code, continue_resp.message
                    )));
                }
                send_command(&mut writer, &encoded).await?;
            }
            let auth_resp = read_response(&mut reader).await?;
            if !auth_resp.is_ok() {
                send_command(&mut writer, "QUIT").await?;
                let _ = read_response(&mut reader).await;
                return Err(Error::Http(format!(
                    "SMTP AUTH XOAUTH2 failed: {} {}",
                    auth_resp.code, auth_resp.message
                )));
            }
        }
    }
    // Authenticate if credentials provided AND server supports AUTH
    else if let Some((user, pass)) = credentials.filter(|_| !server_auth_mechanisms.is_empty()) {
        use base64::Engine;

        // Choose auth mechanism based on server capabilities
        // Priority: PLAIN > LOGIN (matching curl's preference order)
        let use_login = server_auth_mechanisms.contains(&"LOGIN".to_string())
            && !server_auth_mechanisms.contains(&"PLAIN".to_string());

        if use_login {
            // AUTH LOGIN: send username and password separately, base64-encoded
            let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
            let pass_b64 = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());

            send_command(&mut writer, "AUTH LOGIN").await?;
            let resp = read_response(&mut reader).await?;
            if resp.code != 334 {
                return Err(Error::Http(format!(
                    "SMTP AUTH LOGIN failed: {} {}",
                    resp.code, resp.message
                )));
            }
            send_command(&mut writer, &user_b64).await?;
            let resp = read_response(&mut reader).await?;
            if resp.code != 334 {
                return Err(Error::Http(format!(
                    "SMTP AUTH LOGIN failed: {} {}",
                    resp.code, resp.message
                )));
            }
            send_command(&mut writer, &pass_b64).await?;
        } else {
            // AUTH PLAIN
            let auth_string = sasl_authzid.map_or_else(
                || format!("\0{user}\0{pass}"),
                |authzid| format!("{authzid}\0{user}\0{pass}"),
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());

            if sasl_ir {
                // Send initial response inline with AUTH command
                send_command(&mut writer, &format!("AUTH PLAIN {encoded}")).await?;
            } else {
                // Two-step: send AUTH PLAIN, wait for 334, then send credentials
                send_command(&mut writer, "AUTH PLAIN").await?;
                let continue_resp = read_response(&mut reader).await?;
                if continue_resp.code != 334 {
                    return Err(Error::Http(format!(
                        "SMTP AUTH PLAIN expected 334 continue, got: {} {}",
                        continue_resp.code, continue_resp.message
                    )));
                }
                send_command(&mut writer, &encoded).await?;
            }
        }
        let auth_resp = read_response(&mut reader).await?;
        if !auth_resp.is_ok() {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Transfer {
                code: 67,
                message: format!("SMTP AUTH failed: {} {}", auth_resp.code, auth_resp.message),
            });
        }
    }

    // If custom request is set (e.g. -X "vrfy"), send it instead of MAIL flow.
    // For VRFY/EXPN, --mail-rcpt provides the argument (curl compat: test 950).
    if let Some(cmd) = custom_request {
        let full_cmd =
            if mail_rcpt.is_empty() { cmd.to_string() } else { format!("{cmd} {}", mail_rcpt[0]) };
        send_command(&mut writer, &full_cmd).await?;
        let _ = read_response(&mut reader).await;
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        let headers = std::collections::HashMap::new();
        return Ok(crate::protocol::http::response::Response::new(
            250,
            headers,
            Vec::new(),
            url.as_str().to_string(),
        ));
    }

    // Determine envelope sender and recipients.
    let mail_str = String::from_utf8_lossy(mail_data);
    let (header_from, header_to) = extract_mail_addresses(&mail_str);

    let from_addr = if let Some(from) = mail_from {
        from.to_string()
    } else if let Some(addr) = header_from {
        addr
    } else {
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        return Err(Error::Http("no From address".to_string()));
    };

    let rcpt_addrs: Vec<String> = if mail_rcpt.is_empty() {
        if let Some(to) = header_to {
            vec![to]
        } else {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Http("no To address".to_string()));
        }
    } else {
        mail_rcpt.to_vec()
    };

    // MAIL FROM
    let mail_from_cmd = mail_auth.map_or_else(
        || format!("MAIL FROM:<{from_addr}>"),
        |auth| format!("MAIL FROM:<{from_addr}> AUTH=<{auth}>"),
    );
    send_command(&mut writer, &mail_from_cmd).await?;
    let mail_resp = read_response(&mut reader).await?;
    if !mail_resp.is_ok() {
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        // CURLE_SEND_ERROR (55) for SMTP command failures
        return Err(Error::Transfer {
            code: 55,
            message: format!("SMTP MAIL FROM failed: {} {}", mail_resp.code, mail_resp.message),
        });
    }

    // RCPT TO
    for rcpt in &rcpt_addrs {
        send_command(&mut writer, &format!("RCPT TO:<{rcpt}>")).await?;
        let rcpt_resp = read_response(&mut reader).await?;
        if !rcpt_resp.is_ok() {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Transfer {
                code: 55,
                message: format!("SMTP RCPT TO failed: {} {}", rcpt_resp.code, rcpt_resp.message),
            });
        }
    }

    // DATA
    send_command(&mut writer, "DATA").await?;
    let data_resp = read_response(&mut reader).await?;
    if !data_resp.is_intermediate() {
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        return Err(Error::Transfer {
            code: 55,
            message: format!("SMTP DATA failed: {} {}", data_resp.code, data_resp.message),
        });
    }

    // Send message body as raw bytes, escaping leading dots per RFC 5321.
    // Write raw bytes (not line-by-line via .lines()) to preserve long lines (test 900).
    let mut line_start = true;
    for &byte in mail_data {
        if line_start && byte == b'.' {
            writer
                .write_all(b".")
                .await
                .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
        }
        writer
            .write_all(&[byte])
            .await
            .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
        line_start = byte == b'\n';
    }
    // Ensure data ends with CRLF before the terminator
    if !mail_data.is_empty() && !mail_data.ends_with(b"\r\n") {
        if mail_data.ends_with(b"\n") {
            // already has LF, no extra needed (server will handle)
        } else {
            writer
                .write_all(b"\r\n")
                .await
                .map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
        }
    }

    // End data with .CRLF
    send_command(&mut writer, ".").await?;
    let end_resp = read_response(&mut reader).await?;
    if !end_resp.is_ok() {
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        return Err(Error::Transfer {
            code: 55,
            message: format!("SMTP message rejected: {} {}", end_resp.code, end_resp.message),
        });
    }

    // QUIT
    send_command(&mut writer, "QUIT").await?;
    let _ = read_response(&mut reader).await;

    let headers = std::collections::HashMap::new();
    Ok(crate::protocol::http::response::Response::new(
        250,
        headers,
        Vec::new(),
        url.as_str().to_string(),
    ))
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

    #[test]
    fn mail_auth_parameter_format() {
        // Verify MAIL FROM with AUTH= parameter is formatted correctly
        let from_addr = "sender@example.com";
        let auth: Option<&str> = Some("delegated@example.com");
        let cmd = auth.map_or_else(
            || format!("MAIL FROM:<{from_addr}>"),
            |a| format!("MAIL FROM:<{from_addr}> AUTH=<{a}>"),
        );
        assert_eq!(cmd, "MAIL FROM:<sender@example.com> AUTH=<delegated@example.com>");
    }

    #[test]
    fn mail_auth_parameter_none() {
        // Without mail_auth, MAIL FROM should not have AUTH=
        let from_addr = "sender@example.com";
        let auth: Option<&str> = None;
        let cmd = auth.map_or_else(
            || format!("MAIL FROM:<{from_addr}>"),
            |a| format!("MAIL FROM:<{from_addr}> AUTH=<{a}>"),
        );
        assert_eq!(cmd, "MAIL FROM:<sender@example.com>");
    }

    #[test]
    fn sasl_authzid_in_auth_string() {
        // With sasl_authzid, the auth string should be "authzid\0user\0pass"
        use base64::Engine;
        let authzid: Option<&str> = Some("admin@example.com");
        let user = "user";
        let pass = "secret";
        let auth_string = authzid
            .map_or_else(|| format!("\0{user}\0{pass}"), |az| format!("{az}\0{user}\0{pass}"));
        assert_eq!(auth_string, "admin@example.com\0user\0secret");
        // Verify it encodes properly
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());
        assert!(!encoded.is_empty());
    }

    #[test]
    fn sasl_authzid_none_default() {
        // Without sasl_authzid, the auth string should be "\0user\0pass"
        let authzid: Option<&str> = None;
        let user = "user";
        let pass = "secret";
        let auth_string = authzid
            .map_or_else(|| format!("\0{user}\0{pass}"), |az| format!("{az}\0{user}\0{pass}"));
        assert_eq!(auth_string, "\0user\0secret");
    }
}
