//! POP3 protocol handler.
//!
//! Implements a basic POP3 client (RFC 1939) for retrieving email.
//! Supports USER/PASS authentication, STAT, LIST, RETR, and DELE commands.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// A POP3 response from the server.
#[derive(Debug, Clone)]
pub struct Pop3Response {
    /// Whether the response was +OK (true) or -ERR (false).
    pub ok: bool,
    /// The response text after +OK or -ERR.
    pub message: String,
}

/// Read a single-line POP3 response.
///
/// POP3 responses start with `+OK` or `-ERR`.
///
/// # Errors
///
/// Returns an error if the connection drops or the response is malformed.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<Pop3Response, Error> {
    let mut line = String::new();
    let bytes_read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Http(format!("POP3 read error: {e}")))?;

    if bytes_read == 0 {
        return Err(Error::Http("POP3 connection closed unexpectedly".to_string()));
    }

    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

    // Chained strip_prefix doesn't convert to map_or_else cleanly
    #[allow(clippy::option_if_let_else)]
    if let Some(msg) = trimmed.strip_prefix("+OK") {
        Ok(Pop3Response { ok: true, message: msg.trim_start().to_string() })
    } else if let Some(msg) = trimmed.strip_prefix("-ERR") {
        Ok(Pop3Response { ok: false, message: msg.trim_start().to_string() })
    } else {
        Err(Error::Http(format!("POP3 unexpected response: {trimmed}")))
    }
}

/// Read a multi-line POP3 response (terminated by `.` on its own line).
///
/// Used for LIST and RETR responses that include data after the +OK line.
///
/// # Errors
///
/// Returns an error if the connection drops.
pub async fn read_multiline<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<Vec<String>, Error> {
    let mut lines = Vec::new();

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("POP3 read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("POP3 connection closed during multi-line read".to_string()));
        }

        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

        if trimmed == "." {
            break;
        }

        // Byte-stuffing: leading dot is removed
        let content = trimmed.strip_prefix('.').unwrap_or(trimmed);
        lines.push(content.to_string());
    }

    Ok(lines)
}

/// Read the POP3 server greeting, skipping any banner lines.
///
/// The greeting must start with `+OK` or `-ERR`.
///
/// # Errors
///
/// Returns an error if the connection drops before a greeting is found.
async fn read_greeting<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<Pop3Response, Error> {
    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("POP3 greeting read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("POP3 connection closed before greeting".to_string()));
        }

        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed.starts_with("+OK") || trimmed.starts_with("-ERR") {
            return read_response_line(trimmed);
        }
        // Skip non-greeting lines (server banners)
    }
}

/// Parse a single POP3 response line (already read).
fn read_response_line(trimmed: &str) -> Result<Pop3Response, Error> {
    #[allow(clippy::option_if_let_else)]
    if let Some(msg) = trimmed.strip_prefix("+OK") {
        Ok(Pop3Response { ok: true, message: msg.trim_start().to_string() })
    } else if let Some(msg) = trimmed.strip_prefix("-ERR") {
        Ok(Pop3Response { ok: false, message: msg.trim_start().to_string() })
    } else {
        Err(Error::Http(format!("POP3 unexpected response: {trimmed}")))
    }
}

/// Send a POP3 command.
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
        .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("POP3 flush error: {e}")))?;
    Ok(())
}

/// Retrieve email from a POP3 server.
///
/// URL format: `pop3://user:pass@host:port/N`
///
/// If a message number N is specified, retrieves that message.
/// Otherwise, returns a listing of messages.
///
/// # Errors
///
/// Returns an error if login fails or the message cannot be retrieved.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn retrieve(
    url: &crate::url::Url,
    credentials: Option<(&str, &str)>,
    custom_request: Option<&str>,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
) -> Result<Response, Error> {
    use base64::Engine;
    // Reject URLs with CR/LF (curl returns exit code 3, test 875)
    let raw_url = url.as_str();
    if raw_url.contains("%0a")
        || raw_url.contains("%0A")
        || raw_url.contains("%0d")
        || raw_url.contains("%0D")
    {
        return Err(Error::UrlParse("POP3 URL contains CR/LF".to_string()));
    }
    let (host, port) = url.host_and_port()?;
    let url_creds = url.credentials();
    let (user, pass) = url_creds
        .or(credentials)
        .ok_or_else(|| Error::Http("POP3 requires credentials".to_string()))?;

    let path = url.path();
    let msg_num: Option<u32> = path.trim_start_matches('/').parse().ok();

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    // Read greeting — skip banner lines until we find +OK or -ERR
    let greeting = read_greeting(&mut reader).await?;
    if !greeting.ok {
        return Err(Error::Http(format!("POP3 server rejected: {}", greeting.message)));
    }

    // CAPA (curl always sends this before auth)
    send_command(&mut writer, "CAPA").await?;
    let capa_resp = read_response(&mut reader).await?;
    let mut server_auth_plain = false;
    let mut server_auth_login = false;
    if capa_resp.ok {
        let capa_lines = read_multiline(&mut reader).await?;
        // Parse SASL capabilities
        for line in &capa_lines {
            if line.starts_with("SASL") || line.starts_with("sasl") {
                let upper = line.to_uppercase();
                if upper.contains("PLAIN") {
                    server_auth_plain = true;
                }
                if upper.contains("LOGIN") {
                    server_auth_login = true;
                }
            }
        }
    }

    // Authenticate: XOAUTH2 > AUTH PLAIN > AUTH LOGIN > USER/PASS
    if let Some(bearer) = oauth2_bearer {
        let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

        if sasl_ir {
            send_command(&mut writer, &format!("AUTH XOAUTH2 {encoded}")).await?;
        } else {
            send_command(&mut writer, "AUTH XOAUTH2").await?;
            // Read continuation (+)
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            // Send encoded payload
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let auth_resp = read_response(&mut reader).await?;
        if !auth_resp.ok {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH XOAUTH2 failed: {}", auth_resp.message),
            });
        }
    } else if server_auth_plain {
        // AUTH PLAIN (two-step or inline SASL-IR)
        let auth_string = format!("\0{user}\0{pass}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());
        if sasl_ir {
            send_command(&mut writer, &format!("AUTH PLAIN {encoded}")).await?;
        } else {
            send_command(&mut writer, "AUTH PLAIN").await?;
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let auth_resp = read_response(&mut reader).await?;
        if !auth_resp.ok {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH PLAIN failed: {}", auth_resp.message),
            });
        }
    } else if server_auth_login {
        // AUTH LOGIN (two-step or inline SASL-IR)
        let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());
        if sasl_ir {
            send_command(&mut writer, &format!("AUTH LOGIN {user_b64}")).await?;
        } else {
            send_command(&mut writer, "AUTH LOGIN").await?;
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer
                .write_all(format!("{user_b64}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        // Server sends password challenge
        let mut line2 = String::new();
        let _ = reader.read_line(&mut line2).await;
        writer
            .write_all(format!("{pass_b64}\r\n").as_bytes())
            .await
            .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
        let _ = writer.flush().await;
        let auth_resp = read_response(&mut reader).await?;
        if !auth_resp.ok {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH LOGIN failed: {}", auth_resp.message),
            });
        }
    } else {
        // USER/PASS authentication (fallback)
        send_command(&mut writer, &format!("USER {user}")).await?;
        let user_resp = read_response(&mut reader).await?;
        if !user_resp.ok {
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 USER failed: {}", user_resp.message),
            });
        }

        // PASS
        send_command(&mut writer, &format!("PASS {pass}")).await?;
        let pass_resp = read_response(&mut reader).await?;
        if !pass_resp.ok {
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 login failed: {}", pass_resp.message),
            });
        }
    }

    // If custom request is set (e.g. -X NOOP, -X DELE), send that instead.
    // If URL has a message number, append it to the command (e.g. DELE 858).
    if let Some(cmd) = custom_request {
        let full_cmd = msg_num.map_or_else(|| cmd.to_string(), |num| format!("{cmd} {num}"));
        send_command(&mut writer, &full_cmd).await?;
        let cmd_resp = read_response(&mut reader).await?;
        if !cmd_resp.ok {
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            return Err(Error::Http(format!("POP3 {cmd} failed: {}", cmd_resp.message)));
        }
        // Some custom commands (TOP, RETR) return multiline data
        let cmd_upper = cmd.to_uppercase();
        if cmd_upper.starts_with("TOP")
            || cmd_upper.starts_with("RETR")
            || cmd_upper.starts_with("LIST")
        {
            let lines = read_multiline(&mut reader).await?;
            let mut body_str = lines.join("\r\n");
            if !body_str.is_empty() {
                body_str.push_str("\r\n");
            }
            let body = body_str.into_bytes();
            send_command(&mut writer, "QUIT").await?;
            let _ = read_response(&mut reader).await;
            let mut headers = std::collections::HashMap::new();
            let _old = headers.insert("content-length".to_string(), body.len().to_string());
            return Ok(Response::new(200, headers, body, url.as_str().to_string()));
        }
        // Simple commands (DELE, NOOP) — just QUIT
    } else if let Some(num) = msg_num {
        // RETR specific message
        send_command(&mut writer, &format!("RETR {num}")).await?;
        let retr_resp = read_response(&mut reader).await?;
        if !retr_resp.ok {
            return Err(Error::Http(format!("POP3 RETR failed: {}", retr_resp.message)));
        }
        let lines = read_multiline(&mut reader).await?;
        let mut body_str = lines.join("\r\n");
        if !body_str.is_empty() {
            body_str.push_str("\r\n");
        }
        let body = body_str.into_bytes();

        // QUIT
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;

        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-length".to_string(), body.len().to_string());
        return Ok(Response::new(200, headers, body, url.as_str().to_string()));
    } else {
        // LIST all messages
        send_command(&mut writer, "LIST").await?;
        let list_resp = read_response(&mut reader).await?;
        if !list_resp.ok {
            return Err(Error::Http(format!("POP3 LIST failed: {}", list_resp.message)));
        }
        let lines = read_multiline(&mut reader).await?;
        let mut body_str = lines.join("\r\n");
        if !body_str.is_empty() {
            body_str.push_str("\r\n");
        }
        let body = body_str.into_bytes();

        // QUIT
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;

        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-length".to_string(), body.len().to_string());
        return Ok(Response::new(200, headers, body, url.as_str().to_string()));
    }

    // QUIT
    send_command(&mut writer, "QUIT").await?;
    let _ = read_response(&mut reader).await;

    let headers = std::collections::HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_ok_response() {
        let data = b"+OK POP3 server ready\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert!(resp.ok);
        assert_eq!(resp.message, "POP3 server ready");
    }

    #[tokio::test]
    async fn read_err_response() {
        let data = b"-ERR authentication failed\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.message, "authentication failed");
    }

    #[tokio::test]
    async fn read_response_connection_closed() {
        let data = b"";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let result = read_response(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_multiline_basic() {
        let data = b"1 120\r\n2 250\r\n.\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let lines = read_multiline(&mut reader).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "1 120");
        assert_eq!(lines[1], "2 250");
    }

    #[tokio::test]
    async fn read_multiline_with_dot_stuffing() {
        let data = b"..this starts with dot\r\nnormal line\r\n.\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let lines = read_multiline(&mut reader).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], ".this starts with dot");
        assert_eq!(lines[1], "normal line");
    }

    #[tokio::test]
    async fn read_multiline_empty() {
        let data = b".\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let lines = read_multiline(&mut reader).await.unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn pop3_response_fields() {
        let resp = Pop3Response { ok: true, message: "test".to_string() };
        assert!(resp.ok);
        assert_eq!(resp.message, "test");
    }
}
