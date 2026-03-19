//! POP3 protocol handler.
//!
//! Implements a basic POP3 client (RFC 1939) for retrieving email.
//! Supports USER/PASS authentication, STAT, LIST, RETR, and DELE commands.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;
use crate::protocol::ftp::UseSsl;
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

/// Read a continuation line from POP3 server (starts with `+`).
///
/// # Errors
///
/// Returns an error if the read fails.
async fn read_continuation<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<String, Error> {
    let mut line = String::new();
    let bytes_read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Http(format!("POP3 read error: {e}")))?;
    if bytes_read == 0 {
        return Err(Error::Http("POP3 connection closed waiting for continuation".to_string()));
    }
    Ok(line.trim().to_string())
}

/// Perform the POP3 greeting and CAPA exchange.
///
/// Returns `(apop_timestamp, sasl_mechanisms, has_apop, has_stls, capa_ok)`.
///
/// # Errors
///
/// Returns an error if the greeting is rejected.
async fn pop3_greeting_and_capa<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<(Option<String>, Vec<String>, bool, bool, bool), Error> {
    let greeting = read_greeting(reader).await?;
    if !greeting.ok {
        return Err(Error::Http(format!("POP3 server rejected: {}", greeting.message)));
    }

    let apop_timestamp = extract_apop_timestamp(&greeting.message);

    send_command(writer, "CAPA").await?;
    let capa_resp = read_response(reader).await?;

    if !capa_resp.ok {
        return Ok((apop_timestamp, Vec::new(), false, false, false));
    }

    let capa_lines = read_multiline(reader).await?;
    let (sasl_mechs, has_apop) = parse_pop3_capabilities(&capa_lines);
    let has_stls = capa_lines
        .iter()
        .any(|l| l.to_uppercase() == "STLS" || l.to_uppercase().starts_with("STLS "));
    Ok((apop_timestamp, sasl_mechs, has_apop, has_stls, true))
}

/// Parse POP3 CAPA response lines into SASL mechanisms and APOP flag.
fn parse_pop3_capabilities(lines: &[String]) -> (Vec<String>, bool) {
    let mut sasl_mechs = Vec::new();
    let mut has_apop = false;
    for line in lines {
        let upper = line.to_uppercase();
        if upper.starts_with("SASL") {
            for mech in upper.split_whitespace().skip(1) {
                sasl_mechs.push(mech.to_string());
            }
        }
        if upper == "APOP" || upper.starts_with("APOP ") {
            has_apop = true;
        }
    }
    (sasl_mechs, has_apop)
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
    list_only: bool,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    login_options: Option<&str>,
    sasl_authzid: Option<&str>,
    use_ssl: UseSsl,
    tls_config: &crate::tls::TlsConfig,
) -> Result<Response, Error> {
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
    // Credentials are optional for EXTERNAL auth
    let has_creds = url_creds.is_some() || credentials.is_some();
    let (raw_user, pass) = if has_creds {
        url_creds
            .or(credentials)
            .ok_or_else(|| Error::Http("POP3 requires credentials".to_string()))?
    } else {
        ("", "")
    };
    // Strip ";AUTH=..." from username (login options, not part of the name)
    let user_owned = strip_auth_from_username(&percent_decode_str(raw_user));
    let user: &str = &user_owned;

    let path = url.path();
    let msg_num: Option<u32> = path.trim_start_matches('/').parse().ok();

    // Determine if this is implicit TLS (pop3s://) vs explicit STARTTLS
    let use_implicit_tls = url.scheme() == "pop3s";
    let use_starttls = !use_implicit_tls && use_ssl != UseSsl::None;

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    // Establish connection with appropriate TLS mode.
    // For STLS (POP3's STARTTLS), we use concrete types for the initial
    // negotiation (greeting, CAPA, STLS command), then unsplit → TLS handshake
    // → re-split into type-erased boxed streams for the rest of the protocol.
    #[allow(clippy::type_complexity)]
    let (mut reader, mut writer, apop_timestamp, server_sasl_mechs, server_has_apop): (
        BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        Option<String>,
        Vec<String>,
        bool,
    ) = if use_implicit_tls {
        let connector = crate::tls::TlsConnector::new(tls_config)?;
        let (tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        let (r, w) = tokio::io::split(tls_stream);
        let mut rd = BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
        let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
        let (apop_ts, sasl_mechs, has_apop, _has_stls, _capa_ok) =
            pop3_greeting_and_capa(&mut rd, &mut wr).await?;
        (rd, wr, apop_ts, sasl_mechs, has_apop)
    } else {
        // Plain connection — use concrete types so we can unsplit for STLS
        let (r, w) = tokio::io::split(tcp);
        let mut plain_reader = BufReader::new(r);
        let mut plain_writer = w;
        let (apop_ts, sasl_mechs, has_apop, has_stls, capa_ok) =
            pop3_greeting_and_capa(&mut plain_reader, &mut plain_writer).await?;

        // CAPA failed and STLS required → error immediately (no QUIT)
        if !capa_ok && use_starttls && use_ssl == UseSsl::All {
            return Err(Error::Transfer {
                code: 64,
                message: "POP3 STLS required but CAPA failed".to_string(),
            });
        }

        if use_starttls && has_stls {
            send_command(&mut plain_writer, "STLS").await?;
            let stls_resp = read_response(&mut plain_reader).await?;
            if !stls_resp.ok {
                return Err(Error::Protocol(8));
            }
            // Reassemble TCP stream and upgrade to TLS
            let tcp_restored = plain_reader.into_inner().unsplit(plain_writer);
            let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
            let (tls_stream, _) = connector.connect(tcp_restored, &host).await?;
            let (r, w) = tokio::io::split(tls_stream);
            let mut rd =
                BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
            // Re-CAPA over TLS (RFC 2595)
            send_command(&mut wr, "CAPA").await?;
            let capa2 = read_response(&mut rd).await?;
            let (sasl2, apop2) = if capa2.ok {
                let lines = read_multiline(&mut rd).await?;
                parse_pop3_capabilities(&lines)
            } else {
                (Vec::new(), false)
            };
            (rd, wr, apop_ts, sasl2, apop2)
        } else if use_starttls && use_ssl == UseSsl::All && !has_stls {
            let _ = send_command(&mut plain_writer, "QUIT").await;
            return Err(Error::Transfer {
                code: 64,
                message: "POP3 STLS required but not advertised".to_string(),
            });
        } else {
            // No TLS upgrade — box the plain streams
            let rd =
                BufReader::new(Box::new(plain_reader.into_inner())
                    as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(plain_writer);
            (rd, wr, apop_ts, sasl_mechs, has_apop)
        }
    };

    let forced =
        login_options.and_then(|lo| lo.strip_prefix("AUTH=").or_else(|| lo.strip_prefix("auth=")));

    let auth_done = do_pop3_auth(
        &mut reader,
        &mut writer,
        user,
        pass,
        sasl_ir,
        oauth2_bearer,
        sasl_authzid,
        &host,
        port,
        server_has_apop,
        apop_timestamp.as_ref(),
        forced,
        &server_sasl_mechs,
    )
    .await?;

    if !auth_done {
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
            let _ = send_command(&mut writer, "QUIT").await;
            let _ = read_response(&mut reader).await;
            // -ERR → CURLE_WEIRD_SERVER_REPLY (8; curl compat: tests 852, 855)
            return Err(Error::Protocol(8));
        }
        // Some custom commands (TOP, RETR) return multiline data
        let cmd_upper = cmd.to_uppercase();
        if cmd_upper.starts_with("TOP")
            || cmd_upper.starts_with("RETR")
            || cmd_upper.starts_with("LIST")
            || cmd_upper.starts_with("UIDL")
            || cmd_upper.starts_with("CAPA")
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
    } else if list_only && msg_num.is_some() {
        // LIST specific message (curl -l with message number; curl compat: test 852)
        let num = msg_num.unwrap_or(0);
        send_command(&mut writer, &format!("LIST {num}")).await?;
        let list_resp = read_response(&mut reader).await?;
        if !list_resp.ok {
            // -ERR → QUIT + CURLE_WEIRD_SERVER_REPLY (8)
            let _ = send_command(&mut writer, "QUIT").await;
            let _ = read_response(&mut reader).await;
            return Err(Error::Protocol(8));
        }
        let body = format!("{}\r\n", list_resp.message).into_bytes();
        send_command(&mut writer, "QUIT").await?;
        let _ = read_response(&mut reader).await;
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-length".to_string(), body.len().to_string());
        return Ok(Response::new(200, headers, body, url.as_str().to_string()));
    } else if let Some(num) = msg_num {
        // RETR specific message
        send_command(&mut writer, &format!("RETR {num}")).await?;
        let retr_resp = read_response(&mut reader).await?;
        if !retr_resp.ok {
            // -ERR → QUIT + CURLE_WEIRD_SERVER_REPLY (8; curl compat: test 855)
            let _ = send_command(&mut writer, "QUIT").await;
            let _ = read_response(&mut reader).await;
            return Err(Error::Protocol(8));
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

/// Perform POP3 authentication with mechanism negotiation and downgrade support.
///
/// Returns `Ok(true)` if SASL auth succeeded, `Ok(false)` if no SASL mechanism matched
/// (caller should fall through to USER/PASS).
///
/// Returns `Err` if authentication was attempted and failed (no QUIT/retry possible).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn do_pop3_auth<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    writer: &mut W,
    user: &str,
    pass: &str,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    sasl_authzid: Option<&str>,
    host: &str,
    port: u16,
    server_has_apop: bool,
    apop_timestamp: Option<&String>,
    forced: Option<&str>,
    server_sasl_mechs: &[String],
) -> Result<bool, Error> {
    use base64::Engine;

    let has_mech = |mech: &str| server_sasl_mechs.iter().any(|m| m.eq_ignore_ascii_case(mech));
    let should_try =
        |mech: &str| forced.map_or_else(|| has_mech(mech), |f| f.eq_ignore_ascii_case(mech));

    // EXTERNAL: send base64(username) or = for empty
    if should_try("EXTERNAL") {
        let encoded = if user.is_empty() {
            "=".to_string()
        } else {
            base64::engine::general_purpose::STANDARD.encode(user.as_bytes())
        };
        if sasl_ir {
            send_command(writer, &format!("AUTH EXTERNAL {encoded}")).await?;
        } else {
            send_command(writer, "AUTH EXTERNAL").await?;
            let _ = read_continuation(reader).await?;
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let auth_resp = read_response(reader).await?;
        if !auth_resp.ok {
            return Err(Error::Transfer {
                code: 67,
                message: "POP3 AUTH EXTERNAL failed".to_string(),
            });
        }
        return Ok(true);
    }

    // OAUTHBEARER / XOAUTH2
    if let Some(bearer) = oauth2_bearer {
        if should_try("OAUTHBEARER") {
            // RFC 7628 OAUTHBEARER format
            let payload = format!(
                "n,a={user},\x01host={host}\x01port={port}\x01auth=Bearer {bearer}\x01\x01"
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            if sasl_ir {
                send_command(writer, &format!("AUTH OAUTHBEARER {encoded}")).await?;
            } else {
                send_command(writer, "AUTH OAUTHBEARER").await?;
                let _ = read_continuation(reader).await?;
                writer
                    .write_all(format!("{encoded}\r\n").as_bytes())
                    .await
                    .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
                let _ = writer.flush().await;
            }
            // Read response — could be +OK or a continuation with error JSON
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let trimmed = line.trim();
            if trimmed.starts_with("+OK") {
                return Ok(true);
            }
            if trimmed.starts_with('+') && !trimmed.starts_with("+OK") {
                // Server sent error JSON as continuation — send SASL abort (AQ==)
                writer
                    .write_all(b"AQ==\r\n")
                    .await
                    .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
                let _ = writer.flush().await;
                // Read the -ERR response
                let _ = read_response(reader).await;
                return Err(Error::Transfer {
                    code: 67,
                    message: "POP3 AUTH OAUTHBEARER failed".to_string(),
                });
            }
            // -ERR response
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH OAUTHBEARER failed: {trimmed}"),
            });
        }

        if should_try("XOAUTH2") || !should_try("OAUTHBEARER") {
            // XOAUTH2 fallback
            let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            if sasl_ir {
                send_command(writer, &format!("AUTH XOAUTH2 {encoded}")).await?;
            } else {
                send_command(writer, "AUTH XOAUTH2").await?;
                let _ = read_continuation(reader).await?;
                writer
                    .write_all(format!("{encoded}\r\n").as_bytes())
                    .await
                    .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
                let _ = writer.flush().await;
            }
            let auth_resp = read_response(reader).await?;
            if !auth_resp.ok {
                return Err(Error::Transfer {
                    code: 67,
                    message: format!("POP3 AUTH XOAUTH2 failed: {}", auth_resp.message),
                });
            }
            return Ok(true);
        }
    }

    // Track downgrade state
    let mut cram_failed = false;
    let mut ntlm_failed = false;

    // CRAM-MD5
    if should_try("CRAM-MD5") {
        send_command(writer, "AUTH CRAM-MD5").await?;
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await;
        let challenge_b64 = line.trim().trim_start_matches('+').trim();
        if let Ok(challenge_bytes) = base64::engine::general_purpose::STANDARD.decode(challenge_b64)
        {
            let challenge = String::from_utf8_lossy(&challenge_bytes);
            let response_str = crate::auth::cram_md5::cram_md5_response(user, pass, &challenge);
            let encoded = base64::engine::general_purpose::STANDARD.encode(response_str.as_bytes());
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
            let auth_resp = read_response(reader).await?;
            if auth_resp.ok {
                return Ok(true);
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH CRAM-MD5 failed: {}", auth_resp.message),
            });
        }
        // Invalid challenge — send SASL cancel
        writer
            .write_all(b"*\r\n")
            .await
            .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
        let _ = writer.flush().await;
        // Read server's error response
        let _ = read_response(reader).await;
        cram_failed = true;
    }

    // NTLM
    if !cram_failed && should_try("NTLM") || cram_failed && has_mech("NTLM") {
        let type1 = crate::auth::ntlm::create_type1_message();
        if sasl_ir {
            send_command(writer, &format!("AUTH NTLM {type1}")).await?;
        } else {
            send_command(writer, "AUTH NTLM").await?;
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            // Send Type 1
            writer
                .write_all(format!("{type1}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        // Read Type 2 challenge
        let mut line2 = String::new();
        let _ = reader.read_line(&mut line2).await;
        let challenge_b64 = line2.trim().trim_start_matches('+').trim();
        if let Ok(challenge) = crate::auth::ntlm::parse_type2_message(challenge_b64) {
            let type3 = crate::auth::ntlm::create_type3_message(&challenge, user, pass, "")?;
            writer
                .write_all(format!("{type3}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
            let auth_resp = read_response(reader).await?;
            if auth_resp.ok {
                return Ok(true);
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH NTLM failed: {}", auth_resp.message),
            });
        }
        // Bad challenge — cancel
        writer
            .write_all(b"*\r\n")
            .await
            .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
        let _ = writer.flush().await;
        // Read server's error response
        let _ = read_response(reader).await;
        ntlm_failed = true;
    }

    // LOGIN
    if should_try("LOGIN") {
        let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());
        if sasl_ir {
            send_command(writer, &format!("AUTH LOGIN {user_b64}")).await?;
        } else {
            send_command(writer, "AUTH LOGIN").await?;
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer
                .write_all(format!("{user_b64}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let mut line2 = String::new();
        let _ = reader.read_line(&mut line2).await;
        writer
            .write_all(format!("{pass_b64}\r\n").as_bytes())
            .await
            .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
        let _ = writer.flush().await;
        let auth_resp = read_response(reader).await?;
        if !auth_resp.ok {
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH LOGIN failed: {}", auth_resp.message),
            });
        }
        return Ok(true);
    }

    // PLAIN (also used as downgrade target from CRAM-MD5/NTLM)
    let try_plain = should_try("PLAIN") || (cram_failed || ntlm_failed) && has_mech("PLAIN");
    if try_plain {
        let auth_string = sasl_authzid.map_or_else(
            || format!("\0{user}\0{pass}"),
            |authzid| format!("{authzid}\0{user}\0{pass}"),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());
        if sasl_ir {
            send_command(writer, &format!("AUTH PLAIN {encoded}")).await?;
        } else {
            send_command(writer, "AUTH PLAIN").await?;
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            writer
                .write_all(format!("{encoded}\r\n").as_bytes())
                .await
                .map_err(|e| Error::Http(format!("POP3 write error: {e}")))?;
            let _ = writer.flush().await;
        }
        let auth_resp = read_response(reader).await?;
        if !auth_resp.ok {
            return Err(Error::Transfer {
                code: 67,
                message: format!("POP3 AUTH PLAIN failed: {}", auth_resp.message),
            });
        }
        return Ok(true);
    }

    // APOP
    if (server_has_apop || apop_timestamp.is_some()) && !cram_failed && !ntlm_failed {
        if let Some(ts) = apop_timestamp {
            let digest = crate::auth::cram_md5::apop_digest(ts, pass);
            send_command(writer, &format!("APOP {user} {digest}")).await?;
            let auth_resp = read_response(reader).await?;
            if !auth_resp.ok {
                send_command(writer, "QUIT").await?;
                let _ = read_response(reader).await;
                return Err(Error::Transfer {
                    code: 67,
                    message: format!("POP3 APOP failed: {}", auth_resp.message),
                });
            }
            return Ok(true);
        }
    }

    // If CRAM-MD5 or NTLM failed and no PLAIN available, error out
    if cram_failed || ntlm_failed {
        return Err(Error::Transfer {
            code: 67,
            message: "POP3 authentication cancelled, no fallback available".to_string(),
        });
    }

    Ok(false)
}

/// Strip `;AUTH=<mechanism>` from a URL username.
fn strip_auth_from_username(username: &str) -> String {
    let upper = username.to_uppercase();
    upper.find(";AUTH=").map_or_else(|| username.to_string(), |pos| username[..pos].to_string())
}

/// Percent-decode a string.
fn percent_decode_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
            } else {
                out.push('%');
                out.push_str(&hex);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract the APOP timestamp from a POP3 greeting message.
///
/// Looks for a `<...>` pattern in the greeting text.
fn extract_apop_timestamp(greeting: &str) -> Option<String> {
    let start = greeting.find('<')?;
    let end = greeting[start..].find('>')? + start + 1;
    Some(greeting[start..end].to_string())
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
