//! SMTP protocol handler.
//!
//! Implements a full SMTP client (RFC 5321) for sending email messages and
//! executing SMTP commands (VRFY, EXPN, HELP, NOOP, RSET).
//! Supports EHLO/HELO greeting, MAIL FROM, RCPT TO, DATA commands,
//! AUTH PLAIN/LOGIN/XOAUTH2 authentication, and SIZE extension.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;

use crate::protocol::ftp::UseSsl;

/// Configuration for an SMTP transfer.
#[derive(Debug, Clone, Default)]
pub struct SmtpConfig<'a> {
    /// SMTP envelope sender (MAIL FROM).
    pub mail_from: Option<&'a str>,
    /// SMTP envelope recipients (RCPT TO).
    pub mail_rcpt: &'a [String],
    /// SMTP AUTH identity (MAIL AUTH).
    pub mail_auth: Option<&'a str>,
    /// SASL authorization identity.
    pub sasl_authzid: Option<&'a str>,
    /// Send SASL initial response in first message.
    pub sasl_ir: bool,
    /// Custom SMTP command (curl `-X`).
    pub custom_request: Option<&'a str>,
    /// OAuth 2.0 bearer token for XOAUTH2/OAUTHBEARER.
    pub oauth2_bearer: Option<&'a str>,
    /// Convert LF to CRLF in upload data (curl `--crlf`).
    pub crlf: bool,
    /// Authentication username (from `-u user:pass`).
    pub username: Option<&'a str>,
    /// Authentication password (from `-u user:pass`).
    pub password: Option<&'a str>,
    /// Login options (`;AUTH=<mechanism>` from URL).
    pub login_options: Option<&'a str>,
}

/// An SMTP response from the server.
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    /// The 3-digit status code.
    pub code: u16,
    /// The response text (may be multi-line).
    pub message: String,
    /// The raw response lines as received from the server (with status codes).
    pub raw: String,
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

/// EHLO capabilities parsed from server response.
#[derive(Debug, Default)]
struct EhloCapabilities {
    /// Whether the server supports SIZE extension.
    size: bool,
    /// Whether the server supports STARTTLS.
    starttls: bool,
    /// Whether the server supports SMTPUTF8 (RFC 6531).
    smtputf8: bool,
    /// Supported AUTH mechanisms (uppercased).
    auth_mechanisms: Vec<String>,
}

/// Parse EHLO response to extract capabilities.
fn parse_ehlo_capabilities(message: &str) -> EhloCapabilities {
    let mut caps = EhloCapabilities::default();
    for line in message.lines() {
        let line_upper = line.to_uppercase();
        if line_upper.starts_with("SIZE") || line_upper == "SIZE" {
            caps.size = true;
        } else if line_upper == "STARTTLS" || line_upper.starts_with("STARTTLS ") {
            caps.starttls = true;
        } else if line_upper == "SMTPUTF8" || line_upper.starts_with("SMTPUTF8 ") {
            caps.smtputf8 = true;
        } else if let Some(mechs) = line_upper.strip_prefix("AUTH ") {
            for mech in mechs.split_whitespace() {
                caps.auth_mechanisms.push(mech.to_string());
            }
        } else if line_upper == "AUTH" {
            // AUTH with no mechanisms listed
        }
    }
    caps
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
    let mut raw_response = String::new();
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

        // Capture raw line (with status code prefix)
        raw_response.push_str(line);
        raw_response.push_str("\r\n");

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

    Ok(SmtpResponse { code, message: full_message, raw: raw_response })
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

/// Determine the SMTP operation mode based on config.
///
/// curl uses the URL path as the EHLO hostname and determines the mode:
/// - If `--mail-from` is set: mail send mode (MAIL FROM / RCPT TO / DATA)
/// - If `--mail-rcpt` is set without `--mail-from`: VRFY mode (or custom `-X`)
/// - If neither: HELP mode (or custom `-X`)
#[derive(Debug)]
enum SmtpMode {
    /// Send mail: MAIL FROM, RCPT TO, DATA
    Send,
    /// VRFY command with recipients
    Vrfy,
    /// Custom command (EXPN, NOOP, RSET, etc.)
    Custom(String),
    /// HELP command (no recipients, no sender)
    Help,
}

/// Perform the SMTP greeting and EHLO/HELO exchange.
///
/// Reads the server greeting, sends EHLO (with HELO fallback), and returns
/// whether EHLO succeeded along with parsed capabilities.
///
/// # Errors
///
/// Returns an error if the greeting is rejected or HELO fails.
async fn smtp_greeting_and_ehlo<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    ehlo_name: &str,
) -> Result<(bool, EhloCapabilities), Error> {
    let greeting = read_response(reader).await?;
    if !greeting.is_ok() {
        return Err(Error::Http(format!(
            "SMTP server rejected connection: {} {}",
            greeting.code, greeting.message
        )));
    }

    send_command(writer, &format!("EHLO {ehlo_name}")).await?;
    let ehlo_resp = read_response(reader).await?;

    if ehlo_resp.is_ok() {
        Ok((true, parse_ehlo_capabilities(&ehlo_resp.message)))
    } else {
        // Fall back to HELO
        send_command(writer, &format!("HELO {ehlo_name}")).await?;
        let helo_resp = read_response(reader).await?;
        if !helo_resp.is_ok() {
            return Err(Error::Http(format!(
                "SMTP HELO failed: {} {}",
                helo_resp.code, helo_resp.message
            )));
        }
        Ok((false, EhloCapabilities::default()))
    }
}

/// Send an email or execute an SMTP command.
///
/// Connects to the SMTP server specified in the URL, performs EHLO/HELO,
/// optionally authenticates, and then either sends mail or executes commands
/// (VRFY, EXPN, HELP, etc.) depending on the configuration.
///
/// The URL path is used as the EHLO hostname (curl compatibility).
///
/// # Errors
///
/// Returns an error if connection, auth, or transfer fails.
#[allow(clippy::too_many_lines)]
pub async fn send_mail(
    url: &crate::url::Url,
    mail_data: &[u8],
    config: &SmtpConfig<'_>,
    use_ssl: UseSsl,
    tls_config: &crate::tls::TlsConfig,
    pre_connected: Option<tokio::net::TcpStream>,
) -> Result<crate::protocol::http::response::Response, Error> {
    let (host, port) = url.host_and_port()?;

    // Extract the URL path for EHLO — curl uses the first path segment
    // e.g., smtp://host:port/912 -> EHLO 912
    let url_path = url.path();
    let ehlo_name = url_path.strip_prefix('/').unwrap_or(url_path).split('/').next().unwrap_or("");
    // If no path segment, fall back to hostname
    let ehlo_name = if ehlo_name.is_empty() { host.as_str() } else { ehlo_name };

    // Reject URLs with CR/LF in path (curl returns CURLE_URL_MALFORMAT = 3)
    let decoded_path = url_decode(url_path);
    if decoded_path.contains('\r') || decoded_path.contains('\n') {
        return Err(Error::UrlParse("URL contains CR/LF characters".to_string()));
    }

    // Extract credentials: config (from -u flag) takes priority over URL-embedded
    // Strip ";AUTH=..." from URL username (it's login-options, not part of the name)
    let credentials: Option<(String, String)> = config.username.map_or_else(
        || {
            url.credentials().map(|(u, p)| {
                let decoded_user = url_decode(u);
                let clean_user = strip_auth_from_username(&decoded_user);
                (clean_user, p.to_string())
            })
        },
        |user| Some((user.to_string(), config.password.unwrap_or("").to_string())),
    );

    // Determine SMTP mode
    let mode = determine_smtp_mode(config, !mail_data.is_empty());

    // Determine if this is implicit TLS (smtps://) vs explicit STARTTLS
    let use_implicit_tls = url.scheme() == "smtps";
    let use_starttls = !use_implicit_tls && use_ssl != UseSsl::None;

    // Connect to SMTP server (with optional TLS for smtps://)
    let tcp = if let Some(stream) = pre_connected {
        stream
    } else {
        let addr = format!("{host}:{port}");
        tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?
    };

    // Establish connection with appropriate TLS mode.
    // For STARTTLS, we use concrete types for the initial negotiation (greeting,
    // EHLO, STARTTLS command), then unsplit → TLS handshake → re-split into
    // type-erased boxed streams for the rest of the protocol.
    #[allow(clippy::type_complexity)]
    let (mut reader, mut writer, caps, ehlo_ok): (
        BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        EhloCapabilities,
        bool,
    ) = if use_implicit_tls {
        let connector = crate::tls::TlsConnector::new(tls_config)?;
        let (tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        let (r, w) = tokio::io::split(tls_stream);
        let mut rd = BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
        let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
        let (ehlo_ok, caps) = smtp_greeting_and_ehlo(&mut rd, &mut wr, ehlo_name).await?;
        (rd, wr, caps, ehlo_ok)
    } else {
        // Plain connection — use concrete types so we can unsplit for STARTTLS
        let (r, w) = tokio::io::split(tcp);
        let mut plain_reader = BufReader::new(r);
        let mut plain_writer = w;
        let (ehlo_ok, caps) =
            smtp_greeting_and_ehlo(&mut plain_reader, &mut plain_writer, ehlo_name).await?;

        if use_starttls && ehlo_ok && caps.starttls {
            // Server advertises STARTTLS — send the command
            send_command(&mut plain_writer, "STARTTLS").await?;
            let starttls_resp = read_response(&mut plain_reader).await?;
            if !starttls_resp.is_ok() {
                // Server rejected STARTTLS — return CURLE_WEIRD_SERVER_REPLY (8)
                return Err(Error::Protocol(8));
            }

            // Reassemble TCP stream from split halves and upgrade to TLS
            let tcp_restored = plain_reader.into_inner().unsplit(plain_writer);
            let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
            let (tls_stream, _) = connector.connect(tcp_restored, &host).await?;
            let (r, w) = tokio::io::split(tls_stream);
            let mut rd =
                BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);

            // Re-EHLO over the TLS connection (RFC 3207 Section 4.2)
            send_command(&mut wr, &format!("EHLO {ehlo_name}")).await?;
            let ehlo2 = read_response(&mut rd).await?;
            let (ehlo_ok2, caps2) = if ehlo2.is_ok() {
                (true, parse_ehlo_capabilities(&ehlo2.message))
            } else {
                (false, EhloCapabilities::default())
            };
            (rd, wr, caps2, ehlo_ok2)
        } else if use_starttls && use_ssl == UseSsl::All && (!ehlo_ok || !caps.starttls) {
            // STARTTLS required but not available or EHLO failed
            let _ = send_command(&mut plain_writer, "QUIT").await;
            return Err(Error::Transfer {
                code: 64,
                message: "SMTP STARTTLS required but not available".to_string(),
            });
        } else {
            // No TLS upgrade — box the plain streams
            let rd =
                BufReader::new(Box::new(plain_reader.into_inner())
                    as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(plain_writer);
            (rd, wr, caps, ehlo_ok)
        }
    };

    // Authenticate if credentials provided AND server advertises AUTH
    // When EHLO failed (HELO fallback), skip auth (no capability).
    // When EHLO succeeded but no AUTH advertised, skip auth (curl compat: test 940).
    if ehlo_ok && !caps.auth_mechanisms.is_empty() {
        if let Some((ref user, ref pass)) = credentials {
            do_auth(
                &mut reader,
                &mut writer,
                user,
                pass,
                config.sasl_authzid,
                config.sasl_ir,
                &caps.auth_mechanisms,
                config.login_options,
                &host,
                port,
                config.oauth2_bearer,
            )
            .await?;
        }
    }

    // Convert IDN hostnames in recipient addresses and detect SMTPUTF8 need.
    let idn_rcpts: Vec<String> = config
        .mail_rcpt
        .iter()
        .map(|r| crate::idn::idn_email_address(r).unwrap_or_else(|_| r.clone()))
        .collect();
    let need_smtputf8 = config.mail_rcpt.iter().any(|r| crate::idn::has_non_ascii(r))
        || config.mail_from.is_some_and(|f| crate::idn::has_non_ascii(f));

    // Execute the appropriate SMTP mode
    let mut response_body = Vec::new();
    match mode {
        SmtpMode::Send => {
            do_send_mail(
                &mut reader,
                &mut writer,
                mail_data,
                config,
                &caps,
                &idn_rcpts,
                need_smtputf8,
            )
            .await?;
        }
        SmtpMode::Vrfy => {
            for rcpt in &idn_rcpts {
                let mut vrfy_cmd = format!("VRFY {rcpt}");
                if caps.smtputf8 && need_smtputf8 {
                    vrfy_cmd.push_str(" SMTPUTF8");
                }
                send_command(&mut writer, &vrfy_cmd).await?;
                let resp = read_response(&mut reader).await?;
                if !resp.is_ok() && resp.code != 553 {
                    let _ = send_command(&mut writer, "QUIT").await;
                    return Err(Error::Protocol(8));
                }
                response_body.extend_from_slice(resp.raw.as_bytes());
            }
        }
        SmtpMode::Custom(cmd) => {
            if idn_rcpts.is_empty() {
                send_command(&mut writer, &cmd).await?;
            } else {
                for rcpt in &idn_rcpts {
                    let mut custom_cmd = format!("{cmd} {rcpt}");
                    if caps.smtputf8 && need_smtputf8 {
                        custom_cmd.push_str(" SMTPUTF8");
                    }
                    send_command(&mut writer, &custom_cmd).await?;
                }
            }
            let resp = read_response(&mut reader).await?;
            response_body.extend_from_slice(resp.raw.as_bytes());
            if !resp.is_ok() {
                let _ = send_command(&mut writer, "QUIT").await;
                return Err(Error::Protocol(8));
            }
        }
        SmtpMode::Help => {
            send_command(&mut writer, "HELP").await?;
            let resp = read_response(&mut reader).await?;
            response_body.extend_from_slice(resp.raw.as_bytes());
            if !resp.is_ok() {
                let _ = send_command(&mut writer, "QUIT").await;
                return Err(Error::Protocol(8));
            }
        }
    }

    // QUIT
    send_command(&mut writer, "QUIT").await?;

    let headers = std::collections::HashMap::new();
    Ok(crate::protocol::http::response::Response::new(
        250,
        headers,
        response_body,
        url.as_str().to_string(),
    ))
}

/// Determine the SMTP mode based on configuration and mail data.
fn determine_smtp_mode(config: &SmtpConfig<'_>, has_data: bool) -> SmtpMode {
    if let Some(custom) = config.custom_request {
        return SmtpMode::Custom(custom.to_string());
    }
    // If --mail-from is set OR upload data is present, it's send mode
    if config.mail_from.is_some() || has_data {
        return SmtpMode::Send;
    }
    if !config.mail_rcpt.is_empty() {
        return SmtpMode::Vrfy;
    }
    SmtpMode::Help
}

/// Perform AUTH using the best available mechanism.
///
/// curl's negotiation order: EXTERNAL > OAUTHBEARER > XOAUTH2 > CRAM-MD5 > NTLM > LOGIN > PLAIN.
/// When `login_options` is set (e.g. `;AUTH=CRAM-MD5`), only that mechanism is tried.
///
/// Supports SASL downgrade: when CRAM-MD5 or NTLM fails with a bad challenge,
/// sends `*` to cancel and tries the next mechanism (PLAIN).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn do_auth<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    writer: &mut W,
    user: &str,
    pass: &str,
    sasl_authzid: Option<&str>,
    sasl_ir: bool,
    server_mechs: &[String],
    login_options: Option<&str>,
    host: &str,
    port: u16,
    oauth2_bearer: Option<&str>,
) -> Result<(), Error> {
    use base64::Engine;

    let has = |mech: &str| server_mechs.iter().any(|m| m.eq_ignore_ascii_case(mech));
    let forced =
        login_options.and_then(|lo| lo.strip_prefix("AUTH=").or_else(|| lo.strip_prefix("auth=")));

    // Helper: check if we should try this mechanism
    let should_try =
        |mech: &str| forced.map_or_else(|| has(mech), |f| f.eq_ignore_ascii_case(mech));

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
            let resp = read_response(reader).await?;
            if resp.code != 334 {
                return Err(Error::SmtpAuth("AUTH EXTERNAL failed".to_string()));
            }
            send_command(writer, &encoded).await?;
        }
        let auth_resp = read_response(reader).await?;
        if auth_resp.is_ok() {
            return Ok(());
        }
        return Err(Error::SmtpAuth("AUTH EXTERNAL failed".to_string()));
    }

    // OAUTHBEARER (RFC 7628): n,a=user,\x01host=H\x01port=P\x01auth=Bearer T\x01\x01
    if let Some(bearer) = oauth2_bearer {
        if should_try("OAUTHBEARER") {
            let payload = format!(
                "n,a={user},\x01host={host}\x01port={port}\x01auth=Bearer {bearer}\x01\x01"
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            if sasl_ir {
                send_command(writer, &format!("AUTH OAUTHBEARER {encoded}")).await?;
            } else {
                send_command(writer, "AUTH OAUTHBEARER").await?;
                let resp = read_response(reader).await?;
                if resp.code != 334 {
                    return Err(Error::SmtpAuth(format!(
                        "AUTH OAUTHBEARER expected 334, got: {}",
                        resp.code
                    )));
                }
                send_command(writer, &encoded).await?;
            }
            let auth_resp = read_response(reader).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            // Server may send 334 with error JSON — need to send AQ== cancel
            if auth_resp.code == 334 {
                send_command(writer, "AQ==").await?;
                let _ = read_response(reader).await;
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!(
                    "AUTH OAUTHBEARER failed: {} {}",
                    auth_resp.code, auth_resp.message
                ),
            });
        }

        // XOAUTH2 fallback
        if should_try("XOAUTH2") {
            let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            if sasl_ir {
                send_command(writer, &format!("AUTH XOAUTH2 {encoded}")).await?;
            } else {
                send_command(writer, "AUTH XOAUTH2").await?;
                let resp = read_response(reader).await?;
                if resp.code != 334 {
                    return Err(Error::SmtpAuth(format!(
                        "AUTH XOAUTH2 expected 334, got: {}",
                        resp.code
                    )));
                }
                send_command(writer, &encoded).await?;
            }
            let auth_resp = read_response(reader).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            return Err(Error::SmtpAuth(format!(
                "AUTH XOAUTH2 failed: {} {}",
                auth_resp.code, auth_resp.message
            )));
        }
    }

    // Track downgrade state
    let mut cram_failed = false;
    let mut ntlm_failed = false;

    // CRAM-MD5: challenge-response with HMAC-MD5
    if should_try("CRAM-MD5") {
        send_command(writer, "AUTH CRAM-MD5").await?;
        let resp = read_response(reader).await?;
        if resp.code != 334 {
            return Err(Error::SmtpAuth(format!("AUTH CRAM-MD5 expected 334, got: {}", resp.code)));
        }
        // Server sends base64-encoded challenge
        let challenge_b64 = resp.message.trim();
        if let Ok(challenge_bytes) = base64::engine::general_purpose::STANDARD.decode(challenge_b64)
        {
            let challenge = String::from_utf8_lossy(&challenge_bytes);
            let response_str = crate::auth::cram_md5::cram_md5_response(user, pass, &challenge);
            let encoded = base64::engine::general_purpose::STANDARD.encode(response_str.as_bytes());
            send_command(writer, &encoded).await?;
            let auth_resp = read_response(reader).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            return Err(Error::SmtpAuth(format!(
                "AUTH CRAM-MD5 failed: {} {}",
                auth_resp.code, auth_resp.message
            )));
        }
        // Invalid challenge — send SASL cancel
        send_command(writer, "*").await?;
        let _ = read_response(reader).await;
        cram_failed = true;
    }

    // NTLM: 3-step Type 1/2/3 exchange
    if !cram_failed && should_try("NTLM") || cram_failed && has("NTLM") {
        let type1 = crate::auth::ntlm::create_type1_message();
        if sasl_ir {
            send_command(writer, &format!("AUTH NTLM {type1}")).await?;
        } else {
            send_command(writer, "AUTH NTLM").await?;
            let resp = read_response(reader).await?;
            if resp.code != 334 {
                return Err(Error::SmtpAuth(format!("AUTH NTLM expected 334, got: {}", resp.code)));
            }
            // Send Type 1
            send_command(writer, &type1).await?;
        }
        let resp2 = read_response(reader).await?;
        if resp2.code == 334 {
            // Parse Type 2 and generate Type 3
            let challenge_b64 = resp2.message.trim();
            if let Ok(challenge) = crate::auth::ntlm::parse_type2_message(challenge_b64) {
                let type3 = crate::auth::ntlm::create_type3_message(&challenge, user, pass, "")?;
                send_command(writer, &type3).await?;
                let auth_resp = read_response(reader).await?;
                if auth_resp.is_ok() {
                    return Ok(());
                }
                return Err(Error::SmtpAuth(format!(
                    "AUTH NTLM failed: {} {}",
                    auth_resp.code, auth_resp.message
                )));
            }
        }
        // Invalid or bad Type 2 challenge — cancel auth (send * per RFC 4954)
        send_command(writer, "*").await?;
        let _ = read_response(reader).await;
        ntlm_failed = true;
    }

    // LOGIN: base64(user), base64(pass)
    if should_try("LOGIN") && !cram_failed && !ntlm_failed {
        if sasl_ir {
            let encoded_user = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
            send_command(writer, &format!("AUTH LOGIN {encoded_user}")).await?;
        } else {
            send_command(writer, "AUTH LOGIN").await?;
            let resp = read_response(reader).await?;
            if resp.code != 334 {
                return Err(Error::SmtpAuth(format!(
                    "AUTH LOGIN expected 334, got: {} {}",
                    resp.code, resp.message
                )));
            }
            let encoded_user = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
            send_command(writer, &encoded_user).await?;
        }
        let resp = read_response(reader).await?;
        if resp.code != 334 {
            return Err(Error::SmtpAuth(format!(
                "AUTH LOGIN expected 334 for password, got: {} {}",
                resp.code, resp.message
            )));
        }
        let encoded_pass = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());
        send_command(writer, &encoded_pass).await?;
        let auth_resp = read_response(reader).await?;
        if auth_resp.is_ok() {
            return Ok(());
        }
        return Err(Error::SmtpAuth(format!(
            "AUTH LOGIN failed: {} {}",
            auth_resp.code, auth_resp.message
        )));
    }

    // PLAIN: \0user\0pass (also used as downgrade target)
    let try_plain = should_try("PLAIN") || (cram_failed || ntlm_failed) && has("PLAIN");
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
            let resp = read_response(reader).await?;
            if resp.code != 334 {
                return Err(Error::SmtpAuth(format!(
                    "AUTH PLAIN expected 334, got: {} {}",
                    resp.code, resp.message
                )));
            }
            send_command(writer, &encoded).await?;
        }
        let auth_resp = read_response(reader).await?;
        if auth_resp.is_ok() {
            return Ok(());
        }
        return Err(Error::SmtpAuth(format!(
            "AUTH PLAIN failed: {} {}",
            auth_resp.code, auth_resp.message
        )));
    }

    // If CRAM-MD5 or NTLM failed and no PLAIN available, error out
    if cram_failed || ntlm_failed {
        return Err(Error::Transfer {
            code: 67,
            message: "SMTP authentication cancelled, no fallback available".to_string(),
        });
    }

    Ok(())
}

/// Execute the mail send flow: MAIL FROM, RCPT TO, DATA.
async fn do_send_mail<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    writer: &mut W,
    mail_data: &[u8],
    config: &SmtpConfig<'_>,
    caps: &EhloCapabilities,
    idn_rcpts: &[String],
    need_smtputf8: bool,
) -> Result<(), Error> {
    // Determine sender address — default to empty (curl compat: test 915)
    let from_addr = config.mail_from.unwrap_or("");
    let from_addr =
        crate::idn::idn_email_address(from_addr).unwrap_or_else(|_| from_addr.to_string());

    // Build MAIL FROM command
    let mut mail_from_cmd = format!("MAIL FROM:<{from_addr}>");

    // Add AUTH= parameter if specified (RFC 2554)
    if let Some(auth) = config.mail_auth {
        use std::fmt::Write;
        let _ = write!(mail_from_cmd, " AUTH=<{auth}>");
    }

    // Add SIZE= parameter if server supports SIZE extension
    if caps.size {
        use std::fmt::Write;
        let _ = write!(mail_from_cmd, " SIZE={}", mail_data.len());
    }

    // Add SMTPUTF8 if server supports it and addresses have non-ASCII (RFC 6531)
    if caps.smtputf8 && need_smtputf8 {
        mail_from_cmd.push_str(" SMTPUTF8");
    }

    send_command(writer, &mail_from_cmd).await?;
    let mail_resp = read_response(reader).await?;
    if !mail_resp.is_ok() {
        // MAIL FROM rejected → QUIT + exit code 55 (CURLE_SEND_ERROR)
        let _ = send_command(writer, "QUIT").await;
        return Err(Error::SmtpSend(format!(
            "SMTP MAIL FROM failed: {} {}",
            mail_resp.code, mail_resp.message
        )));
    }

    // RCPT TO (one per recipient)
    for rcpt in idn_rcpts {
        send_command(writer, &format!("RCPT TO:<{rcpt}>")).await?;
        let rcpt_resp = read_response(reader).await?;
        if !rcpt_resp.is_ok() {
            // RCPT TO rejected → QUIT + exit code 55 (CURLE_SEND_ERROR)
            let _ = send_command(writer, "QUIT").await;
            return Err(Error::SmtpSend(format!(
                "SMTP RCPT TO failed: {} {}",
                rcpt_resp.code, rcpt_resp.message
            )));
        }
    }

    // DATA
    send_command(writer, "DATA").await?;
    let data_resp = read_response(reader).await?;
    if !data_resp.is_intermediate() {
        return Err(Error::SmtpSend(format!(
            "SMTP DATA failed: {} {}",
            data_resp.code, data_resp.message
        )));
    }

    // Check for 7-bit encoding violations in the body (curl compat: test 649).
    // This check happens after DATA so the SMTP protocol commands are captured.
    if check_7bit_violation(mail_data) {
        return Err(Error::Transfer {
            code: 26,
            message: "7-bit encoding applied to 8-bit data".to_string(),
        });
    }

    // Send message body with proper line handling
    write_smtp_data(writer, mail_data, config.crlf).await?;

    // End data with CRLF.CRLF
    send_command(writer, ".").await?;
    let end_resp = read_response(reader).await?;
    if !end_resp.is_ok() {
        return Err(Error::SmtpSend(format!(
            "SMTP message rejected: {} {}",
            end_resp.code, end_resp.message
        )));
    }

    Ok(())
}

/// Check if a MIME body has `Content-Transfer-Encoding: 7bit` followed by 8-bit data.
///
/// Scans the body for `Content-Transfer-Encoding: 7bit` headers and validates
/// that the corresponding part data contains only 7-bit ASCII bytes.
fn check_7bit_violation(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    // Split on boundary delimiters (lines starting with --)
    let mut in_7bit_part = false;
    let mut past_headers = false;

    for line in text.split('\n') {
        let trimmed = line.trim_end_matches('\r');

        // Boundary delimiter resets state
        if trimmed.starts_with("--") {
            in_7bit_part = false;
            past_headers = false;
            continue;
        }

        // Empty line = end of headers
        if trimmed.is_empty() && !past_headers {
            past_headers = true;
            continue;
        }

        // Check for CTE: 7bit header
        if !past_headers && trimmed.eq_ignore_ascii_case("Content-Transfer-Encoding: 7bit") {
            in_7bit_part = true;
            continue;
        }

        // If we're in a 7bit part body, check for 8-bit bytes
        if in_7bit_part && past_headers && line.as_bytes().iter().any(|&b| b > 127) {
            return true;
        }
    }

    false
}

/// Write SMTP DATA body, handling dot-stuffing and optional CRLF conversion.
///
/// When `crlf` is true, converts lone LF to CRLF (curl `--crlf`).
/// Lines starting with `.` get an extra `.` prepended (dot-stuffing per RFC 5321).
/// Data is sent as-is otherwise, matching curl's behavior.
async fn write_smtp_data<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    crlf: bool,
) -> Result<(), Error> {
    // Buffer output to avoid excessive system calls (important for large uploads).
    let mut buf = Vec::with_capacity(data.len() + data.len() / 50);
    let mut at_line_start = true;
    let mut last_was_crlf = true; // Whether last line ending was proper CRLF

    let mut i = 0;
    while i < data.len() {
        let b = data[i];

        if at_line_start && b == b'.' {
            // Dot-stuff: add extra dot before the line's dot
            buf.push(b'.');
            buf.push(b'.');
            at_line_start = false;
            last_was_crlf = false;
            i += 1;
            continue;
        }

        if b == b'\r' && data.get(i + 1) == Some(&b'\n') {
            // CRLF pair — write it and mark line start
            buf.push(b'\r');
            buf.push(b'\n');
            at_line_start = true;
            last_was_crlf = true;
            i += 2;
            continue;
        }

        if b == b'\n' {
            if crlf {
                // --crlf: convert lone LF to CRLF
                buf.push(b'\r');
                buf.push(b'\n');
                last_was_crlf = true;
            } else {
                // Send bare LF as-is (curl compat: test 900)
                buf.push(b'\n');
                last_was_crlf = false;
            }
            at_line_start = true;
            i += 1;
            continue;
        }

        // Regular byte
        buf.push(b);
        at_line_start = false;
        last_was_crlf = false;
        i += 1;
    }

    // Ensure CRLF before the terminating dot (curl compat: SMTP_EOB = "\r\n.\r\n")
    // If data didn't end with CRLF, add one
    if !last_was_crlf {
        buf.push(b'\r');
        buf.push(b'\n');
    }

    // Write the entire buffer at once
    writer.write_all(&buf).await.map_err(|e| Error::Http(format!("SMTP data write error: {e}")))?;
    writer.flush().await.map_err(|e| Error::Http(format!("SMTP flush error: {e}")))?;
    Ok(())
}

/// Strip `;AUTH=<mechanism>` from a URL username.
///
/// curl allows `smtp://user;AUTH=EXTERNAL@host/` syntax.
fn strip_auth_from_username(username: &str) -> String {
    username
        .find(";AUTH=")
        .or_else(|| username.find(";auth="))
        .or_else(|| username.to_uppercase().find(";AUTH="))
        .map_or_else(|| username.to_string(), |pos| username[..pos].to_string())
}

/// URL-decode a percent-encoded string.
fn url_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                result.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

/// Convert a hex digit character to its value.
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract From and To addresses from email headers.
#[cfg(test)]
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
#[cfg(test)]
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
        let resp = SmtpResponse { code: 250, message: String::new(), raw: String::new() };
        assert!(resp.is_ok());
        assert!(!resp.is_intermediate());
    }

    #[test]
    fn smtp_response_status_intermediate() {
        let resp = SmtpResponse { code: 354, message: String::new(), raw: String::new() };
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
    fn parse_ehlo_caps_with_size_and_auth() {
        let msg = "smtp.example.com\nSIZE 10240000\nAUTH PLAIN LOGIN";
        let caps = parse_ehlo_capabilities(msg);
        assert!(caps.size);
        assert_eq!(caps.auth_mechanisms, vec!["PLAIN", "LOGIN"]);
    }

    #[test]
    fn parse_ehlo_caps_no_size() {
        let msg = "smtp.example.com\nAUTH PLAIN";
        let caps = parse_ehlo_capabilities(msg);
        assert!(!caps.size);
        assert_eq!(caps.auth_mechanisms, vec!["PLAIN"]);
    }

    #[test]
    fn parse_ehlo_caps_size_only() {
        let msg = "smtp.example.com\nSIZE";
        let caps = parse_ehlo_capabilities(msg);
        assert!(caps.size);
        assert!(caps.auth_mechanisms.is_empty());
    }

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("/hello"), "/hello");
        assert_eq!(url_decode("/%0d%0a"), "/\r\n");
        assert_eq!(url_decode("/foo%20bar"), "/foo bar");
    }

    #[test]
    fn determine_mode_send() {
        let config = SmtpConfig {
            mail_from: Some("sender@example.com"),
            mail_rcpt: &[],
            ..SmtpConfig::default()
        };
        assert!(matches!(determine_smtp_mode(&config, false), SmtpMode::Send));
    }

    #[test]
    fn determine_mode_send_with_data() {
        let config = SmtpConfig::default();
        assert!(matches!(determine_smtp_mode(&config, true), SmtpMode::Send));
    }

    #[test]
    fn determine_mode_vrfy() {
        let rcpts = vec!["recipient".to_string()];
        let config = SmtpConfig { mail_rcpt: &rcpts, ..SmtpConfig::default() };
        assert!(matches!(determine_smtp_mode(&config, false), SmtpMode::Vrfy));
    }

    #[test]
    fn determine_mode_help() {
        let config = SmtpConfig::default();
        assert!(matches!(determine_smtp_mode(&config, false), SmtpMode::Help));
    }

    #[test]
    fn determine_mode_custom() {
        let config = SmtpConfig { custom_request: Some("EXPN"), ..SmtpConfig::default() };
        assert!(matches!(determine_smtp_mode(&config, false), SmtpMode::Custom(_)));
    }
}
