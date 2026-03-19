//! IMAP protocol handler.
//!
//! Implements an `IMAP4rev1` client (RFC 3501 / RFC 5092) for reading and
//! managing mailboxes.  Supports CAPABILITY, LOGIN, SELECT, LIST, FETCH,
//! APPEND, SEARCH, and arbitrary custom commands via `-X`.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;
use crate::protocol::ftp::UseSsl;
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
    prefix: char,
    next: u32,
}

impl TagCounter {
    const fn new(prefix: char) -> Self {
        Self { prefix, next: 1 }
    }

    fn next_tag(&mut self) -> String {
        let tag = format!("{}{:03}", self.prefix, self.next);
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
        if trimmed.starts_with("* ") {
            data.push(trimmed.to_string());
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

/// Send raw data (without a tag, for APPEND literal upload).
///
/// # Errors
///
/// Returns an error if the write fails.
async fn send_raw<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<(), Error> {
    stream.write_all(data).await.map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
    stream.write_all(b"\r\n").await.map_err(|e| Error::Http(format!("IMAP write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("IMAP flush error: {e}")))?;
    Ok(())
}

/// Read the untagged greeting sent by the server upon connection.
///
/// The greeting may be preceded by banner lines (e.g. curl's test IMAP server
/// sends an ASCII-art banner before the `* OK ...` line).  We keep reading
/// until we find a line starting with `* OK` or `* PREAUTH`.
///
/// # Errors
///
/// Returns an error if the connection drops before a valid greeting is found.
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
        if trimmed.starts_with("* OK") || trimmed.starts_with("* PREAUTH") {
            return Ok(trimmed.to_string());
        }
        // Skip non-greeting lines (banners, etc.)
    }
}

/// Wait for a continuation response (`+ ...`) from the server.
///
/// # Errors
///
/// Returns an error if the server doesn't send a continuation.
async fn read_continuation<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<String, Error> {
    let mut line = String::new();
    let bytes_read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Http(format!("IMAP read error: {e}")))?;
    if bytes_read == 0 {
        return Err(Error::Http("IMAP connection closed waiting for continuation".to_string()));
    }
    Ok(line.trim().to_string())
}

/// Quote an IMAP string value (RFC 3501 Section 4.3).
///
/// Wraps the value in double-quotes and backslash-escapes any embedded `"` or `\`.
fn imap_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Check whether a string needs IMAP quoting (contains special chars).
fn needs_quoting(s: &str) -> bool {
    s.is_empty()
        || s.contains('"')
        || s.contains('\\')
        || s.contains(' ')
        || s.contains('{')
        || s.contains('(')
        || s.contains(')')
        || s.contains('%')
        || s.contains('*')
        || s.contains(']')
}

/// Parsed IMAP URL parameters.
#[derive(Debug, Default)]
struct ImapParams {
    /// Mailbox name (empty means root / no mailbox).
    mailbox: String,
    /// UID of message to fetch.
    uid: Option<u32>,
    /// MAILINDEX (sequence number) of message to fetch.
    mailindex: Option<u32>,
    /// SECTION (body part) to fetch, e.g. "TEXT", "1", "2.3".
    section: Option<String>,
    /// UIDVALIDITY to verify after SELECT.
    uidvalidity: Option<String>,
    /// SEARCH query from the URL query string (e.g. `?NEW`).
    search: Option<String>,
}

/// Parse an IMAP URL into its component parts.
///
/// RFC 5092 URL format:
/// - `/mailbox` — select + list
/// - `/mailbox/;UID=N` — select + uid fetch
/// - `/mailbox/;MAILINDEX=N` — select + fetch by sequence number
/// - `/mailbox/;MAILINDEX=N/;SECTION=S` — fetch with specific body section
/// - `/mailbox;UIDVALIDITY=N/...` — verify uidvalidity after select
/// - `?query` — search query
fn parse_imap_url(path: &str, query: Option<&str>) -> ImapParams {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let mut params = ImapParams::default();

    if let Some(q) = query {
        if !q.is_empty() {
            params.search = Some(q.to_string());
        }
    }

    // Split path into segments at "/;"
    // Examples:
    //   "INBOX" -> ["INBOX"]
    //   "INBOX/;MAILINDEX=1" -> ["INBOX", "MAILINDEX=1"]
    //   "INBOX/;MAILINDEX=1/;SECTION=TEXT" -> ["INBOX", "MAILINDEX=1", "SECTION=TEXT"]
    //   "INBOX;UIDVALIDITY=123/;MAILINDEX=1" -> ["INBOX;UIDVALIDITY=123", "MAILINDEX=1"]
    let parts: Vec<&str> = path.split("/;").collect();

    if let Some(first) = parts.first() {
        // The first segment is the mailbox, possibly with ;UIDVALIDITY=N
        let mailbox_part = *first;
        if let Some((mbox, rest)) = mailbox_part.split_once(";UIDVALIDITY=") {
            params.mailbox = mbox.to_string();
            params.uidvalidity = Some(rest.to_string());
        } else if let Some((mbox, rest)) = mailbox_part.split_once(";uidvalidity=") {
            params.mailbox = mbox.to_string();
            params.uidvalidity = Some(rest.to_string());
        } else {
            params.mailbox = mailbox_part.to_string();
        }
    }

    // Parse remaining segments for UID, MAILINDEX, SECTION
    for part in parts.iter().skip(1) {
        let part_upper = part.to_uppercase();
        if let Some(val) = part_upper.strip_prefix("UID=") {
            params.uid = val.parse().ok();
        } else if let Some(val) = part_upper.strip_prefix("MAILINDEX=") {
            params.mailindex = val.parse().ok();
        } else if let Some(idx) = part_upper.find("SECTION=") {
            // Use original case for section value
            let section_val = &part[idx + 8..];
            params.section = Some(section_val.to_string());
        }
    }

    params
}

/// Perform the IMAP greeting and CAPABILITY exchange.
///
/// Returns `(is_preauth, auth_mechanisms, server_sasl_ir, has_starttls, cap_ok)`.
///
/// # Errors
///
/// Returns an error if the greeting is rejected.
async fn imap_greeting_and_capability<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    tags: &mut TagCounter,
) -> Result<(bool, Vec<String>, bool, bool, bool), Error> {
    let greeting = read_greeting(reader).await?;
    let is_preauth = greeting.contains("PREAUTH");
    if !greeting.contains("OK") && !is_preauth {
        return Err(Error::Http(format!("IMAP server rejected: {greeting}")));
    }

    let tag = tags.next_tag();
    send_command(writer, &tag, "CAPABILITY").await?;
    let cap_resp = read_response(reader, &tag).await?;

    if !cap_resp.is_ok() {
        // Return empty capabilities — caller checks cap_ok for error
        return Ok((is_preauth, Vec::new(), false, false, false));
    }

    let (auth_mechs, sasl_ir) = parse_imap_capabilities(&cap_resp.data);
    let has_starttls = cap_resp
        .data
        .iter()
        .any(|line| line.split_whitespace().any(|t| t.eq_ignore_ascii_case("STARTTLS")));
    Ok((is_preauth, auth_mechs, sasl_ir, has_starttls, true))
}

/// Parse AUTH mechanisms and SASL-IR from CAPABILITY response data.
fn parse_imap_capabilities(data: &[String]) -> (Vec<String>, bool) {
    let mut auth_mechs = Vec::new();
    let mut sasl_ir = false;
    for line in data {
        for token in line.split_whitespace() {
            if let Some(mech) = token.strip_prefix("AUTH=").or_else(|| token.strip_prefix("auth="))
            {
                auth_mechs.push(mech.to_uppercase());
            }
            if token.eq_ignore_ascii_case("SASL-IR") {
                sasl_ir = true;
            }
        }
    }
    (auth_mechs, sasl_ir)
}

/// Execute an IMAP operation based on URL and options.
///
/// URL format: `imap://user:pass@host:port/mailbox/;UID=N`
///
/// Supports:
/// - FETCH by UID or MAILINDEX with optional SECTION
/// - LIST (when no message specified)
/// - SEARCH (when query string present)
/// - APPEND (when upload data provided via `-T`)
/// - Custom commands via `-X`
///
/// # Errors
///
/// Returns an error if login fails, the mailbox doesn't exist, or the operation fails.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn fetch(
    url: &crate::url::Url,
    method: &str,
    body: Option<&[u8]>,
    custom_request: Option<&str>,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    login_options: Option<&str>,
    sasl_authzid: Option<&str>,
    resolve_overrides: &[(String, String)],
    tag_prefix: char,
    use_ssl: UseSsl,
    tls_config: &crate::tls::TlsConfig,
) -> Result<Response, Error> {
    // Reject URLs with CR or LF in the path (curl compat: test 829).
    // Check BEFORE credentials or connection setup.
    let path = url.path();
    let lower_path = path.to_lowercase();
    if lower_path.contains("%0d")
        || lower_path.contains("%0a")
        || path.contains('\r')
        || path.contains('\n')
    {
        return Err(Error::UrlParse("URL contains CR or LF characters".to_string()));
    }

    let (host, port) = url.host_and_port()?;
    // Credentials are optional for EXTERNAL auth (test 838/840)
    let creds = url.credentials();

    // URL credentials are percent-encoded; decode them for IMAP LOGIN.
    // Strip ";AUTH=..." from username (it's login options, not part of the name).
    let user = creds.map_or_else(String::new, |(raw_user, _)| {
        let decoded_user = percent_decode(raw_user);
        strip_auth_from_username(&decoded_user)
    });
    let pass = creds.map_or_else(String::new, |(_, raw_pass)| percent_decode(raw_pass));

    let imap_params = parse_imap_url(path, url.query());

    // Determine if this is implicit TLS (imaps://) vs explicit STARTTLS
    let use_implicit_tls = url.scheme() == "imaps";
    let use_starttls = !use_implicit_tls && use_ssl != UseSsl::None;

    // Apply resolve overrides: --resolve host:port:addr stores (host, addr) with port stripped
    let resolved_host =
        resolve_overrides
            .iter()
            .find_map(|(pattern, target)| {
                if pattern.eq_ignore_ascii_case(&host) {
                    Some(target.as_str())
                } else {
                    None
                }
            })
            .unwrap_or(&host);
    let addr = format!("{resolved_host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let mut tags = TagCounter::new(tag_prefix);

    // Establish connection with appropriate TLS mode.
    // For STARTTLS, we use concrete types for the initial negotiation
    // (greeting, CAPABILITY, STARTTLS command), then unsplit → TLS handshake
    // → re-split into type-erased boxed streams for the rest of the protocol.
    #[allow(clippy::type_complexity)]
    let (mut reader, mut writer, server_auth_mechs, server_sasl_ir, is_preauth): (
        BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        Vec<String>,
        bool,
        bool,
    ) = if use_implicit_tls {
        let connector = crate::tls::TlsConnector::new(tls_config)?;
        let (tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        let (r, w) = tokio::io::split(tls_stream);
        let mut rd = BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
        let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
        let (is_preauth, auth_mechs, sasl_ir, _has_starttls, _cap_ok) =
            imap_greeting_and_capability(&mut rd, &mut wr, &mut tags).await?;
        (rd, wr, auth_mechs, sasl_ir, is_preauth)
    } else {
        let (r, w) = tokio::io::split(tcp);
        let mut plain_reader = BufReader::new(r);
        let mut plain_writer = w;
        let (is_preauth, auth_mechs, sasl_ir, has_starttls, cap_ok) =
            imap_greeting_and_capability(&mut plain_reader, &mut plain_writer, &mut tags).await?;

        // CAPABILITY failed and STARTTLS required → error immediately (no LOGOUT)
        if !cap_ok && use_starttls && use_ssl == UseSsl::All {
            return Err(Error::Transfer {
                code: 64,
                message: "IMAP STARTTLS required but CAPABILITY failed".to_string(),
            });
        }

        if use_starttls && has_starttls {
            let tag = tags.next_tag();
            send_command(&mut plain_writer, &tag, "STARTTLS").await?;
            let starttls_resp = read_response(&mut plain_reader, &tag).await?;
            if !starttls_resp.is_ok() {
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
            // Re-CAPABILITY over TLS (RFC 2595 Section 3.1)
            let tag = tags.next_tag();
            send_command(&mut wr, &tag, "CAPABILITY").await?;
            let cap2 = read_response(&mut rd, &tag).await?;
            let (auth_mechs2, sasl_ir2) = parse_imap_capabilities(&cap2.data);
            (rd, wr, auth_mechs2, sasl_ir2, is_preauth)
        } else if use_starttls && use_ssl == UseSsl::All && !has_starttls {
            let ltag = tags.next_tag();
            let _ = send_command(&mut plain_writer, &ltag, "LOGOUT").await;
            return Err(Error::Transfer {
                code: 64,
                message: "IMAP STARTTLS required but not advertised".to_string(),
            });
        } else {
            let rd =
                BufReader::new(Box::new(plain_reader.into_inner())
                    as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(plain_writer);
            (rd, wr, auth_mechs, sasl_ir, is_preauth)
        }
    };

    // Skip authentication if PREAUTH was received (curl compat: test 846).
    // The server already authenticated the connection (e.g. via TLS client cert).
    if !is_preauth {
        let forced = login_options
            .and_then(|lo| lo.strip_prefix("AUTH=").or_else(|| lo.strip_prefix("auth=")));

        // Check if forced mechanism is +LOGIN (plain LOGIN command, not SASL AUTHENTICATE LOGIN)
        let force_login_cmd = forced
            .is_some_and(|f| f.eq_ignore_ascii_case("+LOGIN") || f.eq_ignore_ascii_case("LOGIN"));

        // Authenticate using the best available mechanism
        // Order: EXTERNAL > OAUTHBEARER > XOAUTH2 > CRAM-MD5 > NTLM > LOGIN > PLAIN > LOGIN cmd
        // With downgrade: if CRAM-MD5 or NTLM fails with bad challenge, cancel and try next
        let auth_result = do_imap_auth(
            &mut reader,
            &mut writer,
            &mut tags,
            &user,
            &pass,
            sasl_ir,
            server_sasl_ir,
            oauth2_bearer,
            sasl_authzid,
            &host,
            port,
            force_login_cmd,
            forced,
            &server_auth_mechs,
        )
        .await;

        // Auth failed — do NOT send LOGOUT (curl compat: tests 830, 831, 844, 845, 849)
        // The multi interface considers a broken "CONNECT" as a prematurely broken
        // transfer and such a connection will not get a "LOGOUT"
        auth_result?;
    }

    // Determine what operation to perform
    let mut selected_mailbox: Option<String> = None;
    let result = dispatch_imap_operation(
        &mut reader,
        &mut writer,
        &mut tags,
        &imap_params,
        method,
        body,
        custom_request,
        &mut selected_mailbox,
    )
    .await;

    // LOGOUT — always send, even on error (curl compat: test 803)
    let tag = tags.next_tag();
    if send_command(&mut writer, &tag, "LOGOUT").await.is_ok() {
        // Best-effort read LOGOUT response
        let _ = read_response(&mut reader, &tag).await;
    }

    let response_body = result?;

    let headers = std::collections::HashMap::new();
    let mut resp = Response::new(200, headers, response_body, url.as_str().to_string());
    // Set empty raw headers so the CLI doesn't synthesize HTTP framing for
    // a non-HTTP protocol response.
    resp.set_raw_headers(Vec::new());
    Ok(resp)
}

/// A single IMAP operation descriptor for use with [`fetch_multi`].
#[derive(Debug)]
pub struct ImapOperation<'a> {
    /// The IMAP URL for this operation.
    pub url: &'a crate::url::Url,
    /// HTTP method (e.g. "GET", "PUT").
    pub method: &'a str,
    /// Upload body data (for APPEND via `-T`).
    pub body: Option<&'a [u8]>,
    /// Custom IMAP command (from `-X`).
    pub custom_request: Option<&'a str>,
}

/// Execute multiple IMAP operations on a single connection.
///
/// Opens one connection, authenticates once, then dispatches each operation
/// in sequence, reusing SELECT state to avoid redundant SELECTs on the same
/// mailbox (curl compat: tests 804, 815, 816).
///
/// Returns one `Response` per operation.
///
/// # Errors
///
/// Returns an error if connection, authentication, or any operation fails.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn fetch_multi(
    ops: &[ImapOperation<'_>],
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    login_options: Option<&str>,
    sasl_authzid: Option<&str>,
    resolve_overrides: &[(String, String)],
    tag_prefix: char,
    use_ssl: UseSsl,
    tls_config: &crate::tls::TlsConfig,
) -> Result<Vec<Response>, Error> {
    if ops.is_empty() {
        return Ok(Vec::new());
    }

    // Use the first URL for connection setup
    let first_url = ops[0].url;
    let path = first_url.path();

    let (host, port) = first_url.host_and_port()?;
    let creds = first_url.credentials();
    let user = creds.map_or_else(String::new, |(raw_user, _)| {
        let decoded_user = percent_decode(raw_user);
        strip_auth_from_username(&decoded_user)
    });
    let pass = creds.map_or_else(String::new, |(_, raw_pass)| percent_decode(raw_pass));

    let use_implicit_tls = first_url.scheme() == "imaps";
    let use_starttls = !use_implicit_tls && use_ssl != UseSsl::None;

    let resolved_host =
        resolve_overrides
            .iter()
            .find_map(|(pattern, target)| {
                if pattern.eq_ignore_ascii_case(&host) {
                    Some(target.as_str())
                } else {
                    None
                }
            })
            .unwrap_or(&host);
    let addr = format!("{resolved_host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let mut tags = TagCounter::new(tag_prefix);

    // Same STARTTLS setup as fetch()
    #[allow(clippy::type_complexity)]
    let (mut reader, mut writer, server_auth_mechs, server_sasl_ir, is_preauth): (
        BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        Vec<String>,
        bool,
        bool,
    ) = if use_implicit_tls {
        let connector = crate::tls::TlsConnector::new(tls_config)?;
        let (tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        let (r, w) = tokio::io::split(tls_stream);
        let mut rd = BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
        let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
        let (is_preauth, auth_mechs, sasl_ir, _has_starttls, _cap_ok) =
            imap_greeting_and_capability(&mut rd, &mut wr, &mut tags).await?;
        (rd, wr, auth_mechs, sasl_ir, is_preauth)
    } else {
        let (r, w) = tokio::io::split(tcp);
        let mut plain_reader = BufReader::new(r);
        let mut plain_writer = w;
        let (is_preauth, auth_mechs, sasl_ir, has_starttls, cap_ok) =
            imap_greeting_and_capability(&mut plain_reader, &mut plain_writer, &mut tags).await?;

        if !cap_ok && use_starttls && use_ssl == UseSsl::All {
            return Err(Error::Transfer {
                code: 64,
                message: "IMAP STARTTLS required but CAPABILITY failed".to_string(),
            });
        }

        if use_starttls && has_starttls {
            let tag = tags.next_tag();
            send_command(&mut plain_writer, &tag, "STARTTLS").await?;
            let starttls_resp = read_response(&mut plain_reader, &tag).await?;
            if !starttls_resp.is_ok() {
                return Err(Error::Protocol(8));
            }
            let tcp_restored = plain_reader.into_inner().unsplit(plain_writer);
            let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
            let (tls_stream, _) = connector.connect(tcp_restored, &host).await?;
            let (r, w) = tokio::io::split(tls_stream);
            let mut rd =
                BufReader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let mut wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(w);
            let tag = tags.next_tag();
            send_command(&mut wr, &tag, "CAPABILITY").await?;
            let cap2 = read_response(&mut rd, &tag).await?;
            let (auth_mechs2, sasl_ir2) = parse_imap_capabilities(&cap2.data);
            (rd, wr, auth_mechs2, sasl_ir2, is_preauth)
        } else if use_starttls && use_ssl == UseSsl::All && !has_starttls {
            let ltag = tags.next_tag();
            let _ = send_command(&mut plain_writer, &ltag, "LOGOUT").await;
            return Err(Error::Transfer {
                code: 64,
                message: "IMAP STARTTLS required but not advertised".to_string(),
            });
        } else {
            let rd =
                BufReader::new(Box::new(plain_reader.into_inner())
                    as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
            let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(plain_writer);
            (rd, wr, auth_mechs, sasl_ir, is_preauth)
        }
    };

    // Authenticate (skip if PREAUTH)
    if !is_preauth {
        let forced = login_options
            .and_then(|lo| lo.strip_prefix("AUTH=").or_else(|| lo.strip_prefix("auth=")));
        let force_login_cmd = forced
            .is_some_and(|f| f.eq_ignore_ascii_case("+LOGIN") || f.eq_ignore_ascii_case("LOGIN"));
        let auth_result = do_imap_auth(
            &mut reader,
            &mut writer,
            &mut tags,
            &user,
            &pass,
            sasl_ir,
            server_sasl_ir,
            oauth2_bearer,
            sasl_authzid,
            &host,
            port,
            force_login_cmd,
            forced,
            &server_auth_mechs,
        )
        .await;
        auth_result?;
    }

    // Execute each operation, reusing SELECT state
    let mut selected_mailbox: Option<String> = None;
    let mut results = Vec::with_capacity(ops.len());

    for op in ops {
        let op_path = op.url.path();
        // Reject CR/LF in path
        let lower_path = op_path.to_lowercase();
        if lower_path.contains("%0d")
            || lower_path.contains("%0a")
            || op_path.contains('\r')
            || op_path.contains('\n')
        {
            return Err(Error::UrlParse("URL contains CR or LF characters".to_string()));
        }

        let imap_params = parse_imap_url(op_path, op.url.query());
        let result = dispatch_imap_operation(
            &mut reader,
            &mut writer,
            &mut tags,
            &imap_params,
            op.method,
            op.body,
            op.custom_request,
            &mut selected_mailbox,
        )
        .await;

        let response_body = result?;
        let headers = std::collections::HashMap::new();
        let mut resp = Response::new(200, headers, response_body, op.url.as_str().to_string());
        resp.set_raw_headers(Vec::new());
        results.push(resp);
    }

    // LOGOUT
    let tag = tags.next_tag();
    if send_command(&mut writer, &tag, "LOGOUT").await.is_ok() {
        let _ = read_response(&mut reader, &tag).await;
    }

    let _ = path; // suppress warning
    Ok(results)
}

/// Perform IMAP authentication with mechanism negotiation and downgrade support.
///
/// Tries mechanisms in order: EXTERNAL > OAUTHBEARER > XOAUTH2 > CRAM-MD5 > NTLM > PLAIN > LOGIN cmd.
/// When CRAM-MD5 or NTLM fails with a bad challenge, sends `*` to cancel and tries the next mechanism.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn do_imap_auth<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    writer: &mut W,
    tags: &mut TagCounter,
    user: &str,
    pass: &str,
    sasl_ir: bool,
    server_sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    sasl_authzid: Option<&str>,
    host: &str,
    port: u16,
    force_login_cmd: bool,
    forced: Option<&str>,
    server_auth_mechs: &[String],
) -> Result<(), Error> {
    use base64::Engine;

    let has_mech = |mech: &str| server_auth_mechs.iter().any(|m| m.eq_ignore_ascii_case(mech));
    let should_try =
        |mech: &str| forced.map_or_else(|| has_mech(mech), |f| f.eq_ignore_ascii_case(mech));

    // If forced to plain LOGIN command (AUTH=+LOGIN or AUTH=LOGIN)
    if force_login_cmd {
        let tag = tags.next_tag();
        let login_user = if needs_quoting(user) { imap_quote(user) } else { user.to_string() };
        let login_pass = if needs_quoting(pass) { imap_quote(pass) } else { pass.to_string() };
        send_command(writer, &tag, &format!("LOGIN {login_user} {login_pass}")).await?;
        let login_resp = read_response(reader, &tag).await?;
        if !login_resp.is_ok() {
            return Err(Error::Transfer {
                code: 67,
                message: format!("IMAP LOGIN failed: {} {}", login_resp.status, login_resp.message),
            });
        }
        return Ok(());
    }

    // EXTERNAL: send base64(username)
    if should_try("EXTERNAL") {
        let tag = tags.next_tag();
        let use_ir = sasl_ir || server_sasl_ir;
        let encoded = if user.is_empty() {
            "=".to_string() // empty initial response
        } else {
            base64::engine::general_purpose::STANDARD.encode(user.as_bytes())
        };
        if use_ir {
            send_command(writer, &tag, &format!("AUTHENTICATE EXTERNAL {encoded}")).await?;
        } else {
            send_command(writer, &tag, "AUTHENTICATE EXTERNAL").await?;
            let _ = read_continuation(reader).await?;
            send_raw(writer, encoded.as_bytes()).await?;
        }
        let auth_resp = read_response(reader, &tag).await?;
        if !auth_resp.is_ok() {
            return Err(Error::Transfer {
                code: 67,
                message: "IMAP AUTHENTICATE EXTERNAL failed".to_string(),
            });
        }
        return Ok(());
    }

    // OAUTHBEARER / XOAUTH2
    if let Some(bearer) = oauth2_bearer {
        if should_try("OAUTHBEARER") {
            // RFC 7628 OAUTHBEARER
            let payload = format!(
                "n,a={user},\x01host={host}\x01port={port}\x01auth=Bearer {bearer}\x01\x01"
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            let tag = tags.next_tag();
            if server_sasl_ir || sasl_ir {
                send_command(writer, &tag, &format!("AUTHENTICATE OAUTHBEARER {encoded}")).await?;
                // After SASL-IR, server may send continuation with error JSON
                // We need to read next line: if it's '+', send AQ== cancel
                let line = read_continuation(reader).await?;
                if line.starts_with('+') {
                    // Server sent error JSON challenge — send SASL abort (base64 of 0x01)
                    send_raw(writer, b"AQ==").await?;
                    let _ = read_response(reader, &tag).await;
                    return Err(Error::Transfer {
                        code: 67,
                        message: "IMAP OAUTHBEARER failed".to_string(),
                    });
                }
                // If it's not '+', it should be the tagged OK/NO response
                // (handled by read_response which was already consumed)
                // Actually the read_continuation just reads one line — check if it was
                // the tagged response
                if line.starts_with(&tag) {
                    // Tagged response inline
                    if line.contains(" OK ") {
                        return Ok(());
                    }
                    return Err(Error::Transfer {
                        code: 67,
                        message: "IMAP OAUTHBEARER failed".to_string(),
                    });
                }
                // Otherwise read the tagged response normally
                let auth_resp = read_response(reader, &tag).await?;
                if auth_resp.is_ok() {
                    return Ok(());
                }
                return Err(Error::Transfer {
                    code: 67,
                    message: format!(
                        "IMAP OAUTHBEARER failed: {} {}",
                        auth_resp.status, auth_resp.message
                    ),
                });
            }
            // Without SASL-IR: send AUTHENTICATE, wait for continuation, send payload
            send_command(writer, &tag, "AUTHENTICATE OAUTHBEARER").await?;
            let _ = read_continuation(reader).await?;
            send_raw(writer, encoded.as_bytes()).await?;
            let auth_resp = read_response(reader, &tag).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!(
                    "IMAP OAUTHBEARER failed: {} {}",
                    auth_resp.status, auth_resp.message
                ),
            });
        }

        if should_try("XOAUTH2") || !should_try("OAUTHBEARER") {
            // XOAUTH2 fallback (or if XOAUTH2 forced)
            let payload = format!("user={user}\x01auth=Bearer {bearer}\x01\x01");
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            let tag = tags.next_tag();
            if server_sasl_ir || sasl_ir {
                send_command(writer, &tag, &format!("AUTHENTICATE XOAUTH2 {encoded}")).await?;
            } else {
                send_command(writer, &tag, "AUTHENTICATE XOAUTH2").await?;
                let _ = read_continuation(reader).await?;
                send_raw(writer, encoded.as_bytes()).await?;
            }
            let auth_resp = read_response(reader, &tag).await?;
            if !auth_resp.is_ok() {
                return Err(Error::Transfer {
                    code: 67,
                    message: format!(
                        "IMAP XOAUTH2 failed: {} {}",
                        auth_resp.status, auth_resp.message
                    ),
                });
            }
            return Ok(());
        }
    }

    // Track whether CRAM-MD5 or NTLM failed (for downgrade)
    let mut cram_failed = false;
    let mut ntlm_failed = false;

    // CRAM-MD5
    if should_try("CRAM-MD5") {
        let tag = tags.next_tag();
        send_command(writer, &tag, "AUTHENTICATE CRAM-MD5").await?;
        let cont = read_continuation(reader).await?;
        let challenge_b64 = cont.trim_start_matches('+').trim();
        if let Ok(challenge_bytes) = base64::engine::general_purpose::STANDARD.decode(challenge_b64)
        {
            let challenge = String::from_utf8_lossy(&challenge_bytes);
            let response_str = crate::auth::cram_md5::cram_md5_response(user, pass, &challenge);
            let encoded = base64::engine::general_purpose::STANDARD.encode(response_str.as_bytes());
            send_raw(writer, encoded.as_bytes()).await?;
            let auth_resp = read_response(reader, &tag).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!(
                    "IMAP CRAM-MD5 failed: {} {}",
                    auth_resp.status, auth_resp.message
                ),
            });
        }
        // Invalid challenge — send SASL cancel
        send_raw(writer, b"*").await?;
        let _ = read_response(reader, &tag).await;
        cram_failed = true;
    }

    // NTLM
    if !cram_failed && should_try("NTLM") || cram_failed && has_mech("NTLM") {
        let type1 = crate::auth::ntlm::create_type1_message();
        let tag = tags.next_tag();
        let use_ir = sasl_ir || server_sasl_ir;
        if use_ir {
            send_command(writer, &tag, &format!("AUTHENTICATE NTLM {type1}")).await?;
        } else {
            send_command(writer, &tag, "AUTHENTICATE NTLM").await?;
            let _ = read_continuation(reader).await?;
            send_raw(writer, type1.as_bytes()).await?;
        }
        // Read Type 2 challenge
        let cont2 = read_continuation(reader).await?;
        let challenge_b64 = cont2.trim_start_matches('+').trim();
        if let Ok(challenge) = crate::auth::ntlm::parse_type2_message(challenge_b64) {
            let type3 = crate::auth::ntlm::create_type3_message(&challenge, user, pass, "");
            send_raw(writer, type3.as_bytes()).await?;
            let auth_resp = read_response(reader, &tag).await?;
            if auth_resp.is_ok() {
                return Ok(());
            }
            return Err(Error::Transfer {
                code: 67,
                message: format!("IMAP NTLM failed: {} {}", auth_resp.status, auth_resp.message),
            });
        }
        // Bad challenge — cancel
        send_raw(writer, b"*").await?;
        let _ = read_response(reader, &tag).await;
        ntlm_failed = true;
    }

    // PLAIN (also used as downgrade target from CRAM-MD5/NTLM)
    let try_plain = should_try("PLAIN") || (cram_failed || ntlm_failed) && has_mech("PLAIN");
    if try_plain {
        let auth_string = sasl_authzid.map_or_else(
            || format!("\0{user}\0{pass}"),
            |authzid| format!("{authzid}\0{user}\0{pass}"),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_string.as_bytes());
        let tag = tags.next_tag();
        if sasl_ir || server_sasl_ir {
            send_command(writer, &tag, &format!("AUTHENTICATE PLAIN {encoded}")).await?;
        } else {
            send_command(writer, &tag, "AUTHENTICATE PLAIN").await?;
            let _ = read_continuation(reader).await?;
            send_raw(writer, encoded.as_bytes()).await?;
        }
        let auth_resp = read_response(reader, &tag).await?;
        if auth_resp.is_ok() {
            return Ok(());
        }
        return Err(Error::Transfer {
            code: 67,
            message: format!(
                "IMAP AUTHENTICATE PLAIN failed: {} {}",
                auth_resp.status, auth_resp.message
            ),
        });
    }

    // LOGIN SASL mechanism (AUTHENTICATE LOGIN)
    if should_try("LOGIN") {
        let tag = tags.next_tag();
        let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode(pass.as_bytes());
        if sasl_ir || server_sasl_ir {
            send_command(writer, &tag, &format!("AUTHENTICATE LOGIN {user_b64}")).await?;
        } else {
            send_command(writer, &tag, "AUTHENTICATE LOGIN").await?;
            let _ = read_continuation(reader).await?;
            send_raw(writer, user_b64.as_bytes()).await?;
        }
        let _ = read_continuation(reader).await?;
        send_raw(writer, pass_b64.as_bytes()).await?;
        let auth_resp = read_response(reader, &tag).await?;
        if auth_resp.is_ok() {
            return Ok(());
        }
        return Err(Error::Transfer {
            code: 67,
            message: format!(
                "IMAP AUTHENTICATE LOGIN failed: {} {}",
                auth_resp.status, auth_resp.message
            ),
        });
    }

    // If CRAM-MD5 or NTLM failed and no PLAIN available, error out
    if cram_failed || ntlm_failed {
        return Err(Error::Transfer {
            code: 67,
            message: "IMAP authentication cancelled, no fallback available".to_string(),
        });
    }

    // If no password is available, no auth method can work — fail early
    if pass.is_empty() {
        return Err(Error::Transfer {
            code: 67,
            message: "IMAP login denied: no password available".to_string(),
        });
    }

    // Plain LOGIN command (fallback when no SASL mechanism matches)
    let tag = tags.next_tag();
    let login_user = if needs_quoting(user) { imap_quote(user) } else { user.to_string() };
    let login_pass = if needs_quoting(pass) { imap_quote(pass) } else { pass.to_string() };
    send_command(writer, &tag, &format!("LOGIN {login_user} {login_pass}")).await?;
    let login_resp = read_response(reader, &tag).await?;
    if !login_resp.is_ok() {
        return Err(Error::Auth(format!(
            "IMAP LOGIN failed: {} {}",
            login_resp.status, login_resp.message
        )));
    }
    Ok(())
}

/// Dispatch the appropriate IMAP operation based on URL parameters and options.
///
/// `selected_mailbox` tracks which mailbox is already `SELECT`ed to avoid
/// redundant SELECT commands when reusing a connection (curl compat: test 804).
///
/// # Errors
///
/// Returns an error if any IMAP command fails.
#[allow(clippy::too_many_lines, clippy::too_many_arguments, clippy::items_after_statements)]
async fn dispatch_imap_operation<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    tags: &mut TagCounter,
    params: &ImapParams,
    method: &str,
    body: Option<&[u8]>,
    custom_request: Option<&str>,
    selected_mailbox: &mut Option<String>,
) -> Result<Vec<u8>, Error> {
    let has_mailbox = !params.mailbox.is_empty();

    /// Helper: SELECT a mailbox if not already selected.
    async fn select_if_needed<R2: AsyncRead + Unpin, W2: AsyncWrite + Unpin>(
        reader: &mut BufReader<R2>,
        writer: &mut W2,
        tags: &mut TagCounter,
        mailbox: &str,
        selected: &mut Option<String>,
    ) -> Result<Option<ImapResponse>, Error> {
        if selected.as_deref() == Some(mailbox) {
            return Ok(None);
        }
        let tag = tags.next_tag();
        send_command(writer, &tag, &format!("SELECT {mailbox}")).await?;
        let resp = read_response(reader, &tag).await?;
        if !resp.is_ok() {
            return Err(Error::Http(format!(
                "IMAP SELECT failed: {} {}",
                resp.status, resp.message
            )));
        }
        *selected = Some(mailbox.to_string());
        Ok(Some(resp))
    }

    // Upload via -T: IMAP APPEND command.
    // Check this BEFORE custom_request, since -T sets method=PUT and
    // custom_request="PUT", but we want APPEND behavior, not a literal "PUT" cmd.
    let is_upload = method == "PUT" && body.is_some();
    if is_upload {
        if let Some(upload_data) = body {
            if !has_mailbox {
                return Err(Error::Http(
                    "IMAP APPEND requires a mailbox in the URL path".to_string(),
                ));
            }
            let tag = tags.next_tag();
            let append_cmd =
                format!("APPEND {} (\\Seen) {{{}}}", params.mailbox, upload_data.len());
            send_command(writer, &tag, &append_cmd).await?;

            // Wait for continuation response (+ ...)
            let cont = read_continuation(reader).await?;
            if !cont.starts_with('+') {
                return Err(Error::Http(format!(
                    "IMAP APPEND: expected continuation, got: {cont}"
                )));
            }

            // Send the literal data followed by CRLF
            send_raw(writer, upload_data).await?;

            let resp = read_response(reader, &tag).await?;
            if !resp.is_ok() {
                return Err(Error::Http(format!(
                    "IMAP APPEND failed: {} {}",
                    resp.status, resp.message
                )));
            }
            return Ok(Vec::new());
        }
    }

    // Custom request via -X: the raw command is sent directly.
    // If a mailbox is specified in the URL, SELECT it first.
    if let Some(custom_cmd) = custom_request {
        // Determine if this custom command needs a mailbox SELECT first.
        // curl selects the mailbox when the URL path specifies one.
        if has_mailbox {
            let _ =
                select_if_needed(reader, writer, tags, &params.mailbox, selected_mailbox).await?;
        }

        let tag = tags.next_tag();
        send_command(writer, &tag, custom_cmd).await?;
        let resp = read_response(reader, &tag).await?;
        return Ok(format_untagged_data(&resp.data));
    }

    // SEARCH: URL has a query string (e.g. ?NEW)
    if let Some(ref search_query) = params.search {
        if has_mailbox {
            let _ =
                select_if_needed(reader, writer, tags, &params.mailbox, selected_mailbox).await?;
        }
        let tag = tags.next_tag();
        send_command(writer, &tag, &format!("SEARCH {search_query}")).await?;
        let resp = read_response(reader, &tag).await?;
        return Ok(format_untagged_data(&resp.data));
    }

    // FETCH by UID or MAILINDEX
    if params.uid.is_some() || params.mailindex.is_some() {
        // SELECT mailbox first
        if has_mailbox {
            let select_resp =
                select_if_needed(reader, writer, tags, &params.mailbox, selected_mailbox).await?;

            // Verify UIDVALIDITY if requested (only when SELECT was actually sent)
            if let (Some(ref expected_uidvalidity), Some(ref resp)) =
                (&params.uidvalidity, &select_resp)
            {
                // Lines from read_response include "* " prefix.
                // Look for: * OK [UIDVALIDITY <val>] ...
                let found = resp.data.iter().any(|line| {
                    // Strip optional "* " prefix
                    let stripped = line.strip_prefix("* ").unwrap_or(line);
                    stripped.strip_prefix("OK [UIDVALIDITY ").is_some_and(|rest| {
                        rest.split(']')
                            .next()
                            .is_some_and(|v| v.trim() == expected_uidvalidity.as_str())
                    })
                });
                if !found {
                    // CURLE_REMOTE_FILE_NOT_FOUND (78) — UIDVALIDITY mismatch
                    return Err(Error::Transfer {
                        code: 78,
                        message: "UIDVALIDITY mismatch".to_string(),
                    });
                }
            }
        }

        let section = params.section.as_deref().unwrap_or("");
        let body_part =
            if section.is_empty() { "BODY[]".to_string() } else { format!("BODY[{section}]") };

        let tag = tags.next_tag();
        if let Some(uid_num) = params.uid {
            send_command(writer, &tag, &format!("UID FETCH {uid_num} {body_part}")).await?;
        } else if let Some(idx) = params.mailindex {
            send_command(writer, &tag, &format!("FETCH {idx} {body_part}")).await?;
        }
        let fetch_resp = read_response(reader, &tag).await?;
        if !fetch_resp.is_ok() {
            return Err(Error::Http(format!(
                "IMAP FETCH failed: {} {}",
                fetch_resp.status, fetch_resp.message
            )));
        }
        return Ok(extract_fetch_body(&fetch_resp.data));
    }

    // LIST: no message specified, just a mailbox path
    if has_mailbox {
        let tag = tags.next_tag();
        send_command(writer, &tag, &format!("LIST \"{}\" *", params.mailbox)).await?;
        let resp = read_response(reader, &tag).await?;
        return Ok(format_untagged_data(&resp.data));
    }

    // Root path with no mailbox, no custom request: LIST all
    let tag = tags.next_tag();
    send_command(writer, &tag, "LIST \"\" *").await?;
    let resp = read_response(reader, &tag).await?;
    Ok(format_untagged_data(&resp.data))
}

/// Format untagged response data for output.
///
/// Each line gets a `\r\n` line ending.  The lines in `data` already
/// include the `* ` prefix from `read_response`.
///
/// Trailing `)` lines are stripped because they are part of the IMAP
/// FETCH envelope framing, not actual data (curl compat: test 841).
fn format_untagged_data(data: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    let end =
        if data.last().is_some_and(|l| l.trim() == ")") { data.len() - 1 } else { data.len() };
    for line in &data[..end] {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Extract the message body from a FETCH response.
///
/// The server sends:
/// ```text
/// * <seq> FETCH (<part> {<size>}\r\n
/// <body data lines...>
/// )\r\n
/// ```
///
/// This function strips the IMAP framing and returns just the message body.
/// Each body line gets a `\r\n` ending (matching the original message format).
fn extract_fetch_body(data: &[String]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let first = &data[0];
    let is_fetch_framing = first.contains("FETCH") && first.contains('{');

    if is_fetch_framing && data.len() >= 2 {
        // Skip first line (FETCH framing) and last line if it ends with ")"
        // (the closing paren of the FETCH envelope, possibly with post-fetch metadata;
        // curl compat: test 897)
        let end = if data.last().is_some_and(|l| l.trim().ends_with(')')) {
            data.len() - 1
        } else {
            data.len()
        };
        let body_lines = &data[1..end];
        let mut out = Vec::new();
        for line in body_lines {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    } else {
        // Fallback: all data as lines with CRLF
        let mut out = Vec::new();
        for line in data {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

/// Strip `;AUTH=<mechanism>` from a URL username.
fn strip_auth_from_username(username: &str) -> String {
    let upper = username.to_uppercase();
    upper.find(";AUTH=").map_or_else(|| username.to_string(), |pos| username[..pos].to_string())
}

/// Percent-decode a URL path segment.
fn percent_decode(s: &str) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_imap_path_inbox() {
        let params = parse_imap_url("/INBOX", None);
        assert_eq!(params.mailbox, "INBOX");
        assert!(params.uid.is_none());
        assert!(params.mailindex.is_none());
    }

    #[test]
    fn parse_imap_path_with_uid() {
        let params = parse_imap_url("/INBOX/;UID=42", None);
        assert_eq!(params.mailbox, "INBOX");
        assert_eq!(params.uid, Some(42));
    }

    #[test]
    fn parse_imap_path_with_mailindex() {
        let params = parse_imap_url("/800/;MAILINDEX=1", None);
        assert_eq!(params.mailbox, "800");
        assert_eq!(params.mailindex, Some(1));
    }

    #[test]
    fn parse_imap_path_with_mailindex_and_section() {
        let params = parse_imap_url("/801/;MAILINDEX=123/;SECTION=1", None);
        assert_eq!(params.mailbox, "801");
        assert_eq!(params.mailindex, Some(123));
        assert_eq!(params.section.as_deref(), Some("1"));
    }

    #[test]
    fn parse_imap_path_with_uidvalidity() {
        let params =
            parse_imap_url("/802;UIDVALIDITY=3857529045/;MAILINDEX=123/;SECTION=TEXT", None);
        assert_eq!(params.mailbox, "802");
        assert_eq!(params.uidvalidity.as_deref(), Some("3857529045"));
        assert_eq!(params.mailindex, Some(123));
        assert_eq!(params.section.as_deref(), Some("TEXT"));
    }

    #[test]
    fn parse_imap_path_root() {
        let params = parse_imap_url("/", None);
        assert_eq!(params.mailbox, "");
        assert!(params.uid.is_none());
    }

    #[test]
    fn parse_imap_path_with_search() {
        let params = parse_imap_url("/810", Some("NEW"));
        assert_eq!(params.mailbox, "810");
        assert_eq!(params.search.as_deref(), Some("NEW"));
    }

    #[test]
    fn tag_counter_increments() {
        let mut counter = TagCounter::new('A');
        assert_eq!(counter.next_tag(), "A001");
        assert_eq!(counter.next_tag(), "A002");
        assert_eq!(counter.next_tag(), "A003");
    }

    #[test]
    fn imap_quote_simple() {
        assert_eq!(imap_quote("hello"), "\"hello\"");
    }

    #[test]
    fn imap_quote_with_quotes() {
        assert_eq!(imap_quote("\"user"), "\"\\\"user\"");
    }

    #[test]
    fn imap_quote_with_backslash() {
        assert_eq!(imap_quote("sec\\ret"), "\"sec\\\\ret\"");
    }

    #[test]
    fn imap_quote_complex() {
        // Test 800: user is "user, pass is sec"ret{
        assert_eq!(imap_quote("\"user"), "\"\\\"user\"");
        assert_eq!(imap_quote("sec\"ret{"), "\"sec\\\"ret{\"");
    }

    #[test]
    fn needs_quoting_simple() {
        assert!(!needs_quoting("hello"));
        assert!(!needs_quoting("user"));
    }

    #[test]
    fn needs_quoting_special() {
        assert!(needs_quoting("\"user"));
        assert!(needs_quoting("sec\"ret{"));
        assert!(needs_quoting("hello world"));
        assert!(needs_quoting(""));
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
        assert_eq!(resp.data[0], "* 1 EXISTS");
        assert_eq!(resp.data[1], "* 0 RECENT");
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

    #[test]
    fn percent_decode_simple() {
        assert_eq!(percent_decode("/hello"), "/hello");
        assert_eq!(percent_decode("/%0d%0a"), "/\r\n");
    }
}
