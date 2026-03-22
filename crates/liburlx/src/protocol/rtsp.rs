//! RTSP protocol handler.
//!
//! Implements the Real-Time Streaming Protocol (RFC 2326) for streaming
//! media control. RTSP is syntactically similar to HTTP/1.x but uses
//! `RTSP/1.0` version strings and requires a `CSeq` header on every
//! request/response.

use std::collections::HashMap;
use std::fmt::Write as _;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Maximum size of a single RTSP header line.
const MAX_HEADER_LINE_SIZE: usize = 100 * 1024;

/// Maximum total response header section size.
const MAX_HEADER_SIZE: usize = 300 * 1024;

/// RTSP request method types matching curl's `CURL_RTSPREQ_*` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RtspRequest {
    /// No request type set.
    None = 0,
    /// OPTIONS request.
    Options = 1,
    /// DESCRIBE request.
    Describe = 2,
    /// ANNOUNCE request.
    Announce = 3,
    /// SETUP request.
    Setup = 4,
    /// PLAY request.
    Play = 5,
    /// PAUSE request.
    Pause = 6,
    /// TEARDOWN request.
    Teardown = 7,
    /// GET_PARAMETER request.
    GetParameter = 8,
    /// SET_PARAMETER request.
    SetParameter = 9,
    /// RECORD request.
    Record = 10,
    /// RECEIVE (interleaved RTP data).
    Receive = 11,
}

impl RtspRequest {
    /// Convert from a numeric value (curl RTSPREQ enum).
    pub fn from_long(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Options),
            2 => Some(Self::Describe),
            3 => Some(Self::Announce),
            4 => Some(Self::Setup),
            5 => Some(Self::Play),
            6 => Some(Self::Pause),
            7 => Some(Self::Teardown),
            8 => Some(Self::GetParameter),
            9 => Some(Self::SetParameter),
            10 => Some(Self::Record),
            11 => Some(Self::Receive),
            _ => Option::None,
        }
    }

    /// Get the RTSP method string.
    pub fn method_str(self) -> &'static str {
        match self {
            Self::None | Self::Options => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Announce => "ANNOUNCE",
            Self::Setup => "SETUP",
            Self::Play => "PLAY",
            Self::Pause => "PAUSE",
            Self::Teardown => "TEARDOWN",
            Self::GetParameter => "GET_PARAMETER",
            Self::SetParameter => "SET_PARAMETER",
            Self::Record => "RECORD",
            Self::Receive => "RECEIVE",
        }
    }
}

/// Persistent RTSP session state across `perform()` calls.
pub struct RtspSession {
    /// The TCP stream to the RTSP server.
    stream: TcpStream,
    /// Client CSeq counter (incremented per request).
    pub client_cseq: u32,
    /// Server CSeq counter (from last response).
    pub server_cseq: u32,
    /// Last received CSeq from server response.
    pub cseq_recv: u32,
    /// Session ID extracted from response `Session:` header.
    pub session_id: Option<String>,
}

impl RtspSession {
    /// Set the client CSeq counter.
    pub fn set_client_cseq(&mut self, cseq: u32) {
        self.client_cseq = cseq;
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get the client CSeq counter.
    pub fn client_cseq(&self) -> u32 {
        self.client_cseq
    }

    /// Get the server CSeq counter.
    pub fn server_cseq(&self) -> u32 {
        self.server_cseq
    }

    /// Get the last received CSeq.
    pub fn cseq_recv(&self) -> u32 {
        self.cseq_recv
    }
}

/// Send an RTSP request and read the response.
#[allow(clippy::too_many_arguments)]
pub async fn request<S>(
    stream: &mut S,
    method: &str,
    url: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    cseq: u32,
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("{method} {url} RTSP/1.0\r\n");

    let has_cseq = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cseq"));
    if !has_cseq {
        let _ = write!(req, "CSeq: {cseq}\r\n");
    }

    for (key, value) in custom_headers {
        let _ = write!(req, "{key}: {value}\r\n");
    }

    if let Some(data) = body {
        if !data.is_empty()
            && !custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            let _ = write!(req, "Content-Length: {}\r\n", data.len());
        }
    }

    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("RTSP write error: {e}")))?;

    if let Some(data) = body {
        if !data.is_empty() {
            stream
                .write_all(data)
                .await
                .map_err(|e| Error::Http(format!("RTSP body write error: {e}")))?;
        }
    }

    stream.flush().await.map_err(|e| Error::Http(format!("RTSP flush error: {e}")))?;

    read_response(stream, url).await
}

/// Perform an RTSP transfer using a persistent session.
#[allow(clippy::too_many_arguments)]
pub async fn perform_with_session(
    url: &crate::url::Url,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    verbose: bool,
    session: &mut Option<RtspSession>,
    rtsp_request_type: RtspRequest,
    rtsp_stream_uri: Option<&str>,
    rtsp_transport: Option<&str>,
    rtsp_session_id_override: Option<&str>,
    rtsp_headers: &[(String, String)],
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;

    if rtsp_request_type == RtspRequest::Setup && rtsp_transport.is_none() {
        return Err(Error::Transfer {
            code: 43,
            message: "SETUP requires CURLOPT_RTSP_TRANSPORT".to_string(),
        });
    }

    if session.is_none() {
        if verbose {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("* Trying {host}:{port}...");
            }
        }

        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await.map_err(Error::Connect)?;

        if verbose {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("* Connected to {host} ({host}) port {port}");
            }
        }

        *session = Some(RtspSession {
            stream: tcp,
            client_cseq: 1,
            server_cseq: 0,
            cseq_recv: 0,
            session_id: None,
        });
    }

    let sess =
        session.as_mut().ok_or_else(|| Error::Http("RTSP session not initialized".to_string()))?;

    let stream_uri = rtsp_stream_uri.unwrap_or_else(|| url.as_str());

    let mut all_headers: Vec<(String, String)> = Vec::new();

    if rtsp_request_type == RtspRequest::Setup {
        if let Some(transport) = rtsp_transport {
            all_headers.push(("Transport".to_string(), transport.to_string()));
        }
    }

    // Add Session header if we have a session ID
    let session_id_to_send =
        rtsp_session_id_override.map(ToString::to_string).or_else(|| sess.session_id.clone());
    if let Some(ref sid) = session_id_to_send {
        all_headers.push(("Session".to_string(), sid.clone()));
    }

    if rtsp_request_type == RtspRequest::Describe {
        all_headers.push(("Accept".to_string(), "application/sdp".to_string()));
    }

    if body.is_some_and(|b| !b.is_empty()) {
        let has_content_type = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            || rtsp_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !has_content_type {
            match rtsp_request_type {
                RtspRequest::Announce => {
                    all_headers.push(("Content-Type".to_string(), "application/sdp".to_string()));
                }
                RtspRequest::GetParameter | RtspRequest::SetParameter => {
                    all_headers.push(("Content-Type".to_string(), "text/parameters".to_string()));
                }
                _ => {}
            }
        }
    }

    for (k, v) in rtsp_headers {
        all_headers.push((k.clone(), v.clone()));
    }

    for (k, v) in headers {
        all_headers.push((k.clone(), v.clone()));
    }

    let cseq = sess.client_cseq;

    if rtsp_request_type == RtspRequest::Receive {
        let resp = Response::new(200, HashMap::new(), Vec::new(), stream_uri.to_string());
        return Ok(resp);
    }

    let response = request(
        &mut sess.stream,
        rtsp_request_type.method_str(),
        stream_uri,
        &all_headers,
        body,
        cseq,
    )
    .await?;

    sess.client_cseq = cseq + 1;

    if let Some(session_hdr) = response.header("session") {
        let session_id = session_hdr.split(';').next().unwrap_or(session_hdr).trim().to_string();
        sess.session_id = Some(session_id);
    }

    if let Some(cseq_hdr) = response.header("cseq") {
        if let Ok(resp_cseq) = cseq_hdr.trim().parse::<u32>() {
            sess.cseq_recv = resp_cseq;
            sess.server_cseq = resp_cseq;

            if resp_cseq != cseq {
                return Err(Error::RtspCseqError(format!("expected CSeq {cseq}, got {resp_cseq}")));
            }
        }
    } else {
        return Err(Error::RtspCseqError("no CSeq in server response".to_string()));
    }

    if let Some(ref sent_session) = session_id_to_send {
        if let Some(session_hdr) = response.header("session") {
            let resp_session = session_hdr.split(';').next().unwrap_or(session_hdr).trim();
            if !sent_session.is_empty() && resp_session != sent_session.as_str() {
                return Err(Error::RtspSessionError(format!(
                    "expected session '{sent_session}', got '{resp_session}'"
                )));
            }
        }
    }

    if verbose {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("* Connection #0 to host {host} left intact");
        }
    }

    Ok(response)
}

/// Perform an RTSP transfer (simple, non-session mode for CLI).
pub async fn perform(
    url: &crate::url::Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    verbose: bool,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;

    if verbose {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("* Trying {host}:{port}...");
        }
    }

    let addr = format!("{host}:{port}");
    let mut tcp = TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    if verbose {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("* Connected to {host} ({host}) port {port}");
        }
    }

    let rtsp_method = if method == "GET" || method == "HEAD" || method == "POST" || method == "PUT"
    {
        "OPTIONS"
    } else {
        method
    };

    let url_str = url.to_full_string();
    let response = request(&mut tcp, rtsp_method, &url_str, headers, body, 1).await?;

    if verbose {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("* Connection #0 to host {host} left intact");
        }
    }

    Ok(response)
}

async fn read_header_bytes<S>(stream: &mut S) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut total: usize = 0;
    let mut byte = [0u8; 1];

    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| Error::Http(format!("RTSP read error: {e}")))?;
        if n == 0 {
            if buf.is_empty() {
                return Err(Error::Http("RTSP connection closed before response".to_string()));
            }
            break;
        }

        buf.push(byte[0]);
        total += 1;

        if total > MAX_HEADER_SIZE {
            return Err(Error::Transfer {
                code: 56,
                message: "RTSP response headers too large".to_string(),
            });
        }

        let len = buf.len();
        if (len >= 4 && buf[len - 4..] == *b"\r\n\r\n") || (len >= 2 && buf[len - 2..] == *b"\n\n")
        {
            break;
        }
    }

    Ok(buf)
}

async fn read_response<S>(stream: &mut S, url: &str) -> Result<Response, Error>
where
    S: AsyncRead + Unpin,
{
    let header_buf = read_header_bytes(stream).await?;
    let raw_headers = header_buf.clone();

    let header_str =
        String::from_utf8_lossy(&header_buf[..header_buf.len().saturating_sub(2)]).to_string();
    let mut lines = header_str.lines();

    let status_line = lines.next().ok_or_else(|| Error::Http("RTSP empty response".to_string()))?;
    let (status_code, _reason) = parse_status_line(status_line)?;

    let mut headers = HashMap::new();
    let mut headers_ordered = Vec::new();
    let mut header_original_names = HashMap::new();

    parse_header_lines(lines, &mut headers, &mut headers_ordered, &mut header_original_names)?;

    let body = read_content_body(stream, &headers).await?;

    let mut response =
        Response::with_raw_headers(status_code, headers, body, url.to_string(), raw_headers);
    response.set_header_original_names(header_original_names);
    response.set_headers_ordered(headers_ordered);

    Ok(response)
}

fn parse_header_lines<'a>(
    lines: impl Iterator<Item = &'a str>,
    headers: &mut HashMap<String, String>,
    headers_ordered: &mut Vec<(String, String)>,
    header_original_names: &mut HashMap<String, String>,
) -> Result<(), Error> {
    let mut current_line = String::new();

    for line in lines {
        if line.is_empty() {
            break;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            current_line.push(' ');
            current_line.push_str(line.trim());
            continue;
        }

        if !current_line.is_empty() {
            if current_line.len() > MAX_HEADER_LINE_SIZE {
                return Err(Error::Transfer {
                    code: 100,
                    message: "RTSP header line too large".to_string(),
                });
            }
            insert_header(&current_line, headers, headers_ordered, header_original_names);
        }

        current_line = line.to_string();
    }

    if !current_line.is_empty() {
        insert_header(&current_line, headers, headers_ordered, header_original_names);
    }

    Ok(())
}

async fn read_content_body<S>(
    stream: &mut S,
    headers: &HashMap<String, String>,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    if let Some(cl_str) = headers.get("content-length") {
        let content_length = cl_str
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::Http(format!("RTSP invalid Content-Length: {cl_str}")))?;
        let mut body_buf = vec![0u8; content_length];
        let _n = stream
            .read_exact(&mut body_buf)
            .await
            .map_err(|e| Error::Http(format!("RTSP body read error: {e}")))?;
        Ok(body_buf)
    } else {
        Ok(Vec::new())
    }
}

fn parse_status_line(line: &str) -> Result<(u16, String), Error> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::Transfer {
            code: 8,
            message: format!("Weird RTSP server reply: {line}"),
        });
    }

    let version = parts[0];
    if !version.starts_with("RTSP/") {
        return Err(Error::Transfer {
            code: 8,
            message: format!("Weird RTSP server reply: {line}"),
        });
    }

    let ver = &version[5..];
    if ver != "1.0" {
        return Err(Error::Transfer {
            code: 8,
            message: format!("Unsupported RTSP version: {version}"),
        });
    }

    let status_code = parts[1].parse::<u16>().map_err(|_| Error::Transfer {
        code: 8,
        message: format!("RTSP invalid status code: {}", parts[1]),
    })?;

    let reason = if parts.len() > 2 { parts[2].to_string() } else { String::new() };

    Ok((status_code, reason))
}

fn insert_header(
    line: &str,
    headers: &mut HashMap<String, String>,
    headers_ordered: &mut Vec<(String, String)>,
    header_original_names: &mut HashMap<String, String>,
) {
    if let Some((key, value)) = line.split_once(':') {
        let key_trimmed = key.trim();
        let value_trimmed = value.trim();
        let key_lower = key_trimmed.to_ascii_lowercase();

        let _old = headers.insert(key_lower.clone(), value_trimmed.to_string());
        headers_ordered.push((key_trimmed.to_string(), value_trimmed.to_string()));
        let _old = header_original_names.insert(key_lower, key_trimmed.to_string());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_line_ok() {
        let (code, reason) = parse_status_line("RTSP/1.0 200 OK").unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn parse_status_line_bad_version() {
        let err = parse_status_line("RTSP/1.1234567 200 OK").unwrap_err();
        assert!(err.to_string().contains("Unsupported RTSP version"));
    }

    #[test]
    fn parse_status_line_not_rtsp() {
        let err = parse_status_line("HTTP/1.1 200 OK").unwrap_err();
        assert!(err.to_string().contains("Weird RTSP server reply"));
    }

    #[test]
    fn rtsp_request_from_long() {
        assert_eq!(RtspRequest::from_long(0), Some(RtspRequest::None));
        assert_eq!(RtspRequest::from_long(1), Some(RtspRequest::Options));
        assert_eq!(RtspRequest::from_long(4), Some(RtspRequest::Setup));
        assert_eq!(RtspRequest::from_long(11), Some(RtspRequest::Receive));
        assert_eq!(RtspRequest::from_long(99), Option::None);
    }

    #[test]
    fn rtsp_request_method_str() {
        assert_eq!(RtspRequest::Options.method_str(), "OPTIONS");
        assert_eq!(RtspRequest::Describe.method_str(), "DESCRIBE");
        assert_eq!(RtspRequest::Setup.method_str(), "SETUP");
        assert_eq!(RtspRequest::GetParameter.method_str(), "GET_PARAMETER");
    }

    #[tokio::test]
    async fn request_and_response() {
        let response_data = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, OPTIONS\r\n\r\n";
        let (mut client, mut server) = tokio::io::duplex(4096);
        let _handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();
            server.write_all(response_data).await.unwrap();
            server.flush().await.unwrap();
        });

        let headers: Vec<(String, String)> = vec![];
        let resp = request(&mut client, "OPTIONS", "rtsp://localhost/test", &headers, None, 1)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn response_with_body() {
        let response_data = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 11\r\n\r\nhello world";
        let (mut client, mut server) = tokio::io::duplex(4096);
        let _handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();
            server.write_all(response_data).await.unwrap();
            server.flush().await.unwrap();
        });

        let headers: Vec<(String, String)> = vec![];
        let resp = request(&mut client, "DESCRIBE", "rtsp://localhost/test", &headers, None, 2)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body(), b"hello world");
    }
}
