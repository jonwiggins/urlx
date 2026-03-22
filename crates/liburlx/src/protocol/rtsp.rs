//! RTSP protocol handler.
//!
//! Implements the Real-Time Streaming Protocol (RFC 2326 / RFC 7826)
//! for controlling media streams. RTSP is text-based and HTTP-like,
//! using TCP (default port 554) with interleaved binary RTP data.

use std::collections::HashMap;
use std::fmt::Write;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// RTSP request types (maps to `CURL_RTSPREQ_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtspRequest {
    /// No request type set.
    None = 0,
    /// OPTIONS request.
    Options = 1,
    /// DESCRIBE request.
    Describe = 2,
    /// ANNOUNCE request (upload SDP data).
    Announce = 3,
    /// SETUP request (requires Transport header).
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
    /// RECEIVE interleaved RTP data (no RTSP request sent).
    Receive = 11,
}

impl RtspRequest {
    /// Convert from a long value (`CURL_RTSPREQ_*` constant).
    ///
    /// # Errors
    ///
    /// Returns an error for unknown values.
    pub fn from_long(val: i64) -> Result<Self, Error> {
        match val {
            0 => Ok(Self::None),
            1 => Ok(Self::Options),
            2 => Ok(Self::Describe),
            3 => Ok(Self::Announce),
            4 => Ok(Self::Setup),
            5 => Ok(Self::Play),
            6 => Ok(Self::Pause),
            7 => Ok(Self::Teardown),
            8 => Ok(Self::GetParameter),
            9 => Ok(Self::SetParameter),
            10 => Ok(Self::Record),
            11 => Ok(Self::Receive),
            _ => Err(Error::Transfer {
                code: 43, // CURLE_BAD_FUNCTION_ARGUMENT
                message: format!("unknown RTSP request type: {val}"),
            }),
        }
    }

    /// Returns the RTSP method string for this request type.
    fn method_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Options => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Announce => "ANNOUNCE",
            Self::Setup => "SETUP",
            Self::Play => "PLAY",
            Self::Pause => "PAUSE",
            Self::Teardown => "TEARDOWN",
            Self::GetParameter => "GET_PARAMETER",
            Self::SetParameter => "SET_PARAMETER",
            Self::Record => "RECORD",
            Self::Receive => "",
        }
    }
}

/// Persistent RTSP connection state across `perform()` calls.
pub struct RtspSession {
    /// The TCP stream, stored as std between async runtimes.
    stream: std::net::TcpStream,
}

impl std::fmt::Debug for RtspSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspSession").finish()
    }
}

/// An interleaved RTP packet received during RTSP transfer.
#[derive(Debug)]
pub struct RtpPacket {
    /// The full RTP frame: `$` + channel + 2-byte length + payload.
    pub data: Vec<u8>,
}

/// Configuration for an RTSP request.
#[derive(Debug)]
pub struct RtspConfig {
    /// The RTSP request type.
    pub request: RtspRequest,
    /// The stream URI (used in the request line instead of the URL).
    pub stream_uri: Option<String>,
    /// Transport header value (required for SETUP).
    pub transport: Option<String>,
    /// Session ID (auto-tracked from server responses).
    pub session_id: Option<String>,
    /// Client CSeq counter (auto-incremented).
    pub client_cseq: u32,
    /// Custom headers.
    pub headers: Vec<(String, String)>,
    /// Request body (for ANNOUNCE, GET_PARAMETER with POST data, etc.).
    pub body: Option<Vec<u8>>,
    /// Upload body from read callback (ANNOUNCE PUT style).
    pub upload_body: Option<Vec<u8>>,
    /// Whether verbose output is enabled.
    pub verbose: bool,
}

/// Result of an RTSP transfer, including updated state.
pub struct RtspResult {
    /// The HTTP-like response.
    pub response: Response,
    /// Updated session ID (from server's Session header).
    pub session_id: Option<String>,
    /// Updated client CSeq (incremented after request).
    pub client_cseq: u32,
    /// Server CSeq from the response.
    pub server_cseq: Option<u32>,
    /// Interleaved RTP packets received during this transfer.
    pub rtp_packets: Vec<RtpPacket>,
    /// The RTSP session (connection) to reuse.
    pub session: Option<RtspSession>,
}

/// Reassemble a TCP stream from split halves and convert to std.
fn reassemble(
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
) -> Result<std::net::TcpStream, Error> {
    let read_half = reader.into_inner();
    let tcp = read_half
        .reunite(writer)
        .map_err(|e| Error::Http(format!("failed to reunite RTSP stream: {e}")))?;
    tcp.into_std().map_err(Error::Connect)
}

/// Perform an RTSP transfer.
///
/// Sends an RTSP request and reads the response, handling interleaved
/// RTP data. Returns the response, updated state, and any RTP packets.
///
/// # Errors
///
/// Returns errors for connection failures, protocol errors, CSeq
/// mismatches, and session ID mismatches.
pub async fn perform(
    url: &crate::url::Url,
    config: &mut RtspConfig,
    existing_session: Option<RtspSession>,
) -> Result<RtspResult, Error> {
    // Validate: SETUP requires Transport
    if config.request == RtspRequest::Setup && config.transport.is_none() {
        return Err(Error::Transfer {
            code: 43, // CURLE_BAD_FUNCTION_ARGUMENT
            message: "SETUP requires a Transport header".to_string(),
        });
    }

    // Get or create TCP connection
    let tcp = if let Some(session) = existing_session {
        TcpStream::from_std(session.stream).map_err(Error::Connect)?
    } else {
        let (host, port) = url.host_and_port()?;
        let addr = format!("{host}:{port}");
        TcpStream::connect(&addr).await.map_err(Error::Connect)?
    };

    // Use into_split() so we can reunite later
    let (read_half, mut writer) = tcp.into_split();
    let mut reader = BufReader::new(read_half);

    let mut rtp_packets = Vec::new();

    // For RECEIVE, just read interleaved data without sending a request
    if config.request == RtspRequest::Receive {
        read_interleaved_rtp(&mut reader, &mut rtp_packets).await?;

        let std_stream = reassemble(reader, writer)?;
        return Ok(RtspResult {
            response: Response::new(200, HashMap::new(), Vec::new(), url.as_str().to_string()),
            session_id: config.session_id.clone(),
            client_cseq: config.client_cseq,
            server_cseq: None,
            rtp_packets,
            session: Some(RtspSession { stream: std_stream }),
        });
    }

    // Determine the request URI
    let request_uri = config.stream_uri.as_deref().unwrap_or(url.as_str());

    // Build the RTSP request
    let method = config.request.method_str();
    let cseq = config.client_cseq;

    let mut request = format!("{method} {request_uri} RTSP/1.0\r\nCSeq: {cseq}\r\n");

    // Add Session header if we have one (and this isn't a SETUP)
    if let Some(ref session_id) = config.session_id {
        if config.request != RtspRequest::Setup {
            request.push_str(&format!("Session: {session_id}\r\n"));
        }
    }

    // Add Transport header for SETUP
    if let Some(ref transport) = config.transport {
        if config.request == RtspRequest::Setup {
            request.push_str(&format!("Transport: {transport}\r\n"));
        }
    }

    // Determine body and Content-Type
    let body_data = config.upload_body.as_ref().or(config.body.as_ref()).map(|b| b.as_slice());

    // Check if custom headers include Content-Type
    let has_custom_content_type =
        config.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Content-Type"));

    // Add default Content-Type based on request type
    if body_data.is_some() && !has_custom_content_type {
        let default_ct = match config.request {
            RtspRequest::Announce => "application/sdp",
            RtspRequest::GetParameter | RtspRequest::SetParameter => "text/parameters",
            _ => "application/sdp",
        };
        request.push_str(&format!("Content-Type: {default_ct}\r\n"));
    }

    // Add Content-Length if we have a body
    if let Some(body) = body_data {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    // Add DESCRIBE Accept header
    if config.request == RtspRequest::Describe {
        let has_accept = config.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Accept"));
        if !has_accept {
            request.push_str("Accept: application/sdp\r\n");
        }
    }

    // Add custom headers
    for (name, value) in &config.headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }

    // End of headers
    request.push_str("\r\n");

    // Send request
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("RTSP write error: {e}")))?;

    // Append body if present
    if let Some(body) = body_data {
        writer
            .write_all(body)
            .await
            .map_err(|e| Error::Http(format!("RTSP body write error: {e}")))?;
    }

    writer.flush().await.map_err(|e| Error::Http(format!("RTSP flush error: {e}")))?;

    // Read any interleaved RTP data before the response
    read_interleaved_rtp(&mut reader, &mut rtp_packets).await?;

    // Read response status line
    let mut status_line = String::new();
    let n = reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| Error::Http(format!("RTSP read error: {e}")))?;
    if n == 0 {
        return Err(Error::Http("RTSP connection closed".to_string()));
    }

    let status_line = status_line.trim_end();

    // Parse RTSP/x.y status code
    let (status_code, _reason) = parse_status_line(status_line)?;

    // Read response headers
    let mut response_headers = HashMap::new();
    let mut response_session_id = None;
    let mut response_cseq: Option<u32> = None;
    let mut content_length: usize = 0;

    loop {
        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("RTSP header read error: {e}")))?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed.is_empty() {
            break;
        }

        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("CSeq") {
                response_cseq = value.parse::<u32>().ok();
            } else if name.eq_ignore_ascii_case("Session") {
                // Session ID: strip parameters after `;` and whitespace
                let session_val = value.split(';').next().unwrap_or(value).trim();
                response_session_id = Some(session_val.to_string());
            } else if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse::<usize>().unwrap_or(0);
            }

            let _old = response_headers.insert(name.to_lowercase(), value.to_string());
        }
    }

    // Check CSeq match
    if let Some(server_cseq) = response_cseq {
        if server_cseq != cseq {
            let std_stream = reassemble(reader, writer)?;
            return Err(Error::RtspCseqMismatch {
                expected: cseq,
                got: server_cseq,
                session: Some(RtspSession { stream: std_stream }),
            });
        }
    } else {
        // No CSeq in response — treat as mismatch (test 689)
        let std_stream = reassemble(reader, writer)?;
        return Err(Error::RtspCseqMismatch {
            expected: cseq,
            got: 0,
            session: Some(RtspSession { stream: std_stream }),
        });
    }

    // Check Session ID match (if we already have a session and server returns one)
    if let Some(ref our_session) = config.session_id {
        if let Some(ref server_session) = response_session_id {
            if our_session != server_session {
                let std_stream = reassemble(reader, writer)?;
                return Err(Error::RtspSessionMismatch {
                    expected: our_session.clone(),
                    got: server_session.clone(),
                    session: Some(RtspSession { stream: std_stream }),
                });
            }
        }
    }

    // Update session ID from server
    let updated_session_id = response_session_id.or_else(|| config.session_id.clone());

    // Read response body based on Content-Length
    let mut body = Vec::new();
    if content_length > 0 {
        // Read interleaved data that may precede content
        read_interleaved_rtp(&mut reader, &mut rtp_packets).await?;

        body.resize(content_length, 0);
        let _ = reader
            .read_exact(&mut body)
            .await
            .map_err(|e| Error::Http(format!("RTSP body read error: {e}")))?;
    }

    // Read any trailing interleaved RTP data
    read_interleaved_rtp(&mut reader, &mut rtp_packets).await?;

    // Increment CSeq for next request
    let next_cseq = cseq + 1;

    // Reassemble the stream for session persistence
    let std_stream = reassemble(reader, writer)?;

    Ok(RtspResult {
        response: Response::new(status_code, response_headers, body, url.as_str().to_string()),
        session_id: updated_session_id,
        client_cseq: next_cseq,
        server_cseq: response_cseq,
        rtp_packets,
        session: Some(RtspSession { stream: std_stream }),
    })
}

/// Parse an RTSP status line like `RTSP/1.0 200 OK`.
///
/// Returns `(status_code, reason_phrase)`.
fn parse_status_line(line: &str) -> Result<(u16, String), Error> {
    // Must start with RTSP/
    if !line.starts_with("RTSP/") {
        return Err(Error::Http(format!("not an RTSP response: {line}")));
    }

    // Check version: must be RTSP/1.0
    let after_rtsp = &line[5..];
    let space_pos = after_rtsp
        .find(' ')
        .ok_or_else(|| Error::Http(format!("malformed RTSP status line: {line}")))?;

    let version = &after_rtsp[..space_pos];
    if version != "1.0" {
        // CURLE_WEIRD_SERVER_REPLY (8) — test 577
        return Err(Error::Transfer {
            code: 8,
            message: format!("unsupported RTSP version: RTSP/{version}"),
        });
    }

    let rest = after_rtsp[space_pos + 1..].trim();
    let status_str = if rest.len() >= 3 { &rest[..3] } else { rest };
    let status_code = status_str
        .parse::<u16>()
        .map_err(|_| Error::Http(format!("invalid RTSP status code: {rest}")))?;

    let reason = if rest.len() > 4 { rest[4..].to_string() } else { String::new() };

    Ok((status_code, reason))
}

/// Read interleaved RTP frames from the stream.
///
/// RTP frames are prefixed with `$` (0x24), followed by 1-byte channel,
/// 2-byte big-endian length, and the payload.
async fn read_interleaved_rtp(
    reader: &mut BufReader<OwnedReadHalf>,
    packets: &mut Vec<RtpPacket>,
) -> Result<(), Error> {
    loop {
        // Peek at the next byte to check for interleaved data
        let buf = match reader.fill_buf().await {
            Ok([]) | Err(_) => break,
            Ok(buf) => buf,
        };

        if buf[0] != b'$' {
            break;
        }

        // Read the 4-byte RTP header: $ + channel + length(2)
        let mut header = [0u8; 4];
        let _ = reader
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::Http(format!("RTP header read error: {e}")))?;

        let length = u16::from_be_bytes([header[2], header[3]]) as usize;

        // Read the payload
        let mut payload = vec![0u8; length];
        let _ = reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| Error::Http(format!("RTP payload read error: {e}")))?;

        // Build the full packet (header + payload)
        let mut data = Vec::with_capacity(4 + length);
        data.extend_from_slice(&header);
        data.extend_from_slice(&payload);

        packets.push(RtpPacket { data });
    }

    Ok(())
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
    fn parse_status_line_okie_dokie() {
        let (code, reason) = parse_status_line("RTSP/1.0 200 Okie Dokie").unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "Okie Dokie");
    }

    #[test]
    fn parse_status_line_204() {
        let (code, reason) = parse_status_line("RTSP/1.0 204 OK").unwrap();
        assert_eq!(code, 204);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn parse_status_line_bad_version() {
        let err = parse_status_line("RTSP/1.1234567 200 OK").unwrap_err();
        match err {
            Error::Transfer { code, .. } => assert_eq!(code, 8),
            _ => panic!("expected Transfer error"),
        }
    }

    #[test]
    fn rtsp_request_from_long() {
        assert_eq!(RtspRequest::from_long(1).unwrap(), RtspRequest::Options);
        assert_eq!(RtspRequest::from_long(4).unwrap(), RtspRequest::Setup);
        assert_eq!(RtspRequest::from_long(11).unwrap(), RtspRequest::Receive);
        assert!(RtspRequest::from_long(99).is_err());
    }

    #[test]
    fn rtsp_request_method_str() {
        assert_eq!(RtspRequest::Options.method_str(), "OPTIONS");
        assert_eq!(RtspRequest::Describe.method_str(), "DESCRIBE");
        assert_eq!(RtspRequest::Announce.method_str(), "ANNOUNCE");
        assert_eq!(RtspRequest::Setup.method_str(), "SETUP");
        assert_eq!(RtspRequest::Play.method_str(), "PLAY");
        assert_eq!(RtspRequest::Teardown.method_str(), "TEARDOWN");
        assert_eq!(RtspRequest::GetParameter.method_str(), "GET_PARAMETER");
    }
}
