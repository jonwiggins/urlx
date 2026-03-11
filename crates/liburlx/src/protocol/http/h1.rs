//! HTTP/1.x request/response codec.
//!
//! Constructs HTTP/1.0 and HTTP/1.1 requests, sends them over a stream,
//! and parses responses. Supports both `Connection: close` and keep-alive
//! modes. In keep-alive mode, the response body is read precisely using
//! Content-Length or chunked encoding, leaving the stream ready for reuse.
//!
//! Supports `Expect: 100-continue` for delaying body transmission until
//! the server confirms readiness.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::{Response, ResponseHttpVersion};
use crate::throttle::{RateLimiter, SpeedLimits, THROTTLE_CHUNK_SIZE};

/// Maximum response header size (64 KB, same as curl's default).
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Send an HTTP/1.x request and read the response.
///
/// When `keep_alive` is true, the request omits `Connection: close` and
/// reads the response body precisely (using Content-Length or chunked
/// encoding), leaving the stream ready for reuse.
///
/// If `use_http10` is true, the request line uses `HTTP/1.0` instead of
/// `HTTP/1.1`. HTTP/1.0 connections are not kept alive.
///
/// If `expect_100_timeout` is set and the request has a body, the
/// `Expect: 100-continue` header is sent. The client waits up to the
/// timeout for a `100 Continue` before sending the body.
///
/// Returns the response and a boolean indicating whether the connection
/// can be reused.
///
/// # Errors
///
/// Returns errors for I/O failures or malformed responses.
#[allow(clippy::too_many_arguments, clippy::large_futures, clippy::fn_params_excessive_bools)]
pub async fn request<S>(
    stream: &mut S,
    method: &str,
    host: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
    keep_alive: bool,
    use_http10: bool,
    expect_100_timeout: Option<Duration>,
    ignore_content_length: bool,
    speed_limits: &SpeedLimits,
    chunked_upload: bool,
) -> Result<(Response, bool), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let http_ver = if use_http10 { "HTTP/1.0" } else { "HTTP/1.1" };
    // Build the request line
    let mut req = format!("{method} {request_target} {http_ver}\r\nHost: {host}\r\n");

    // Add default headers if not overridden
    let has_user_agent = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    if !has_user_agent {
        req.push_str("User-Agent: urlx/0.1.0\r\n");
    }

    let has_accept = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept"));
    if !has_accept {
        req.push_str("Accept: */*\r\n");
    }

    // Add custom headers (deduplicate: last header with same name wins)
    {
        let mut seen: Vec<String> = Vec::new();
        let mut keep = vec![true; custom_headers.len()];
        for i in (0..custom_headers.len()).rev() {
            let name_lower = custom_headers[i].0.to_lowercase();
            if seen.iter().any(|s| s.eq_ignore_ascii_case(&name_lower)) {
                keep[i] = false;
            } else {
                seen.push(name_lower);
            }
        }
        for (i, (name, value)) in custom_headers.iter().enumerate() {
            if keep[i] {
                let _ = write!(req, "{name}: {value}\r\n");
            }
        }
    }

    // Add Content-Length or Transfer-Encoding for bodies
    let has_content_length =
        custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    let has_transfer_encoding =
        custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    // Use chunked encoding if requested and HTTP/1.1 (HTTP/1.0 doesn't support chunked)
    let use_chunked =
        chunked_upload && !use_http10 && !has_content_length && !has_transfer_encoding;
    let use_expect = expect_100_timeout.is_some() && body.is_some_and(|b| !b.is_empty());
    if let Some(body_data) = body {
        if use_chunked {
            req.push_str("Transfer-Encoding: chunked\r\n");
        } else if !has_content_length {
            let _ = write!(req, "Content-Length: {}\r\n", body_data.len());
        }
    }
    if use_expect {
        req.push_str("Expect: 100-continue\r\n");
    }

    // Connection management — HTTP/1.0 always closes
    if !keep_alive || use_http10 {
        req.push_str("Connection: close\r\n");
    }

    req.push_str("\r\n");

    // Send request headers
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("write failed: {e}")))?;

    // Create send rate limiter for body uploads
    let mut send_limiter = RateLimiter::for_send(speed_limits);

    // Handle Expect: 100-continue
    if use_expect {
        stream.flush().await.map_err(|e| Error::Http(format!("flush failed: {e}")))?;

        let timeout_dur = expect_100_timeout.unwrap_or(Duration::from_secs(1));
        match tokio::time::timeout(timeout_dur, read_response_headers(stream)).await {
            Ok(Ok((header_bytes, body_prefix))) => {
                let (status, _headers, _original_names) = parse_headers(&header_bytes)?;
                if status == 100 {
                    // Server said continue — send body
                    if let Some(body_data) = body {
                        if use_chunked {
                            write_chunked_body(stream, body_data, &mut send_limiter).await?;
                        } else {
                            throttled_write(stream, body_data, &mut send_limiter).await?;
                        }
                    }
                } else {
                    // Server responded with final status — don't send body
                    // Re-parse the full response from what we already have
                    let (final_status, final_headers, final_original_names) =
                        parse_headers(&header_bytes)?;
                    let is_head = method.eq_ignore_ascii_case("HEAD");
                    let no_body = is_head
                        || final_status == 204
                        || final_status == 304
                        || (100..200).contains(&final_status);
                    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
                    let (response_body, body_read_to_eof, trailers) = if no_body {
                        (Vec::new(), false, HashMap::new())
                    } else {
                        read_body_from_headers(
                            stream,
                            &final_headers,
                            body_prefix,
                            keep_alive,
                            ignore_content_length,
                            &mut recv_limiter,
                        )
                        .await?
                    };
                    let server_wants_close = final_headers
                        .get("connection")
                        .is_some_and(|v| v.eq_ignore_ascii_case("close"));
                    let can_reuse =
                        keep_alive && !use_http10 && !server_wants_close && !body_read_to_eof;
                    let mut resp =
                        Response::new(final_status, final_headers, response_body, url.to_string());
                    resp.set_header_original_names(final_original_names);
                    resp.set_http_version(if use_http10 {
                        ResponseHttpVersion::Http10
                    } else {
                        ResponseHttpVersion::Http11
                    });
                    if !trailers.is_empty() {
                        resp.set_trailers(trailers);
                    }
                    return Ok((resp, can_reuse));
                }
            }
            Err(_) => {
                // Timeout waiting for 100 Continue — send body anyway (curl behavior)
                if let Some(body_data) = body {
                    if use_chunked {
                        write_chunked_body(stream, body_data, &mut send_limiter).await?;
                    } else {
                        throttled_write(stream, body_data, &mut send_limiter).await?;
                    }
                }
            }
            Ok(Err(e)) => return Err(e),
        }
    } else {
        // No 100-continue — send body immediately
        if let Some(body_data) = body {
            if use_chunked {
                write_chunked_body(stream, body_data, &mut send_limiter).await?;
            } else {
                throttled_write(stream, body_data, &mut send_limiter).await?;
            }
        }
    }

    stream.flush().await.map_err(|e| Error::Http(format!("flush failed: {e}")))?;

    let is_head = method.eq_ignore_ascii_case("HEAD");

    // Read response headers, skipping 1xx informational responses
    let (mut header_bytes, mut body_prefix) = read_response_headers(stream).await?;
    let (mut status, mut headers, mut original_names) = parse_headers(&header_bytes)?;

    // Skip 1xx informational responses (100 Continue, 103 Early Hints, etc.)
    while (100..200).contains(&status) {
        // The body_prefix may contain the start of the next response
        let next = read_response_headers_with_prefix(stream, body_prefix).await?;
        header_bytes = next.0;
        body_prefix = next.1;
        let parsed = parse_headers(&header_bytes)?;
        status = parsed.0;
        headers = parsed.1;
        original_names = parsed.2;
    }

    // 204 and 304 responses have no body per HTTP spec
    let no_body = is_head || status == 204 || status == 304;

    // Read body with download rate limiting
    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
    let (response_body, body_read_to_eof, trailers) = if no_body {
        (Vec::new(), false, HashMap::new())
    } else {
        read_body_from_headers(
            stream,
            &headers,
            body_prefix,
            keep_alive && !use_http10,
            ignore_content_length,
            &mut recv_limiter,
        )
        .await?
    };

    // Determine if connection can be reused
    let server_wants_close =
        headers.get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let can_reuse = keep_alive && !use_http10 && !server_wants_close && !body_read_to_eof;

    let mut resp = Response::new(status, headers, response_body, url.to_string());
    resp.set_header_original_names(original_names);
    resp.set_http_version(if use_http10 {
        ResponseHttpVersion::Http10
    } else {
        ResponseHttpVersion::Http11
    });
    if !trailers.is_empty() {
        resp.set_trailers(trailers);
    }
    Ok((resp, can_reuse))
}

/// Check if an I/O error is a TLS `close_notify` error that should be treated as EOF.
///
/// Many real-world servers close TLS connections without sending a `close_notify`
/// alert. Rustls treats this as an error, but curl (OpenSSL) treats it as a
/// normal EOF. We match curl's behavior for compatibility.
fn is_close_notify_error(e: &std::io::Error) -> bool {
    let msg = e.to_string();
    msg.contains("close_notify") || msg.contains("CloseNotify")
}

/// Write a request body using HTTP/1.1 chunked transfer encoding.
///
/// Each chunk is sent as `{hex_length}\r\n{data}\r\n`. The body is
/// terminated with a final `0\r\n\r\n` chunk.
///
/// # Errors
///
/// Returns an error if writing to the stream fails.
async fn write_chunked_body<S>(
    stream: &mut S,
    body: &[u8],
    send_limiter: &mut RateLimiter,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    if send_limiter.is_active() {
        let mut offset = 0;
        while offset < body.len() {
            let end = (offset + THROTTLE_CHUNK_SIZE).min(body.len());
            let chunk = &body[offset..end];
            let chunk_len = chunk.len();

            // Write chunk header: hex size + CRLF
            let header = format!("{chunk_len:x}\r\n");
            stream
                .write_all(header.as_bytes())
                .await
                .map_err(|e| Error::Http(format!("chunked header write failed: {e}")))?;

            // Write chunk data
            stream
                .write_all(chunk)
                .await
                .map_err(|e| Error::Http(format!("chunked data write failed: {e}")))?;

            // Write chunk trailer CRLF
            stream
                .write_all(b"\r\n")
                .await
                .map_err(|e| Error::Http(format!("chunked trailer write failed: {e}")))?;

            send_limiter.record(chunk_len).await?;
            offset = end;
        }
    } else {
        // Write entire body as single chunk
        let header = format!("{:x}\r\n", body.len());
        stream
            .write_all(header.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("chunked header write failed: {e}")))?;
        stream
            .write_all(body)
            .await
            .map_err(|e| Error::Http(format!("chunked data write failed: {e}")))?;
        stream
            .write_all(b"\r\n")
            .await
            .map_err(|e| Error::Http(format!("chunked trailer write failed: {e}")))?;
    }

    // Write terminating chunk: 0\r\n\r\n
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|e| Error::Http(format!("chunked terminator write failed: {e}")))?;

    Ok(())
}

/// Read response headers incrementally from a stream.
///
/// Returns the raw header bytes (including the trailing `\r\n\r\n`) and
/// any body data that was read past the header boundary.
async fn read_response_headers<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) if is_close_notify_error(&e) => 0, // Treat as EOF
            Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
        };

        if n == 0 {
            if buf.is_empty() {
                return Err(Error::Http("empty response (connection closed)".to_string()));
            }
            return Err(Error::Http("incomplete response headers".to_string()));
        }

        buf.extend_from_slice(&tmp[..n]);

        // Check for end of headers
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = pos + 4;
            let body_prefix = buf[header_end..].to_vec();
            buf.truncate(header_end);
            return Ok((buf, body_prefix));
        }

        if buf.len() > MAX_HEADER_SIZE {
            return Err(Error::Http(format!(
                "response headers too large: {} bytes (max {MAX_HEADER_SIZE})",
                buf.len()
            )));
        }
    }
}

/// Read response headers with an initial prefix buffer.
///
/// Like [`read_response_headers`] but starts with existing data in the buffer
/// (e.g., leftover from a previous 1xx response).
async fn read_response_headers_with_prefix<S>(
    stream: &mut S,
    prefix: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf = prefix;
    let mut tmp = [0u8; 4096];

    // Check if headers are already complete in the prefix
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let header_end = pos + 4;
        let body_prefix = buf[header_end..].to_vec();
        buf.truncate(header_end);
        return Ok((buf, body_prefix));
    }

    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) if is_close_notify_error(&e) => 0, // Treat as EOF
            Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
        };

        if n == 0 {
            if buf.is_empty() {
                return Err(Error::Http("empty response (connection closed)".to_string()));
            }
            return Err(Error::Http("incomplete response headers".to_string()));
        }

        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = pos + 4;
            let body_prefix = buf[header_end..].to_vec();
            buf.truncate(header_end);
            return Ok((buf, body_prefix));
        }

        if buf.len() > MAX_HEADER_SIZE {
            return Err(Error::Http(format!(
                "response headers too large: {} bytes (max {MAX_HEADER_SIZE})",
                buf.len()
            )));
        }
    }
}

/// Parse raw header bytes into a status code, header map, and original name casing map.
#[allow(clippy::type_complexity)]
fn parse_headers(
    data: &[u8],
) -> Result<(u16, HashMap<String, String>, HashMap<String, String>), Error> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers_buf);

    let header_len = match parsed.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete response headers".to_string()));
        }
        Err(e) => {
            return Err(Error::Http(format!("failed to parse response: {e}")));
        }
    };

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Http(format!(
            "response headers too large: {header_len} bytes (max {MAX_HEADER_SIZE})"
        )));
    }

    let status =
        parsed.code.ok_or_else(|| Error::Http("response has no status code".to_string()))?;

    let mut headers = HashMap::with_capacity(parsed.headers.len());
    let mut original_names = HashMap::with_capacity(parsed.headers.len());
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
        // Preserve the first occurrence of the original header name casing
        let _old = original_names.entry(name.clone()).or_insert_with(|| header.name.to_string());
        // For set-cookie, append with newline to preserve multiple values
        if name == "set-cookie" {
            let _entry = headers
                .entry(name)
                .and_modify(|existing: &mut String| {
                    existing.push('\n');
                    existing.push_str(&value);
                })
                .or_insert(value);
        } else {
            let _old = headers.insert(name, value);
        }
    }

    Ok((status, headers, original_names))
}

/// Write body data with optional rate limiting.
///
/// If the rate limiter is active, writes data in chunks with throttling.
/// Otherwise, writes all data at once.
async fn throttled_write<S>(
    stream: &mut S,
    data: &[u8],
    limiter: &mut RateLimiter,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    if !limiter.is_active() {
        stream.write_all(data).await.map_err(|e| Error::Http(format!("body write failed: {e}")))?;
        return Ok(());
    }

    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + THROTTLE_CHUNK_SIZE).min(data.len());
        let chunk = &data[offset..end];
        stream
            .write_all(chunk)
            .await
            .map_err(|e| Error::Http(format!("body write failed: {e}")))?;
        limiter.record(chunk.len()).await?;
        offset = end;
    }
    Ok(())
}

/// Read exactly `content_length` bytes of body, using any already-read prefix.
///
/// When a rate limiter is active, reads in chunks with throttling.
async fn read_exact_body<S>(
    stream: &mut S,
    content_length: usize,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut body = prefix;

    if body.len() >= content_length {
        body.truncate(content_length);
        if limiter.is_active() {
            limiter.record(content_length).await?;
        }
        return Ok(body);
    }

    if !limiter.is_active() {
        // Fast path: read all remaining bytes at once
        let remaining = content_length - body.len();
        let mut remaining_buf = vec![0u8; remaining];
        match stream.read_exact(&mut remaining_buf).await {
            Ok(_) => {}
            Err(e) if is_close_notify_error(&e) => {
                // Treat as truncated — return what we have
                return Ok(body);
            }
            Err(e) => return Err(Error::Http(format!("body read failed: {e}"))),
        }
        body.extend_from_slice(&remaining_buf);
        return Ok(body);
    }

    // Throttled path: read in chunks
    // Account for prefix bytes already received
    if !body.is_empty() {
        limiter.record(body.len()).await?;
    }

    while body.len() < content_length {
        let remaining = content_length - body.len();
        let chunk_size = remaining.min(THROTTLE_CHUNK_SIZE);
        let mut chunk_buf = vec![0u8; chunk_size];
        match stream.read_exact(&mut chunk_buf).await {
            Ok(_) => {}
            Err(e) if is_close_notify_error(&e) => break,
            Err(e) => return Err(Error::Http(format!("body read failed: {e}"))),
        }
        body.extend_from_slice(&chunk_buf);
        limiter.record(chunk_size).await?;
    }

    Ok(body)
}

/// Read the response body based on headers (Content-Length, chunked, or EOF).
///
/// Returns the body bytes, whether the body was read to EOF, and any trailer headers.
#[allow(clippy::large_futures)]
async fn read_body_from_headers<S>(
    stream: &mut S,
    headers: &HashMap<String, String>,
    body_prefix: Vec<u8>,
    keep_alive: bool,
    ignore_content_length: bool,
    limiter: &mut RateLimiter,
) -> Result<(Vec<u8>, bool, HashMap<String, String>), Error>
where
    S: AsyncRead + Unpin,
{
    let is_chunked =
        headers.get("transfer-encoding").is_some_and(|te| te.eq_ignore_ascii_case("chunked"));

    if is_chunked {
        let (body, trailers) = read_chunked_body_streaming(stream, body_prefix, limiter).await?;
        Ok((body, false, trailers))
    } else if !ignore_content_length && headers.contains_key("content-length") {
        let cl = &headers["content-length"];
        let content_length: usize =
            cl.parse().map_err(|e| Error::Http(format!("invalid Content-Length: {e}")))?;
        let body = read_exact_body(stream, content_length, body_prefix, limiter).await?;
        Ok((body, false, HashMap::new()))
    } else if keep_alive && !ignore_content_length {
        // No Content-Length, no chunked, but keep-alive → assume empty body
        Ok((body_prefix, false, HashMap::new()))
    } else {
        // No Content-Length (or ignoring it), connection close → read until EOF
        let body = read_to_eof_throttled(stream, body_prefix, limiter).await?;
        Ok((body, true, HashMap::new()))
    }
}

/// Read until EOF with optional throttling.
async fn read_to_eof_throttled<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    if !limiter.is_active() {
        // Fast path: read all at once
        let mut body = prefix;
        match stream.read_to_end(&mut body).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !body.is_empty() => {}
            Err(e) if is_close_notify_error(&e) => {} // Treat as EOF (curl compat)
            Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
        }
        return Ok(body);
    }

    // Throttled path: read in chunks
    let mut body = prefix;
    if !body.is_empty() {
        limiter.record(body.len()).await?;
    }

    let mut buf = [0u8; THROTTLE_CHUNK_SIZE];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&buf[..n]);
                limiter.record(n).await?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !body.is_empty() => break,
            Err(e) if is_close_notify_error(&e) => break, // Treat as EOF (curl compat)
            Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
        }
    }
    Ok(body)
}

/// Read a chunked transfer-encoded body incrementally from a stream.
///
/// Returns the decoded body and any trailer headers. Applies rate
/// limiting after each decoded chunk.
async fn read_chunked_body_streaming<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
) -> Result<(Vec<u8>, HashMap<String, String>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf = prefix;
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        // Ensure we have a complete chunk size line
        while find_crlf(&buf, pos).is_none() {
            let mut tmp = [0u8; 4096];
            let n = match stream.read(&mut tmp).await {
                Ok(n) => n,
                Err(e) if is_close_notify_error(&e) => 0,
                Err(e) => return Err(Error::Http(format!("chunked read failed: {e}"))),
            };
            if n == 0 {
                return Ok((decoded, HashMap::new()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        let line_end = find_crlf(&buf, pos)
            .ok_or_else(|| Error::Http("incomplete chunked encoding".into()))?;

        let size_str = std::str::from_utf8(&buf[pos..line_end])
            .map_err(|_| Error::Http("invalid chunk size encoding".into()))?;
        let size_str = size_str.split(';').next().unwrap_or(size_str).trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| Error::Http(format!("invalid chunk size '{size_str}': {e}")))?;

        pos = line_end + 2;

        if chunk_size == 0 {
            // Read trailers + final CRLF after last chunk
            // Trailers end with an empty line (\r\n\r\n) or just \r\n if none
            let mut trailers = HashMap::new();
            loop {
                // Ensure we have at least one line
                while find_crlf(&buf, pos).is_none() {
                    let mut tmp = [0u8; 256];
                    let n = match stream.read(&mut tmp).await {
                        Ok(n) => n,
                        Err(e) if is_close_notify_error(&e) => 0,
                        Err(e) => {
                            return Err(Error::Http(format!("chunked trailer read failed: {e}")));
                        }
                    };
                    if n == 0 {
                        return Ok((decoded, trailers));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let Some(line_end) = find_crlf(&buf, pos) else { break };
                if line_end == pos {
                    // Empty line — end of trailers
                    break;
                }
                // Parse trailer header
                if let Ok(line) = std::str::from_utf8(&buf[pos..line_end]) {
                    if let Some((name, value)) = line.split_once(':') {
                        let _ =
                            trailers.insert(name.trim().to_lowercase(), value.trim().to_string());
                    }
                }
                pos = line_end + 2;
            }
            return Ok((decoded, trailers));
        }

        // Ensure we have the full chunk data + trailing \r\n
        let needed = pos + chunk_size + 2;
        while buf.len() < needed {
            let mut tmp = [0u8; 4096];
            let n = match stream.read(&mut tmp).await {
                Ok(n) => n,
                Err(e) if is_close_notify_error(&e) => 0,
                Err(e) => return Err(Error::Http(format!("chunk data read failed: {e}"))),
            };
            if n == 0 {
                // Partial chunk — take what we have
                let available = buf.len().saturating_sub(pos).min(chunk_size);
                decoded.extend_from_slice(&buf[pos..pos + available]);
                return Ok((decoded, HashMap::new()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        decoded.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size + 2;

        // Apply rate limiting after each decoded chunk
        if limiter.is_active() {
            limiter.record(chunk_size).await?;
        }
    }
}

/// Decode a chunked transfer-encoded body from a complete buffer.
///
/// Format: each chunk is `<hex-size>[;extensions]\r\n<data>\r\n`,
/// terminated by a zero-length chunk `0\r\n\r\n`.
///
/// # Errors
///
/// Returns [`Error::Http`] if the chunked encoding is malformed.
fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    let mut pos = 0;

    loop {
        let line_end = find_crlf(data, pos)
            .ok_or_else(|| Error::Http("incomplete chunked encoding: missing chunk size".into()))?;

        let size_str = std::str::from_utf8(&data[pos..line_end])
            .map_err(|_| Error::Http("invalid chunk size encoding".into()))?;
        let size_str = size_str.split(';').next().unwrap_or(size_str).trim();

        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| Error::Http(format!("invalid chunk size '{size_str}': {e}")))?;

        pos = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = pos + chunk_size;
        if chunk_end > data.len() {
            body.extend_from_slice(&data[pos..]);
            break;
        }
        body.extend_from_slice(&data[pos..chunk_end]);

        pos = chunk_end + 2;
        if pos > data.len() {
            break;
        }
    }

    Ok(body)
}

/// Find the position of `\r\n` starting at `offset`.
fn find_crlf(data: &[u8], offset: usize) -> Option<usize> {
    if data.len() < offset + 2 {
        return None;
    }
    data[offset..].windows(2).position(|w| w == b"\r\n").map(|p| offset + p)
}

/// Parse a raw HTTP/1.1 response into a `Response`.
///
/// This parses from a complete byte buffer. Used for unit tests and
/// for responses read via `read_to_end`.
///
/// # Errors
///
/// Returns [`Error::Http`] if the response is malformed.
pub fn parse_response(data: &[u8], effective_url: &str, is_head: bool) -> Result<Response, Error> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers_buf);

    let header_len = match parsed.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete response headers".to_string()));
        }
        Err(e) => {
            return Err(Error::Http(format!("failed to parse response: {e}")));
        }
    };

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Http(format!(
            "response headers too large: {header_len} bytes (max {MAX_HEADER_SIZE})"
        )));
    }

    let status =
        parsed.code.ok_or_else(|| Error::Http("response has no status code".to_string()))?;

    let mut headers = HashMap::with_capacity(parsed.headers.len());
    let mut original_names = HashMap::with_capacity(parsed.headers.len());
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
        let _old = original_names.entry(name.clone()).or_insert_with(|| header.name.to_string());
        if name == "set-cookie" {
            let _entry = headers
                .entry(name)
                .and_modify(|existing: &mut String| {
                    existing.push('\n');
                    existing.push_str(&value);
                })
                .or_insert(value);
        } else {
            let _old = headers.insert(name, value);
        }
    }

    let version = match parsed.version {
        Some(0) => ResponseHttpVersion::Http10,
        _ => ResponseHttpVersion::Http11,
    };

    if is_head {
        let mut resp = Response::new(status, headers, Vec::new(), effective_url.to_string());
        resp.set_header_original_names(original_names);
        resp.set_http_version(version);
        return Ok(resp);
    }

    let body_data = &data[header_len..];

    let is_chunked =
        headers.get("transfer-encoding").is_some_and(|te| te.eq_ignore_ascii_case("chunked"));

    let body = if is_chunked {
        decode_chunked(body_data)?
    } else if let Some(cl) = headers.get("content-length") {
        let content_length: usize =
            cl.parse().map_err(|e| Error::Http(format!("invalid Content-Length: {e}")))?;
        if body_data.len() < content_length {
            body_data.to_vec()
        } else {
            body_data[..content_length].to_vec()
        }
    } else {
        body_data.to_vec()
    };

    let mut resp = Response::new(status, headers, body, effective_url.to_string());
    resp.set_header_original_names(original_names);
    resp.set_http_version(version);
    Ok(resp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names, clippy::large_futures)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body(), b"hello");
        assert_eq!(resp.header("content-length"), Some("5"));
    }

    #[test]
    fn parse_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.status(), 404);
        assert_eq!(resp.body_str().unwrap(), "not found");
    }

    #[test]
    fn parse_500() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.status(), 500);
    }

    #[test]
    fn parse_multiple_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Custom: foo\r\nContent-Length: 2\r\n\r\nhi";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.header("content-type"), Some("text/plain"));
        assert_eq!(resp.header("x-custom"), Some("foo"));
        assert_eq!(resp.body_str().unwrap(), "hi");
    }

    #[test]
    fn parse_no_content_length_uses_all_data() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nall the body data";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "all the body data");
    }

    #[test]
    fn parse_incomplete_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        let result = parse_response(raw, "http://example.com", false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_preserves_effective_url() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw, "http://final.example.com/page", false).unwrap();
        assert_eq!(resp.effective_url(), "http://final.example.com/page");
    }

    #[test]
    fn parse_head_response_no_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", true).unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.body().is_empty());
    }

    #[test]
    fn parse_redirect_301() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://example.com/new\r\n\r\n";
        let resp = parse_response(raw, "http://example.com/old", false).unwrap();
        assert_eq!(resp.status(), 301);
        assert!(resp.is_redirect());
        assert_eq!(resp.header("location"), Some("http://example.com/new"));
    }

    #[test]
    fn parse_chunked_single_chunk() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");
    }

    #[test]
    fn parse_chunked_multiple_chunks() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "hello world");
    }

    #[test]
    fn parse_chunked_empty_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert!(resp.body().is_empty());
    }

    #[test]
    fn parse_chunked_with_chunk_extensions() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "hello");
    }

    #[test]
    fn parse_chunked_with_trailers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nTrailer: value\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "hello");
    }

    #[test]
    fn parse_chunked_hex_sizes() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "0123456789");
    }

    #[test]
    fn parse_chunked_uppercase_hex() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n";
        let resp = parse_response(raw, "http://example.com", false).unwrap();
        assert_eq!(resp.body_str().unwrap(), "0123456789");
    }

    #[tokio::test]
    async fn request_get_over_mock_stream() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("GET /test HTTP/1.1\r\n"));
            assert!(req.contains("Host: example.com"));

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello world");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_post_with_body() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("POST /submit HTTP/1.1\r\n"));
            assert!(req.contains("Content-Length: 13"));
            assert!(req.contains("hello request"));

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _can_reuse) = request(
            &mut client,
            "POST",
            "example.com",
            "/submit",
            &[],
            Some(b"hello request"),
            "http://example.com/submit",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "ok");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_with_custom_headers() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("X-Custom: test-value"));
            assert!(req.contains("Authorization: Bearer token123"));

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let headers = vec![
            ("X-Custom".to_string(), "test-value".to_string()),
            ("Authorization".to_string(), "Bearer token123".to_string()),
        ];

        let (resp, _can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/",
            &headers,
            None,
            "http://example.com/",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_keep_alive_can_reuse() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            // Should NOT contain Connection: close
            assert!(!req.contains("Connection: close"));

            // Send response with Content-Length (required for keep-alive)
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            server.write_all(response).await.unwrap();
            // Don't shutdown — keep-alive means connection stays open
        });

        let (resp, can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            true,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");
        assert!(can_reuse, "connection should be reusable");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_keep_alive_server_closes() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _n = server.read(&mut buf).await.unwrap();

            // Server says Connection: close
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            true,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");
        assert!(!can_reuse, "server said Connection: close");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_http10_sends_correct_version() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("GET /test HTTP/1.0\r\n"), "expected HTTP/1.0: {req}");
            assert!(req.contains("Connection: close"), "HTTP/1.0 should have Connection: close");

            let response = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            true, // keep_alive requested
            true, // use_http10
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");
        assert!(!can_reuse, "HTTP/1.0 should not be reusable");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_expect_100_continue() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("Expect: 100-continue"), "should have Expect header");
            assert!(!req.contains("hello body"), "body should not be sent before 100 Continue");

            // Send 100 Continue
            server.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.unwrap();
            server.flush().await.unwrap();

            // Read the body
            let mut body_buf = vec![0u8; 1024];
            let n = server.read(&mut body_buf).await.unwrap();
            let body = String::from_utf8_lossy(&body_buf[..n]);
            assert!(body.contains("hello body"), "should receive body after 100 Continue");

            // Send final response
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _can_reuse) = request(
            &mut client,
            "POST",
            "example.com",
            "/upload",
            &[],
            Some(b"hello body"),
            "http://example.com/upload",
            false,
            false,
            Some(Duration::from_secs(5)),
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "ok");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_expect_100_server_rejects() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let _n = server.read(&mut buf).await.unwrap();

            // Server rejects with 417 (Expectation Failed)
            let response = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 8\r\n\r\nrejected";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _can_reuse) = request(
            &mut client,
            "POST",
            "example.com",
            "/upload",
            &[],
            Some(b"should not be sent"),
            "http://example.com/upload",
            false,
            false,
            Some(Duration::from_secs(5)),
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 417);
        assert_eq!(resp.body_str().unwrap(), "rejected");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_skips_1xx_responses() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _n = server.read(&mut buf).await.unwrap();

            // Send 100 Continue and actual response in a single write
            // (both arrive in the buffer together, as they would on a real connection)
            server
                .write_all(
                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
                )
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _can_reuse) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "done");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_header_deduplication_last_wins() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            // The last X-Custom header should win
            assert!(req.contains("X-Custom: second"), "expected last value: {req}");
            // First duplicate should be removed
            assert!(!req.contains("X-Custom: first"), "first duplicate should be gone: {req}");
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let headers = vec![
            ("X-Custom".to_string(), "first".to_string()),
            ("X-Custom".to_string(), "second".to_string()),
        ];

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &headers,
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_user_content_length_not_duplicated() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            // Count Content-Length occurrences
            let count = req.matches("Content-Length").count();
            assert_eq!(count, 1, "should only have one Content-Length: {req}");
            assert!(
                req.contains("Content-Length: 99"),
                "user Content-Length should be used: {req}"
            );
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let headers = vec![("Content-Length".to_string(), "99".to_string())];

        let (resp, _) = request(
            &mut client,
            "POST",
            "example.com",
            "/test",
            &headers,
            Some(b"hello"),
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_ignore_content_length_reads_to_eof() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();
            // Send Content-Length: 5 but actually send 11 bytes, then close
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello world";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            true, // ignore_content_length
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        // Should read all 11 bytes because Content-Length is ignored
        assert_eq!(resp.body_str().unwrap(), "hello world");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_chunked_with_trailers() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();
            // Chunked response with trailers
            let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                             5\r\nhello\r\n\
                             6\r\n world\r\n\
                             0\r\n\
                             X-Checksum: abc123\r\n\
                             X-Timestamp: 1234567890\r\n\
                             \r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.body_str().unwrap(), "hello world");
        assert_eq!(resp.trailer("X-Checksum"), Some("abc123"));
        assert_eq!(resp.trailer("X-Timestamp"), Some("1234567890"));
        assert!(resp.trailers().len() >= 2);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_chunked_no_trailers() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();
            // Chunked response without trailers
            let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                             5\r\nhello\r\n\
                             0\r\n\
                             \r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resp.body_str().unwrap(), "hello");
        assert!(resp.trailers().is_empty());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_upload_sends_chunked_body() {
        use tokio::io::{duplex, AsyncReadExt};

        let (client, mut server) = duplex(4096);
        let mut client = client;

        let server_task = tokio::spawn(async move {
            // Read the request and verify chunked encoding
            let mut buf = vec![0u8; 4096];
            let mut received = Vec::new();
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                let s = String::from_utf8_lossy(&received);
                // Wait until we see the end of chunked body (0\r\n\r\n)
                if s.contains("0\r\n\r\n") {
                    break;
                }
            }

            let request_text = String::from_utf8_lossy(&received).to_string();

            let lower = request_text.to_lowercase();
            // Verify Transfer-Encoding: chunked header is present
            assert!(
                lower.contains("transfer-encoding: chunked"),
                "should contain chunked header: {request_text}"
            );
            // Verify body is chunked encoded
            assert!(
                request_text.contains("5\r\nhello\r\n0\r\n"),
                "should contain chunked body: {request_text}"
            );

            // Send response
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "POST",
            "example.com",
            "/upload",
            &[],
            Some(b"hello"),
            "http://example.com/upload",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "ok");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_upload_disabled_sends_content_length() {
        use tokio::io::{duplex, AsyncReadExt};

        let (client, mut server) = duplex(4096);
        let mut client = client;

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut received = Vec::new();
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                let s = String::from_utf8_lossy(&received);
                if s.contains("hello") {
                    break;
                }
            }

            let request_text = String::from_utf8_lossy(&received).to_string();
            let lower = request_text.to_lowercase();
            assert!(
                lower.contains("content-length: 5"),
                "should contain content-length: {request_text}"
            );
            assert!(
                !lower.contains("transfer-encoding"),
                "should not contain chunked: {request_text}"
            );

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "POST",
            "example.com",
            "/upload",
            &[],
            Some(b"hello"),
            "http://example.com/upload",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_header_order_matches_curl() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();

            // curl sends: Host, User-Agent, Accept (in that order)
            let host_pos = req.find("Host:").unwrap();
            let ua_pos = req.find("User-Agent:").unwrap();
            let accept_pos = req.find("Accept:").unwrap();
            assert!(host_pos < ua_pos, "Host must come before User-Agent: {req}");
            assert!(ua_pos < accept_pos, "User-Agent must come before Accept: {req}");

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_custom_user_agent_replaces_default() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();

            // Custom User-Agent should replace default, not append
            assert!(req.contains("User-Agent: MyAgent/1.0"), "custom User-Agent missing: {req}");
            let ua_count = req.matches("User-Agent:").count();
            assert_eq!(ua_count, 1, "should have exactly one User-Agent: {req}");

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let headers = vec![("User-Agent".to_string(), "MyAgent/1.0".to_string())];

        let (resp, _) = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &headers,
            None,
            "http://example.com/test",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_head_no_hang() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();

            // HEAD response: has Content-Length but no body
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // This should complete without hanging
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            request(
                &mut client,
                "HEAD",
                "example.com",
                "/test",
                &[],
                None,
                "http://example.com/test",
                false,
                false,
                None,
                false,
                &SpeedLimits::default(),
                false,
            ),
        )
        .await;

        let (resp, can_reuse) = result.expect("HEAD request should not hang").unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.body().is_empty(), "HEAD response should have empty body");
        assert!(!can_reuse, "Connection: close means no reuse");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_connection_close_no_hang() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = server.read(&mut buf).await.unwrap();

            // Response with Connection: close and no Content-Length
            let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            request(
                &mut client,
                "GET",
                "example.com",
                "/test",
                &[],
                None,
                "http://example.com/test",
                false,
                false,
                None,
                false,
                &SpeedLimits::default(),
                false,
            ),
        )
        .await;

        let (resp, _) = result.expect("Connection: close response should not hang").unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");

        server_task.await.unwrap();
    }

    #[test]
    fn parse_response_preserves_header_casing() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom-Header: value\r\nContent-Length: 2\r\n\r\nhi";
        let resp = parse_response(raw, "http://example.com", false).unwrap();

        // Internal lookup still works (case-insensitive)
        assert_eq!(resp.header("content-type"), Some("text/html"));
        assert_eq!(resp.header("Content-Type"), Some("text/html"));

        // Original names are preserved
        let names = resp.header_original_names();
        assert_eq!(names.get("content-type"), Some(&"Content-Type".to_string()));
        assert_eq!(names.get("x-custom-header"), Some(&"X-Custom-Header".to_string()));
        assert_eq!(names.get("content-length"), Some(&"Content-Length".to_string()));
    }

    #[tokio::test]
    async fn request_header_order_with_post() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();

            // Verify exact order: Host, User-Agent, Accept, Content-Type, Content-Length
            let host_pos = req.find("Host:").unwrap();
            let ua_pos = req.find("User-Agent:").unwrap();
            let accept_pos = req.find("Accept:").unwrap();
            let ct_pos = req.find("Content-Type:").unwrap();
            let cl_pos = req.find("Content-Length:").unwrap();
            assert!(host_pos < ua_pos, "Host < User-Agent");
            assert!(ua_pos < accept_pos, "User-Agent < Accept");
            assert!(accept_pos < ct_pos, "Accept < Content-Type (custom)");
            assert!(ct_pos < cl_pos, "Content-Type < Content-Length");

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let headers =
            vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];

        let (resp, _) = request(
            &mut client,
            "POST",
            "example.com",
            "/submit",
            &headers,
            Some(b"key=value"),
            "http://example.com/submit",
            false,
            false,
            None,
            false,
            &SpeedLimits::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }
}
