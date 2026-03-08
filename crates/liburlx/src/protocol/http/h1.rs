//! HTTP/1.1 request/response codec.
//!
//! Constructs HTTP/1.1 requests, sends them over a stream, and parses responses.
//! Supports both `Connection: close` and keep-alive modes. In keep-alive mode,
//! the response body is read precisely using Content-Length or chunked encoding,
//! leaving the stream ready for reuse.

use std::collections::HashMap;
use std::fmt::Write as _;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Maximum response header size (64 KB, same as curl's default).
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Send an HTTP/1.1 request and read the response.
///
/// When `keep_alive` is true, the request omits `Connection: close` and
/// reads the response body precisely (using Content-Length or chunked
/// encoding), leaving the stream ready for reuse.
///
/// Returns the response and a boolean indicating whether the connection
/// can be reused.
///
/// # Errors
///
/// Returns errors for I/O failures or malformed responses.
#[allow(clippy::too_many_arguments)]
pub async fn request<S>(
    stream: &mut S,
    method: &str,
    host: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
    keep_alive: bool,
) -> Result<(Response, bool), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build the request line
    let mut req = format!("{method} {request_target} HTTP/1.1\r\nHost: {host}\r\n");

    // Add default headers if not overridden
    let has_user_agent = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    if !has_user_agent {
        req.push_str("User-Agent: urlx/0.1.0\r\n");
    }

    let has_accept = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept"));
    if !has_accept {
        req.push_str("Accept: */*\r\n");
    }

    // Add custom headers
    for (name, value) in custom_headers {
        let _ = write!(req, "{name}: {value}\r\n");
    }

    // Add Content-Length for bodies
    if let Some(body_data) = body {
        let _ = write!(req, "Content-Length: {}\r\n", body_data.len());
    }

    // Connection management
    if !keep_alive {
        req.push_str("Connection: close\r\n");
    }

    req.push_str("\r\n");

    // Send request headers
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("write failed: {e}")))?;

    // Send body if present
    if let Some(body_data) = body {
        stream
            .write_all(body_data)
            .await
            .map_err(|e| Error::Http(format!("body write failed: {e}")))?;
    }

    stream.flush().await.map_err(|e| Error::Http(format!("flush failed: {e}")))?;

    let is_head = method.eq_ignore_ascii_case("HEAD");

    // Read response headers incrementally
    let (header_bytes, body_prefix) = read_response_headers(stream).await?;

    // Parse response headers
    let (status, headers) = parse_headers(&header_bytes)?;

    // 1xx, 204, and 304 responses have no body per HTTP spec
    let no_body = is_head || status == 204 || status == 304 || (100..200).contains(&status);

    // Read body
    let (response_body, body_read_to_eof) = if no_body {
        (Vec::new(), false)
    } else {
        let is_chunked =
            headers.get("transfer-encoding").is_some_and(|te| te.eq_ignore_ascii_case("chunked"));

        if is_chunked {
            let body = read_chunked_body_streaming(stream, body_prefix).await?;
            (body, false)
        } else if let Some(cl) = headers.get("content-length") {
            let content_length: usize =
                cl.parse().map_err(|e| Error::Http(format!("invalid Content-Length: {e}")))?;
            let body = read_exact_body(stream, content_length, body_prefix).await?;
            (body, false)
        } else if keep_alive {
            // No Content-Length, no chunked, but keep-alive → assume empty body
            // (reading to EOF would hang since the server keeps the connection open)
            (body_prefix, false)
        } else {
            // No Content-Length, no chunked, connection close → read until EOF
            let mut body = body_prefix;
            match stream.read_to_end(&mut body).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !body.is_empty() => {}
                Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
            }
            (body, true)
        }
    };

    // Determine if connection can be reused
    let server_wants_close =
        headers.get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let can_reuse = keep_alive && !server_wants_close && !body_read_to_eof;

    Ok((Response::new(status, headers, response_body, url.to_string()), can_reuse))
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
        let n =
            stream.read(&mut tmp).await.map_err(|e| Error::Http(format!("read failed: {e}")))?;

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

/// Parse raw header bytes into a status code and header map.
fn parse_headers(data: &[u8]) -> Result<(u16, HashMap<String, String>), Error> {
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

    let mut headers = HashMap::new();
    for header in parsed.headers.iter() {
        let name = header.name.to_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
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

    Ok((status, headers))
}

/// Read exactly `content_length` bytes of body, using any already-read prefix.
async fn read_exact_body<S>(
    stream: &mut S,
    content_length: usize,
    prefix: Vec<u8>,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut body = prefix;

    if body.len() >= content_length {
        body.truncate(content_length);
        return Ok(body);
    }

    let remaining = content_length - body.len();
    let mut remaining_buf = vec![0u8; remaining];
    let _n = stream
        .read_exact(&mut remaining_buf)
        .await
        .map_err(|e| Error::Http(format!("body read failed: {e}")))?;
    body.extend_from_slice(&remaining_buf);
    Ok(body)
}

/// Read a chunked transfer-encoded body incrementally from a stream.
async fn read_chunked_body_streaming<S>(stream: &mut S, prefix: Vec<u8>) -> Result<Vec<u8>, Error>
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
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| Error::Http(format!("chunked read failed: {e}")))?;
            if n == 0 {
                return Ok(decoded);
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
            // Read trailing CRLF after last chunk
            while buf.len() < pos + 2 {
                let mut tmp = [0u8; 256];
                let n = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| Error::Http(format!("chunked trailer read failed: {e}")))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break;
        }

        // Ensure we have the full chunk data + trailing \r\n
        let needed = pos + chunk_size + 2;
        while buf.len() < needed {
            let mut tmp = [0u8; 4096];
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| Error::Http(format!("chunk data read failed: {e}")))?;
            if n == 0 {
                // Partial chunk — take what we have
                let available = buf.len().saturating_sub(pos).min(chunk_size);
                decoded.extend_from_slice(&buf[pos..pos + available]);
                return Ok(decoded);
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        decoded.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }

    Ok(decoded)
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

    let mut headers = HashMap::new();
    for header in parsed.headers.iter() {
        let name = header.name.to_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
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

    if is_head {
        return Ok(Response::new(status, headers, Vec::new(), effective_url.to_string()));
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

    Ok(Response::new(status, headers, body, effective_url.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello");
        assert!(!can_reuse, "server said Connection: close");

        server_task.await.unwrap();
    }
}
