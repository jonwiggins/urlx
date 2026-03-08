//! HTTP/1.1 request/response codec.
//!
//! Constructs HTTP/1.1 requests, sends them over a stream, and parses responses.

use std::collections::HashMap;
use std::fmt::Write as _;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Maximum response header size (64 KB, same as curl's default).
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Send an HTTP/1.1 request and read the response.
///
/// # Errors
///
/// Returns errors for I/O failures or malformed responses.
pub async fn request<S>(
    stream: &mut S,
    method: &str,
    host: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
) -> Result<Response, Error>
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

    req.push_str("Connection: close\r\n\r\n");

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

    // For HEAD requests, we don't expect a body
    let is_head = method.eq_ignore_ascii_case("HEAD");

    // Read the entire response.
    // Many servers close TLS connections without close_notify (UnexpectedEof).
    // If we already have data, treat it as a complete response.
    let mut buf = Vec::new();
    match stream.read_to_end(&mut buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => {
            // Got data before unexpected EOF — proceed with what we have
        }
        Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
    }

    parse_response(&buf, url, is_head)
}

/// Decode a chunked transfer-encoded body.
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
        // Find the end of the chunk size line
        let line_end = find_crlf(data, pos)
            .ok_or_else(|| Error::Http("incomplete chunked encoding: missing chunk size".into()))?;

        // Parse the chunk size (hex, possibly with extensions after ';')
        let size_str = std::str::from_utf8(&data[pos..line_end])
            .map_err(|_| Error::Http("invalid chunk size encoding".into()))?;
        let size_str = size_str.split(';').next().unwrap_or(size_str).trim();

        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| Error::Http(format!("invalid chunk size '{size_str}': {e}")))?;

        // Move past the size line's \r\n
        pos = line_end + 2;

        // Zero-length chunk = end of body
        if chunk_size == 0 {
            break;
        }

        // Read chunk data
        let chunk_end = pos + chunk_size;
        if chunk_end > data.len() {
            // Partial chunk — take what we have
            body.extend_from_slice(&data[pos..]);
            break;
        }
        body.extend_from_slice(&data[pos..chunk_end]);

        // Skip the trailing \r\n after chunk data
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
        let _old = headers.insert(name, value);
    }

    // HEAD responses have no body
    if is_head {
        return Ok(Response::new(status, headers, Vec::new(), effective_url.to_string()));
    }

    // Determine body boundaries
    let body_data = &data[header_len..];

    // Handle Transfer-Encoding: chunked
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
        // Chunk extensions after the size are allowed by HTTP spec
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
        // Chunk sizes are in hex
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

        let resp = request(
            &mut client,
            "GET",
            "example.com",
            "/test",
            &[],
            None,
            "http://example.com/test",
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

        let resp = request(
            &mut client,
            "POST",
            "example.com",
            "/submit",
            &[],
            Some(b"hello request"),
            "http://example.com/submit",
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

        let resp =
            request(&mut client, "GET", "example.com", "/", &headers, None, "http://example.com/")
                .await
                .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }
}
