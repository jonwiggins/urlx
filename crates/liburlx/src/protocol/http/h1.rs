//! HTTP/1.1 request/response codec.
//!
//! Constructs HTTP/1.1 requests, sends them over a stream, and parses responses.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Maximum response header size (64 KB, same as curl's default).
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Send an HTTP/1.1 GET request and read the response.
///
/// # Errors
///
/// Returns errors for I/O failures or malformed responses.
pub async fn get<S>(
    stream: &mut S,
    host: &str,
    request_target: &str,
    url: &str,
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build and send the request
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: urlx/0.1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("write failed: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("flush failed: {e}")))?;

    // Read the entire response
    let mut buf = Vec::new();
    let _bytes_read =
        stream.read_to_end(&mut buf).await.map_err(|e| Error::Http(format!("read failed: {e}")))?;

    parse_response(&buf, url)
}

/// Parse a raw HTTP/1.1 response into a `Response`.
///
/// # Errors
///
/// Returns [`Error::Http`] if the response is malformed.
pub fn parse_response(data: &[u8], effective_url: &str) -> Result<Response, Error> {
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

    // Determine body boundaries
    let body_data = &data[header_len..];

    // Handle Content-Length
    let body = if let Some(cl) = headers.get("content-length") {
        let content_length: usize =
            cl.parse().map_err(|e| Error::Http(format!("invalid Content-Length: {e}")))?;
        if body_data.len() < content_length {
            // Accept partial body (connection closed early)
            body_data.to_vec()
        } else {
            body_data[..content_length].to_vec()
        }
    } else {
        // No Content-Length: use all remaining data (connection: close)
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
        let resp = parse_response(raw, "http://example.com").unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body(), b"hello");
        assert_eq!(resp.header("content-length"), Some("5"));
    }

    #[test]
    fn parse_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let resp = parse_response(raw, "http://example.com").unwrap();
        assert_eq!(resp.status(), 404);
        assert_eq!(resp.body_str().unwrap(), "not found");
    }

    #[test]
    fn parse_500() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror";
        let resp = parse_response(raw, "http://example.com").unwrap();
        assert_eq!(resp.status(), 500);
    }

    #[test]
    fn parse_multiple_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Custom: foo\r\nContent-Length: 2\r\n\r\nhi";
        let resp = parse_response(raw, "http://example.com").unwrap();
        assert_eq!(resp.header("content-type"), Some("text/plain"));
        assert_eq!(resp.header("x-custom"), Some("foo"));
        assert_eq!(resp.body_str().unwrap(), "hi");
    }

    #[test]
    fn parse_no_content_length_uses_all_data() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nall the body data";
        let resp = parse_response(raw, "http://example.com").unwrap();
        assert_eq!(resp.body_str().unwrap(), "all the body data");
    }

    #[test]
    fn parse_incomplete_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        let result = parse_response(raw, "http://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parse_preserves_effective_url() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw, "http://final.example.com/page").unwrap();
        assert_eq!(resp.effective_url(), "http://final.example.com/page");
    }

    #[tokio::test]
    async fn get_over_mock_stream() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /test HTTP/1.1\r\n"));
            assert!(request.contains("Host: example.com"));

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let resp =
            get(&mut client, "example.com", "/test", "http://example.com/test").await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body_str().unwrap(), "hello world");

        server_task.await.unwrap();
    }
}
