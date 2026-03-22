//! Gopher protocol handler.
//!
//! Implements the Gopher protocol (RFC 1436) for menu browsing and file
//! retrieval. Supports both plaintext (`gopher://`) and TLS-encrypted
//! (`gophers://`) connections.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Perform a Gopher transfer.
///
/// Sends the selector (URL path) to the server and reads the full response.
/// For `gophers://` URLs, the connection is wrapped in TLS.
///
/// URL format: `gopher://host[:port]/[type][selector]`
///
/// The first character of the path (after the leading `/`) is the Gopher
/// item type indicator. It is stripped before sending the selector to the
/// server, matching curl's behavior.
///
/// # Errors
///
/// Returns an error if the connection or transfer fails.
pub async fn transfer(
    url: &crate::url::Url,
    tls_config: &crate::tls::TlsConfig,
    use_tls: bool,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();

    // Gopher URL path: /Tselector where T is the item type character.
    // Strip the leading / and the type character to get the selector.
    // If path is "/" or empty, send empty selector (root menu).
    // Percent-decode the selector before sending — curl sends decoded bytes
    // to the gopher server (e.g. %09 → tab, %20 → space).
    let raw_selector = if path.len() > 2 { &path[2..] } else { "" };
    let selector = percent_decode(raw_selector);

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    // Send selector followed by CR-LF, then read all response data
    let request = format!("{selector}\r\n");
    let body = if use_tls {
        let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
        let (mut tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        tls_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("Gopher write error: {e}")))?;
        tls_stream.flush().await.map_err(|e| Error::Http(format!("Gopher flush error: {e}")))?;
        let mut data = Vec::new();
        let _n = tls_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("Gopher read error: {e}")))?;
        data
    } else {
        let mut tcp = tcp;
        tcp.write_all(request.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("Gopher write error: {e}")))?;
        tcp.flush().await.map_err(|e| Error::Http(format!("Gopher flush error: {e}")))?;
        let mut data = Vec::new();
        let _n = tcp
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("Gopher read error: {e}")))?;
        data
    };

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

/// Percent-decode a URL string.
///
/// Converts `%XX` sequences to the corresponding byte values.
/// Incomplete or invalid sequences are passed through as-is.
fn percent_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// Convert a hex ASCII character to its numeric value.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn selector_extraction_from_path() {
        // Gopher paths: /Tselector where T is item type
        let path = "/1some/menu";
        let selector = if path.len() > 2 { &path[2..] } else { "" };
        assert_eq!(selector, "some/menu");
    }

    #[test]
    fn selector_extraction_root() {
        let path = "/";
        let selector = if path.len() > 2 { &path[2..] } else { "" };
        assert_eq!(selector, "");
    }

    #[test]
    fn selector_extraction_type_only() {
        let path = "/1";
        let selector = if path.len() > 2 { &path[2..] } else { "" };
        assert_eq!(selector, "");
    }

    #[test]
    fn percent_decode_basic() {
        use super::percent_decode;
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a%09b"), "a\tb");
        assert_eq!(percent_decode("%2F"), "/");
    }

    #[test]
    fn percent_decode_incomplete() {
        use super::percent_decode;
        // Incomplete sequences are passed through
        assert_eq!(percent_decode("test%2"), "test%2");
        assert_eq!(percent_decode("test%"), "test%");
    }

    #[test]
    fn percent_decode_gopher_query() {
        use super::percent_decode;
        // Matches curl test 1202: %09 → tab, %20 → space
        assert_eq!(
            percent_decode("/the/search/engine%09query%20succeeded/1202"),
            "/the/search/engine\tquery succeeded/1202"
        );
    }
}
