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
    let selector = if path.len() > 2 { &path[2..] } else { "" };

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
}
