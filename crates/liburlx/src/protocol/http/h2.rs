//! HTTP/2 request/response codec.
//!
//! Uses the `h2` crate to send HTTP/2 requests over a TLS stream
//! after ALPN negotiation selects the h2 protocol.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Send an HTTP/2 request and read the response.
///
/// Takes ownership of the stream since h2 manages its own I/O.
///
/// # Errors
///
/// Returns errors for I/O failures or protocol errors.
pub async fn request<S>(
    stream: S,
    method: &str,
    host: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Perform h2 client handshake
    let (mut client, h2_conn) = h2::client::handshake(stream)
        .await
        .map_err(|e| Error::Http(format!("h2 handshake failed: {e}")))?;

    // Spawn a task to drive the h2 connection in the background
    let _handle = tokio::spawn(async move {
        let _r = h2_conn.await;
    });

    // Build the request
    let uri: http::Uri = format!("https://{host}{request_target}")
        .parse()
        .map_err(|e: http::uri::InvalidUri| Error::Http(format!("invalid URI: {e}")))?;

    let method: http::Method = method
        .parse()
        .map_err(|e: http::method::InvalidMethod| Error::Http(format!("invalid method: {e}")))?;

    let mut builder = http::Request::builder().method(method).uri(uri);

    // Add headers
    builder = builder.header("host", host);

    let has_user_agent = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    if !has_user_agent {
        builder = builder.header("user-agent", "urlx/0.1.0");
    }

    let has_accept = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept"));
    if !has_accept {
        builder = builder.header("accept", "*/*");
    }

    for (name, value) in custom_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    let is_head = builder.method_ref().is_some_and(|m| m == http::Method::HEAD);

    let has_body = body.is_some();
    let req =
        builder.body(()).map_err(|e| Error::Http(format!("failed to build h2 request: {e}")))?;

    // Send the request
    let (response_fut, mut send_stream) = client
        .send_request(req, !has_body)
        .map_err(|e| Error::Http(format!("h2 send failed: {e}")))?;

    // Send body if present
    if let Some(body_data) = body {
        send_stream
            .send_data(body_data.to_vec().into(), true)
            .map_err(|e| Error::Http(format!("h2 body send failed: {e}")))?;
    }

    // Receive response
    let h2_response =
        response_fut.await.map_err(|e| Error::Http(format!("h2 response error: {e}")))?;

    let status = h2_response.status().as_u16();

    // Convert headers
    let mut headers = HashMap::new();
    for (name, value) in h2_response.headers() {
        let name = name.as_str().to_lowercase();
        let value = String::from_utf8_lossy(value.as_bytes()).to_string();
        let _old = headers.insert(name, value);
    }

    // HEAD responses have no body
    if is_head {
        return Ok(Response::new(status, headers, Vec::new(), url.to_string()));
    }

    // Read body
    let mut body_stream = h2_response.into_body();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| Error::Http(format!("h2 body read error: {e}")))?;
        body_bytes.extend_from_slice(&chunk);
        // Release flow control capacity
        let _r = body_stream.flow_control().release_capacity(chunk.len());
    }

    Ok(Response::new(status, headers, body_bytes, url.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    // h2 tests require a full h2 server, tested via integration tests
}
