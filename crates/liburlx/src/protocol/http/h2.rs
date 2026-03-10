//! HTTP/2 request/response codec.
//!
//! Uses the `h2` crate to send HTTP/2 requests over a TLS stream
//! after ALPN negotiation selects the h2 protocol.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Error;
use crate::protocol::http::response::{PushedResponse, Response};
use crate::throttle::{RateLimiter, SpeedLimits, THROTTLE_CHUNK_SIZE};

/// HTTP/2-specific configuration options.
///
/// Controls h2 handshake settings including flow control window sizes,
/// server push behavior, frame sizes, and PING keep-alive intervals.
#[derive(Debug, Clone, Default)]
pub struct Http2Config {
    /// Initial stream-level flow control window size in bytes.
    ///
    /// Controls how much data a single stream can receive before the
    /// sender must wait for a `WINDOW_UPDATE` frame. Default is 65,535 bytes
    /// (the HTTP/2 spec default). Must be between 1 and 2^31-1.
    pub window_size: Option<u32>,

    /// Initial connection-level flow control window size in bytes.
    ///
    /// Controls total data across all streams before the sender must
    /// wait for a connection-level `WINDOW_UPDATE`. Default is 65,535 bytes.
    pub connection_window_size: Option<u32>,

    /// Maximum frame size in bytes.
    ///
    /// The maximum size of a single HTTP/2 frame payload. Must be between
    /// 16,384 and 16,777,215 (2^24-1). Default is 16,384.
    pub max_frame_size: Option<u32>,

    /// Maximum header list size in bytes.
    ///
    /// The maximum size of the decoded header list. Default is unlimited.
    pub max_header_list_size: Option<u32>,

    /// Enable or disable HTTP/2 server push.
    ///
    /// When `Some(false)`, tells the server not to send `PUSH_PROMISE` frames.
    /// Default is `None` (server push enabled, matching h2 crate default).
    pub enable_push: Option<bool>,

    /// Stream priority weight (1-256).
    ///
    /// Higher weight streams get proportionally more bandwidth relative
    /// to siblings. Note: HTTP/2 priority was deprecated in RFC 9113 and
    /// many servers ignore it. Stored for API compatibility with
    /// `CURLOPT_STREAM_WEIGHT`.
    pub stream_weight: Option<u16>,

    /// PING frame interval for connection keep-alive.
    ///
    /// When set, periodically sends HTTP/2 PING frames to keep the
    /// connection alive and detect dead connections.
    pub ping_interval: Option<Duration>,
}

/// Send an HTTP/2 request and read the response.
///
/// Takes ownership of the stream since h2 manages its own I/O.
/// Collects any server-pushed responses (`PUSH_PROMISE` frames) during
/// the transfer and attaches them to the returned Response.
///
/// # Errors
///
/// Returns errors for I/O failures or protocol errors.
#[allow(clippy::too_many_arguments)]
pub async fn request<S>(
    stream: S,
    method: &str,
    host: &str,
    request_target: &str,
    custom_headers: &[(String, String)],
    body: Option<&[u8]>,
    url: &str,
    speed_limits: &SpeedLimits,
    h2_config: &Http2Config,
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Build h2 client with configured settings
    let mut builder = h2::client::Builder::new();
    if let Some(window_size) = h2_config.window_size {
        let _b = builder.initial_window_size(window_size);
    }
    if let Some(conn_window) = h2_config.connection_window_size {
        let _b = builder.initial_connection_window_size(conn_window);
    }
    if let Some(max_frame) = h2_config.max_frame_size {
        let _b = builder.max_frame_size(max_frame);
    }
    if let Some(max_header) = h2_config.max_header_list_size {
        let _b = builder.max_header_list_size(max_header);
    }
    if let Some(enable_push) = h2_config.enable_push {
        let _b = builder.enable_push(enable_push);
    }

    // Perform h2 client handshake with configured builder
    let (mut client, mut h2_conn): (
        h2::client::SendRequest<bytes::Bytes>,
        h2::client::Connection<S, bytes::Bytes>,
    ) = builder
        .handshake(stream)
        .await
        .map_err(|e| Error::Http(format!("h2 handshake failed: {e}")))?;

    // Spawn PING keep-alive task if interval is configured
    let ping_task = h2_config.ping_interval.and_then(|interval| {
        h2_conn.ping_pong().map(|ping_pong| tokio::spawn(ping_keepalive(ping_pong, interval)))
    });

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
    let (mut response_fut, mut send_stream): (
        h2::client::ResponseFuture,
        h2::SendStream<bytes::Bytes>,
    ) = client
        .send_request(req, !has_body)
        .map_err(|e| Error::Http(format!("h2 send failed: {e}")))?;

    // Extract push promises stream BEFORE awaiting the response.
    // push_promises() clones internal state, so it's independent of response_fut.
    let mut push_stream = response_fut.push_promises();

    // Spawn a background task to collect any server-pushed responses
    let push_task = tokio::spawn(async move {
        let mut pushed = Vec::new();
        while let Some(result) = push_stream.push_promise().await {
            match result {
                Ok(push_promise) => {
                    let (req, resp_future) = push_promise.into_parts();
                    // Extract the URL from the push promise request
                    let push_url = req.uri().to_string();

                    // Await the pushed response (skip failures silently)
                    if let Ok(h2_resp) = resp_future.await {
                        let status = h2_resp.status().as_u16();
                        let mut headers = HashMap::new();
                        for (name, value) in h2_resp.headers() {
                            let name = name.as_str().to_lowercase();
                            let value = String::from_utf8_lossy(value.as_bytes()).to_string();
                            let _old = headers.insert(name, value);
                        }

                        // Read pushed response body
                        let mut body_stream = h2_resp.into_body();
                        let mut body_bytes = Vec::new();
                        while let Some(chunk) = body_stream.data().await {
                            match chunk {
                                Ok(data) => {
                                    let chunk_len = data.len();
                                    body_bytes.extend_from_slice(&data);
                                    let _r = body_stream.flow_control().release_capacity(chunk_len);
                                }
                                Err(_) => break,
                            }
                        }

                        pushed.push(PushedResponse {
                            url: push_url,
                            status,
                            headers,
                            body: body_bytes,
                        });
                    }
                }
                Err(_) => break, // Stop on push promise stream errors
            }
        }
        pushed
    });

    // Send body if present, with optional rate limiting
    if let Some(body_data) = body {
        let mut send_limiter = RateLimiter::for_send(speed_limits);
        if send_limiter.is_active() {
            // Throttled: send in chunks
            let mut offset = 0;
            while offset < body_data.len() {
                let end = (offset + THROTTLE_CHUNK_SIZE).min(body_data.len());
                let is_last = end == body_data.len();
                let chunk = body_data[offset..end].to_vec();
                let chunk_len = chunk.len();
                send_stream
                    .send_data(chunk.into(), is_last)
                    .map_err(|e| Error::Http(format!("h2 body send failed: {e}")))?;
                send_limiter.record(chunk_len).await?;
                offset = end;
            }
        } else {
            send_stream
                .send_data(body_data.to_vec().into(), true)
                .map_err(|e| Error::Http(format!("h2 body send failed: {e}")))?;
        }
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
        // Collect any push promises that arrived (short timeout)
        let pushed = tokio::time::timeout(Duration::from_millis(50), push_task)
            .await
            .map_or_else(|_| Vec::new(), std::result::Result::unwrap_or_default);
        // Stop PING keep-alive task
        if let Some(task) = ping_task {
            task.abort();
        }
        let mut resp = Response::new(status, headers, Vec::new(), url.to_string());
        if !pushed.is_empty() {
            resp.set_pushed_responses(pushed);
        }
        return Ok(resp);
    }

    // Read body with optional rate limiting
    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
    let mut body_stream = h2_response.into_body();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| Error::Http(format!("h2 body read error: {e}")))?;
        let chunk_len = chunk.len();
        body_bytes.extend_from_slice(&chunk);
        // Release flow control capacity
        let _r = body_stream.flow_control().release_capacity(chunk_len);
        // Apply rate limiting after each data frame
        if recv_limiter.is_active() {
            recv_limiter.record(chunk_len).await?;
        }
    }

    // Collect any push promises that arrived during the transfer.
    // Use a short timeout since push promises should arrive before/during
    // the response — if none arrived by now, none are coming.
    let pushed = tokio::time::timeout(Duration::from_millis(50), push_task)
        .await
        .map_or_else(|_| Vec::new(), std::result::Result::unwrap_or_default);

    // Stop PING keep-alive task
    if let Some(task) = ping_task {
        task.abort();
    }

    let mut resp = Response::new(status, headers, body_bytes, url.to_string());
    if !pushed.is_empty() {
        resp.set_pushed_responses(pushed);
    }
    Ok(resp)
}

/// Periodically send HTTP/2 PING frames for connection keep-alive.
///
/// Runs until the connection is closed or the task is aborted.
async fn ping_keepalive(mut ping_pong: h2::PingPong, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        // Send PING and wait for PONG; if it fails, the connection is dead
        if ping_pong.ping(h2::Ping::opaque()).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pushed_response_struct() {
        let pr = PushedResponse {
            url: "/style.css".to_string(),
            status: 200,
            headers: HashMap::new(),
            body: Vec::new(),
        };
        assert_eq!(pr.url, "/style.css");
        assert_eq!(pr.status, 200);
    }

    #[test]
    fn http2_config_default() {
        let config = Http2Config::default();
        assert!(config.window_size.is_none());
        assert!(config.connection_window_size.is_none());
        assert!(config.max_frame_size.is_none());
        assert!(config.max_header_list_size.is_none());
        assert!(config.enable_push.is_none());
        assert!(config.stream_weight.is_none());
        assert!(config.ping_interval.is_none());
    }

    #[test]
    fn http2_config_custom() {
        let config = Http2Config {
            window_size: Some(1_048_576),
            connection_window_size: Some(2_097_152),
            max_frame_size: Some(32_768),
            max_header_list_size: Some(8192),
            enable_push: Some(false),
            stream_weight: Some(128),
            ping_interval: Some(Duration::from_secs(30)),
        };
        assert_eq!(config.window_size, Some(1_048_576));
        assert_eq!(config.connection_window_size, Some(2_097_152));
        assert_eq!(config.max_frame_size, Some(32_768));
        assert_eq!(config.max_header_list_size, Some(8192));
        assert_eq!(config.enable_push, Some(false));
        assert_eq!(config.stream_weight, Some(128));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn http2_config_clone() {
        let original = Http2Config {
            window_size: Some(65_535),
            enable_push: Some(true),
            ..Http2Config::default()
        };
        #[allow(clippy::redundant_clone)]
        let cloned = original.clone();
        assert_eq!(cloned.window_size, Some(65_535));
        assert_eq!(cloned.enable_push, Some(true));
        assert!(cloned.max_frame_size.is_none());
    }

    #[test]
    fn http2_config_debug() {
        let config = Http2Config::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("Http2Config"));
    }
}
