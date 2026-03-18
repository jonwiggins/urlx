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

/// Check if the Transfer-Encoding header value includes "chunked" as one of
/// the comma-separated encodings (e.g. "chunked", "gzip, chunked").
fn te_contains_chunked(te: &str) -> bool {
    te.split(',').any(|part| part.trim().eq_ignore_ascii_case("chunked"))
}

/// Extract the non-chunked Transfer-Encoding algorithms from the TE header.
/// For example, "gzip, chunked" returns `Some("gzip")`, "chunked" returns `None`,
/// and "gzip" returns `Some("gzip")`.
pub(crate) fn te_compression_encoding(te: &str) -> Option<String> {
    let parts: Vec<&str> = te
        .split(',')
        .map(str::trim)
        .filter(|p| !p.eq_ignore_ascii_case("chunked") && !p.eq_ignore_ascii_case("identity"))
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Maximum response header size (100 KB, matching curl's default `CURL_MAX_HTTP_HEADER`).
/// curl returns `CURLE_TOO_LARGE` (exit 100) when headers exceed this limit (test 1154).
const MAX_HEADER_SIZE: usize = 100 * 1024;

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
    http09_allowed: bool,
    deadline: Option<tokio::time::Instant>,
    raw: bool,
) -> Result<(Response, bool), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let http_ver = if use_http10 { "HTTP/1.0" } else { "HTTP/1.1" };
    // Check if user provided a custom Host header
    let custom_host = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host"));
    // Build the request line
    let mut req = if custom_host {
        format!("{method} {request_target} {http_ver}\r\n")
    } else {
        format!("{method} {request_target} {http_ver}\r\nHost: {host}\r\n")
    };

    // Deduplicate custom headers: among set-entries (non-empty values),
    // last one wins per header name. Removal markers (empty in removed_headers)
    // are separate and don't suppress custom set-entries.
    // Exception: Host header uses first-wins (curl compat: test 1121).
    let mut seen_set: Vec<String> = Vec::new();
    let mut keep = vec![true; custom_headers.len()];
    // Host: first-wins — scan forward, mark duplicates
    {
        let mut seen_host = false;
        for i in 0..custom_headers.len() {
            if custom_headers[i].0.eq_ignore_ascii_case("host") {
                if seen_host {
                    keep[i] = false;
                } else {
                    seen_host = true;
                }
            }
        }
        if seen_host {
            seen_set.push("host".to_string());
        }
    }
    // All other headers: last-wins — scan in reverse (skip Host, already handled)
    for i in (0..custom_headers.len()).rev() {
        if custom_headers[i].0.eq_ignore_ascii_case("host") {
            continue; // Host dedup handled above
        }
        let name_lower = custom_headers[i].0.to_lowercase();
        if seen_set.contains(&name_lower) {
            keep[i] = false;
        } else {
            seen_set.push(name_lower);
        }
    }

    // Emit custom Host header immediately (if user provided one via -H)
    if custom_host {
        for (i, (name, value)) in custom_headers.iter().enumerate() {
            if keep[i] && name.eq_ignore_ascii_case("host") {
                let _ = write!(req, "{name}: {value}\r\n");
                break;
            }
        }
    }

    // Headers that curl emits before User-Agent (priority headers).
    // curl emits Proxy-Authorization before User-Agent always.
    // Auto-generated Authorization (Basic/Digest/NTLM/Bearer) is also prioritized.
    // Custom -H "Authorization: ..." stays in its original position (curl compat: test 317).
    let priority_order: &[&str] = &["proxy-authorization", "range", "content-range"];
    let auto_auth_prefixes = ["Basic ", "Digest ", "NTLM ", "Bearer ", "Negotiate "];

    // Emit priority custom headers right after Host (curl compat order)
    for &prio_name in priority_order {
        for (i, (name, value)) in custom_headers.iter().enumerate() {
            if keep[i] && name.eq_ignore_ascii_case(prio_name) {
                if value.is_empty() {
                    let _ = write!(req, "{name}:\r\n");
                } else {
                    let _ = write!(req, "{name}: {value}\r\n");
                }
            }
        }
    }
    // Auto-generated Authorization headers (Basic/Digest/NTLM/Bearer) go in priority position.
    // Custom -H "Authorization: custom" stays in normal position (curl compat: test 317).
    for (i, (name, value)) in custom_headers.iter().enumerate() {
        if keep[i]
            && name.eq_ignore_ascii_case("authorization")
            && auto_auth_prefixes.iter().any(|p| value.starts_with(p))
        {
            let _ = write!(req, "{name}: {value}\r\n");
        }
    }

    // Emit User-Agent in its fixed position: custom value from -A, or default.
    // An empty value (from -A "" or -H "User-Agent:") suppresses the header entirely.
    let custom_ua = custom_headers
        .iter()
        .enumerate()
        .find(|(i, (k, _))| keep[*i] && k.eq_ignore_ascii_case("user-agent"));
    match custom_ua {
        Some((_, (_, value))) if value.is_empty() => {
            // Empty User-Agent = suppress entirely (curl compat)
        }
        Some((_, (name, value))) => {
            let _ = write!(req, "{name}: {value}\r\n");
        }
        None => {
            req.push_str("User-Agent: curl/0.1.0\r\n");
        }
    }

    // Emit default Accept right after User-Agent (curl compat), or skip
    // if Accept was explicitly set via -H (in which case it goes in command-line order).
    let has_accept = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept"));
    if !has_accept {
        req.push_str("Accept: */*\r\n");
    }

    // Compute chunked/TE state before emitting remaining headers.
    let has_content_length =
        custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    let has_transfer_encoding =
        custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let explicit_chunked = custom_headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    let te_suppressed = custom_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.is_empty());
    let use_chunked = !use_http10 && !te_suppressed && (chunked_upload || explicit_chunked);
    let has_expect = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("expect"));
    // Whether to auto-emit the Expect: 100-continue header (don't if user provided it)
    let use_expect =
        expect_100_timeout.is_some() && body.is_some_and(|b| !b.is_empty()) && !has_expect;
    // Whether to follow the 100-continue protocol (wait for server response before body).
    // Do this both when we auto-emit and when the user explicitly provides Expect header.
    let has_user_expect_100 = custom_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("expect") && v.eq_ignore_ascii_case("100-continue"));
    let do_expect_protocol =
        use_expect || (has_user_expect_100 && body.is_some_and(|b| !b.is_empty()));

    // Emit auto Transfer-Encoding: chunked BEFORE custom headers (curl compat order).
    if body.is_some() && use_chunked && !explicit_chunked {
        req.push_str("Transfer-Encoding: chunked\r\n");
    }

    // Emit remaining custom headers (non-priority, non-user-agent) in command-line order.
    // Multipart Content-Type is deferred to after Content-Length (curl header ordering).
    let mut deferred_content_type: Option<(String, String)> = None;
    let mut content_type_emitted = false;
    for (i, (name, value)) in custom_headers.iter().enumerate() {
        // Skip priority headers, auto-auth, User-Agent, and Host (emitted elsewhere)
        let is_priority = priority_order.iter().any(|p| name.eq_ignore_ascii_case(p));
        let is_auto_auth = name.eq_ignore_ascii_case("authorization")
            && auto_auth_prefixes.iter().any(|p| value.starts_with(p));
        let is_ua = name.eq_ignore_ascii_case("user-agent");
        let is_host = name.eq_ignore_ascii_case("host");
        if keep[i] && !is_priority && !is_auto_auth && !is_ua && !is_host {
            // Defer form/multipart Content-Type to after Content-Length (curl compat)
            // Keep other Content-Types (like application/json) in place (test 383)
            if name.eq_ignore_ascii_case("content-type")
                && (value.contains("boundary=")
                    || value.contains("application/x-www-form-urlencoded"))
            {
                deferred_content_type = Some((name.clone(), value.clone()));
                continue;
            }
            if name.eq_ignore_ascii_case("content-type") {
                content_type_emitted = true;
                // Empty Content-Type → suppress entirely (NTLM Type 1 probe, test 170)
                if value.is_empty() {
                    continue;
                }
            }
            if value.is_empty() {
                // Empty value from -H "Name;" → send header with no value
                let _ = write!(req, "{name}:\r\n");
            } else {
                let _ = write!(req, "{name}: {value}\r\n");
            }
        }
    }

    // Add auto Content-Length for bodies (after custom headers, before Content-Type).
    if let Some(body_data) = body {
        if !use_chunked && !has_content_length && !has_transfer_encoding {
            let _ = write!(req, "Content-Length: {}\r\n", body_data.len());
        }
    }

    // Emit deferred Content-Type or auto-add it for POST (curl compat: test 669).
    // Note: for custom methods with -d (form data), Content-Type is added by the
    // Easy handle layer (see easy.rs form_data handling), not here.
    if let Some((name, value)) = deferred_content_type {
        let _ = write!(req, "{name}: {value}\r\n");
    } else if !content_type_emitted && method.eq_ignore_ascii_case("POST") && body.is_some() {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }

    // Emit auto Expect: 100-continue after Content-Length and Content-Type (curl order: test 1129)
    if use_expect {
        req.push_str("Expect: 100-continue\r\n");
    }

    // Connection management — only send Connection: close for HTTP/1.1 non-keepalive.
    // HTTP/1.0 defaults to close, so omit it (curl compat).
    if !keep_alive && !use_http10 {
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

    // Handle Expect: 100-continue protocol (both auto-emitted and user-provided)
    if do_expect_protocol {
        stream.flush().await.map_err(|e| Error::Http(format!("flush failed: {e}")))?;

        let timeout_dur = expect_100_timeout.unwrap_or(Duration::from_secs(1));
        match tokio::time::timeout(timeout_dur, read_response_headers(stream)).await {
            Ok(Ok((header_bytes, body_prefix))) => {
                let ParsedHeaders { status, .. } = parse_headers(&header_bytes)?;
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
                    let ph = parse_headers(&header_bytes)?;
                    let is_head = method.eq_ignore_ascii_case("HEAD");
                    let no_body = is_head
                        || ph.status == 204
                        || ph.status == 304
                        || (100..200).contains(&ph.status);
                    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
                    let (response_body, body_read_to_eof, trailers, raw_trailers) = if no_body {
                        (Vec::new(), false, HashMap::new(), Vec::new())
                    } else {
                        read_body_from_headers(
                            stream,
                            &ph.headers,
                            body_prefix,
                            keep_alive,
                            ignore_content_length,
                            &mut recv_limiter,
                            deadline,
                            raw,
                        )
                        .await?
                    };
                    let server_wants_close = ph
                        .headers
                        .get("connection")
                        .is_some_and(|v| v.eq_ignore_ascii_case("close"));
                    let can_reuse =
                        keep_alive && !use_http10 && !server_wants_close && !body_read_to_eof;
                    let mut resp =
                        Response::new(ph.status, ph.headers, response_body, url.to_string());
                    resp.set_header_original_names(ph.original_names);
                    resp.set_headers_ordered(ph.headers_ordered);
                    resp.set_status_reason(ph.reason);
                    resp.set_uses_crlf(ph.uses_crlf);
                    resp.set_http_version(ph.version);
                    resp.set_raw_headers(header_bytes);
                    if !trailers.is_empty() {
                        resp.set_trailers(trailers);
                    }
                    if !raw_trailers.is_empty() {
                        resp.set_raw_trailers(raw_trailers);
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

    // HTTP/0.9: no headers at all — return body-only response
    if header_bytes.is_empty() {
        // Reject HTTP/0.9 responses unless explicitly allowed (curl compat: tests 1172, 1174)
        if !http09_allowed {
            return Err(Error::Http("unsupported HTTP version in response".to_string()));
        }
        // Read remaining body to EOF
        let mut body = body_prefix;
        let mut tmp = [0u8; 8192];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        let mut resp = Response::new(200, HashMap::new(), body, url.to_string());
        // Set empty raw headers so format_headers outputs nothing
        resp.set_raw_headers(Vec::new());
        return Ok((resp, false));
    }

    let mut ph = parse_headers(&header_bytes)?;

    // Skip 1xx informational responses (100 Continue, 103 Early Hints, etc.)
    // Collect the raw bytes of 1xx responses so they can be included in output
    // when --include is used (curl includes 1xx headers before the final response).
    let mut informational_prefix: Vec<u8> = Vec::new();
    while (100..200).contains(&ph.status) {
        // Preserve this 1xx response's raw headers (already includes trailing blank line)
        informational_prefix.extend_from_slice(&header_bytes);
        // The body_prefix may contain the start of the next response
        let next = read_response_headers_with_prefix(stream, body_prefix).await?;
        header_bytes = next.0;
        body_prefix = next.1;
        ph = parse_headers(&header_bytes)?;
    }

    // Validate Content-Length header (curl returns CURLE_WEIRD_SERVER_REPLY = 8).
    // Return a response with body_error so the caller can detect it and return
    // exit code 8 while still outputting the partial headers.
    if let Some(cl) = ph.headers.get("content-length").cloned() {
        // Validate Content-Length: reject non-numeric, check comma-separated duplicates
        let trimmed = cl.trim().to_string();
        let has_non_digit = trimmed.bytes().any(|b| !b.is_ascii_digit() && b != b',' && b != b' ');
        let has_comma = trimmed.contains(',');
        if !trimmed.is_empty() && !trimmed.starts_with('-') && (has_non_digit || has_comma) {
            // Check if it's a comma-separated list (valid per HTTP spec: test 770)
            let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
            let parsed_values: Vec<Option<u64>> =
                parts.iter().map(|p| p.parse::<u64>().ok()).collect();
            if parsed_values.iter().any(Option::is_none) {
                // Non-numeric content-length value
                let mut resp =
                    Response::new(ph.status, ph.headers.clone(), Vec::new(), url.to_string());
                resp.set_headers_ordered(ph.headers_ordered);
                resp.set_status_reason(ph.reason);
                resp.set_uses_crlf(ph.uses_crlf);
                resp.set_http_version(ph.version);
                resp.set_raw_headers(header_bytes.clone());
                resp.set_body_error(Some("invalid_content_length".to_string()));
                return Ok((resp, true));
            }
            // All values must be equal (test 771: different values = error)
            let first = parsed_values[0];
            if !parsed_values.iter().all(|v| v == &first) {
                let mut resp =
                    Response::new(ph.status, ph.headers.clone(), Vec::new(), url.to_string());
                resp.set_headers_ordered(ph.headers_ordered);
                resp.set_status_reason(ph.reason);
                resp.set_uses_crlf(ph.uses_crlf);
                resp.set_http_version(ph.version);
                resp.set_raw_headers(header_bytes.clone());
                resp.set_body_error(Some("conflicting_content_length".to_string()));
                return Ok((resp, true));
            }
            // Replace comma-separated value with single value for downstream parsing
            if let Some(val) = first {
                let _ = ph.headers.insert("content-length".to_string(), val.to_string());
            }
        }
        if cl.starts_with('-') {
            // Remove Content-Length and everything after from ordered headers
            let mut trunc_ordered = Vec::new();
            for (k, v) in &ph.headers_ordered {
                if k.eq_ignore_ascii_case("content-length") {
                    break;
                }
                trunc_ordered.push((k.clone(), v.clone()));
            }

            // Build raw header bytes truncated at Content-Length
            let mut trunc_raw = Vec::new();
            let line_ending: &[u8] = if ph.uses_crlf { b"\r\n" } else { b"\n" };
            // Find status line in original header bytes
            if let Some(first_line_end) =
                header_bytes.windows(line_ending.len()).position(|w| w == line_ending)
            {
                trunc_raw.extend_from_slice(&header_bytes[..first_line_end]);
                trunc_raw.extend_from_slice(line_ending);
            }
            for (k, v) in &trunc_ordered {
                trunc_raw.extend_from_slice(k.as_bytes());
                // raw values from extract_raw_header_values already include ": " prefix
                trunc_raw.extend_from_slice(v.as_bytes());
                trunc_raw.extend_from_slice(line_ending);
            }

            let trunc_headers: HashMap<String, String> =
                trunc_ordered.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();

            let mut resp = Response::new(ph.status, trunc_headers, Vec::new(), url.to_string());
            resp.set_headers_ordered(trunc_ordered);
            resp.set_status_reason(ph.reason);
            resp.set_uses_crlf(ph.uses_crlf);
            resp.set_http_version(ph.version);
            resp.set_raw_headers(trunc_raw);
            resp.set_body_error(Some("negative_content_length".to_string()));
            return Ok((resp, true));
        }
    }

    // Reject duplicate Location headers (curl compat: test 772)
    if let Some(loc) = ph.headers.get("location") {
        if loc.contains('\x00') {
            let mut resp =
                Response::new(ph.status, ph.headers.clone(), Vec::new(), url.to_string());
            resp.set_headers_ordered(ph.headers_ordered);
            resp.set_status_reason(ph.reason);
            resp.set_uses_crlf(ph.uses_crlf);
            resp.set_http_version(ph.version);
            resp.set_raw_headers(header_bytes.clone());
            resp.set_body_error(Some("duplicate_location".to_string()));
            return Ok((resp, true));
        }
    }

    // 204 and 304 responses have no body per HTTP spec.
    // Also skip body when a Range request got a non-206/416 response
    // (server doesn't support ranges — curl returns CURLE_RANGE_ERROR
    // without consuming the body).
    // Skip body when a Range request got a non-206/416 response AND there's
    // no Content-Length/chunked (would hang reading to EOF if server doesn't close).
    let sent_range = custom_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
    let has_body_framing = ph.headers.contains_key("content-length")
        || ph.headers.get("transfer-encoding").is_some_and(|te| te_contains_chunked(te));
    let range_failed = sent_range && ph.status != 206 && ph.status != 416 && !has_body_framing;
    // For 3xx redirects without Content-Length/chunked, skip body read to avoid
    // hanging when the server says Connection: close but doesn't actually close.
    let is_redirect_no_cl = (300..400).contains(&ph.status)
        && ph.headers.get("location").is_some_and(|v| !v.trim().is_empty())
        && !ph.headers.contains_key("content-length")
        && !ph.headers.get("transfer-encoding").is_some_and(|te| te_contains_chunked(te));
    let no_body =
        is_head || ph.status == 204 || ph.status == 304 || range_failed || is_redirect_no_cl;

    // Read body with download rate limiting
    let mut recv_limiter = RateLimiter::for_recv(speed_limits);
    // If server says Connection: close, treat as non-keepalive for body reading
    // (read until EOF when no Content-Length, instead of assuming empty body).
    // HTTP/1.0 responses default to connection close unless Connection: keep-alive
    // is present (curl compat: test 349).
    let server_close =
        ph.headers.get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let response_is_http10 = ph.version == ResponseHttpVersion::Http10;
    let server_keepalive =
        ph.headers.get("connection").is_some_and(|v| v.eq_ignore_ascii_case("keep-alive"));
    let effective_keepalive =
        keep_alive && !use_http10 && !server_close && (!response_is_http10 || server_keepalive);
    let (response_body, body_read_to_eof, trailers, raw_trailers, body_error) = if no_body {
        (Vec::new(), false, HashMap::new(), Vec::new(), None)
    } else {
        match read_body_from_headers(
            stream,
            &ph.headers,
            body_prefix,
            effective_keepalive,
            ignore_content_length,
            &mut recv_limiter,
            deadline,
            raw,
        )
        .await
        {
            Ok((body, eof, trailers, raw_trailers)) => (body, eof, trailers, raw_trailers, None),
            Err(Error::PartialBody { partial_body, message }) => {
                // Chunked decode error with partial data — return headers + partial body
                (partial_body, true, HashMap::new(), Vec::new(), Some(message))
            }
            Err(e) => {
                // Other body read errors — return headers only
                (Vec::new(), true, HashMap::new(), Vec::new(), Some(e.to_string()))
            }
        }
    };

    // Determine if connection can be reused
    let server_wants_close =
        ph.headers.get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let can_reuse = keep_alive && !use_http10 && !server_wants_close && !body_read_to_eof;

    let mut resp = Response::new(ph.status, ph.headers, response_body, url.to_string());
    resp.set_header_original_names(ph.original_names);
    resp.set_headers_ordered(ph.headers_ordered);
    resp.set_status_reason(ph.reason);
    resp.set_uses_crlf(ph.uses_crlf);
    resp.set_http_version(ph.version);
    // Prepend 1xx informational response headers so --include shows them
    if informational_prefix.is_empty() {
        resp.set_raw_headers(header_bytes);
    } else {
        let mut combined = informational_prefix;
        combined.extend_from_slice(&header_bytes);
        resp.set_raw_headers(combined);
    }
    if !trailers.is_empty() {
        resp.set_trailers(trailers);
    }
    if !raw_trailers.is_empty() {
        resp.set_raw_trailers(raw_trailers);
    }

    // If body reading failed, mark the response as partial for the caller
    if let Some(err) = body_error {
        resp.set_body_error(Some(err));
        return Ok((resp, false));
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
    // Only write body chunks if there's actual data; empty body skips straight
    // to the terminating zero-length chunk (curl compat: test 1333).
    if !body.is_empty() {
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
/// Find the end of HTTP headers in a buffer.
///
/// Supports both `\r\n\r\n` (standard) and `\n\n` (bare LF) header terminators.
/// Returns `(position, length)` where position is the start of the terminator
/// and length is the terminator's byte count (4 for CRLF, 2 for LF).
fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    // Find the earliest occurrence of any header terminator pattern:
    // \r\n\r\n (standard), \n\r\n (mixed), or \n\n (bare LF).
    // Return the one at the lowest position.
    let candidates = [
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| (p, 4)),
        buf.windows(3).position(|w| w == b"\n\r\n").map(|p| (p, 3)),
        buf.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)),
    ];
    candidates.into_iter().flatten().min_by_key(|(pos, _)| *pos)
}

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
            // If response doesn't start with "HTTP/", treat as HTTP/0.9
            // (raw body, no headers). Return empty headers + all data as body prefix.
            if !buf.starts_with(b"HTTP/") {
                return Ok((Vec::new(), buf));
            }
            return Err(Error::Http("incomplete response headers".to_string()));
        }

        buf.extend_from_slice(&tmp[..n]);

        // Check for end of headers (supports both \r\n\r\n and \n\n)
        if let Some((pos, len)) = find_header_end(&buf) {
            let header_end = pos + len;
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
    if let Some((pos, len)) = find_header_end(&buf) {
        let header_end = pos + len;
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

        if let Some((pos, len)) = find_header_end(&buf) {
            let header_end = pos + len;
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

/// Parsed response headers.
struct ParsedHeaders {
    status: u16,
    reason: Option<String>,
    version: ResponseHttpVersion,
    uses_crlf: bool,
    headers: HashMap<String, String>,
    original_names: HashMap<String, String>,
    headers_ordered: Vec<(String, String)>,
}

/// Parse raw header bytes into structured response headers.
fn parse_headers(data: &[u8]) -> Result<ParsedHeaders, Error> {
    // Find the end of headers (double CRLF or double LF)
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| data.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
        .unwrap_or(data.len());

    // Reject headers containing null bytes (curl compat: CURLE_WEIRD_SERVER_REPLY)
    if data[..header_end].contains(&0) {
        return Err(Error::Http("Weird server reply: binary zero in headers".to_string()));
    }

    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers_buf);

    let header_len = match parsed.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete response headers".to_string()));
        }
        Err(e) => {
            let emsg = e.to_string();
            // httparse rejects unknown HTTP versions (e.g. HTTP/1.2).
            // curl returns CURLE_UNSUPPORTED_PROTOCOL (1) for these.
            // Only treat as version error if the response actually started with "HTTP/".
            if emsg.contains("invalid HTTP version") && data.starts_with(b"HTTP/") {
                return Err(Error::UnsupportedProtocol(
                    "unsupported HTTP version in response".to_string(),
                ));
            }
            // httparse has a limited header buffer (64). If the response has more
            // headers than that, fall through to the dynamic-buffer retry below.
            if emsg.contains("too many headers") {
                // Retry with a larger, heap-allocated header buffer to count them
                return parse_headers_large(data);
            }
            return Err(Error::Http(format!("Weird server reply: {e}")));
        }
    };

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Http(format!(
            "response headers too large: {header_len} bytes (max {MAX_HEADER_SIZE})"
        )));
    }

    let status =
        parsed.code.ok_or_else(|| Error::Http("response has no status code".to_string()))?;
    let reason = parsed.reason.map(str::to_string);
    let version = match parsed.version {
        Some(0) => ResponseHttpVersion::Http10,
        Some(1) | None => ResponseHttpVersion::Http11,
        Some(v) => {
            return Err(Error::UnsupportedProtocol(format!("unsupported HTTP version: 1.{v}")));
        }
    };
    // Detect line ending style: if we find \r\n it's CRLF, otherwise bare LF
    let uses_crlf = data.windows(2).any(|w| w == b"\r\n");

    // Extract raw header values from the wire data (httparse trims whitespace,
    // but curl preserves it in -i output)
    let raw_values = extract_raw_header_values(&data[..header_len]);

    let mut headers = HashMap::with_capacity(parsed.headers.len());
    let mut original_names = HashMap::with_capacity(parsed.headers.len());
    let mut headers_ordered = Vec::with_capacity(parsed.headers.len());
    for (idx, header) in parsed.headers.iter().enumerate() {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
        // For wire-order list, use the raw (untrimmed) value if available
        let raw_value = raw_values.get(idx).cloned().unwrap_or_else(|| value.clone());
        headers_ordered.push((header.name.to_string(), raw_value));
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
        } else if name == "content-length" {
            // Track duplicate Content-Length: if values differ, mark as conflicting
            let _entry = headers
                .entry(name)
                .and_modify(|existing: &mut String| {
                    if existing.trim() != value.trim() {
                        // Mark conflicting by appending with comma
                        existing.push(',');
                        existing.push_str(&value);
                    }
                })
                .or_insert(value);
        } else if name == "location" && headers.contains_key("location") {
            // Duplicate Location headers with *different* values: mark as error (curl compat: test 772)
            // Identical duplicates are allowed (curl compat: test 773)
            let _entry = headers.entry(name).and_modify(|existing: &mut String| {
                if *existing != value {
                    existing.push('\x00'); // sentinel for duplicate detection
                    existing.push_str(&value);
                }
            });
        } else {
            let _old = headers.insert(name, value);
        }
    }

    Ok(ParsedHeaders {
        status,
        reason,
        version,
        uses_crlf,
        headers,
        original_names,
        headers_ordered,
    })
}

/// Maximum number of HTTP response headers allowed (curl compat: test 747).
const MAX_HEADER_COUNT: usize = 5000;

/// Re-parse headers with a large heap-allocated buffer.
///
/// Called when the initial 64-entry stack buffer is too small.
/// Enforces curl's 5000-header limit (`CURLE_TOO_LARGE` = 100).
fn parse_headers_large(data: &[u8]) -> Result<ParsedHeaders, Error> {
    let mut headers_buf: Vec<httparse::Header<'_>> =
        vec![httparse::EMPTY_HEADER; MAX_HEADER_COUNT + 1];
    let mut parsed = httparse::Response::new(&mut headers_buf);

    let header_len = match parsed.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete response headers".to_string()));
        }
        Err(e) => {
            let emsg = e.to_string();
            if emsg.contains("too many headers") {
                // Even 5001 slots were not enough — reject
                return Err(Error::Transfer {
                    code: 100,
                    message: format!("Too many response headers, {MAX_HEADER_COUNT} is max"),
                });
            }
            return Err(Error::Http(format!("Weird server reply: {e}")));
        }
    };

    // Count actual headers (non-empty name)
    let count = parsed.headers.iter().filter(|h| !h.name.is_empty()).count();
    if count > MAX_HEADER_COUNT {
        return Err(Error::Transfer {
            code: 100,
            message: format!("Too many response headers, {MAX_HEADER_COUNT} is max"),
        });
    }

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Http(format!(
            "response headers too large: {header_len} bytes (max {MAX_HEADER_SIZE})"
        )));
    }

    let status =
        parsed.code.ok_or_else(|| Error::Http("response has no status code".to_string()))?;
    let reason = parsed.reason.map(str::to_string);
    let version = match parsed.version {
        Some(0) => ResponseHttpVersion::Http10,
        Some(1) | None => ResponseHttpVersion::Http11,
        Some(v) => {
            return Err(Error::UnsupportedProtocol(format!("unsupported HTTP version: 1.{v}")));
        }
    };
    let uses_crlf = data.windows(2).any(|w| w == b"\r\n");
    let raw_values = extract_raw_header_values(&data[..header_len]);

    let mut headers = HashMap::with_capacity(parsed.headers.len());
    let mut original_names = HashMap::with_capacity(parsed.headers.len());
    let mut headers_ordered = Vec::with_capacity(parsed.headers.len());
    for (idx, header) in parsed.headers.iter().enumerate() {
        if header.name.is_empty() {
            break;
        }
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
        let raw_value = raw_values.get(idx).cloned().unwrap_or_else(|| value.clone());
        headers_ordered.push((header.name.to_string(), raw_value));
        let _old = original_names.entry(name.clone()).or_insert_with(|| header.name.to_string());
        let _old2 = headers.insert(name, value);
    }

    Ok(ParsedHeaders {
        status,
        reason,
        version,
        uses_crlf,
        headers,
        original_names,
        headers_ordered,
    })
}

/// Extract raw header values from wire data, preserving leading/trailing whitespace.
///
/// `httparse` trims OWS from header values per RFC 7230, but curl preserves
/// the raw whitespace in `-i` output. This function extracts the untrimmed
/// values by parsing the raw header block.
fn extract_raw_header_values(header_data: &[u8]) -> Vec<String> {
    let mut values = Vec::new();
    let text = String::from_utf8_lossy(header_data);
    let mut first_line = true;
    for line in text.split('\n') {
        // Skip the status line
        if first_line {
            first_line = false;
            continue;
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        // Empty line marks end of headers
        if line.is_empty() {
            break;
        }
        // Extract value after first ":" — include the colon separator and any
        // following whitespace so that format_headers can reconstruct the wire
        // format exactly (e.g., "Set-Cookie:value" vs "Set-Cookie: value").
        if let Some(colon_pos) = line.find(':') {
            let raw = &line[colon_pos..]; // includes ":" and everything after
            values.push(raw.to_string());
        }
    }
    values
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
                // Treat as truncated — return partial body error
                // (curl compat: test 376 — CURLE_PARTIAL_FILE when Content-Length > actual)
                return Err(Error::PartialBody {
                    message: "transfer closed with outstanding read data remaining".to_string(),
                    partial_body: body,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Connection closed before all Content-Length bytes received
                // (curl compat: test 376 — CURLE_PARTIAL_FILE)
                return Err(Error::PartialBody {
                    message: "transfer closed with outstanding read data remaining".to_string(),
                    partial_body: body,
                });
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
            Err(e)
                if is_close_notify_error(&e) || e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                // Connection closed before all Content-Length bytes received
                return Err(Error::PartialBody {
                    message: "transfer closed with outstanding read data remaining".to_string(),
                    partial_body: body,
                });
            }
            Err(e) => return Err(Error::Http(format!("body read failed: {e}"))),
        }
        body.extend_from_slice(&chunk_buf);
        limiter.record(chunk_size).await?;
    }

    Ok(body)
}

/// Read the response body based on headers (Content-Length, chunked, or EOF).
///
/// Returns the body bytes, whether the body was read to EOF, any trailer headers,
/// and raw trailer bytes.
#[allow(clippy::large_futures, clippy::too_many_arguments)]
async fn read_body_from_headers<S>(
    stream: &mut S,
    headers: &HashMap<String, String>,
    body_prefix: Vec<u8>,
    keep_alive: bool,
    ignore_content_length: bool,
    limiter: &mut RateLimiter,
    deadline: Option<tokio::time::Instant>,
    raw: bool,
) -> Result<(Vec<u8>, bool, HashMap<String, String>, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let is_chunked = headers.get("transfer-encoding").is_some_and(|te| te_contains_chunked(te));

    // In raw mode, skip chunked decoding — pass bytes through as-is (curl --raw)
    // Still parse chunk framing to know when to stop, but include all framing in output.
    if is_chunked && raw {
        let body = read_chunked_raw(stream, body_prefix, limiter).await?;
        return Ok((body, false, HashMap::new(), Vec::new()));
    }

    if is_chunked {
        match read_chunked_body_streaming(stream, body_prefix, limiter).await {
            Ok((body, trailers, raw_trailers)) => Ok((body, false, trailers, raw_trailers)),
            Err(Error::PartialBody { partial_body, message }) => {
                Err(Error::PartialBody { message, partial_body })
            }
            Err(e) => Err(e),
        }
    } else if !ignore_content_length && headers.contains_key("content-length") {
        let cl = &headers["content-length"];
        if let Ok(content_length) = cl.parse::<usize>() {
            let body = read_exact_body(stream, content_length, body_prefix, limiter).await?;
            Ok((body, false, HashMap::new(), Vec::new()))
        } else {
            // Content-Length overflows usize — read to EOF (curl compat: test 395)
            let mut body = body_prefix;
            let mut tmp = [0u8; 8192];
            loop {
                match stream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(e) if is_close_notify_error(&e) => break,
                    Err(e) => return Err(Error::Http(format!("body read failed: {e}"))),
                }
            }
            Ok((body, true, HashMap::new(), Vec::new()))
        }
    } else if keep_alive && !ignore_content_length {
        // No Content-Length, no chunked, but keep-alive → assume empty body
        Ok((body_prefix, false, HashMap::new(), Vec::new()))
    } else {
        // No Content-Length (or ignoring it), connection close → read until EOF
        let body = read_to_eof_throttled(stream, body_prefix, limiter, deadline).await?;
        Ok((body, true, HashMap::new(), Vec::new()))
    }
}

/// Read until EOF with optional throttling and deadline.
///
/// If a `deadline` is provided and a read exceeds it, returns whatever data
/// has been received so far (curl outputs partial data on timeout).
async fn read_to_eof_throttled<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
    deadline: Option<tokio::time::Instant>,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    if !limiter.is_active() {
        // Fast path: read chunks until EOF or deadline
        let mut body = prefix;
        let mut buf = [0u8; 8192];
        loop {
            let read_fut = stream.read(&mut buf);
            let result = if let Some(dl) = deadline {
                match tokio::time::timeout_at(dl, read_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        // Deadline hit — return partial body with error
                        return Err(Error::PartialBody {
                            message: "transfer timeout".into(),
                            partial_body: body,
                        });
                    }
                }
            } else {
                read_fut.await
            };
            match result {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !body.is_empty() => {
                    break;
                }
                Err(e) if is_close_notify_error(&e) => break,
                Err(e) => return Err(Error::Http(format!("read failed: {e}"))),
            }
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
        let read_fut = stream.read(&mut buf);
        let result = if let Some(dl) = deadline {
            match tokio::time::timeout_at(dl, read_fut).await {
                Ok(r) => r,
                Err(_) => {
                    return Err(Error::PartialBody {
                        message: "transfer timeout".into(),
                        partial_body: body,
                    });
                }
            }
        } else {
            read_fut.await
        };
        match result {
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

/// Read a chunked transfer-encoded body in raw mode (--raw).
///
/// Passes through chunk framing bytes (sizes, CRLF terminators) as-is but still
/// parses chunk sizes to know when to stop reading. The output includes the raw
/// chunked encoding including the terminating `0\r\n\r\n`.
async fn read_chunked_raw<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf = prefix;
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
                // Connection closed — return what we have
                return Ok(buf);
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        let (line_end, eol_len) = find_line_ending(&buf, pos)
            .ok_or_else(|| Error::Http("incomplete chunked encoding".into()))?;

        let size_str = std::str::from_utf8(&buf[pos..line_end])
            .map_err(|_| Error::Http("invalid chunk size encoding".into()))?;
        let size_str = size_str.split(';').next().unwrap_or(size_str).trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| Error::Http(format!("invalid chunk size '{size_str}': {e}")))?;

        pos = line_end + eol_len;

        if chunk_size == 0 {
            // Read until we have the final empty line after trailers
            loop {
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
                        return Ok(buf);
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let Some((le, el)) = find_line_ending(&buf, pos) else {
                    break;
                };
                if le == pos {
                    // Empty line — end of chunked encoding
                    pos = le + el;
                    break;
                }
                pos = le + el;
            }
            // Truncate to include only the chunked data (not any pipelined data)
            buf.truncate(pos);
            return Ok(buf);
        }

        // Skip past chunk data + trailing CRLF
        let needed = pos + chunk_size + 2; // data + CRLF
        while buf.len() < needed {
            let mut tmp = [0u8; 4096];
            let n = match stream.read(&mut tmp).await {
                Ok(n) => n,
                Err(e) if is_close_notify_error(&e) => 0,
                Err(e) => return Err(Error::Http(format!("chunked read failed: {e}"))),
            };
            if n == 0 {
                return Ok(buf);
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        pos = needed;

        let _ = limiter.record(chunk_size).await;
    }
}

/// Read a chunked transfer-encoded body incrementally from a stream.
///
/// Returns the decoded body, any trailer headers (parsed), and raw trailer bytes.
/// Applies rate limiting after each decoded chunk.
async fn read_chunked_body_streaming<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    limiter: &mut RateLimiter,
) -> Result<(Vec<u8>, HashMap<String, String>, Vec<u8>), Error>
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
                // Connection closed before seeing the terminal 0-chunk.
                // This is a premature close — return partial body error.
                return Err(Error::PartialBody {
                    message: "transfer closed with outstanding read data remaining".to_string(),
                    partial_body: decoded,
                });
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        let (line_end, eol_len) = find_line_ending(&buf, pos)
            .ok_or_else(|| Error::Http("incomplete chunked encoding".into()))?;

        let size_str =
            std::str::from_utf8(&buf[pos..line_end]).map_err(|_| Error::PartialBody {
                message: "invalid chunk size encoding".into(),
                partial_body: decoded.clone(),
            })?;
        let size_str = size_str.split(';').next().unwrap_or(size_str).trim();
        let chunk_size = usize::from_str_radix(size_str, 16).map_err(|e| Error::PartialBody {
            message: format!("invalid chunk size '{size_str}': {e}"),
            partial_body: decoded.clone(),
        })?;

        pos = line_end + eol_len;

        if chunk_size == 0 {
            // Read trailers + final CRLF after last chunk
            // Trailers end with an empty line (\r\n\r\n) or just \r\n if none
            let mut trailers = HashMap::new();
            let mut raw_trailers = Vec::new();
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
                        return Ok((decoded, trailers, raw_trailers));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let Some((line_end, trailer_eol_len)) = find_line_ending(&buf, pos) else {
                    break;
                };
                if line_end == pos {
                    // Empty line — end of trailers
                    break;
                }
                // Capture raw trailer bytes (including line ending)
                raw_trailers.extend_from_slice(&buf[pos..line_end + trailer_eol_len]);
                // Parse trailer header
                if let Ok(line) = std::str::from_utf8(&buf[pos..line_end]) {
                    if let Some((name, value)) = line.split_once(':') {
                        let _ =
                            trailers.insert(name.trim().to_lowercase(), value.trim().to_string());
                    }
                }
                pos = line_end + trailer_eol_len;
            }
            return Ok((decoded, trailers, raw_trailers));
        }

        // Ensure we have the full chunk data + trailing line ending (\r\n or \n)
        // We need at least chunk_size + 1 bytes (for bare \n) to safely check
        let needed_min = pos + chunk_size + 1;
        while buf.len() < needed_min {
            let mut tmp = [0u8; 4096];
            let n = match stream.read(&mut tmp).await {
                Ok(n) => n,
                Err(e) if is_close_notify_error(&e) => 0,
                Err(e) => return Err(Error::Http(format!("chunk data read failed: {e}"))),
            };
            if n == 0 {
                // Partial chunk — take what we have and signal error
                let available = buf.len().saturating_sub(pos).min(chunk_size);
                decoded.extend_from_slice(&buf[pos..pos + available]);
                return Err(Error::PartialBody {
                    message: "transfer closed with outstanding read data remaining".to_string(),
                    partial_body: decoded,
                });
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        decoded.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size;
        // Skip trailing line ending after chunk data (\r\n or bare \n)
        if pos < buf.len() && buf[pos] == b'\r' {
            pos += 1;
        }
        if pos < buf.len() && buf[pos] == b'\n' {
            pos += 1;
        }

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
/// Find the position of a line ending (\r\n or bare \n) starting from `offset`.
///
/// Returns the position of the start of the line ending and the length of the
/// line ending (2 for CRLF, 1 for bare LF). Returns `None` if no line ending
/// is found.
fn find_line_ending(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if data.len() <= offset {
        return None;
    }
    // Find the first \n (whether preceded by \r or not)
    let p = data[offset..].iter().position(|&b| b == b'\n')?;
    // Check if it's \r\n (CRLF) or bare \n (LF)
    if p > 0 && data[offset + p - 1] == b'\r' {
        Some((offset + p - 1, 2))
    } else {
        Some((offset + p, 1))
    }
}

/// Find the position of a CRLF or bare LF starting from `offset`.
///
/// Wrapper for backward compatibility. Returns the position of the line ending start.
fn find_crlf(data: &[u8], offset: usize) -> Option<usize> {
    find_line_ending(data, offset).map(|(pos, _)| pos)
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
            // httparse rejects unknown HTTP versions (e.g. HTTP/1.2).
            // curl returns CURLE_UNSUPPORTED_PROTOCOL (1) for these.
            // Only treat as version error if the response actually started with "HTTP/".
            if e.to_string().contains("invalid HTTP version") && data.starts_with(b"HTTP/") {
                return Err(Error::UnsupportedProtocol(
                    "unsupported HTTP version in response".to_string(),
                ));
            }
            return Err(Error::Http(format!("Weird server reply: {e}")));
        }
    };

    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Http(format!(
            "response headers too large: {header_len} bytes (max {MAX_HEADER_SIZE})"
        )));
    }

    let status =
        parsed.code.ok_or_else(|| Error::Http("response has no status code".to_string()))?;

    let raw_values = extract_raw_header_values(&data[..header_len]);

    let mut headers = HashMap::with_capacity(parsed.headers.len());
    let mut original_names = HashMap::with_capacity(parsed.headers.len());
    let mut headers_ordered = Vec::with_capacity(parsed.headers.len());
    for (idx, header) in parsed.headers.iter().enumerate() {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();
        let raw_value = raw_values.get(idx).cloned().unwrap_or_else(|| value.clone());
        headers_ordered.push((header.name.to_string(), raw_value));
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
    let uses_crlf = data.windows(2).any(|w| w == b"\r\n");

    if is_head {
        let mut resp = Response::new(status, headers, Vec::new(), effective_url.to_string());
        resp.set_header_original_names(original_names);
        resp.set_headers_ordered(headers_ordered);
        resp.set_uses_crlf(uses_crlf);
        resp.set_http_version(version);
        return Ok(resp);
    }

    let body_data = &data[header_len..];

    let is_chunked = headers.get("transfer-encoding").is_some_and(|te| te_contains_chunked(te));

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
    resp.set_headers_ordered(headers_ordered);
    resp.set_uses_crlf(uses_crlf);
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            // HTTP/1.0 defaults to close, so no explicit Connection: close needed (curl compat)
            assert!(
                !req.contains("Connection: close"),
                "HTTP/1.0 should not send redundant Connection: close"
            );

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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
            false,
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
            true,
            None,
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
            true,
            None,
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
            true,
            None,
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
                true,
                None,
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
                true,
                None,
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

            // For POST with body and no custom Content-Type, h1.rs auto-adds
            // Content-Type after Content-Length (matching curl -d behavior):
            // Host, User-Agent, Accept, Content-Length, Content-Type
            let host_pos = req.find("Host:").unwrap();
            let ua_pos = req.find("User-Agent:").unwrap();
            let accept_pos = req.find("Accept:").unwrap();
            let ct_pos = req.find("Content-Type:").unwrap();
            let cl_pos = req.find("Content-Length:").unwrap();
            assert!(host_pos < ua_pos, "Host < User-Agent");
            assert!(ua_pos < accept_pos, "User-Agent < Accept");
            assert!(accept_pos < cl_pos, "Accept < Content-Length");
            assert!(cl_pos < ct_pos, "Content-Length < auto Content-Type");

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // No custom Content-Type — let h1.rs auto-add it for POST
        let headers = vec![];

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
            true,
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        server_task.await.unwrap();
    }
}
