//! Response formatting and output utilities.
//!
//! Contains functions for formatting HTTP responses, writing trace files,
//! and expanding `--write-out` variable templates.

use std::io::Write;
use std::process::ExitCode;

/// Format response headers as HTTP status line + headers.
///
/// Preserves original header ordering, casing, and duplicates from the server.
/// Uses the server's original reason phrase when available.
pub fn format_headers(response: &liburlx::Response) -> String {
    // If raw header bytes are available, use them directly to preserve
    // exact wire format (line endings, whitespace, header name casing).
    // The raw bytes include the trailing blank line separator (\r\n\r\n or \n\n).
    if let Some(raw) = response.raw_headers() {
        return String::from_utf8_lossy(raw).into_owned();
    }

    // Fallback: reconstruct from parsed data
    let version = http_version_string(response);
    let version_label = match version.as_str() {
        "2" => "2".to_string(),
        "3" => "3".to_string(),
        v => v.to_string(),
    };
    let eol = if response.uses_crlf() { "\r\n" } else { "\n" };
    let reason = response.status_reason().unwrap_or_else(|| http_status_text(response.status()));
    let mut result = if reason.is_empty() {
        format!("HTTP/{version_label} {}{eol}", response.status())
    } else {
        format!("HTTP/{version_label} {} {reason}{eol}", response.status())
    };

    let ordered = response.headers_ordered();
    if ordered.is_empty() {
        let original_names = response.header_original_names();
        for (name, value) in response.headers() {
            let display_name = original_names.get(name).map_or(name.as_str(), String::as_str);
            result.push_str(display_name);
            result.push_str(": ");
            result.push_str(value);
            result.push_str(eol);
        }
    } else {
        for (name, raw_value) in ordered {
            result.push_str(name);
            if !raw_value.starts_with(':') {
                result.push_str(": ");
            }
            result.push_str(raw_value);
            result.push_str(eol);
        }
    }
    result.push_str(eol);
    result
}

/// Write trace output to a file.
///
/// `--trace` writes hex + ASCII dump; `--trace-ascii` writes plain text.
/// If `trace_time` is true, each section is prefixed with a timestamp.
pub fn write_trace_file(
    path: &str,
    response: &liburlx::Response,
    url: &str,
    method: &str,
    request_headers: &[(String, String)],
    is_hex: bool,
    trace_time: bool,
) {
    use std::fmt::Write as _;

    let mut out = String::new();

    // Timestamp prefix helper
    let time_prefix = || -> String {
        if trace_time {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}.{:06} ", now.as_secs(), now.subsec_micros())
        } else {
            String::new()
        }
    };

    // Reconstruct approximate request headers
    let request_line = format!("{method} {url} HTTP/1.1\r\n");
    let mut req_text = request_line;
    for (name, value) in request_headers {
        req_text.push_str(name);
        req_text.push_str(": ");
        req_text.push_str(value);
        req_text.push_str("\r\n");
    }
    req_text.push_str("\r\n");

    // Write request headers section
    let _ = writeln!(out, "{}== Info: Request to {url}", time_prefix());
    let _ = writeln!(out, "{}=> Send header, {} bytes", time_prefix(), req_text.len());
    if is_hex {
        hex_dump(&mut out, req_text.as_bytes(), &time_prefix);
    } else {
        for line in req_text.lines() {
            let _ = writeln!(out, "{}=> {line}", time_prefix());
        }
    }

    // Write response headers section
    let resp_headers = format_headers(response);
    let _ = writeln!(out, "{}<= Recv header, {} bytes", time_prefix(), resp_headers.len());
    if is_hex {
        hex_dump(&mut out, resp_headers.as_bytes(), &time_prefix);
    } else {
        for line in resp_headers.lines() {
            let _ = writeln!(out, "{}<= {line}", time_prefix());
        }
    }

    // Write response body section
    let body = response.body();
    if !body.is_empty() {
        let _ = writeln!(out, "{}<= Recv data, {} bytes", time_prefix(), body.len());
        if is_hex {
            hex_dump(&mut out, body, &time_prefix);
        } else {
            let text = String::from_utf8_lossy(body);
            for line in text.lines() {
                let _ = writeln!(out, "{}{line}", time_prefix());
            }
        }
    }

    if let Err(e) = std::fs::write(path, out) {
        eprintln!("curl: error writing trace file '{path}': {e}");
    }
}

/// Write a hex dump of data, 16 bytes per line.
pub fn hex_dump(out: &mut String, data: &[u8], time_prefix: &dyn Fn() -> String) {
    use std::fmt::Write;

    for (offset, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{}{:04x}: ", time_prefix(), offset * 16);

        // Hex bytes
        for (i, &byte) in chunk.iter().enumerate() {
            let _ = write!(out, "{byte:02x} ");
            if i == 7 {
                out.push(' ');
            }
        }

        // Padding for incomplete lines
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }

        // ASCII representation
        out.push(' ');
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                out.push(byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
}

/// Get a human-readable HTTP status text.
pub const fn http_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Supports both `filename="quoted"` and `filename=unquoted` forms.
/// Returns `None` if the header is absent or doesn't contain a filename.
pub fn content_disposition_filename(response: &liburlx::Response) -> Option<String> {
    let header = response.header("content-disposition")?;
    // Look for filename= parameter
    let filename_start = header.find("filename=")?;
    let after = &header[filename_start + 9..];
    if let Some(quoted) = after.strip_prefix('"') {
        // Quoted filename: extract until closing quote
        let end = quoted.find('"')?;
        Some(quoted[..end].to_string())
    } else {
        // Unquoted: take until semicolon or end
        let end = after.find(';').unwrap_or(after.len());
        let name = after[..end].trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }
}

/// Parse a rate limit string like "100K", "1M", "500" into bytes per second.
///
/// Supports suffixes: K/k (1024), M/m (1024*1024), G/g (1024^3).
/// Output a single response to stdout or file.
pub fn output_response(
    response: &liburlx::Response,
    output_file: Option<&str>,
    write_out: Option<&str>,
    include_headers: bool,
    silent: bool,
    suppress_body: bool,
) -> ExitCode {
    // Build all header text including redirect chain (for -L --include)
    let all_headers = if include_headers {
        let mut h = String::new();
        for redir in response.redirect_responses() {
            h.push_str(&format_headers(redir));
        }
        h.push_str(&format_headers(response));
        Some(h)
    } else {
        None
    };

    let body = if suppress_body { &[] as &[u8] } else { response.body() };

    // "-" means stdout (curl compat)
    let effective_output = output_file.filter(|p| *p != "-");

    if let Some(path) = effective_output {
        // When --output is set, everything (headers if --include, then body) goes to the file
        let mut data = Vec::new();
        if let Some(ref headers) = all_headers {
            data.extend_from_slice(headers.as_bytes());
        }
        data.extend_from_slice(body);
        if let Err(e) = std::fs::write(path, &data) {
            if !silent {
                eprintln!("curl: error writing to {path}: {e}");
            }
            return ExitCode::FAILURE;
        }
    } else {
        // No --output: write to stdout
        if let Some(ref headers) = all_headers {
            if let Err(e) = std::io::stdout().write_all(headers.as_bytes()) {
                if !silent {
                    eprintln!("curl: write error: {e}");
                }
                return ExitCode::FAILURE;
            }
        }
        if let Err(e) = std::io::stdout().write_all(body) {
            if !silent {
                eprintln!("curl: write error: {e}");
            }
            return ExitCode::FAILURE;
        }
    }

    if let Some(fmt) = write_out {
        let output = format_write_out(fmt, response);
        print!("{output}");
    }

    ExitCode::SUCCESS
}

/// Return the HTTP version string for a response (e.g., "1.1", "2", "3").
pub fn http_version_string(response: &liburlx::Response) -> String {
    response.http_version().to_string()
}

/// Format a `--write-out` string by replacing `%{variable}` placeholders.
#[allow(clippy::too_many_lines)]
pub fn format_write_out(fmt: &str, response: &liburlx::Response) -> String {
    let info = response.transfer_info();
    let mut result = fmt.to_string();

    // Replace known variables
    result = result.replace("%{http_code}", &response.status().to_string());
    result = result.replace("%{response_code}", &response.status().to_string());
    result = result.replace("%{url_effective}", response.effective_url());
    result = result.replace("%{content_type}", response.content_type().unwrap_or(""));
    result = result.replace("%{size_download}", &response.size_download().to_string());
    result =
        result.replace("%{time_namelookup}", &format!("{:.6}", info.time_namelookup.as_secs_f64()));
    result = result.replace("%{time_connect}", &format!("{:.6}", info.time_connect.as_secs_f64()));
    result =
        result.replace("%{time_appconnect}", &format!("{:.6}", info.time_appconnect.as_secs_f64()));
    result = result
        .replace("%{time_pretransfer}", &format!("{:.6}", info.time_pretransfer.as_secs_f64()));
    result = result
        .replace("%{time_starttransfer}", &format!("{:.6}", info.time_starttransfer.as_secs_f64()));
    result = result.replace("%{time_total}", &format!("{:.6}", info.time_total.as_secs_f64()));
    result = result.replace("%{num_redirects}", &info.num_redirects.to_string());
    result = result.replace("%{speed_download}", &format!("{:.3}", info.speed_download));
    result = result.replace("%{speed_upload}", &format!("{:.3}", info.speed_upload));
    result = result.replace("%{size_upload}", &info.size_upload.to_string());
    // Additional curl-compatible variables
    result = result.replace("%{http_version}", &http_version_string(response));
    let eff_scheme = response.effective_url().split("://").next().unwrap_or("");
    result = result.replace("%{scheme}", eff_scheme);
    // URL component variables (url.* and urle.* families)
    // Parse effective URL to extract components
    {
        let eff_url = response.effective_url();
        let (u_scheme, u_user, u_pass, u_host, u_port, u_path, u_query, u_fragment) =
            parse_url_components(eff_url);
        #[allow(clippy::literal_string_with_formatting_args)]
        {
            result = result.replace("%{url.scheme}", &u_scheme);
            result = result.replace("%{url.host}", &u_host);
            result = result.replace("%{url.port}", &u_port);
            result = result.replace("%{url.path}", &u_path);
            result = result.replace("%{url.query}", &u_query);
            result = result.replace("%{url.user}", &u_user);
            result = result.replace("%{url.password}", &u_pass);
            result = result.replace("%{url.fragment}", &u_fragment);
            result = result.replace("%{urle.scheme}", &u_scheme);
            result = result.replace("%{urle.host}", &u_host);
            result = result.replace("%{urle.port}", &u_port);
            result = result.replace("%{urle.path}", &u_path);
            result = result.replace("%{urle.query}", &u_query);
            result = result.replace("%{urle.user}", &u_user);
            result = result.replace("%{urle.password}", &u_pass);
            result = result.replace("%{urle.fragment}", &u_fragment);
        }
    }
    // Header sizes: approximate from response headers
    let header_size: usize = response.headers().iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    result = result.replace("%{size_header}", &header_size.to_string());
    // num_connects: 1 for the initial request, +1 for each redirect that required
    // a new connection (Connection: close or different host).
    let num_connects = {
        let mut count: u32 = 1;
        for redir_resp in response.redirect_responses() {
            let has_close =
                redir_resp.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
            if has_close {
                count += 1;
            }
        }
        count
    };
    #[allow(clippy::literal_string_with_formatting_args)]
    {
        result = result.replace("%{num_connects}", &num_connects.to_string());
    }
    result = result
        .replace("%{time_redirect}", &format!("{:.6}", info.time_namelookup.as_secs_f64() * 0.0));
    // redirect_url: curl normalizes the Location URL (adds trailing slash for bare hostnames)
    let redirect_url = response.header("location").unwrap_or("").to_string();
    let redirect_url_normalized = if redirect_url.is_empty() {
        redirect_url
    } else {
        // Normalize: bare hostname URLs need trailing slash (e.g. https://host -> https://host/)
        if redirect_url.contains("://")
            && !redirect_url.ends_with('/')
            && redirect_url.matches('/').count() == 2
        {
            format!("{redirect_url}/")
        } else {
            redirect_url
        }
    };
    #[allow(clippy::literal_string_with_formatting_args)]
    {
        result = result.replace("%{redirect_url}", &redirect_url_normalized);
    }
    let method = if info.effective_method.is_empty() { "GET" } else { &info.effective_method };
    result = result.replace("%{method}", method);
    result = result.replace("%{errormsg}", "");
    result = result.replace("%{exitcode}", "0");
    result = result.replace("%{num_retries}", &info.num_retries.to_string());
    // Connection info: use parsed URL components
    let (_, _, _, rip_host, rip_port, _, _, _) = parse_url_components(response.effective_url());
    let url_host = rip_host.as_str();
    let url_port: u16 = rip_port.parse().unwrap_or(0);
    // Resolve hostname to IP for %{remote_ip}
    let resolved_ip = std::net::ToSocketAddrs::to_socket_addrs(&(url_host, url_port))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map_or_else(|| url_host.to_string(), |addr| addr.ip().to_string());
    #[allow(clippy::literal_string_with_formatting_args)]
    {
        result = result.replace("%{remote_ip}", &resolved_ip);
        result = result.replace("%{remote_port}", &url_port.to_string());
        result = result.replace("%{local_ip}", "");
        result = result.replace("%{local_port}", "0");
    }

    // Handle escape sequences
    result = result.replace("\\n", "\n");
    result = result.replace("\\t", "\t");
    result = result.replace("\\r", "\r");

    result
}

/// Parse a URL string into its components.
/// Returns (scheme, user, password, host, port, path, query, fragment).
fn parse_url_components(
    url: &str,
) -> (String, String, String, String, String, String, String, String) {
    let scheme = url.split("://").next().unwrap_or("").to_string();
    let rest = url.find("://").map_or("", |p| &url[p + 3..]);

    // Split fragment
    let (rest, fragment) = rest.split_once('#').map_or((rest, ""), |(r, f)| (r, f));

    // Split query
    let (rest, query) = rest.split_once('?').map_or((rest, ""), |(r, q)| (r, q));

    // Split path from authority
    let (authority, path) = rest.find('/').map_or((rest, "/"), |p| (&rest[..p], &rest[p..]));

    // Split userinfo from host
    let (userinfo, hostport) = authority.split_once('@').map_or(("", authority), |(u, h)| (u, h));

    // Split user:password
    let (user, pass) = userinfo.split_once(':').map_or((userinfo, ""), |(u, p)| (u, p));

    // Split host:port
    let (host, port) = if hostport.starts_with('[') {
        // IPv6
        hostport.find(']').map_or((hostport, ""), |bracket| {
            let h = &hostport[..=bracket];
            let p = hostport.get(bracket + 2..).unwrap_or("");
            (h, p)
        })
    } else {
        hostport.rsplit_once(':').map_or((hostport, ""), |(h, p)| {
            if p.parse::<u16>().is_ok() {
                (h, p)
            } else {
                (hostport, "")
            }
        })
    };

    // Default port from scheme
    let port_str = if port.is_empty() {
        match scheme.as_str() {
            "http" => "80",
            "https" => "443",
            "ftp" => "21",
            "ftps" => "990",
            _ => "0",
        }
        .to_string()
    } else {
        port.to_string()
    };

    (
        scheme,
        user.to_string(),
        pass.to_string(),
        host.to_string(),
        port_str,
        path.to_string(),
        query.to_string(),
        fragment.to_string(),
    )
}
