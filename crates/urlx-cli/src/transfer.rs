//! Transfer execution, retry logic, and error mapping.
//!
//! Contains the main [`run`] function that orchestrates URL transfers,
//! retry logic, and curl-compatible exit code mapping.

use std::io::Write;
use std::process::ExitCode;

use crate::args::{is_protocol_allowed, parse_args, percent_encode, print_usage, CliOptions};
use crate::output::{
    content_disposition_filename, format_headers, format_write_out, http_status_text,
    output_response, write_trace_file,
};

/// Takes the last path segment. Falls back to `"index.html"` if no filename.
pub fn remote_name_from_url(url: &str) -> String {
    // Strip scheme (e.g., "http://")
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);

    // Strip query string and fragment
    let without_query = without_scheme
        .split('?')
        .next()
        .unwrap_or(without_scheme)
        .split('#')
        .next()
        .unwrap_or(without_scheme);

    // Find the path part (after the first '/')
    if let Some(slash_pos) = without_query.find('/') {
        let path = &without_query[slash_pos..];
        if let Some(name) = path.rsplit('/').next() {
            if name.is_empty() {
                return "index.html".to_string();
            }
            return name.to_string();
        }
    }

    "index.html".to_string()
}

/// Set a file's modification time from an HTTP `Last-Modified` header value.
///
/// Parses the RFC 7231 date format (e.g., "Tue, 15 Nov 1994 08:12:31 GMT")
/// and sets the file's modification time accordingly. Best-effort: errors
/// are silently ignored unless not in silent mode.
pub fn set_file_mtime(path: &str, last_modified: &str, silent: bool) {
    if let Some(timestamp) = parse_http_date(last_modified) {
        let mtime = filetime::FileTime::from_unix_time(timestamp, 0);
        if let Err(e) = filetime::set_file_mtime(path, mtime) {
            if !silent {
                eprintln!("urlx: warning: could not set file time: {e}");
            }
        }
    }
}

/// Parse an HTTP date string into a Unix timestamp (seconds since epoch).
///
/// Supports RFC 7231 preferred format: `"Sun, 06 Nov 1994 08:49:37 GMT"`.
/// Returns `None` if parsing fails.
pub fn parse_http_date(s: &str) -> Option<i64> {
    // RFC 7231: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }

    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1_u32,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: i64 = time_parts[0].parse().ok()?;
    let minute: i64 = time_parts[1].parse().ok()?;
    let second: i64 = time_parts[2].parse().ok()?;

    // Convert to Unix timestamp using a simplified calculation
    // Days from epoch (1970-01-01) to the given date
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += i64::from(month_days[m as usize]);
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += i64::from(day) - 1;

    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Check if a year is a leap year.
pub const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Extract hostname from a URL string.
///
/// Handles `scheme://host:port/path` format. Returns the host part only.
pub fn extract_hostname(url: &str) -> String {
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    let without_userinfo =
        without_path.rfind('@').map_or(without_path, |pos| &without_path[pos + 1..]);
    // Strip port
    without_userinfo.rsplit_once(':').map_or(without_userinfo, |(host, _)| host).to_string()
}

/// Append query parameters to a URL string.
///
/// Each query string is appended with `&` if the URL already has a `?`,
/// or with `?` if it doesn't. Values containing `=` are used as-is;
/// plain values are URL-encoded.
pub fn append_url_queries(url: &str, queries: &[String]) -> String {
    let mut result = url.to_string();
    for query in queries {
        let separator = if result.contains('?') { '&' } else { '?' };
        result.push(separator);
        if query.contains('=') {
            // name=value format: encode only the value
            if let Some((name, value)) = query.split_once('=') {
                result.push_str(name);
                result.push('=');
                result.push_str(&percent_encode(value));
            }
        } else {
            // Plain string: use as-is (already encoded or literal)
            result.push_str(query);
        }
    }
    result
}

/// Extract filename from a `Content-Disposition` response header.
///
/// Supports both `filename="quoted"` and `filename=unquoted` forms.
/// Generate equivalent C code using libcurl for `--libcurl` output.
pub fn generate_libcurl_code(opts: &CliOptions) -> String {
    let url = opts.urls.first().map_or("", String::as_str);
    let mut code = String::new();
    code.push_str("/*** Code generated by urlx --libcurl ***/\n");
    code.push_str("#include <curl/curl.h>\n\n");
    code.push_str("int main(void) {\n");
    code.push_str("    CURL *curl;\n");
    code.push_str("    CURLcode res;\n\n");
    code.push_str("    curl = curl_easy_init();\n");
    code.push_str("    if (curl) {\n");
    code.push_str("        curl_easy_setopt(curl, CURLOPT_URL, \"");
    code.push_str(url);
    code.push_str("\");\n");
    if opts.include_headers {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);\n");
    }
    if opts.silent {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);\n");
    }
    if opts.fail_on_error {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);\n");
    }
    code.push_str("        res = curl_easy_perform(curl);\n");
    code.push_str("        curl_easy_cleanup(curl);\n");
    code.push_str("    }\n");
    code.push_str("    return (int)res;\n");
    code.push_str("}\n");
    code
}

#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        print_usage();
        return ExitCode::FAILURE;
    }

    let Some(mut opts) = parse_args(args) else {
        return ExitCode::FAILURE;
    };

    // Expand URL globs unless --globoff is set
    if !opts.globoff {
        let mut expanded = Vec::new();
        for url in &opts.urls {
            match liburlx::glob::expand_glob(url) {
                Ok(urls) => expanded.extend(urls),
                Err(e) => {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: glob error: {e}");
                    }
                    return ExitCode::FAILURE;
                }
            }
        }
        opts.urls = expanded;
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if opts.urls.len() > 1 {
        return run_multi(
            &opts.easy,
            &opts.urls,
            opts.output_file.as_deref(),
            opts.write_out.as_deref(),
            opts.silent,
            opts.show_error,
            opts.fail_on_error,
            opts.parallel,
            opts.parallel_max,
        );
    }

    // Single URL: use Easy API
    if let Some(url) = opts.urls.first() {
        // --url-query: append query parameters to URL
        let url = if opts.url_queries.is_empty() {
            url.clone()
        } else {
            append_url_queries(url, &opts.url_queries)
        };

        // --proto-default: add default scheme if URL has none
        let url = if let Some(ref default_proto) = opts.proto_default {
            if url.contains("://") {
                url
            } else {
                format!("{default_proto}://{url}")
            }
        } else {
            url
        };

        // --proto: validate URL scheme against allowed protocols
        if let Some(ref proto_list) = opts.proto {
            if !is_protocol_allowed(&url, proto_list) {
                if !opts.silent || opts.show_error {
                    eprintln!("urlx: protocol not allowed by --proto");
                }
                return ExitCode::FAILURE;
            }
        }

        if let Err(e) = opts.easy.url(&url) {
            if !opts.silent || opts.show_error {
                eprintln!("urlx: error parsing URL: {e}");
            }
            return ExitCode::FAILURE;
        }

        // --netrc: load credentials from .netrc file for this URL
        if opts.user_credentials.is_none() {
            if let Some(ref netrc_path) = opts.netrc_file {
                match std::fs::read_to_string(netrc_path) {
                    Ok(contents) => {
                        let host = extract_hostname(&url);
                        if let Some(entry) = liburlx::netrc::lookup(&contents, &host) {
                            let user = entry.login.unwrap_or_default();
                            let pass = entry.password.unwrap_or_default();
                            if opts.use_digest {
                                opts.easy.digest_auth(&user, &pass);
                            } else {
                                opts.easy.basic_auth(&user, &pass);
                            }
                        }
                    }
                    Err(e) => {
                        if !opts.netrc_optional {
                            if !opts.silent || opts.show_error {
                                eprintln!("urlx: can't read netrc file '{netrc_path}': {e}");
                            }
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
        }

        // -O/--remote-name: derive output filename from URL
        if opts.remote_name && opts.output_file.is_none() {
            opts.output_file = Some(remote_name_from_url(&url));
        }
    }

    // --create-dirs: create parent directories for output file
    if opts.create_dirs {
        if let Some(ref path) = opts.output_file {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        if !opts.silent || opts.show_error {
                            eprintln!("urlx: error creating directories: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }

    if opts.show_progress && !opts.silent {
        opts.easy.progress_callback(liburlx::make_progress_callback(|info| {
            let pct = if info.dl_total > 0 { (info.dl_now * 100) / info.dl_total } else { 0 };
            let bar_width: usize = 40;
            #[allow(clippy::cast_possible_truncation)]
            let filled = ((pct as usize) * bar_width) / 100;
            let empty = bar_width.saturating_sub(filled);
            eprint!(
                "\r[{}{}] {}% ({} bytes)",
                "#".repeat(filled),
                " ".repeat(empty),
                pct,
                info.dl_now,
            );
            true
        }));
    }

    let result = perform_with_retry(&mut opts);

    // Save cookie jar after transfer (even on error)
    if opts.cookie_jar_file.is_some() {
        if let Err(e) = opts.easy.save_cookie_jar() {
            if !opts.silent || opts.show_error {
                eprintln!("urlx: error saving cookies: {e}");
            }
        }
    }

    match result {
        Ok(response) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }

            // --etag-save: save ETag from response header
            if let Some(ref path) = opts.etag_save_file {
                if let Some(etag) = response.header("etag") {
                    if let Err(e) = std::fs::write(path, etag) {
                        if !opts.silent || opts.show_error {
                            eprintln!("urlx: error saving ETag to '{path}': {e}");
                        }
                    }
                }
            }

            // --fail: exit 22 on HTTP error status codes
            if opts.fail_on_error && response.status() >= 400 {
                if !opts.silent || opts.show_error {
                    eprintln!(
                        "urlx: The requested URL returned error: {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    );
                }
                return ExitCode::from(22);
            }

            // --max-filesize: check response body size
            if let Some(max_size) = opts.max_filesize {
                if response.body().len() as u64 > max_size {
                    if !opts.silent || opts.show_error {
                        eprintln!(
                            "urlx: maximum file size exceeded ({} > {max_size} bytes)",
                            response.body().len(),
                        );
                    }
                    return ExitCode::from(63);
                }
            }

            // -J/--remote-header-name: override output filename from Content-Disposition
            if opts.remote_header_name {
                if let Some(name) = content_disposition_filename(&response) {
                    opts.output_file = Some(name);
                }
            }

            // --dump-header: write headers to file
            if let Some(ref path) = opts.dump_header {
                let header_text = format_headers(&response);
                if let Err(e) = std::fs::write(path, header_text) {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: error writing headers to {path}: {e}");
                    }
                    return ExitCode::FAILURE;
                }
            }

            // --trace / --trace-ascii: write trace to file
            if opts.trace_file.is_some() || opts.trace_ascii_file.is_some() {
                let url_str = opts.urls.first().map_or("", String::as_str);
                let method = opts.easy.method_str().unwrap_or("GET");
                let request_headers = opts.easy.header_list();

                if let Some(ref path) = opts.trace_file {
                    write_trace_file(
                        path,
                        &response,
                        url_str,
                        method,
                        request_headers,
                        true,
                        opts.trace_time,
                    );
                }
                if let Some(ref path) = opts.trace_ascii_file {
                    write_trace_file(
                        path,
                        &response,
                        url_str,
                        method,
                        request_headers,
                        false,
                        opts.trace_time,
                    );
                }
            }

            // --libcurl: output equivalent C code
            if opts.libcurl {
                let c_code = generate_libcurl_code(&opts);
                eprintln!("{c_code}");
            }

            let exit = output_response(
                &response,
                opts.output_file.as_deref(),
                opts.write_out.as_deref(),
                opts.include_headers,
                opts.silent,
            );

            // --remote-time: set output file's modification time from Last-Modified
            if opts.remote_time {
                if let Some(ref path) = opts.output_file {
                    if let Some(last_modified) = response.header("last-modified") {
                        set_file_mtime(path, last_modified, opts.silent);
                    }
                }
            }

            exit
        }
        Err(e) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }
            if !opts.silent || opts.show_error {
                eprintln!("urlx: {e}");
            }
            error_to_exit_code(&e)
        }
    }
}

/// Map a liburlx error to a curl-compatible exit code.
///
/// Matches curl's exit code conventions for the most common errors.
pub fn error_to_exit_code(err: &liburlx::Error) -> ExitCode {
    match err {
        liburlx::Error::UrlParse(_) => ExitCode::from(3),
        liburlx::Error::Connect(io_err) => {
            match io_err.kind() {
                // DNS resolution failure
                std::io::ErrorKind::Other => {
                    let msg = io_err.to_string();
                    if msg.contains("dns") || msg.contains("DNS") || msg.contains("resolve") {
                        ExitCode::from(6) // CURLE_COULDNT_RESOLVE_HOST
                    } else {
                        ExitCode::from(7) // CURLE_COULDNT_CONNECT
                    }
                }
                _ => ExitCode::from(7), // CURLE_COULDNT_CONNECT
            }
        }
        liburlx::Error::Tls(e) => {
            let msg = e.to_string();
            if msg.contains("certificate") || msg.contains("verify") {
                ExitCode::from(60) // CURLE_PEER_FAILED_VERIFICATION
            } else {
                ExitCode::from(35) // CURLE_SSL_CONNECT_ERROR
            }
        }
        liburlx::Error::Http(msg) => {
            if msg.contains("too many redirects") || msg.contains("Too many redirects") {
                ExitCode::from(47) // CURLE_TOO_MANY_REDIRECTS
            } else if msg.contains("fail_on_error") {
                ExitCode::from(22) // CURLE_HTTP_RETURNED_ERROR
            } else {
                ExitCode::from(56) // CURLE_RECV_ERROR
            }
        }
        liburlx::Error::Timeout(_) | liburlx::Error::SpeedLimit { .. } => {
            ExitCode::from(28) // CURLE_OPERATION_TIMEDOUT
        }
        liburlx::Error::Io(_) => ExitCode::from(23), // CURLE_WRITE_ERROR
        liburlx::Error::Ssh(_) => ExitCode::from(67), // CURLE_LOGIN_DENIED
        liburlx::Error::Transfer { code, .. } => {
            ExitCode::from(u8::try_from(*code).map_or(1, |c| c))
        }
        _ => ExitCode::FAILURE,
    }
}

/// Perform a transfer with optional retry logic.
pub fn perform_with_retry(opts: &mut CliOptions) -> Result<liburlx::Response, liburlx::Error> {
    // --etag-compare: send If-None-Match header from saved ETag
    if let Some(ref path) = opts.etag_compare_file {
        if let Ok(etag) = std::fs::read_to_string(path) {
            let etag = etag.trim().to_string();
            if !etag.is_empty() {
                opts.easy.header("If-None-Match", &etag);
            }
        }
    }

    let max_retries = opts.retry_count;
    let delay = std::time::Duration::from_secs(opts.retry_delay_secs);
    let max_time = if opts.retry_max_time_secs > 0 {
        Some(std::time::Duration::from_secs(opts.retry_max_time_secs))
    } else {
        None
    };
    let start = std::time::Instant::now();

    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            // Check max time budget
            if let Some(max) = max_time {
                if start.elapsed() >= max {
                    break;
                }
            }
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            if !opts.silent {
                eprintln!(
                    "Warning: Transient problem: {} — retrying after {} seconds. Retry {} of {}.",
                    last_err.as_ref().map_or("unknown error", |_| "transfer error"),
                    delay.as_secs(),
                    attempt,
                    max_retries,
                );
            }
        }

        match opts.easy.perform() {
            Ok(response) => {
                // Retry on 408, 429, 500, 502, 503, 504 if retries remain
                if is_retryable_status(response.status()) && attempt < max_retries {
                    last_err = Some(liburlx::Error::Http(format!(
                        "HTTP {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    )));
                    continue;
                }
                return Ok(response);
            }
            Err(e) => {
                last_err = Some(e);
                if attempt == max_retries {
                    break;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| liburlx::Error::Http("retry exhausted".to_string())))
}

/// Check if an HTTP status code is retryable (transient error).
pub const fn is_retryable_status(code: u16) -> bool {
    matches!(code, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Run multiple URLs concurrently using the Multi API.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn run_multi(
    template: &liburlx::Easy,
    urls: &[String],
    _output_file: Option<&str>,
    write_out: Option<&str>,
    silent: bool,
    show_error: bool,
    fail_on_error: bool,
    parallel: bool,
    parallel_max: usize,
) -> ExitCode {
    let mut multi = liburlx::Multi::new();
    if parallel {
        multi.max_total_connections(parallel_max);
    }

    for url in urls {
        let mut easy = template.clone();
        if let Err(e) = easy.url(url) {
            if !silent || show_error {
                eprintln!("urlx: error parsing URL '{url}': {e}");
            }
            return ExitCode::FAILURE;
        }
        multi.add(easy);
    }

    let results = match multi.perform_blocking() {
        Ok(results) => results,
        Err(e) => {
            if !silent || show_error {
                eprintln!("urlx: {e}");
            }
            return ExitCode::FAILURE;
        }
    };
    let mut any_failed = false;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(response) => {
                if fail_on_error && response.status() >= 400 {
                    any_failed = true;
                    continue;
                }
                if let Err(e) = std::io::stdout().write_all(response.body()) {
                    if !silent || show_error {
                        eprintln!("urlx: write error: {e}");
                    }
                    any_failed = true;
                }
                if let Some(fmt) = write_out {
                    let output = format_write_out(fmt, &response);
                    print!("{output}");
                }
            }
            Err(e) => {
                if !silent || show_error {
                    eprintln!("urlx: transfer {} ({}): {e}", i + 1, urls[i]);
                }
                any_failed = true;
            }
        }
    }

    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
