//! Transfer execution, retry logic, and error mapping.
//!
//! Contains the main [`run`] function that orchestrates URL transfers,
//! retry logic, and curl-compatible exit code mapping.

use std::process::ExitCode;

use crate::args::{
    is_protocol_allowed, parse_args, percent_encode, print_usage, print_version, CliOptions,
    ParseResult,
};
use crate::output::{
    content_disposition_filename, format_headers, http_status_text, output_response,
    write_trace_file,
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

/// Parse a loose date string into a Unix timestamp.
///
/// Supports formats like `"dec 12 12:00:00 1999 GMT"`, `"12 Dec 1999 12:00:00"`,
/// and other common curl-compatible date formats.
pub fn parse_loose_date(s: &str) -> Option<i64> {
    let month_names =
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let mut month: Option<u32> = None;
    let mut day: Option<u32> = None;
    let mut year: Option<i64> = None;
    let mut hour: i64 = 0;
    let mut minute: i64 = 0;
    let mut second: i64 = 0;

    for part in &parts {
        let lower = part.to_lowercase();
        // Check for month name
        if let Some(pos) = month_names.iter().position(|&m| lower == m) {
            month = Some(u32::try_from(pos).unwrap_or(0) + 1);
        } else if part.contains(':') {
            // Time component HH:MM:SS
            let time_parts: Vec<&str> = part.split(':').collect();
            if time_parts.len() >= 2 {
                hour = time_parts[0].parse().unwrap_or(0);
                minute = time_parts[1].parse().unwrap_or(0);
                if time_parts.len() >= 3 {
                    second = time_parts[2].parse().unwrap_or(0);
                }
            }
        } else if lower == "gmt" || lower == "utc" {
            // Timezone — ignore (we assume GMT)
        } else if let Ok(num) = part.parse::<u32>() {
            if num > 31 {
                year = Some(i64::from(num));
            } else if day.is_none() {
                day = Some(num);
            }
        }
    }

    let month = month?;
    let day = day?;
    let year = year?;

    // Convert to Unix timestamp
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

/// Format a `SystemTime` as an HTTP date string (RFC 7231).
///
/// Returns a string like `"Sun, 06 Nov 1994 08:49:37 GMT"`.
pub fn format_http_date(time: std::time::SystemTime) -> String {
    let secs = time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    // Convert Unix timestamp to date components
    #[allow(clippy::cast_possible_wrap)]
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Day of week (1970-01-01 was Thursday = 4)
    #[allow(clippy::cast_sign_loss)]
    let dow = ((days + 4) % 7) as usize;
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // Convert days since epoch to year/month/day
    let month_days_normal = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let month_names =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    let mut remaining_days = days;
    let mut year: i64 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let mut month = 0usize;
    for (m, &days_in_month) in month_days_normal.iter().enumerate() {
        let dim = if m == 1 && is_leap_year(year) { 29 } else { days_in_month };
        if remaining_days < dim {
            month = m;
            break;
        }
        remaining_days -= dim;
    }
    let day = remaining_days + 1;

    format!(
        "{}, {:02} {} {year} {:02}:{:02}:{:02} GMT",
        day_names[dow], day, month_names[month], hour, minute, second,
    )
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

    let mut opts = match parse_args(args) {
        ParseResult::Options(opts) => *opts,
        ParseResult::Help => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        ParseResult::Version => {
            print_version();
            return ExitCode::SUCCESS;
        }
        ParseResult::Error => {
            return ExitCode::FAILURE;
        }
    };

    // Expand URL globs unless --globoff is set
    if !opts.globoff {
        let mut expanded = Vec::new();
        for url in &opts.urls {
            match liburlx::glob::expand_glob(url) {
                Ok(urls) => expanded.extend(urls),
                Err(e) => {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: {e}");
                    }
                    return ExitCode::from(3); // CURLE_URL_MALFORMAT
                }
            }
        }
        opts.urls = expanded;
    }

    // -G/--get: move POST body data into URL query string
    if opts.get_mode {
        if let Some(body_data) = opts.easy.take_body() {
            let query = String::from_utf8_lossy(&body_data);
            // Append data directly to each URL as query string
            for url in &mut opts.urls {
                let sep = if url.contains('?') { '&' } else { '?' };
                url.push(sep);
                url.push_str(&query);
            }
        }
        // Only default to GET if no explicit method was set (e.g. -I sets HEAD)
        if opts.easy.method_is_default() {
            opts.easy.method("GET");
        }
        // Remove auto-added Content-Type for form data
        opts.easy.remove_header("Content-Type");
        opts.easy.set_form_data(false);
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if opts.urls.len() > 1 {
        return run_multi(
            &opts.easy,
            &opts.urls,
            opts.output_file.as_deref(),
            opts.write_out.as_deref(),
            opts.include_headers,
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

        // -T filename: append filename to URL path if URL ends with /
        let url = if let Some(ref filename) = opts.upload_filename {
            if url.ends_with('/') {
                // Percent-encode special chars in the filename for the URL path
                let encoded: String = filename
                    .chars()
                    .map(|c| match c {
                        '[' => "%5b".to_string(),
                        ']' => "%5d".to_string(),
                        ' ' => "%20".to_string(),
                        _ => c.to_string(),
                    })
                    .collect();
                format!("{url}{encoded}")
            } else {
                url
            }
        } else {
            url
        };

        if let Err(e) = opts.easy.url(&url) {
            if !opts.silent || opts.show_error {
                eprintln!("urlx: error parsing URL: {e}");
            }
            return ExitCode::from(3); // CURLE_URL_MALFORMAT
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

    // -C - auto-resume: determine offset from existing output file size
    if opts.auto_resume {
        if let Some(ref path) = opts.output_file {
            if let Ok(meta) = std::fs::metadata(path) {
                let size = meta.len();
                if size > 0 {
                    opts.easy.resume_from(size);
                }
            }
            // If file doesn't exist, no resume offset (start from 0)
        }
    }

    // PUT with -C offset: use Content-Range header instead of Range, and slice the body
    if opts.is_upload {
        if let Some(offset) = opts.resume_offset {
            if offset > 0 {
                // For PUT uploads, curl sends Content-Range instead of Range
                if let Some(body_data) = opts.easy.take_body() {
                    let total = body_data.len() as u64;
                    let end = total.saturating_sub(1);
                    if offset <= end {
                        // Slice the body from offset onwards
                        #[allow(clippy::cast_possible_truncation)]
                        let start = offset as usize;
                        let sliced = &body_data[start..];
                        opts.easy.header("Content-Range", &format!("bytes {offset}-{end}/{total}"));
                        opts.easy.body(sliced);
                    } else {
                        // Offset beyond file size — send empty body
                        opts.easy.body(&[]);
                    }
                }
                // Clear the Range setting that resume_from() set (it's for GET, not PUT)
                opts.easy.clear_range();
            }
        }
    }

    // Stdin PUT: add chunked Transfer-Encoding and Expect: 100-continue (curl compat)
    if opts.is_stdin_upload {
        // Enable Expect: 100-continue via the timeout mechanism (h1.rs adds the header)
        opts.easy.expect_100_timeout(std::time::Duration::from_secs(1));
        // Enable chunked upload (unless user explicitly suppressed Transfer-Encoding)
        if !opts.easy.has_header("Transfer-Encoding") {
            opts.easy.set_chunked_upload(true);
        }
    }

    // -z/--time-cond: set If-Modified-Since or If-Unmodified-Since header
    if let Some(ref cond) = opts.time_cond {
        let (negate, date_str) =
            cond.strip_prefix('-').map_or((false, cond.as_str()), |stripped| (true, stripped));
        // Try to parse as a file path first (use file mtime), then as a date string
        let date_val = if std::path::Path::new(date_str).exists() {
            std::fs::metadata(date_str).ok().and_then(|m| m.modified().ok()).map(format_http_date)
        } else {
            // Try parsing as RFC 7231 first, then loose date format
            if parse_http_date(date_str).is_some() {
                Some(date_str.to_string())
            } else {
                parse_loose_date(date_str).and_then(|ts| {
                    u64::try_from(ts).ok().map(|secs| {
                        format_http_date(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs),
                        )
                    })
                })
            }
        };
        if let Some(date) = date_val {
            if negate {
                opts.easy.header("If-Unmodified-Since", &date);
            } else {
                opts.easy.header("If-Modified-Since", &date);
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

            // Check for failed resume: when -C was used and server returned non-206
            // (curl returns CURLE_RANGE_ERROR = 33)
            if opts.resume_check {
                let status = response.status();
                if status != 206 {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: server returned {status} but resume was requested");
                    }
                    return ExitCode::from(33); // CURLE_RANGE_ERROR
                }
            }

            // --fail / --fail-with-body: exit 22 on HTTP error status codes
            if opts.fail_on_error && response.status() >= 400 && !opts.fail_with_body {
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

            // --fail-with-body: output body first, then return error exit code
            if opts.fail_with_body && response.status() >= 400 {
                if !opts.silent || opts.show_error {
                    eprintln!(
                        "urlx: The requested URL returned error: {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    );
                }
                return ExitCode::from(22);
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
        liburlx::Error::UrlParse(_) => ExitCode::from(3), // CURLE_URL_MALFORMAT
        liburlx::Error::UnsupportedProtocol(_) => ExitCode::from(1), // CURLE_UNSUPPORTED_PROTOCOL
        liburlx::Error::DnsResolve(_) => ExitCode::from(6), // CURLE_COULDNT_RESOLVE_HOST
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
            if msg.contains("range not satisfiable") || msg.contains("Range not satisfiable") {
                ExitCode::from(33) // CURLE_RANGE_ERROR
            } else if msg.contains("empty response") || msg.contains("Empty response") {
                ExitCode::from(52) // CURLE_GOT_NOTHING
            } else if msg.contains("too many redirects") || msg.contains("Too many redirects") {
                ExitCode::from(47) // CURLE_TOO_MANY_REDIRECTS
            } else if msg.contains("fail_on_error") {
                ExitCode::from(22) // CURLE_HTTP_RETURNED_ERROR
            } else if msg.contains("unsupported protocol") || msg.contains("Unsupported protocol") {
                ExitCode::from(1) // CURLE_UNSUPPORTED_PROTOCOL
            } else if msg.contains("partial") || msg.contains("Partial") {
                ExitCode::from(18) // CURLE_PARTIAL_FILE
            } else if msg.contains("upload") || msg.contains("Upload") {
                ExitCode::from(25) // CURLE_UPLOAD_FAILED
            } else if msg.contains("send") || msg.contains("Send") {
                ExitCode::from(55) // CURLE_SEND_ERROR
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
                // Retry on 408, 429, 500, 502, 503, 504 (or all errors with --retry-all-errors)
                let should_retry = if opts.retry_all_errors {
                    response.status() >= 400
                } else {
                    is_retryable_status(response.status())
                };
                if should_retry && attempt < max_retries {
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
    output_file: Option<&str>,
    write_out: Option<&str>,
    include_headers: bool,
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
                // First URL uses --output file if specified; rest go to stdout
                let file_for_this = if i == 0 { output_file } else { None };
                let exit =
                    output_response(&response, file_for_this, write_out, include_headers, silent);
                if exit != ExitCode::SUCCESS {
                    any_failed = true;
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn format_http_date_epoch() {
        let epoch = std::time::UNIX_EPOCH;
        assert_eq!(format_http_date(epoch), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn format_http_date_known() {
        // Mon, 15 Jan 2024 11:30:00 GMT = 1705318200
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_705_318_200);
        let result = format_http_date(time);
        assert_eq!(result, "Mon, 15 Jan 2024 11:30:00 GMT");
    }

    #[test]
    fn format_http_date_roundtrip() {
        // Create a date, format it, parse it back, check consistency
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(784_111_777);
        let formatted = format_http_date(time);
        let parsed_ts = parse_http_date(&formatted);
        assert_eq!(parsed_ts, Some(784_111_777));
    }

    #[test]
    fn parse_http_date_valid() {
        let ts = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(ts.is_some());
        assert_eq!(ts.unwrap(), 784_111_777);
    }

    #[test]
    fn parse_http_date_invalid() {
        assert!(parse_http_date("not a date").is_none());
    }

    #[test]
    fn remote_name_from_url_basic() {
        assert_eq!(remote_name_from_url("http://example.com/file.tar.gz"), "file.tar.gz");
    }

    #[test]
    fn remote_name_from_url_trailing_slash() {
        assert_eq!(remote_name_from_url("http://example.com/"), "index.html");
    }

    #[test]
    fn remote_name_from_url_with_query() {
        assert_eq!(remote_name_from_url("http://example.com/file.zip?v=2"), "file.zip");
    }

    #[test]
    fn is_retryable_status_codes() {
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(504));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(404));
    }

    #[test]
    fn extract_hostname_simple() {
        assert_eq!(extract_hostname("https://example.com/path"), "example.com");
    }

    #[test]
    fn extract_hostname_with_port() {
        assert_eq!(extract_hostname("http://localhost:8080/"), "localhost");
    }

    #[test]
    fn extract_hostname_with_userinfo() {
        assert_eq!(extract_hostname("http://user:pass@host.com/"), "host.com");
    }

    #[test]
    fn is_leap_year_tests() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn error_to_exit_code_url_parse() {
        let err = liburlx::Error::UrlParse("bad url".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(3));
    }

    #[test]
    fn error_to_exit_code_timeout() {
        let err = liburlx::Error::Timeout(std::time::Duration::from_secs(30));
        assert_eq!(error_to_exit_code(&err), ExitCode::from(28));
    }

    #[test]
    fn error_to_exit_code_tls_verify() {
        let err = liburlx::Error::Tls(Box::<dyn std::error::Error + Send + Sync>::from(
            "certificate verify failed",
        ));
        assert_eq!(error_to_exit_code(&err), ExitCode::from(60));
    }

    #[test]
    fn error_to_exit_code_tls_connect() {
        let err = liburlx::Error::Tls(Box::<dyn std::error::Error + Send + Sync>::from(
            "handshake failed",
        ));
        assert_eq!(error_to_exit_code(&err), ExitCode::from(35));
    }

    #[test]
    fn error_to_exit_code_http_too_many_redirects() {
        let err = liburlx::Error::Http("too many redirects".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(47));
    }

    #[test]
    fn error_to_exit_code_http_unsupported_protocol() {
        let err = liburlx::Error::Http("unsupported protocol".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(1));
    }

    #[test]
    fn error_to_exit_code_unsupported_protocol_variant() {
        let err = liburlx::Error::UnsupportedProtocol("gopher".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(1));
    }

    #[test]
    fn error_to_exit_code_dns_resolve() {
        let err = liburlx::Error::DnsResolve("nonexistent.example.com".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(6));
    }

    #[test]
    fn error_to_exit_code_http_recv() {
        let err = liburlx::Error::Http("connection reset".to_string());
        assert_eq!(error_to_exit_code(&err), ExitCode::from(56));
    }
}
