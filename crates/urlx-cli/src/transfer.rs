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
    content_disposition_filename, format_headers, format_write_out, http_status_text,
    output_response, write_trace_file,
};

/// Substitute `#1`, `#2`, etc. in an output filename template with glob match values.
///
/// `#N` references the Nth glob group (1-indexed). If N is out of range, the `#N`
/// is kept literally (curl compat: test 87).
pub fn substitute_glob_template(template: &str, glob_values: &[String]) -> String {
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '#' {
            // Collect digits after '#'
            let mut digits = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    digits.push(d);
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            if digits.is_empty() {
                result.push('#');
            } else if let Ok(n) = digits.parse::<usize>() {
                if n >= 1 && n <= glob_values.len() {
                    result.push_str(&glob_values[n - 1]);
                } else {
                    // Out of range: keep literal #N (curl compat)
                    result.push('#');
                    result.push_str(&digits);
                }
            } else {
                result.push('#');
                result.push_str(&digits);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Takes the last path segment. Falls back to `"curl_response"` if no filename.
///
/// Matches curl 8.10+ behavior: when URL ends with `/`, tries to extract the
/// last directory component. Falls back to `"curl_response"` when empty.
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
        // Strip trailing slashes and find last segment
        let trimmed = path.trim_end_matches('/');
        if let Some(name) = trimmed.rsplit('/').next() {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }

    "curl_response".to_string()
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
                eprintln!("curl: warning: could not set file time: {e}");
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
    if parts.len() < 3 {
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

/// Extract the username from a URL's userinfo, if present.
///
/// Returns `None` if no userinfo is in the URL.
#[allow(clippy::option_if_let_else)]
fn extract_url_username(url: &str) -> Option<String> {
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some(at_pos) = without_path.rfind('@') {
        let userinfo = &without_path[..at_pos];
        let user = userinfo.split(':').next().unwrap_or(userinfo);
        if user.is_empty() {
            None
        } else {
            // URL-decode the username
            Some(url_decode(user))
        }
    } else {
        None
    }
}

/// Extract the username from a URL, including empty usernames.
///
/// Unlike [`extract_url_username`], this returns `Some("")` for `http://:pass@host/`.
/// Used for HTTP auth where empty username is valid (curl compat: test 367).
#[allow(clippy::option_if_let_else)]
fn extract_url_username_raw(url: &str) -> Option<String> {
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some(at_pos) = without_path.rfind('@') {
        let userinfo = &without_path[..at_pos];
        let user = userinfo.split(':').next().unwrap_or(userinfo);
        Some(url_decode(user))
    } else {
        None
    }
}

/// Extract the password from a URL's userinfo, if present.
///
/// Returns `None` if no password is in the URL (user-only: `user@host`).
#[allow(clippy::option_if_let_else)]
fn extract_url_password(url: &str) -> Option<String> {
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some(at_pos) = without_path.rfind('@') {
        let userinfo = &without_path[..at_pos];
        if let Some((_user, pass)) = userinfo.split_once(':') {
            Some(url_decode(pass))
        } else {
            None // user@host, no password
        }
    } else {
        None
    }
}

/// Strip credentials from a URL: `ftp://user:pass@host/` → `ftp://host/`.
#[allow(clippy::option_if_let_else)]
fn strip_url_credentials(url: &str) -> String {
    let scheme_end = url.find("://").map_or(0, |p| p + 3);
    let rest = &url[scheme_end..];
    if let Some(at_pos) = rest.find('@') {
        format!("{}{}", &url[..scheme_end], &rest[at_pos + 1..])
    } else {
        url.to_string()
    }
}

/// URL-decode a percent-encoded string.
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(hex_str) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                        result.push(val as char);
                        continue;
                    }
                }
                result.push('%');
                result.push(h as char);
                result.push(l as char);
            } else {
                result.push('%');
            }
        } else {
            result.push(b as char);
        }
    }
    result
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
        ParseResult::Error(code) => {
            return ExitCode::from(code);
        }
    };

    // --fail-with-body + --fail: --fail wins (curl compat: test 360)
    if opts.fail_with_body && opts.fail_on_error && !opts.has_post_data {
        // Check if both explicit --fail and --fail-with-body were used
        // (--fail-with-body also sets fail_on_error internally)
        // Only warn when --fail was explicitly also passed
        let has_explicit_fail = args.iter().any(|a| a == "-f" || a == "--fail");
        if has_explicit_fail {
            eprintln!("Warning: --fail deselects --fail-with-body here");
            opts.fail_with_body = false;
        }
    }

    // Check for conflicting request method flags (curl returns exit code 2)
    {
        let has_head = opts.easy.method_str() == Some("HEAD");
        let has_body = opts.easy.has_body();
        let has_multipart = opts.easy.has_multipart();
        if has_head && has_body && has_multipart {
            eprintln!("curl: (2) Mutually exclusive options detected");
            return ExitCode::from(2);
        }
        // -T (upload/PUT) and -d (POST data) conflict (curl compat: test 378)
        if opts.is_upload && opts.has_post_data {
            eprintln!(
                "Warning: You can only select one HTTP request method! You asked for both PUT "
            );
            eprintln!("Warning: (-T, --upload-file) and POST (-d, --data).");
            return ExitCode::from(2);
        }
        // -d (POST data) and -C (resume/continue-at) conflict (curl compat: test 426)
        if opts.has_post_data && (opts.resume_check || opts.auto_resume) {
            return ExitCode::from(2);
        }
    }

    // Expand URL globs unless --globoff is set
    if !opts.globoff {
        let mut expanded_urls = Vec::new();
        let mut expanded_values = Vec::new();
        for url in &opts.urls {
            match liburlx::glob::expand_glob_with_values(url) {
                Ok(entries) => {
                    for (expanded_url, values) in entries {
                        expanded_urls.push(expanded_url);
                        expanded_values.push(values);
                    }
                }
                Err(e) => {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (3) {e}");
                    }
                    return ExitCode::from(3); // CURLE_URL_MALFORMAT
                }
            }
        }
        opts.urls = expanded_urls;
        opts.glob_values = expanded_values;
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
        // -G converts POST to GET, but explicit -I (HEAD) or -X wins
        let current = opts.easy.method_str().map(String::from);
        match current.as_deref() {
            None | Some("POST") => opts.easy.method("GET"),
            _ => {} // preserve HEAD (-I) or any -X override
        }
        // Remove auto-added Content-Type for form data
        opts.easy.remove_header("Content-Type");
        opts.easy.set_form_data(false);
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if opts.urls.len() > 1 {
        // Build per-URL output filenames with #N glob template substitution
        let per_url_output: Vec<String> = if let Some(ref tmpl) = opts.output_file {
            opts.urls
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let values = opts.glob_values.get(i).map(Vec::as_slice).unwrap_or_default();
                    substitute_glob_template(tmpl, values)
                })
                .collect()
        } else {
            Vec::new()
        };

        return run_multi(
            &opts.easy,
            &opts.urls,
            &per_url_output,
            opts.write_out.as_deref(),
            opts.include_headers,
            opts.silent,
            opts.show_error,
            opts.fail_on_error,
            opts.parallel,
            opts.parallel_max,
            opts.skip_existing,
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
                    eprintln!("curl: protocol not allowed by --proto");
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
                eprintln!("curl: error parsing URL: {e}");
            }
            return ExitCode::from(3); // CURLE_URL_MALFORMAT
        }

        // --netrc: load credentials from .netrc file for this URL
        // Priority: -u overrides netrc, netrc overrides URL (for compulsory --netrc/-n),
        // URL overrides netrc (for --netrc-optional) except when URL has user but no password.
        if opts.user_credentials.is_none() {
            if let Some(ref netrc_path) = opts.netrc_file {
                match std::fs::read_to_string(netrc_path) {
                    Ok(contents) => {
                        let host = extract_hostname(&url);
                        let url_user = extract_url_username(&url);
                        let url_pass = extract_url_password(&url);

                        // Determine if we should use netrc
                        let use_netrc = if opts.netrc_optional {
                            // --netrc-optional: use netrc if URL has no credentials,
                            // or if URL has user but no password (look up password)
                            url_user.is_none() || url_pass.is_none()
                        } else {
                            // --netrc (compulsory): always use netrc (overrides URL)
                            true
                        };

                        if use_netrc {
                            // Look up in netrc: if URL has a username, search for that user
                            #[allow(clippy::option_if_let_else)]
                            let entry = if let Some(ref uname) = url_user {
                                match liburlx::netrc::lookup_user(&contents, &host, uname) {
                                    Ok(Some(e)) => Ok(Some(e)),
                                    Ok(None) => liburlx::netrc::lookup(&contents, &host),
                                    Err(e) => Err(e),
                                }
                            } else {
                                liburlx::netrc::lookup(&contents, &host)
                            };

                            match entry {
                                Ok(Some(entry)) => {
                                    // Use URL username if netrc has no login
                                    let user = entry
                                        .login
                                        .or_else(|| url_user.clone())
                                        .unwrap_or_default();
                                    let pass = entry.password.unwrap_or_default();
                                    if url.starts_with("ftp://")
                                        || url.starts_with("ftps://")
                                        || url.starts_with("sftp://")
                                        || url.starts_with("scp://")
                                    {
                                        // Embed credentials in URL for FTP/SSH (don't percent-encode)
                                        let base_url = strip_url_credentials(&url);
                                        let scheme_end = base_url.find("://").map_or(0, |p| p + 3);
                                        let new_url = format!(
                                            "{}{}:{}@{}",
                                            &base_url[..scheme_end],
                                            user,
                                            pass,
                                            &base_url[scheme_end..],
                                        );
                                        if let Err(e) = opts.easy.url(&new_url) {
                                            if !opts.silent || opts.show_error {
                                                eprintln!(
                                                    "urlx: error parsing URL with netrc credentials: {e}"
                                                );
                                            }
                                            return ExitCode::from(3);
                                        }
                                    } else if opts.use_digest {
                                        opts.easy.digest_auth(&user, &pass);
                                    } else {
                                        opts.easy.basic_auth(&user, &pass);
                                    }
                                }
                                Ok(None) => {}
                                Err(_) => {
                                    // Syntax error in netrc (e.g., unterminated quote)
                                    if !opts.silent || opts.show_error {
                                        eprintln!("curl: bad syntax in netrc file '{netrc_path}'");
                                    }
                                    return ExitCode::from(26);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if !opts.netrc_optional {
                            // Missing netrc file: curl returns CURLE_FAILED_INIT (2)
                            // when --netrc is used but the file doesn't exist
                            if !opts.silent || opts.show_error {
                                eprintln!("curl: (2) could not read netrc file '{netrc_path}'");
                            }
                            return ExitCode::from(2);
                        }
                    }
                }
            }
        }

        // For FTP/SSH: if -u was provided, embed credentials into the URL
        // (FTP and SSH read credentials from the URL, not from auth_credentials).
        if let Some((ref user, ref pass)) = opts.user_credentials {
            if url.starts_with("ftp://")
                || url.starts_with("ftps://")
                || url.starts_with("sftp://")
                || url.starts_with("scp://")
                || url.starts_with("smtp://")
                || url.starts_with("smtps://")
                || url.starts_with("imap://")
                || url.starts_with("imaps://")
                || url.starts_with("pop3://")
                || url.starts_with("pop3s://")
            {
                let base_url = strip_url_credentials(&url);
                let scheme_end = base_url.find("://").map_or(0, |p| p + 3);
                let new_url = format!(
                    "{}{}:{}@{}",
                    &base_url[..scheme_end],
                    user,
                    pass,
                    &base_url[scheme_end..]
                );
                if let Err(e) = opts.easy.url(&new_url) {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: error parsing URL with -u credentials: {e}");
                    }
                    return ExitCode::from(3);
                }
            }
        }

        // For HTTP: if -u was NOT provided and no netrc was loaded,
        // extract credentials from URL userinfo (http://user:pass@host/)
        // and set basic auth. Empty username is valid (curl compat: test 367).
        if opts.user_credentials.is_none()
            && !url.starts_with("ftp://")
            && !url.starts_with("ftps://")
            && !url.starts_with("smtp://")
            && !url.starts_with("smtps://")
            && !url.starts_with("imap://")
            && !url.starts_with("imaps://")
            && !url.starts_with("pop3://")
            && !url.starts_with("pop3s://")
        {
            let url_user = extract_url_username_raw(&url);
            let url_pass = extract_url_password(&url);
            if url_user.is_some() || url_pass.is_some() {
                let user = url_user.unwrap_or_default();
                let pass = url_pass.unwrap_or_default();
                if !opts.easy.has_auth_header() {
                    if opts.use_digest {
                        opts.easy.digest_auth(&user, &pass);
                    } else {
                        opts.easy.basic_auth(&user, &pass);
                    }
                }
            }
        }

        // -O/--remote-name: derive output filename from URL
        if opts.remote_name && opts.output_file.is_none() {
            let name = remote_name_from_url(&url);
            // --output-dir: prepend directory to filename
            if let Some(ref dir) = opts.output_dir {
                opts.output_file =
                    Some(std::path::Path::new(dir).join(&name).to_string_lossy().to_string());
            } else {
                opts.output_file = Some(name);
            }
        }
    }

    // Substitute #N glob templates in output filename (single-URL path)
    if let Some(ref tmpl) = opts.output_file {
        let values = opts.glob_values.first().map(Vec::as_slice).unwrap_or_default();
        if !values.is_empty() {
            opts.output_file = Some(substitute_glob_template(tmpl, values));
        }
    }

    // --create-dirs: create parent directories for output file
    if opts.create_dirs {
        if let Some(ref path) = opts.output_file {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        if !opts.silent || opts.show_error {
                            eprintln!("curl: error creating directories: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }

    // Proxy from environment variables (if no explicit -x/--proxy was set)
    if !opts.easy.has_proxy() {
        let scheme = opts.easy.url_ref().map(|u| u.scheme().to_lowercase()).unwrap_or_default();
        let env_var = match scheme.as_str() {
            "https" => std::env::var("https_proxy").or_else(|_| std::env::var("HTTPS_PROXY")).ok(),
            _ => std::env::var("http_proxy").or_else(|_| std::env::var("HTTP_PROXY")).ok(),
        };
        if let Some(proxy_url) = env_var {
            if !proxy_url.is_empty() {
                let _ = opts.easy.proxy(&proxy_url);
            }
        }
    }

    // POP3 with -l/--list-only: set custom request to LIST
    // (curl uses -l to send LIST instead of RETR for POP3)
    if opts.easy.is_ftp_list_only() {
        let scheme = opts.easy.url_ref().map(|u| u.scheme().to_lowercase()).unwrap_or_default();
        if scheme == "pop3" || scheme == "pop3s" {
            opts.easy.custom_request_target("LIST");
        }
    }

    // --skip-existing: skip transfer if output file already exists
    if opts.skip_existing {
        if let Some(ref path) = opts.output_file {
            if std::path::Path::new(path).exists() {
                if !opts.silent {
                    eprintln!("Note: skips transfer, \"{}\" exists locally", path);
                }
                return ExitCode::SUCCESS;
            }
        }
    }

    // -C - auto-resume: determine offset from existing output file size
    if opts.auto_resume {
        if opts.is_upload {
            // FTP upload with -C -: signal resume (SIZE will be sent, test 362)
            opts.easy.resume_from(0);
        } else if let Some(ref path) = opts.output_file {
            if let Ok(meta) = std::fs::metadata(path) {
                let size = meta.len();
                if size > 0 {
                    opts.easy.resume_from(size);
                }
            }
            // If file doesn't exist, no resume offset (start from 0)
        }
    }

    // Deferred -T file read: load upload file BEFORE Content-Range handling
    // so that take_body() has data to slice for resumed uploads (test 33).
    if let Some(ref path) = opts.upload_file_path {
        match std::fs::read(path) {
            Ok(data) => {
                opts.easy.body(&data);
            }
            Err(e) => {
                if !opts.silent || opts.show_error {
                    eprintln!("curl: can't read file '{path}': {e}");
                }
                return ExitCode::from(26); // CURLE_READ_ERROR
            }
        }
    }

    // PUT with -C offset: handle HTTP vs FTP resume differently
    if opts.is_upload {
        if let Some(offset) = opts.resume_offset {
            if offset > 0 {
                // Check if this is an FTP upload (keep Range header for FTP module)
                let is_ftp_upload = opts
                    .urls
                    .first()
                    .is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
                if !is_ftp_upload {
                    // For HTTP PUT uploads, curl sends Content-Range and slices the body
                    if let Some(body_data) = opts.easy.take_body() {
                        let total = body_data.len() as u64;
                        let end = total.saturating_sub(1);
                        if offset <= end {
                            // Slice the body from offset onwards
                            #[allow(clippy::cast_possible_truncation)]
                            let start = offset as usize;
                            let sliced = &body_data[start..];
                            opts.easy
                                .header("Content-Range", &format!("bytes {offset}-{end}/{total}"));
                            opts.easy.body(sliced);
                        } else {
                            // Offset beyond file size — send empty body
                            opts.easy.body(&[]);
                        }
                    }
                    // Clear the Range setting that resume_from() set (it's for GET, not PUT)
                    opts.easy.clear_range();
                }
                // For FTP, keep the Range header intact — FTP module reads it
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
        opts.time_cond_negate = negate;
        // Try to parse as a file path first (use file mtime), then as a date string
        let date_val = if std::path::Path::new(date_str).exists() {
            let mtime = std::fs::metadata(date_str).ok().and_then(|m| m.modified().ok());
            if let Some(ref t) = mtime {
                #[allow(clippy::cast_possible_wrap)]
                let ts = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).ok();
                opts.time_cond_ts = ts;
            }
            mtime.map(format_http_date)
        } else {
            // Try parsing as RFC 7231 first, then loose date format
            if let Some(ts) = parse_http_date(date_str) {
                opts.time_cond_ts = Some(ts);
                Some(date_str.to_string())
            } else if let Some(ts) = parse_loose_date(date_str) {
                opts.time_cond_ts = Some(ts);
                u64::try_from(ts).ok().map(|secs| {
                    format_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
                })
            } else {
                None
            }
        };
        // For FTP, use MDTM-based time condition instead of HTTP headers
        let is_ftp_url =
            opts.urls.first().is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
        if is_ftp_url {
            if let Some(ts) = opts.time_cond_ts {
                opts.easy.ftp_time_condition(ts, negate);
            }
        } else if let Some(date) = date_val {
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

    // Non-HTTP protocols: --include doesn't output HTTP headers (curl compat).
    // Suppress include_headers for FTP/IMAP/POP3/SMTP/MQTT URLs.
    if opts.urls.first().is_some_and(|u| {
        let lower = u.to_lowercase();
        lower.starts_with("ftp://")
            || lower.starts_with("ftps://")
            || lower.starts_with("imap://")
            || lower.starts_with("imaps://")
            || lower.starts_with("pop3://")
            || lower.starts_with("pop3s://")
            || lower.starts_with("smtp://")
            || lower.starts_with("smtps://")
            || lower.starts_with("mqtt://")
    }) {
        opts.include_headers = false;
    }

    // -D/--dump-header: validate directory exists before transfer (curl compat: test 419)
    if let Some(ref path) = opts.dump_header {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                if !opts.silent || opts.show_error {
                    eprintln!("curl: (23) Failed creating file '{path}'");
                }
                return ExitCode::from(23); // CURLE_WRITE_ERROR
            }
        }
    }

    // --etag-save: validate/create directory before transfer
    if let Some(ref path) = opts.etag_save_file {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                if opts.create_dirs {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        if !opts.silent || opts.show_error {
                            eprintln!("curl: error creating directories for etag file: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
                } else {
                    if !opts.silent || opts.show_error {
                        eprintln!(
                            "urlx: (26) Failed to open/read local data from file/application"
                        );
                    }
                    return ExitCode::from(26); // CURLE_READ_ERROR
                }
            }
        }
    }

    // For non-HTTP protocols, -X sets a custom protocol command (not HTTP request target).
    // Only set custom_request_target for non-HTTP schemes to avoid breaking HTTP -X behavior.
    if let Some(ref custom_req) = opts.custom_request_original {
        let scheme = opts.easy.url_ref().map(|u| u.scheme().to_lowercase()).unwrap_or_default();
        if matches!(scheme.as_str(), "smtp" | "smtps" | "imap" | "imaps" | "pop3" | "pop3s") {
            opts.easy.custom_request_target(custom_req);
        }
    }

    let result = perform_with_retry(&mut opts);

    // Save cookie jar after transfer (even on error)
    if opts.cookie_jar_file.is_some() {
        if let Err(e) = opts.easy.save_cookie_jar() {
            if !opts.silent || opts.show_error {
                eprintln!("curl: error saving cookies: {e}");
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
                    let trimmed = etag.trim();
                    if trimmed.is_empty() {
                        // Blank ETag: create an empty file (curl compat: test 347)
                        let _ = std::fs::write(path, "");
                    } else {
                        // curl writes the etag followed by a newline
                        let content = format!("{trimmed}\n");
                        if let Err(e) = std::fs::write(path, content) {
                            if !opts.silent || opts.show_error {
                                eprintln!("curl: error saving ETag to '{path}': {e}");
                            }
                        }
                    }
                }
            }

            // Check for failed resume: when -C was used for a download and server
            // returned non-206 (curl returns CURLE_RANGE_ERROR = 33).
            // For uploads (PUT), 200 is a valid response — don't check.
            // FTP handles resume internally — don't apply HTTP resume logic.
            // 416 Range Not Satisfiable = file already fully downloaded (success,
            // output headers but suppress body).
            let is_ftp = opts
                .urls
                .first()
                .is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
            let is_file = opts.urls.first().is_some_and(|u| u.starts_with("file:"));
            if opts.resume_check && !opts.is_upload && !is_ftp && !is_file {
                let status = response.status();
                if status == 416 {
                    // File already complete — output headers only, exit success
                    let exit = output_response(
                        &response,
                        opts.output_file.as_deref(),
                        opts.write_out.as_deref(),
                        opts.include_headers,
                        opts.silent,
                        true, // suppress body
                    );
                    return exit;
                }
                // 200 with Content-Range is a valid resume response (curl compat: test 188)
                let has_content_range = response.header("content-range").is_some();
                if status != 206 && !(status == 200 && has_content_range) {
                    // Output headers but suppress body. When auto-resuming (-C -),
                    // don't write to the output file (it's the resume source).
                    let out_file =
                        if opts.auto_resume { None } else { opts.output_file.as_deref() };
                    let _exit = output_response(
                        &response,
                        out_file,
                        opts.write_out.as_deref(),
                        opts.include_headers,
                        opts.silent,
                        true, // suppress body
                    );
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: server returned {status} but resume was requested");
                    }
                    return ExitCode::from(33); // CURLE_RANGE_ERROR
                }
            }

            // --fail / --fail-with-body: exit 22 on HTTP error status codes
            if opts.fail_on_error && response.status() >= 400 && !opts.fail_with_body {
                // Output headers (but not body) before returning error (curl compat: test 752)
                if opts.include_headers {
                    let _ = output_response(
                        &response,
                        opts.output_file.as_deref(),
                        None,
                        true, // include headers
                        opts.silent,
                        true, // headers only, suppress body
                    );
                }
                if !opts.silent || opts.show_error {
                    eprintln!("curl: (22) The requested URL returned error: {}", response.status(),);
                }
                return ExitCode::from(22);
            }

            // --max-filesize: check Content-Length header and actual body size
            if let Some(max_size) = opts.max_filesize {
                // Check Content-Length first (before download, curl compat: test 393)
                let cl_header = response.header("content-length");
                // If Content-Length is present but unparseable (e.g., too large), treat as exceeded
                let cl_exceeded =
                    cl_header.is_some_and(|v| v.parse::<u64>().map_or(true, |cl| cl > max_size));
                let exceeded = cl_exceeded || response.body().len() as u64 > max_size;
                if exceeded {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: maximum file size exceeded",);
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
                        eprintln!("curl: error writing headers to {path}: {e}");
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

            // -z/--time-cond body suppression: if the response has Last-Modified
            // and the condition is not met, suppress body output (curl compat).
            let suppress_body = opts.time_cond_ts.is_some_and(|cond_ts| {
                response.header("last-modified").and_then(parse_http_date).is_some_and(|lm_ts| {
                    if opts.time_cond_negate {
                        // -z -date: If-Unmodified-Since — suppress if doc IS newer
                        lm_ts > cond_ts
                    } else {
                        // -z date: If-Modified-Since — suppress if doc is NOT newer
                        lm_ts <= cond_ts
                    }
                })
            });

            let exit = output_response(
                &response,
                opts.output_file.as_deref(),
                opts.write_out.as_deref(),
                opts.include_headers,
                opts.silent,
                suppress_body,
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
                    eprintln!("curl: (22) The requested URL returned error: {}", response.status(),);
                }
                return ExitCode::from(22);
            }

            // Body error: output was written, now return appropriate error exit code
            if let Some(body_err) = response.body_error() {
                // --remove-on-error: delete output file on body error
                if opts.remove_on_error {
                    if let Some(ref path) = opts.output_file {
                        if path != "-" {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
                if body_err == "partial" {
                    // FTP partial file — data was already output, return error 18
                    return ExitCode::from(18); // CURLE_PARTIAL_FILE
                }
                if body_err.contains("transfer closed")
                    || body_err.contains("outstanding read data")
                {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (18) {body_err}");
                    }
                    return ExitCode::from(18); // CURLE_PARTIAL_FILE
                }
                if body_err.contains("bad_content_encoding") {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (61) Unrecognized or bad content encoding");
                    }
                    return ExitCode::from(61); // CURLE_BAD_CONTENT_ENCODING
                }
                if body_err.contains("negative_content_length")
                    || body_err.contains("invalid_content_length")
                    || body_err.contains("conflicting_content_length")
                    || body_err.contains("duplicate_location")
                {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (8) Weird server reply");
                    }
                    return ExitCode::from(8);
                }
                if body_err.contains("timeout") {
                    if !opts.silent || opts.show_error {
                        let timeout_str = opts
                            .easy
                            .timeout_duration()
                            .map_or_else(String::new, |d| format!(" after {d:?}"));
                        eprintln!("curl: (28) timeout{timeout_str}");
                    }
                    return ExitCode::from(28); // CURLE_OPERATION_TIMEDOUT
                }
                if !opts.silent || opts.show_error {
                    eprintln!("curl: (56) {body_err}");
                }
                return ExitCode::from(56); // CURLE_RECV_ERROR
            }

            exit
        }
        Err(e) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }

            // Output last response data on error (curl compat — headers/body before error)
            if let Some(resp) = opts.easy.last_response() {
                // For redirect responses (max-redirects exceeded), only output headers
                // (curl doesn't output the body of the final redirect on error)
                if resp.is_redirect() {
                    if opts.include_headers {
                        use std::io::Write;
                        let mut h = String::new();
                        for redir in resp.redirect_responses() {
                            h.push_str(&format_headers(redir));
                        }
                        h.push_str(&format_headers(resp));
                        if let Some(path) = opts.output_file.as_deref().filter(|p| *p != "-") {
                            let _ = std::fs::write(path, h.as_bytes());
                        } else {
                            let _ = std::io::stdout().write_all(h.as_bytes());
                        }
                    }
                } else {
                    // For 416 with resume, suppress body (file already downloaded)
                    let suppress = opts.resume_check && resp.status() == 416;
                    let _ = output_response(
                        resp,
                        opts.output_file.as_deref(),
                        opts.write_out.as_deref(),
                        opts.include_headers,
                        opts.silent,
                        suppress,
                    );
                }
            }

            // --max-filesize: if the error was caused by an oversized Content-Length,
            // return exit code 63 instead of the transport error (curl compat: test 393)
            if let Some(max_size) = opts.max_filesize {
                if let Some(resp) = opts.easy.last_response() {
                    if let Some(cl_str) = resp.header("content-length") {
                        // If Content-Length is unparseable or exceeds max, it's a size error
                        if cl_str.parse::<u64>().map_or(true, |cl| cl > max_size) {
                            return ExitCode::from(63); // CURLE_FILESIZE_EXCEEDED
                        }
                    }
                }
            }

            // 416 Range Not Satisfiable with resume = file already fully downloaded (success)
            if opts.resume_check {
                if let Some(resp) = opts.easy.last_response() {
                    if resp.status() == 416 {
                        return ExitCode::SUCCESS;
                    }
                }
            }
            // Process -w write-out even on error (curl compat: test 196)
            if let Some(ref w) = opts.write_out {
                use std::io::Write as _;
                // Create a minimal response for write-out formatting
                let wo = if let Some(resp) = opts.easy.last_response() {
                    format_write_out(w, resp)
                } else {
                    // No response available — just process escape sequences
                    let mut s = w.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r");
                    s = s.replace("%{num_retries}", &opts.retry_attempts.to_string());
                    s
                };
                let _ = std::io::stdout().write_all(wo.as_bytes());
                let _ = std::io::stdout().flush();
            }
            if !opts.silent || opts.show_error {
                eprintln!("curl: {e}");
            }
            // --remove-on-error: delete output file on transfer failure
            if opts.remove_on_error {
                if let Some(ref path) = opts.output_file {
                    if path != "-" {
                        let _ = std::fs::remove_file(path);
                    }
                }
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
            if msg.contains("Weird server reply") || msg.contains("binary zero") {
                ExitCode::from(8) // CURLE_WEIRD_SERVER_REPLY
            } else if msg.contains("range not satisfiable") || msg.contains("Range not satisfiable")
            {
                ExitCode::from(33) // CURLE_RANGE_ERROR
            } else if msg.contains("empty response") || msg.contains("Empty response") {
                ExitCode::from(52) // CURLE_GOT_NOTHING
            } else if msg.contains("too many redirects") || msg.contains("Too many redirects") {
                ExitCode::from(47) // CURLE_TOO_MANY_REDIRECTS
            } else if msg.contains("fail_on_error") {
                ExitCode::from(22) // CURLE_HTTP_RETURNED_ERROR
            } else if msg.contains("unsupported protocol")
                || msg.contains("Unsupported protocol")
                || msg.contains("invalid HTTP version")
                || msg.contains("unsupported HTTP version")
            {
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
        liburlx::Error::FileError(_) => ExitCode::from(37), // CURLE_FILE_COULDNT_READ_FILE
        liburlx::Error::Io(_) => ExitCode::from(23),        // CURLE_WRITE_ERROR
        liburlx::Error::Ssh(msg) => {
            if msg.contains("No such file")
                || msg.contains("not found")
                || msg.contains("does not exist")
            {
                ExitCode::from(78) // CURLE_REMOTE_FILE_NOT_FOUND
            } else if msg.contains("permission denied") || msg.contains("Permission denied") {
                ExitCode::from(9) // CURLE_REMOTE_ACCESS_DENIED
            } else if msg.contains("quote") || msg.contains("Quote") {
                ExitCode::from(21) // CURLE_QUOTE_ERROR
            } else {
                ExitCode::from(67) // CURLE_LOGIN_DENIED
            }
        }
        liburlx::Error::Transfer { code, .. } => {
            ExitCode::from(u8::try_from(*code).map_or(1, |c| c))
        }
        liburlx::Error::PartialBody { .. } => ExitCode::from(56), // CURLE_RECV_ERROR
        liburlx::Error::SmtpAuth(_) => ExitCode::from(67),        // CURLE_LOGIN_DENIED
        liburlx::Error::SmtpSend(_) => ExitCode::from(55),        // CURLE_SEND_ERROR
        liburlx::Error::Protocol(code) => ExitCode::from(u8::try_from(*code).map_or(1, |c| c)),
        _ => ExitCode::FAILURE,
    }
}

/// Perform a transfer with optional retry logic.
pub fn perform_with_retry(opts: &mut CliOptions) -> Result<liburlx::Response, liburlx::Error> {
    // --etag-compare: send If-None-Match header from saved ETag
    if let Some(ref path) = opts.etag_compare_file {
        let etag =
            std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()).unwrap_or_default();
        if etag.is_empty() {
            // curl sends empty quotes when etag file is missing or empty
            opts.easy.header("If-None-Match", "\"\"");
        } else {
            opts.easy.header("If-None-Match", &etag);
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
            Ok(mut response) => {
                // Retry on 408, 429, 500, 502, 503, 504 (or all errors with --retry-all-errors)
                let should_retry = if opts.retry_all_errors {
                    response.status() >= 400
                } else {
                    is_retryable_status(response.status())
                };
                // Check Retry-After header against --retry-max-time (test 366)
                let retry_after_too_long = if should_retry {
                    if let (Some(max), Some(ra)) = (max_time, response.header("retry-after")) {
                        ra.trim().parse::<u64>().ok().is_some_and(|secs| {
                            start.elapsed() + std::time::Duration::from_secs(secs) > max
                        })
                    } else {
                        false
                    }
                } else {
                    false
                };
                if should_retry && !retry_after_too_long && attempt < max_retries {
                    // Output the failed response before retrying (curl compat: test 197)
                    let _ = output_response(
                        &response,
                        opts.output_file.as_deref(),
                        None, // no -w on intermediate retry responses
                        opts.include_headers,
                        opts.silent,
                        false,
                    );
                    last_err = Some(liburlx::Error::Http(format!(
                        "HTTP {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    )));
                    continue;
                }
                // Set num_retries on the final response
                if attempt > 0 {
                    let mut info = response.transfer_info().clone();
                    info.num_retries = attempt;
                    response.set_transfer_info(info);
                }
                return Ok(response);
            }
            Err(e) => {
                last_err = Some(e);
                opts.retry_attempts = attempt;
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

/// Run multiple URLs using the Multi API (parallel) or sequentially (default).
///
/// Sequential mode shares cookie jar state between transfers (curl behavior).
/// Parallel mode uses the Multi API for concurrent transfers.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn run_multi(
    template: &liburlx::Easy,
    urls: &[String],
    output_files: &[String],
    write_out: Option<&str>,
    include_headers: bool,
    silent: bool,
    show_error: bool,
    fail_on_error: bool,
    parallel: bool,
    parallel_max: usize,
    skip_existing: bool,
) -> ExitCode {
    if parallel {
        return run_multi_parallel(
            template,
            urls,
            output_files,
            write_out,
            include_headers,
            silent,
            show_error,
            fail_on_error,
            parallel_max,
        );
    }

    // Sequential mode: run each URL one at a time, sharing the Easy handle
    // and tokio runtime so cookies, connection pool, and TCP state carry
    // between requests (curl behavior — avoids [DISCONNECT] between requests)
    let rt =
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap_or_else(|e| {
            eprintln!("curl: failed to create runtime: {e}");
            std::process::exit(1);
        });

    let mut easy = template.clone();
    let mut any_failed = false;

    for (i, url) in urls.iter().enumerate() {
        // --skip-existing: skip transfer if output file already exists
        if skip_existing {
            if let Some(path) = output_files.get(i) {
                if std::path::Path::new(path).exists() {
                    if !silent {
                        eprintln!("Note: skips transfer, \"{path}\" exists locally");
                    }
                    continue;
                }
            }
        }

        if let Err(e) = easy.url(url) {
            if !silent || show_error {
                eprintln!("curl: error parsing URL '{url}': {e}");
            }
            return ExitCode::FAILURE;
        }

        // Extract credentials from URL userinfo (user:pass@host) for each URL
        {
            let url_user = extract_url_username_raw(url);
            let url_pass = extract_url_password(url);
            if url_user.is_some() || url_pass.is_some() {
                let user = url_user.unwrap_or_default();
                let pass = url_pass.unwrap_or_default();
                // Remove old auth header and set new one per URL
                easy.remove_header("Authorization");
                easy.basic_auth(&user, &pass);
            }
        }

        match rt.block_on(easy.perform_async()) {
            Ok(response) => {
                if fail_on_error && response.status() >= 400 {
                    any_failed = true;
                    continue;
                }
                // Each URL uses its corresponding output file (from #N substitution)
                let file_for_this = output_files.get(i).map(String::as_str);
                let exit = output_response(
                    &response,
                    file_for_this,
                    write_out,
                    include_headers,
                    silent,
                    false,
                );
                if exit != ExitCode::SUCCESS {
                    any_failed = true;
                }
            }
            Err(e) => {
                if !silent || show_error {
                    eprintln!("curl: transfer {} ({}): {e}", i + 1, url);
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

/// Run multiple URLs concurrently using the Multi API.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn run_multi_parallel(
    template: &liburlx::Easy,
    urls: &[String],
    output_files: &[String],
    write_out: Option<&str>,
    include_headers: bool,
    silent: bool,
    show_error: bool,
    fail_on_error: bool,
    parallel_max: usize,
) -> ExitCode {
    let mut multi = liburlx::Multi::new();
    multi.max_total_connections(parallel_max);

    for url in urls {
        let mut easy = template.clone();
        if let Err(e) = easy.url(url) {
            if !silent || show_error {
                eprintln!("curl: error parsing URL '{url}': {e}");
            }
            return ExitCode::FAILURE;
        }
        multi.add(easy);
    }

    let results = match multi.perform_blocking() {
        Ok(results) => results,
        Err(e) => {
            if !silent || show_error {
                eprintln!("curl: {e}");
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
                let file_for_this = output_files.get(i).map(String::as_str);
                let exit = output_response(
                    &response,
                    file_for_this,
                    write_out,
                    include_headers,
                    silent,
                    false,
                );
                if exit != ExitCode::SUCCESS {
                    any_failed = true;
                }
            }
            Err(e) => {
                if !silent || show_error {
                    eprintln!("curl: transfer {} ({}): {e}", i + 1, urls[i]);
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
        assert_eq!(remote_name_from_url("http://example.com/"), "curl_response");
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
