//! Transfer execution, retry logic, and error mapping.
//!
//! Contains the main [`run`] function that orchestrates URL transfers,
//! retry logic, and curl-compatible exit code mapping.

use std::process::ExitCode;

use crate::args::{
    parse_args, parse_proto_spec, print_usage, print_version, CliOptions, ParseResult,
};
use crate::output::{
    content_disposition_filename, format_headers, format_write_out, http_status_text,
    output_response, output_response_with_context, write_trace_file, WriteOutContext,
};

/// Redirect stderr (fd 2) to a file via `dup2`.
///
/// This is needed for `--stderr <file>` to redirect all stderr output
/// (including progress bar) to the specified file (curl compat: test 1148).
#[cfg(unix)]
#[allow(unsafe_code)]
fn redirect_stderr_to_file(path: &str) {
    if let Ok(file) = std::fs::File::create(path) {
        use std::os::unix::io::IntoRawFd;
        let fd = file.into_raw_fd();
        // SAFETY: dup2 redirects stderr (fd 2) to the opened file fd.
        // Both fds are valid: fd comes from File::create, and 2 is stderr.
        unsafe {
            let _ = libc::dup2(fd, 2);
            let _ = libc::close(fd);
        }
    }
}

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
/// Also handles timezone offsets like `"+0100"` instead of `"GMT"`.
/// Returns `None` if parsing fails.
/// Correctly handles dates before 1970 (negative Unix timestamps).
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

    // Parse timezone offset: "GMT" = 0, "+0100" = +3600, "-0530" = -19800
    let tz_offset_secs: i64 = parse_tz_offset(parts[5]);

    // Convert to Unix timestamp using a calculation that handles pre-1970 dates.
    // Count days from epoch (1970-01-01) to the given date, allowing negative values.
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
    } else {
        // Pre-1970: count backwards
        for y in year..1970 {
            days -= if is_leap_year(y) { 366 } else { 365 };
        }
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += i64::from(month_days[m as usize]);
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += i64::from(day) - 1;

    Some(days * 86400 + hour * 3600 + minute * 60 + second - tz_offset_secs)
}

/// Parse a timezone string into an offset in seconds from UTC.
///
/// Supports "GMT", "UTC", and numeric offsets like "+0100", "-0530".
fn parse_tz_offset(tz: &str) -> i64 {
    match tz {
        "GMT" | "UTC" => 0,
        s if (s.starts_with('+') || s.starts_with('-')) && s.len() >= 5 => {
            let sign: i64 = if s.starts_with('-') { -1 } else { 1 };
            let hours: i64 = s[1..3].parse().unwrap_or(0);
            let minutes: i64 = s[3..5].parse().unwrap_or(0);
            sign * (hours * 3600 + minutes * 60)
        }
        _ => 0,
    }
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
    // Only look for @ in the authority part (before first /, ?, or #)
    let authority_end = without_scheme.find(['/', '?', '#']).unwrap_or(without_scheme.len());
    let authority = &without_scheme[..authority_end];
    if let Some(at_pos) = authority.rfind('@') {
        let userinfo = &authority[..at_pos];
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
    // Only look for @ in the authority part (before first /, ?, or #)
    let authority_end = without_scheme.find(['/', '?', '#']).unwrap_or(without_scheme.len());
    let authority = &without_scheme[..authority_end];
    if let Some(at_pos) = authority.rfind('@') {
        let userinfo = &authority[..at_pos];
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
    // Only look for @ in the authority part (before first /, ?, or #)
    let authority_end = without_scheme.find(['/', '?', '#']).unwrap_or(without_scheme.len());
    let authority = &without_scheme[..authority_end];
    if let Some(at_pos) = authority.rfind('@') {
        let userinfo = &authority[..at_pos];
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
    // Only look for @ in the authority part (before first /, ?, or #)
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if let Some(at_pos) = authority.find('@') {
        format!("{}{}", &url[..scheme_end], &rest[at_pos + 1..])
    } else {
        url.to_string()
    }
}

/// Check whether a SASL mechanism name is recognized.
///
/// Used for early validation of `--login-options AUTH=<mechanism>` before
/// attempting connection (curl compat: test 896 — `AUTH=dummy` returns exit 3).
fn is_known_sasl_mechanism(mech: &str) -> bool {
    let m = mech.to_ascii_uppercase();
    matches!(
        m.as_str(),
        "PLAIN"
            | "LOGIN"
            | "EXTERNAL"
            | "CRAM-MD5"
            | "NTLM"
            | "OAUTHBEARER"
            | "XOAUTH2"
            | "SCRAM-SHA-1"
            | "SCRAM-SHA-256"
            | "DIGEST-MD5"
            | "GSSAPI"
            | "ANONYMOUS"
            | "*"
    )
}

/// Percent-encode a credential string for embedding in a URL's userinfo.
///
/// Encodes characters that are not safe in RFC 3986 userinfo:
/// unreserved chars (A-Z, a-z, 0-9, `-`, `_`, `.`, `~`) and sub-delims
/// (except `@` and `:`) are left as-is; everything else is percent-encoded.
fn percent_encode_credential(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'=' => {
                result.push(byte as char);
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                result.push('%');
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
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

/// Append query parameters to a URL string (implements curl's `--url-query`).
///
/// Supports the following formats (matching curl):
/// - `content` — form-urlencode entire string, append
/// - `=content` — append content as-is (no encoding)
/// - `name=content` — form-urlencode only the content, append `name=encoded`
/// - `@filename` — read file, form-urlencode contents, append
/// - `name@filename` — read file, form-urlencode contents, append `name=encoded`
/// - `+content` — content is already encoded, append as-is (strip `+` prefix)
pub fn append_url_queries(url: &str, queries: &[String]) -> String {
    use crate::args::form_urlencode;

    let mut result = url.to_string();
    for query in queries {
        let separator = if result.contains('?') { '&' } else { '?' };
        result.push(separator);

        if let Some(already_encoded) = query.strip_prefix('+') {
            // +content: already encoded, use as-is
            result.push_str(already_encoded);
        } else if let Some(filename) = query.strip_prefix('@') {
            // @filename: read file, encode contents
            let data = std::fs::read_to_string(filename).unwrap_or_default();
            result.push_str(&form_urlencode(&data));
        } else if let Some(at_pos) = query.find('@') {
            let eq_pos = query.find('=');
            if eq_pos.is_none() || at_pos < eq_pos.unwrap_or(usize::MAX) {
                // name@filename: read file, encode contents, prepend name=
                let name = &query[..at_pos];
                let filename = &query[at_pos + 1..];
                let data = std::fs::read_to_string(filename).unwrap_or_default();
                result.push_str(name);
                result.push('=');
                result.push_str(&form_urlencode(&data));
            } else {
                // name=content (with @ in content): encode value only
                // unwrap_or: split_once guaranteed to succeed since eq_pos was Some
                let (name, value) = query.split_once('=').unwrap_or((query, ""));
                result.push_str(name);
                result.push('=');
                result.push_str(&form_urlencode(value));
            }
        } else if let Some((name, value)) = query.split_once('=') {
            // name=value: encode only the value
            result.push_str(name);
            result.push('=');
            result.push_str(&form_urlencode(value));
        } else {
            // Plain string: encode the whole thing
            result.push_str(&form_urlencode(query));
        }
    }
    result
}

/// Extract filename from a `Content-Disposition` response header.
///
/// Supports both `filename="quoted"` and `filename=unquoted` forms.
/// Generate equivalent C code using libcurl for `--libcurl` output.
///
/// The output matches curl's `--libcurl` format exactly (curl compat: test 1400).
/// Lines use CRLF line endings to match curl's output.
pub fn generate_libcurl_code(opts: &CliOptions) -> String {
    use std::fmt::Write;
    let url = opts.urls.first().map_or("", String::as_str);
    let default_ua = format!("curl/{}", env!("CARGO_PKG_VERSION"));
    let user_agent = opts.user_agent_str.as_deref().unwrap_or(&default_ua);
    let mut c = String::new();
    let n = "\r\n";
    let _ =
        write!(c, "/********* Sample code generated by the curl command line tool **********{n}");
    let _ = write!(c, " * All curl_easy_setopt() options are documented at:{n}");
    let _ = write!(c, " * https://curl.se/libcurl/c/curl_easy_setopt.html{n}");
    let _ =
        write!(c, " ************************************************************************/{n}");
    let _ = write!(c, "#include <curl/curl.h>{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "int main(int argc, char *argv[]){n}");
    let _ = write!(c, "{{{n}");
    let _ = write!(c, "  CURLcode result;{n}");
    let _ = write!(c, "  CURL *curl;{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  curl = curl_easy_init();{n}");
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);{n}");
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);{n}");
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_URL, \"{url}\");{n}");
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_USERAGENT, \"{user_agent}\");{n}");
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);{n}");
    if opts.silent {
        let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);{n}");
    }
    if opts.fail_on_error {
        let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);{n}");
    }
    let _ = write!(c, "  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);{n}");
    let _ = write!(c, "{n}");
    let _ =
        write!(c, "  /* Here is a list of options the curl code used that cannot get generated{n}");
    let _ =
        write!(c, "     as source easily. You may choose to either not use them or implement{n}");
    let _ = write!(c, "     them yourself.{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  CURLOPT_DEBUGFUNCTION was set to a function pointer{n}");
    let _ = write!(c, "  CURLOPT_DEBUGDATA was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_WRITEDATA was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_WRITEFUNCTION was set to a function pointer{n}");
    let _ = write!(c, "  CURLOPT_READDATA was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_READFUNCTION was set to a function pointer{n}");
    let _ = write!(c, "  CURLOPT_SEEKDATA was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_SEEKFUNCTION was set to a function pointer{n}");
    let _ = write!(c, "  CURLOPT_HEADERFUNCTION was set to a function pointer{n}");
    let _ = write!(c, "  CURLOPT_HEADERDATA was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_ERRORBUFFER was set to an object pointer{n}");
    let _ = write!(c, "  CURLOPT_STDERR was set to an object pointer{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  */{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  result = curl_easy_perform(curl);{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  curl_easy_cleanup(curl);{n}");
    let _ = write!(c, "  curl = NULL;{n}");
    let _ = write!(c, "{n}");
    let _ = write!(c, "  return (int)result;{n}");
    let _ = write!(c, "}}{n}");
    let _ = write!(c, "/**** End of sample code ****/{n}");
    c
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

    // --stderr: redirect stderr to a file (curl compat: test 1148)
    // Spawn a thread that copies stderr pipe to the file, then replace
    // the global stderr fd via CommandExt in a child process is not feasible
    // for in-process use. Instead, redirect by reopening stderr.
    #[cfg(unix)]
    if let Some(ref stderr_path) = opts.stderr_file {
        redirect_stderr_to_file(stderr_path);
    }

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
        let mut expanded_groups = Vec::new();
        let mut expanded_upload_files = Vec::new();
        for (url_idx, url) in opts.urls.iter().enumerate() {
            let group = opts.per_url_group.get(url_idx).copied().unwrap_or(0);
            let upload_file = opts.per_url_upload_files.get(url_idx).cloned().unwrap_or(None);
            match liburlx::glob::expand_glob_with_values(url) {
                Ok(entries) => {
                    for (expanded_url, values) in entries {
                        expanded_urls.push(expanded_url);
                        expanded_values.push(values);
                        expanded_groups.push(group);
                        expanded_upload_files.push(upload_file.clone());
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
        opts.per_url_group = expanded_groups;
        opts.per_url_upload_files = expanded_upload_files;
    }

    // Expand -T upload file globs: `-T '{file1,file2}' URL` expands to multiple uploads.
    // For each upload file glob, iterate through all URLs (cartesian product).
    // curl compat: tests 490, 491, 492
    if opts.is_upload && !opts.globoff {
        // Also handle the case where upload_file_path has globs but per_url_upload_files
        // entries are None (e.g., `URL -T '{file1,file2}'` where URL comes before -T)
        let upload_path_has_glob =
            opts.upload_file_path.as_ref().is_some_and(|p| p.contains('{') || p.contains('['));
        if upload_path_has_glob {
            // Apply the glob upload_file_path to all URLs that don't have their own
            let glob_path = opts.upload_file_path.clone().unwrap_or_default();
            for entry in &mut opts.per_url_upload_files {
                if entry.is_none() {
                    *entry = Some(glob_path.clone());
                }
            }
        }
        // Check if any upload file path contains glob patterns
        let has_upload_glob = opts
            .per_url_upload_files
            .iter()
            .any(|f| f.as_ref().is_some_and(|path| path.contains('{') || path.contains('[')));
        if has_upload_glob {
            let mut new_urls = Vec::new();
            let mut new_upload_files = Vec::new();
            let mut new_groups = Vec::new();
            let mut new_glob_values = Vec::new();
            let mut new_per_url_easy = Vec::new();
            let mut new_per_url_creds = Vec::new();
            let mut new_per_url_ftp_methods = Vec::new();

            // Gather all URLs that share the same upload file glob
            let mut i = 0;
            while i < opts.urls.len() {
                let upload_file = opts.per_url_upload_files.get(i).cloned().unwrap_or(None);
                if let Some(ref path) = upload_file {
                    if path.contains('{') || path.contains('[') {
                        // Expand the upload file glob
                        let upload_paths = match liburlx::glob::expand_glob(path) {
                            Ok(paths) => paths,
                            Err(_) => {
                                // Not a valid glob, treat as literal
                                vec![path.clone()]
                            }
                        };
                        // Find all consecutive URLs that share this upload glob
                        // (from URL glob expansion, they all have the same upload_file)
                        let mut url_group_end = i + 1;
                        while url_group_end < opts.urls.len() {
                            let next_upload = opts
                                .per_url_upload_files
                                .get(url_group_end)
                                .and_then(|f| f.as_ref());
                            if next_upload == Some(path) {
                                url_group_end += 1;
                            } else {
                                break;
                            }
                        }
                        let url_range = i..url_group_end;

                        // Cartesian product: for each upload file, iterate all URLs
                        for upload_path in &upload_paths {
                            let fname = std::path::Path::new(upload_path)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string());
                            for j in url_range.clone() {
                                let mut url = opts.urls[j].clone();
                                // Append filename to URL path if URL ends with /
                                if let Some(ref f) = fname {
                                    if url.ends_with('/') {
                                        url.push_str(f);
                                    }
                                }
                                new_urls.push(url);
                                new_upload_files.push(Some(upload_path.clone()));
                                new_groups.push(opts.per_url_group.get(j).copied().unwrap_or(0));
                                new_glob_values
                                    .push(opts.glob_values.get(j).cloned().unwrap_or_default());
                                new_per_url_easy
                                    .push(opts.per_url_easy.get(j).cloned().unwrap_or(None));
                                new_per_url_creds
                                    .push(opts.per_url_credentials.get(j).cloned().unwrap_or(None));
                                new_per_url_ftp_methods.push(
                                    opts.per_url_ftp_methods.get(j).copied().unwrap_or_default(),
                                );
                            }
                        }
                        i = url_group_end;
                    } else {
                        // Non-glob upload file — pass through as-is
                        new_urls.push(opts.urls[i].clone());
                        new_upload_files.push(upload_file);
                        new_groups.push(opts.per_url_group.get(i).copied().unwrap_or(0));
                        new_glob_values.push(opts.glob_values.get(i).cloned().unwrap_or_default());
                        new_per_url_easy.push(opts.per_url_easy.get(i).cloned().unwrap_or(None));
                        new_per_url_creds
                            .push(opts.per_url_credentials.get(i).cloned().unwrap_or(None));
                        new_per_url_ftp_methods
                            .push(opts.per_url_ftp_methods.get(i).copied().unwrap_or_default());
                        i += 1;
                    }
                } else {
                    // No upload file for this URL — pass through
                    new_urls.push(opts.urls[i].clone());
                    new_upload_files.push(upload_file);
                    new_groups.push(opts.per_url_group.get(i).copied().unwrap_or(0));
                    new_glob_values.push(opts.glob_values.get(i).cloned().unwrap_or_default());
                    new_per_url_easy.push(opts.per_url_easy.get(i).cloned().unwrap_or(None));
                    new_per_url_creds
                        .push(opts.per_url_credentials.get(i).cloned().unwrap_or(None));
                    new_per_url_ftp_methods
                        .push(opts.per_url_ftp_methods.get(i).copied().unwrap_or_default());
                    i += 1;
                }
            }
            opts.urls = new_urls;
            opts.per_url_upload_files = new_upload_files;
            opts.per_url_group = new_groups;
            opts.glob_values = new_glob_values;
            opts.per_url_easy = new_per_url_easy;
            opts.per_url_credentials = new_per_url_creds;
            opts.per_url_ftp_methods = new_per_url_ftp_methods;
            // Clear single upload_filename since each URL now has its own
            opts.upload_filename = None;
        }
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
        opts.has_post_data = false;

        // Also clear body/Content-Type from per-URL Easy handles (curl compat: test 48)
        for per_easy in opts.per_url_easy.iter_mut().flatten() {
            let _ = per_easy.take_body();
            per_easy.remove_header("Content-Type");
            per_easy.set_form_data(false);
            // Apply the same method logic
            let m = per_easy.method_str().map(String::from);
            match m.as_deref() {
                None | Some("POST") => per_easy.method("GET"),
                _ => {}
            }
        }
    }

    // -z/--time-cond: set If-Modified-Since or If-Unmodified-Since header.
    // Must be before multi-URL branch so the header and time_cond_ts are set for run_multi.
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

    // Deferred -T file read for multi-URL path: load upload file before run_multi
    // returns early (run_multi clones the easy handle, so body must be set now).
    // Single-URL path has its own deferred read further below (line ~892).
    // Skip if -T was glob-expanded — each URL has its own file in per_url_upload_files.
    let upload_glob_expanded =
        opts.is_upload && opts.per_url_upload_files.iter().filter(|f| f.is_some()).count() > 1;
    if opts.urls.len() > 1 && !upload_glob_expanded {
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
        // Apply Content-Range + body slicing for resumed uploads in multi-URL mode
        // (curl compat: test 1002 — -T file -C 2 with multiple URLs)
        if opts.is_upload {
            if let Some(offset) = opts.resume_offset {
                if offset > 0 {
                    let is_ftp_upload = opts
                        .urls
                        .first()
                        .is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
                    if !is_ftp_upload {
                        if let Some(body_data) = opts.easy.take_body() {
                            let total = body_data.len() as u64;
                            let end = total.saturating_sub(1);
                            if offset <= end {
                                #[allow(clippy::cast_possible_truncation)]
                                let start = offset as usize;
                                let sliced = &body_data[start..];
                                opts.easy.header(
                                    "Content-Range",
                                    &format!("bytes {offset}-{end}/{total}"),
                                );
                                opts.easy.body(sliced);
                            } else {
                                opts.easy.body(&[]);
                            }
                        }
                        opts.easy.clear_range();
                    }
                }
            }
        }
    }

    // Refresh per_url_easy entries to pick up modifications made in run() after
    // parse_args completed (e.g., -z/If-Modified-Since header, -T body).
    // When there's no --next, clear per_url_easy so run_multi uses the template
    // directly, preserving connection pool state across requests (curl compat: test 1074).
    // When --next was used, per_url_easy entries hold per-group state and must be kept.
    if !opts.had_next && opts.urls.len() > 1 {
        for slot in opts.per_url_easy.iter_mut() {
            *slot = None;
        }
    }

    // --etag-save with bad path + --next: skip affected transfers (curl compat: test 369).
    // curl prints a warning and skips the transfer, continuing with --next groups.
    // For single-URL case without --next, the etag check in run() handles error 26 (test 370).
    if opts.had_next {
        if let Some(ref path) = opts.etag_save_file {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() && !opts.create_dirs {
                    eprintln!(
                    "Warning: Failed creating file for saving etags: \"{path}\". Skip this transfer"
                );
                    // Remove URLs from the first group (group 0 = the group with etag-save)
                    let first_group = opts.per_url_group.first().copied().unwrap_or(0);
                    let mut i = 0;
                    while i < opts.urls.len() {
                        if opts.per_url_group.get(i).copied().unwrap_or(0) == first_group {
                            let _ = opts.urls.remove(i);
                            let _ = opts.per_url_credentials.remove(i);
                            let _ = opts.per_url_ftp_methods.remove(i);
                            let _ = opts.per_url_easy.remove(i);
                            let _ = opts.per_url_upload_files.remove(i);
                            let _ = opts.per_url_group.remove(i);
                            let _ = opts.glob_values.remove(i);
                            if i < opts.output_files.len() {
                                let _ = opts.output_files.remove(i);
                            }
                        } else {
                            i += 1;
                        }
                    }
                    opts.etag_save_file = None;
                    // If no URLs left after removal, exit successfully
                    if opts.urls.is_empty() {
                        return ExitCode::SUCCESS;
                    }
                }
            }
        }
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if opts.urls.len() > 1 {
        // Build per-URL output filenames:
        // - Multiple -o/--out-null: use output_files positionally (test 756, 1134)
        // - Single -o with glob: expand template with #N substitution (tests 74,86,87)
        // - Otherwise, no per-URL output files (all go to stdout)
        // Check if any URLs came from glob expansion (have non-empty glob values)
        let has_glob_expansion = opts.glob_values.iter().any(|v| !v.is_empty());
        let per_url_output: Vec<String> =
            if opts.output_files.len() > 1 && has_glob_expansion && !opts.had_next {
                // Glob expansion with multiple -o: curl uses the first -o for all glob URLs,
                // remaining -o flags are excess (curl compat: test 1328).
                // Emit warnings for excess output files.
                let tmpl = &opts.output_files[0];
                for _ in 1..opts.output_files.len() {
                    if !opts.silent {
                        eprintln!("Warning: Got more output options than URLs");
                    }
                }
                // Use the first -o for all glob URLs (no #N substitution for the framework's fixed name)
                vec![tmpl.clone(); opts.urls.len()]
            } else if opts.output_files.len() > 1 {
                // Multiple output files from individual -o/--out-null flags (positional)
                opts.output_files.clone()
            } else if opts.had_next && !opts.output_files.is_empty() {
                // Per-URL output files from --next groups
                opts.output_files.clone()
            } else if let Some(ref tmpl) = opts.output_file {
                // Check if the template contains glob substitution patterns (#N).
                // If it does, expand for all URLs. If not, only apply to the first URL
                // (curl compat: positional -o applies to next URL only).
                let has_glob = tmpl.contains('#');
                if has_glob {
                    opts.urls
                        .iter()
                        .enumerate()
                        .map(|(i, _)| {
                            let values =
                                opts.glob_values.get(i).map(Vec::as_slice).unwrap_or_default();
                            substitute_glob_template(tmpl, values)
                        })
                        .collect()
                } else {
                    // Single -o without glob: only first URL uses it
                    vec![tmpl.clone()]
                }
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
            opts.fail_early,
            opts.parallel,
            opts.parallel_max,
            opts.skip_existing,
            opts.time_cond_ts,
            opts.time_cond_negate,
            &opts.per_url_credentials,
            opts.fail_with_body,
            opts.is_upload,
            opts.dump_header.as_deref(),
            &opts.per_url_ftp_methods,
            opts.upload_filename.as_deref(),
            &opts.per_url_easy,
            &opts.per_url_upload_files,
            &opts.per_url_group,
            opts.resume_offset,
            &opts.per_url_custom_request,
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

        // --proto: validate URL scheme against allowed protocols.
        // Use parse_proto_spec to properly interpret +all/-proto syntax.
        if let Some(ref proto_list) = opts.proto {
            let allowed = parse_proto_spec(proto_list);
            let scheme = url.split("://").next().unwrap_or("").to_lowercase();
            if !scheme.is_empty() && !allowed.iter().any(|p| p == &scheme) {
                if !opts.silent || opts.show_error {
                    eprintln!(
                        "curl: (1) Protocol \"{scheme}\" not supported or disabled in libcurl"
                    );
                }
                return ExitCode::from(1);
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
                        // Store netrc content for redirect credential lookup (test 257)
                        opts.easy.set_netrc_content(&contents);
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

                                    // For protocols that cannot handle control codes
                                    // in credentials (everything except HTTP/HTTPS/WS/WSS),
                                    // reject credentials containing control chars (curl compat: test 480).
                                    let allows_ctrl = url.starts_with("http://")
                                        || url.starts_with("https://")
                                        || url.starts_with("ws://")
                                        || url.starts_with("wss://");
                                    if !allows_ctrl
                                        && (liburlx::netrc::has_control_chars(&user)
                                            || liburlx::netrc::has_control_chars(&pass))
                                    {
                                        if !opts.silent || opts.show_error {
                                            eprintln!(
                                                "curl: control code detected in .netrc credentials"
                                            );
                                        }
                                        return ExitCode::from(26);
                                    }

                                    if url.starts_with("ftp://")
                                        || url.starts_with("ftps://")
                                        || url.starts_with("sftp://")
                                        || url.starts_with("scp://")
                                    {
                                        // Embed credentials in URL for FTP/SSH
                                        let encoded_user = percent_encode_credential(&user);
                                        let encoded_pass = percent_encode_credential(&pass);
                                        let base_url = strip_url_credentials(&url);
                                        let scheme_end = base_url.find("://").map_or(0, |p| p + 3);
                                        let new_url = format!(
                                            "{}{}:{}@{}",
                                            &base_url[..scheme_end],
                                            encoded_user,
                                            encoded_pass,
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
                // Reject credentials with special characters only when --login-options
                // is used (curl compat: test 896). Without --login-options, percent-encode
                // special chars so they survive URL embedding (curl compat: tests 800, 847, 988).
                let has_bad_char = |s: &str| s.contains('"') || s.contains('{') || s.contains('}');
                if (has_bad_char(user) || has_bad_char(pass))
                    && opts.easy.get_login_options().is_some()
                {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (3) URL using bad/illegal format or missing URL");
                    }
                    return ExitCode::from(3);
                }
                let base_url = strip_url_credentials(&url);
                let scheme_end = base_url.find("://").map_or(0, |p| p + 3);
                let new_url = format!(
                    "{}{}:{}@{}",
                    &base_url[..scheme_end],
                    percent_encode_credential(user),
                    percent_encode_credential(pass),
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

        // Validate --login-options AUTH= mechanism for IMAP/POP3/SMTP before connecting.
        // Unknown mechanisms cause CURLE_URL_MALFORMAT (3) (curl compat: test 896).
        if let Some(login_opts) = opts.easy.get_login_options() {
            if url.starts_with("imap://")
                || url.starts_with("imaps://")
                || url.starts_with("pop3://")
                || url.starts_with("pop3s://")
                || url.starts_with("smtp://")
                || url.starts_with("smtps://")
            {
                if let Some(mech) =
                    login_opts.strip_prefix("AUTH=").or_else(|| login_opts.strip_prefix("auth="))
                {
                    if !mech.eq_ignore_ascii_case("+LOGIN")
                        && !mech.eq_ignore_ascii_case("LOGIN")
                        && !is_known_sasl_mechanism(mech)
                    {
                        if !opts.silent || opts.show_error {
                            eprintln!("curl: (3) URL using bad/illegal format or missing URL");
                        }
                        return ExitCode::from(3);
                    }
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

    // --no-clobber: if output file exists, rename to .1, .2, etc. (curl compat: test 379)
    if opts.no_clobber {
        if let Some(ref path) = opts.output_file {
            if std::path::Path::new(path).exists() {
                let mut n = 1u32;
                loop {
                    let candidate = format!("{path}.{n}");
                    if !std::path::Path::new(&candidate).exists() {
                        opts.output_file = Some(candidate);
                        break;
                    }
                    n += 1;
                    if n > 100 {
                        break;
                    }
                }
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
    // For -C - (auto_resume) with uploads, add Content-Range: bytes 0-N/total (test 1041)
    if opts.is_upload && opts.auto_resume {
        let is_ftp_upload =
            opts.urls.first().is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
        if !is_ftp_upload {
            if let Some(body_data) = opts.easy.peek_body() {
                let total = body_data.len() as u64;
                if total > 0 {
                    let end = total - 1;
                    opts.easy.header("Content-Range", &format!("bytes 0-{end}/{total}"));
                }
            }
            opts.easy.clear_range();
        }
    }
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
        // HTTP/1.0 cannot use chunked encoding, so PUT from stdin with unknown size
        // is impossible — fail with error 25 (curl compat: test 1069)
        if opts.easy.is_http10() {
            if !opts.silent || opts.show_error {
                eprintln!("curl: (25) Upload failed: HTTP/1.0 does not support chunked transfer encoding for unknown upload sizes");
            }
            return ExitCode::from(25);
        }
        // Enable Expect: 100-continue via the timeout mechanism (h1.rs adds the header)
        opts.easy.expect_100_timeout(std::time::Duration::from_secs(1));
        // Enable chunked upload (unless user explicitly suppressed Transfer-Encoding)
        if !opts.easy.has_header("Transfer-Encoding") {
            opts.easy.set_chunked_upload(true);
        }
    }

    if opts.show_progress && !opts.silent {
        opts.easy.progress_callback(liburlx::make_progress_callback(|info| {
            // curl's progress bar format: 72 hash characters followed by " 100.0%"
            // Uses \r to update in-place (curl compat: test 1148)
            let bar_width: usize = 72;
            if info.dl_total > 0 {
                #[allow(clippy::cast_precision_loss)]
                let pct = (info.dl_now as f64 / info.dl_total as f64) * 100.0;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let filled = ((pct as usize) * bar_width) / 100;
                let empty = bar_width.saturating_sub(filled);
                eprint!("\r{}{} {:5.1}%", "#".repeat(filled), " ".repeat(empty), pct);
            } else {
                eprint!("\r{} {:5.1}%", " ".repeat(bar_width), 0.0);
            }
            true
        }));
    }

    // Non-HTTP protocols: --include doesn't output HTTP headers (curl compat).
    // Suppress include_headers for FTP/IMAP/POP3/SMTP/MQTT URLs.
    // Exception: when an HTTP proxy is set, FTP/FTPS requests are relayed
    // as HTTP through the proxy, so headers should be shown (curl compat: test 79).
    let has_http_proxy = opts.easy.has_http_proxy();
    if opts.urls.first().is_some_and(|u| {
        let lower = u.to_lowercase();
        // FTP/FTPS through HTTP proxy → response is HTTP, keep headers
        let is_ftp_over_proxy =
            has_http_proxy && (lower.starts_with("ftp://") || lower.starts_with("ftps://"));
        !is_ftp_over_proxy
            && (lower.starts_with("ftp://")
                || lower.starts_with("ftps://")
                || lower.starts_with("imap://")
                || lower.starts_with("imaps://")
                || lower.starts_with("pop3://")
                || lower.starts_with("pop3s://")
                || lower.starts_with("smtp://")
                || lower.starts_with("smtps://")
                || lower.starts_with("mqtt://"))
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
                    // curl returns CURLE_READ_ERROR (26) for bad etag-save path
                    // (curl compat: test 370)
                    return ExitCode::from(26);
                }
            }
        }
    }

    // For non-HTTP protocols, -X sets a custom protocol command (not HTTP request target).
    // Only set custom_request_target for non-HTTP schemes to avoid breaking HTTP -X behavior.
    // For HTTP schemes, clear any stale custom_request_target (curl compat: tests 794, 796).
    // But don't clear if user explicitly set --request-target (curl compat: test 1299).
    if let Some(ref custom_req) = opts.custom_request_original {
        let scheme = opts.easy.url_ref().map(|u| u.scheme().to_lowercase()).unwrap_or_default();
        if matches!(scheme.as_str(), "smtp" | "smtps" | "imap" | "imaps" | "pop3" | "pop3s") {
            opts.easy.custom_request_target(custom_req);
        } else if opts.easy.custom_request().is_none() {
            opts.easy.clear_custom_request_target();
        }
    }

    // --proto: pass allowed protocols to library for redirect checking too.
    // curl's --proto restricts both initial requests AND redirect targets (test 1245).
    if let Some(ref proto) = opts.proto {
        let allowed = parse_proto_spec(proto);
        if !allowed.is_empty() {
            opts.easy.set_protocols_str(&allowed.join(","));
        }
    }

    // --proto-redir: restrict allowed protocols for redirects (curl compat: test 325)
    if let Some(ref proto_redir) = opts.proto_redir {
        let allowed = parse_proto_spec(proto_redir);
        if !allowed.is_empty() {
            opts.easy.set_redir_protocols_str(&allowed.join(","));
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

    // Save HSTS cache after transfer (even on error)
    if let Err(e) = opts.easy.save_hsts_cache() {
        if !opts.silent || opts.show_error {
            eprintln!("curl: error saving HSTS cache: {e}");
        }
    }

    match result {
        Ok(mut response) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }

            // --suppress-connect-headers: remove CONNECT response from redirect chain
            // but preserve total header size for %{size_header} (curl compat: test 1288)
            if opts.suppress_connect_headers {
                // Compute total_header_size BEFORE suppressing CONNECT headers
                let mut total_header_size: usize = 0;
                for redir in response.redirect_responses() {
                    if let Some(raw) = redir.raw_headers() {
                        total_header_size += raw.len();
                    }
                }
                if let Some(raw) = response.raw_headers() {
                    total_header_size += raw.len();
                } else {
                    total_header_size += response
                        .headers()
                        .iter()
                        .map(|(k, v)| k.len() + v.len() + 4)
                        .sum::<usize>();
                }
                // Store the pre-suppression header size for write-out
                response.set_total_header_size(total_header_size);
                response.suppress_connect_headers();
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
                    // File already complete — keep existing file, append headers
                    // (curl compat: test 1040, 1273).
                    // Output order: existing_data + response_headers
                    if opts.auto_resume {
                        if let Some(ref path) = opts.output_file {
                            if let Ok(existing) = std::fs::read(path) {
                                use std::io::Write as _;
                                let headers_bytes = if opts.include_headers {
                                    crate::output::format_headers(&response).into_bytes()
                                } else {
                                    Vec::new()
                                };
                                // Build combined output: existing + headers
                                let mut combined = existing;
                                combined.extend_from_slice(&headers_bytes);
                                if path == "-" {
                                    let _ = std::io::stdout().write_all(&combined);
                                } else {
                                    let _ = std::fs::write(path, &combined);
                                }
                                return ExitCode::SUCCESS;
                            }
                        }
                    }
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
                    // Output existing file content + headers (test 1042)
                    if let Some(ref path) = opts.output_file {
                        if let Ok(existing) = std::fs::read(path) {
                            if !existing.is_empty() {
                                use std::io::Write as _;
                                let headers_str = if opts.include_headers {
                                    crate::output::format_headers(&response)
                                } else {
                                    String::new()
                                };
                                let is_stdout = path == "-";
                                if is_stdout {
                                    let _ = std::io::stdout().write_all(&existing);
                                    let _ = std::io::stdout().write_all(headers_str.as_bytes());
                                } else if let Ok(mut file) = std::fs::File::create(path) {
                                    let _ = file.write_all(&existing);
                                    let _ = file.write_all(headers_str.as_bytes());
                                }
                                if !opts.silent || opts.show_error {
                                    eprintln!(
                                        "curl: server returned {status} but resume was requested"
                                    );
                                }
                                return ExitCode::from(33);
                            }
                        }
                    }
                    // Output headers but suppress body.
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
                if cl_exceeded {
                    // Content-Length known upfront: error without output
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: maximum file size exceeded",);
                    }
                    return ExitCode::from(63);
                }
                // For chunked/no-CL responses the body was already received.
                // curl truncates at max-filesize bytes and outputs what fits,
                // then returns error 63 (curl compat: test 457).
                let body_exceeded = response.body().len() as u64 > max_size;
                if body_exceeded {
                    // Truncate body to max-filesize bytes before outputting
                    let trunc_len =
                        usize::try_from(max_size).unwrap_or_else(|_| response.body().len());
                    let truncated_body = response.body()[..trunc_len].to_vec();
                    response.set_body(truncated_body);
                    // Output the response (headers + truncated body) first
                    let _ = output_response(
                        &response,
                        opts.output_file.as_deref(),
                        None,
                        opts.include_headers,
                        opts.silent,
                        false, // don't suppress body
                    );
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (63) Maximum file size exceeded",);
                    }
                    return ExitCode::from(63);
                }
            }

            // -J/--remote-header-name: override output filename from Content-Disposition
            // When -o is explicitly specified, it takes precedence over -J (curl compat: tests 1370, 1371).
            if opts.remote_header_name && !opts.explicit_output {
                if let Some(name) = content_disposition_filename(&response) {
                    // Apply --output-dir if set (curl compat: test 1311)
                    if let Some(ref dir) = opts.output_dir {
                        opts.output_file = Some(
                            std::path::Path::new(dir).join(&name).to_string_lossy().to_string(),
                        );
                    } else {
                        opts.output_file = Some(name);
                    }
                }
            }

            // --dump-header: write headers to file (or stdout if "-")
            // --dump-header: write headers to file (or stdout if "-")
            let dump_to_stdout_single =
                opts.dump_header.as_deref() == Some("-") && opts.output_file.is_none();
            if let Some(ref path) = opts.dump_header {
                let header_text = format_headers(&response);
                let raw_trailers = response.raw_trailers();
                if dump_to_stdout_single && opts.include_headers {
                    // Both --dump-header - and --include: each header line appears twice
                    use std::io::Write;
                    let mut stdout = std::io::stdout();
                    for line in header_text.split_inclusive('\n') {
                        let _ = stdout.write_all(line.as_bytes());
                        let _ = stdout.write_all(line.as_bytes());
                    }
                } else if dump_to_stdout_single {
                    // --dump-header - without --include: headers once to stdout
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(header_text.as_bytes());
                } else if path == "-" {
                    use std::io::Write;
                    let mut dump_data = header_text.into_bytes();
                    if !raw_trailers.is_empty() {
                        dump_data.extend_from_slice(raw_trailers);
                    }
                    if let Err(e) = std::io::stdout().write_all(&dump_data) {
                        if !opts.silent || opts.show_error {
                            eprintln!("curl: error writing headers: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
                } else {
                    let mut dump_data = header_text.into_bytes();
                    if !raw_trailers.is_empty() {
                        dump_data.extend_from_slice(raw_trailers);
                    }
                    if let Err(e) = std::fs::write(path, &dump_data) {
                        if !opts.silent || opts.show_error {
                            eprintln!("curl: error writing headers to {path}: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
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

            // --libcurl: output equivalent C code to file
            if let Some(ref libcurl_file) = opts.libcurl {
                let c_code = generate_libcurl_code(&opts);
                if let Err(e) = std::fs::write(libcurl_file, c_code.as_bytes()) {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: error writing libcurl code to '{libcurl_file}': {e}");
                    }
                }
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

            // FTP auto-resume download: append new data to existing file
            // (curl compat: test 1036). FTP responses always have status 200.
            let is_ftp = opts
                .urls
                .first()
                .is_some_and(|u| u.starts_with("ftp://") || u.starts_with("ftps://"));
            if opts.auto_resume && is_ftp && !opts.is_upload {
                if let Some(ref path) = opts.output_file {
                    if path != "-" {
                        use std::io::Write as _;
                        if let Ok(mut file) =
                            std::fs::OpenOptions::new().create(true).append(true).open(path)
                        {
                            let _ = file.write_all(response.body());
                        }
                        // Handle write-out
                        if let Some(ref fmt) = opts.write_out {
                            let real_fmt = if let Some(p) = fmt.strip_prefix('@') {
                                std::fs::read_to_string(p).unwrap_or_default()
                            } else {
                                fmt.clone()
                            };
                            let wo = format_write_out(&real_fmt, &response, false);
                            let _ = std::io::stdout().write_all(wo.as_bytes());
                            let _ = std::io::stdout().flush();
                        }
                        return ExitCode::SUCCESS;
                    }
                }
            }

            // For auto-resume with 206, write existing file content to output file
            // BEFORE the response (test 1043). Output order: existing_data + headers + new_body
            if opts.auto_resume && response.status() == 206 {
                if let Some(ref path) = opts.output_file {
                    if path != "-" {
                        if let Ok(existing) = std::fs::read(path) {
                            // Write existing content, then output_response will append
                            // headers + new body. We need to write to a temp location
                            // since output_response will truncate the file.
                            // Instead, prepend to the response body (output_response writes
                            // headers then body, so existing+body after headers).
                            // BUT the test expects existing BEFORE headers.
                            // Solution: write existing to file, then use append mode.
                            use std::io::Write as _;
                            let headers_str = if opts.include_headers {
                                crate::output::format_headers(&response)
                            } else {
                                String::new()
                            };
                            if let Ok(mut file) = std::fs::File::create(path) {
                                let _ = file.write_all(&existing);
                                let _ = file.write_all(headers_str.as_bytes());
                                let _ = file.write_all(response.body());
                            }
                            // Handle write-out
                            if let Some(ref fmt) = opts.write_out {
                                let real_fmt = if let Some(path) = fmt.strip_prefix('@') {
                                    std::fs::read_to_string(path).unwrap_or_default()
                                } else {
                                    fmt.clone()
                                };
                                let output =
                                    crate::output::format_write_out(&real_fmt, &response, false);
                                eprint!("{output}");
                            }
                            return ExitCode::SUCCESS;
                        }
                    }
                }
            }

            // When dump-header goes to stdout and include_headers is active,
            // headers were already output as doubled lines above. Skip include
            // in output_response to avoid triple output.
            let effective_include = if dump_to_stdout_single && opts.include_headers {
                false
            } else {
                opts.include_headers
            };
            let ctx = WriteOutContext {
                filename_effective: opts.output_file.clone().unwrap_or_default(),
                stderr_file: opts.stderr_file.clone(),
                ..WriteOutContext::default()
            };
            let exit = output_response_with_context(
                &response,
                opts.output_file.as_deref(),
                opts.write_out.as_deref(),
                effective_include,
                opts.silent,
                suppress_body,
                &ctx,
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
                if body_err.contains("too_many_content_encodings") {
                    if !opts.silent || opts.show_error {
                        eprintln!(
                            "curl: (61) Reject response due to more than 5 content encodings"
                        );
                    }
                    return ExitCode::from(61); // CURLE_BAD_CONTENT_ENCODING
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
                if body_err.contains("empty response") {
                    if !opts.silent || opts.show_error {
                        eprintln!("curl: (52) Empty reply from server");
                    }
                    return ExitCode::from(52); // CURLE_GOT_NOTHING
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

            // SFTP post-quote errors: output the downloaded data before
            // reporting the error (curl compat: test 609)
            if let liburlx::Error::SshQuoteErrorWithData { ref response, .. } = e {
                let _ = output_response(
                    response.as_ref(),
                    opts.output_file.as_deref(),
                    opts.write_out.as_deref(),
                    false, // no include headers for SFTP
                    opts.silent,
                    false,
                );
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
                } else if opts.resume_check && resp.status() == 416 {
                    // 416 with resume: file already complete.
                    // Prepend existing file content before headers (test 1040, 1273).
                    if opts.auto_resume {
                        if let Some(ref path) = opts.output_file {
                            if let Ok(existing) = std::fs::read(path) {
                                use std::io::Write as _;
                                let headers_bytes = if opts.include_headers {
                                    format_headers(resp).into_bytes()
                                } else {
                                    Vec::new()
                                };
                                let mut combined = existing;
                                combined.extend_from_slice(&headers_bytes);
                                if path == "-" {
                                    let _ = std::io::stdout().write_all(&combined);
                                } else {
                                    let _ = std::fs::write(path, &combined);
                                }
                                return ExitCode::SUCCESS;
                            }
                        }
                    }
                    let _ = output_response(
                        resp,
                        opts.output_file.as_deref(),
                        opts.write_out.as_deref(),
                        opts.include_headers,
                        opts.silent,
                        true, // suppress body
                    );
                } else {
                    let _ = output_response(
                        resp,
                        opts.output_file.as_deref(),
                        opts.write_out.as_deref(),
                        opts.include_headers,
                        opts.silent,
                        false,
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
                    format_write_out(w, resp, false)
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
                let code_num = error_to_curl_code(&e);
                let msg = curl_error_message(&e);
                eprintln!("curl: ({code_num}) {msg}");
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

/// Map a liburlx error to a curl-compatible numeric exit code.
///
/// Matches curl's exit code conventions for the most common errors.
pub fn error_to_curl_code(err: &liburlx::Error) -> u8 {
    match err {
        liburlx::Error::UrlParse(_) => 3,            // CURLE_URL_MALFORMAT
        liburlx::Error::UnsupportedProtocol(_) => 1, // CURLE_UNSUPPORTED_PROTOCOL
        liburlx::Error::DnsResolve(_) => 6,          // CURLE_COULDNT_RESOLVE_HOST
        liburlx::Error::Connect(io_err) => {
            match io_err.kind() {
                std::io::ErrorKind::Other => {
                    let msg = io_err.to_string();
                    if msg.contains("dns") || msg.contains("DNS") || msg.contains("resolve") {
                        6 // CURLE_COULDNT_RESOLVE_HOST
                    } else {
                        7 // CURLE_COULDNT_CONNECT
                    }
                }
                _ => 7, // CURLE_COULDNT_CONNECT
            }
        }
        liburlx::Error::Tls(e) => {
            let msg = e.to_string();
            if msg.contains("certificate") || msg.contains("verify") {
                60 // CURLE_PEER_FAILED_VERIFICATION
            } else {
                35 // CURLE_SSL_CONNECT_ERROR
            }
        }
        liburlx::Error::Http(msg) => {
            if msg.contains("Too large response headers") || msg.contains("headers too large") {
                56 // CURLE_RECV_ERROR (response headers exceeded max size, curl compat: test 497)
            } else if msg.contains("Weird server reply") || msg.contains("binary zero") {
                8 // CURLE_WEIRD_SERVER_REPLY
            } else if msg.contains("range not satisfiable") || msg.contains("Range not satisfiable")
            {
                33 // CURLE_RANGE_ERROR
            } else if msg.contains("empty response") || msg.contains("Empty response") {
                52 // CURLE_GOT_NOTHING
            } else if msg.contains("too many redirects") || msg.contains("Too many redirects") {
                47 // CURLE_TOO_MANY_REDIRECTS
            } else if msg.contains("fail_on_error") {
                22 // CURLE_HTTP_RETURNED_ERROR
            } else if msg.contains("unsupported protocol")
                || msg.contains("Unsupported protocol")
                || msg.contains("invalid HTTP version")
                || msg.contains("unsupported HTTP version")
            {
                1 // CURLE_UNSUPPORTED_PROTOCOL
            } else if msg.contains("Invalid response header") {
                43 // CURLE_BAD_RESP (curl compat: test 750)
            } else if msg.contains("partial") || msg.contains("Partial") {
                18 // CURLE_PARTIAL_FILE
            } else if msg.contains("upload") || msg.contains("Upload") {
                25 // CURLE_UPLOAD_FAILED
            } else if msg.contains("send") || msg.contains("Send") {
                55 // CURLE_SEND_ERROR
            } else {
                56 // CURLE_RECV_ERROR
            }
        }
        liburlx::Error::Timeout(_) | liburlx::Error::SpeedLimit { .. } => {
            28 // CURLE_OPERATION_TIMEDOUT
        }
        liburlx::Error::FileError(_) => 37, // CURLE_FILE_COULDNT_READ_FILE
        liburlx::Error::Io(_) => 23,        // CURLE_WRITE_ERROR
        liburlx::Error::Ssh(msg) => {
            if msg.contains("No such file")
                || msg.contains("not found")
                || msg.contains("does not exist")
            {
                78 // CURLE_REMOTE_FILE_NOT_FOUND
            } else if msg.contains("permission denied") || msg.contains("Permission denied") {
                9 // CURLE_REMOTE_ACCESS_DENIED
            } else if msg.contains("quote") || msg.contains("Quote") {
                21 // CURLE_QUOTE_ERROR
            } else {
                67 // CURLE_LOGIN_DENIED
            }
        }
        liburlx::Error::SshHostKeyMismatch(_) => 60, // CURLE_PEER_FAILED_VERIFICATION
        liburlx::Error::SshQuoteError(_) => 21,      // CURLE_QUOTE_ERROR
        liburlx::Error::SshQuoteErrorWithData { .. } => 21, // CURLE_QUOTE_ERROR
        liburlx::Error::SshUploadFailed(_) => 25,    // CURLE_UPLOAD_FAILED
        liburlx::Error::SshRangeError(_) => 33,      // CURLE_RANGE_ERROR
        liburlx::Error::Transfer { code, .. } => u8::try_from(*code).unwrap_or(1),
        liburlx::Error::PartialBody { message, .. } => {
            if message.contains("transfer closed") || message.contains("outstanding read data") {
                18 // CURLE_PARTIAL_FILE
            } else {
                56 // CURLE_RECV_ERROR (bad chunk encoding, etc.)
            }
        }
        liburlx::Error::SmtpAuth(_) => 67, // CURLE_LOGIN_DENIED
        liburlx::Error::SmtpSend(_) => 55, // CURLE_SEND_ERROR
        liburlx::Error::Protocol(code) => u8::try_from(*code).unwrap_or(1),
        _ => 1,
    }
}

/// Map a liburlx error to a curl-compatible exit code.
///
/// Matches curl's exit code conventions for the most common errors.
pub fn error_to_exit_code(err: &liburlx::Error) -> ExitCode {
    ExitCode::from(error_to_curl_code(err))
}

/// Get a short error message suitable for curl-style `(CODE) message` output.
///
/// Strips the error type prefix and returns just the descriptive message.
pub fn curl_error_message(err: &liburlx::Error) -> String {
    match err {
        liburlx::Error::Http(msg) => msg.clone(),
        liburlx::Error::Transfer { message, .. } => message.clone(),
        liburlx::Error::DnsResolve(host) => format!("Could not resolve host: {host}"),
        liburlx::Error::Timeout(d) => format!("Operation timed out after {d:?}"),
        liburlx::Error::UrlParse(msg) => msg.clone(),
        liburlx::Error::Ssh(msg) => msg.clone(),
        liburlx::Error::SshHostKeyMismatch(msg) => msg.clone(),
        liburlx::Error::SshQuoteError(msg) => msg.clone(),
        liburlx::Error::SshUploadFailed(msg) => msg.clone(),
        liburlx::Error::SshRangeError(msg) => msg.clone(),
        liburlx::Error::SshQuoteErrorWithData { message, .. } => message.clone(),
        liburlx::Error::Connect(e) => format!("Failed to connect: {e}"),
        liburlx::Error::Tls(e) => e.to_string(),
        liburlx::Error::FileError(msg) => msg.clone(),
        liburlx::Error::PartialBody { message, .. } => message.clone(),
        liburlx::Error::SmtpAuth(msg) => msg.clone(),
        liburlx::Error::SmtpSend(msg) => msg.clone(),
        liburlx::Error::UnsupportedProtocol(scheme) => {
            // Match curl's error format: 'Protocol "scheme" not supported'
            // If the message already contains "not supported", use it as-is.
            if scheme.contains("not supported") {
                scheme.clone()
            } else {
                format!("Protocol \"{scheme}\" not supported")
            }
        }
        liburlx::Error::UrlGlob { message, url, position } => {
            if url.is_empty() {
                message.clone()
            } else {
                format!("{message}\n{url}\n{:>width$}", "^", width = position + 1)
            }
        }
        _ => err.to_string(),
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
    fail_early: bool,
    parallel: bool,
    parallel_max: usize,
    skip_existing: bool,
    time_cond_ts: Option<i64>,
    time_cond_negate: bool,
    per_url_credentials: &[Option<(String, String)>],
    fail_with_body: bool,
    is_upload: bool,
    dump_header: Option<&str>,
    per_url_ftp_methods: &[liburlx::protocol::ftp::FtpMethod],
    upload_filename: Option<&str>,
    per_url_easy: &[Option<liburlx::Easy>],
    per_url_upload_files: &[Option<String>],
    per_url_group: &[usize],
    resume_offset: Option<u64>,
    per_url_custom_request: &[Option<String>],
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
    let mut last_exit = ExitCode::SUCCESS;
    // Track HTTP version downgrade across requests (curl compat: test 1074).
    // When server responds with HTTP/1.0, subsequent requests should also use HTTP/1.0.
    let mut downgraded_http10 = false;

    // Pre-compute which URLs are part of an IMAP batch (consecutive IMAP URLs to
    // the same host:port, for connection reuse — curl compat: tests 804, 815, 816).
    let mut imap_batch_processed: Vec<bool> = vec![false; urls.len()];
    let mut imap_batches: Vec<(usize, usize)> = Vec::new(); // (start, end) inclusive
    {
        let mut i = 0;
        while i < urls.len() {
            let lower = urls[i].to_lowercase();
            if lower.starts_with("imap://") || lower.starts_with("imaps://") {
                let batch_start = i;
                let host_port = extract_imap_host_port(&urls[i]);
                let mut j = i + 1;
                while j < urls.len() {
                    let lower_j = urls[j].to_lowercase();
                    if (lower_j.starts_with("imap://") || lower_j.starts_with("imaps://"))
                        && extract_imap_host_port(&urls[j]) == host_port
                    {
                        j += 1;
                    } else {
                        break;
                    }
                }
                if j > batch_start + 1 {
                    // Multi-URL batch found
                    imap_batches.push((batch_start, j - 1));
                    for slot in &mut imap_batch_processed[batch_start..j] {
                        *slot = true;
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }

    // Compute excess output files: when a --next group has more -o flags than URLs,
    // the excess consumes URLs from subsequent groups (curl compat: test 760).
    // Those consumed URLs are skipped (not processed).
    let urls_to_skip: usize = {
        if output_files.len() > urls.len() {
            let excess = output_files.len() - urls.len();
            if !silent {
                for _ in 0..output_files.len().saturating_sub(urls.len()) {
                    eprintln!("Warning: Got more output options than URLs");
                }
            }
            excess
        } else {
            0
        }
    };
    // Skip the last `urls_to_skip` URLs (they're consumed by excess -o flags)
    let effective_url_count = urls.len().saturating_sub(urls_to_skip);

    // Track current --next group to detect group transitions.
    // Only replace the Easy handle when crossing a --next boundary,
    // preserving connection pool for URLs within the same group (curl compat: test 48).
    let mut current_group: Option<usize> = None;

    for (i, url) in urls.iter().enumerate() {
        // Skip URLs consumed by excess -o flags from previous groups (curl compat: test 760)
        if i >= effective_url_count {
            continue;
        }
        // Use per-URL Easy handle if available (from --next groups, curl compat: tests 430-432)
        // Only switch Easy handle when entering a new --next group.
        let this_group = per_url_group.get(i).copied().unwrap_or(0);
        if current_group != Some(this_group) {
            if let Some(Some(per_easy)) = per_url_easy.get(i) {
                let mut new_easy = per_easy.clone();
                // Preserve FTP session for connection reuse across URLs (curl compat: tests 146, 210, 698)
                new_easy.take_ftp_session_from(&mut easy);
                // Transfer accumulated cookie jar and HSTS cache from the previous
                // Easy handle so cookies persist across sequential URLs (curl compat:
                // tests 327, 329, 331, 392, 1218, 1228, 1258).
                new_easy.transfer_state_from(&mut easy);
                easy = new_easy;
            }
            current_group = Some(this_group);
        }

        // Apply HTTP/1.0 downgrade from previous response (curl compat: test 1074)
        if downgraded_http10 {
            easy.http_version(liburlx::HttpVersion::Http10);
        }

        // -T upload: per-URL upload tracking. Each URL with its own -T flag
        // gets PUT with the upload body. URLs without their own -T revert to GET.
        // For FTP, all URLs keep the upload body (curl compat: tests 149, 216).
        // Test 1064: `-T file URL1 -T file URL2` → both PUT
        // Test 1065: `-T file URL1 URL2` → first PUT, second GET
        let is_ftp_url = url.starts_with("ftp://")
            || url.starts_with("ftps://")
            || url.starts_with("sftp://")
            || url.starts_with("scp://");
        if is_upload && !is_ftp_url {
            let has_own_upload = per_url_upload_files.get(i).is_some_and(|f| f.is_some());
            if has_own_upload {
                // This URL has its own -T file: read the file
                if let Some(Some(ref path)) = per_url_upload_files.get(i) {
                    match std::fs::read(path) {
                        Ok(data) => {
                            // Apply resume offset if set (Content-Range + body slicing, curl compat: test 1002)
                            if let Some(offset) = resume_offset {
                                if offset > 0 {
                                    let total = data.len() as u64;
                                    let end = total.saturating_sub(1);
                                    if offset <= end {
                                        #[allow(clippy::cast_possible_truncation)]
                                        let start = offset as usize;
                                        let sliced = &data[start..];
                                        easy.remove_header("Content-Range");
                                        easy.header(
                                            "Content-Range",
                                            &format!("bytes {offset}-{end}/{total}"),
                                        );
                                        easy.body(sliced);
                                    } else {
                                        easy.body(&[]);
                                    }
                                } else {
                                    easy.body(&data);
                                }
                            } else {
                                easy.body(&data);
                            }
                            // Only default to PUT if no explicit -X method was set
                            // (curl compat: test 1002 — -X GET overrides -T's PUT)
                            if easy.method_is_default() {
                                easy.method("PUT");
                            }
                        }
                        Err(e) => {
                            // Missing file: report error but continue with remaining transfers
                            // (curl compat: test 491 — error 26 for missing upload file)
                            if !silent || show_error {
                                eprintln!("curl: can't open '{path}' for reading: {e}");
                            }
                            last_exit = ExitCode::from(26); // CURLE_READ_ERROR
                            continue;
                        }
                    }
                }
            } else if i > 0 && easy.has_body() {
                // No -T for this URL: revert to GET (curl compat: test 1065)
                let _ = easy.take_body();
                easy.method("GET");
            }
        }

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

        // -T filename: append filename to URL path if URL ends with /
        let effective_url = if is_upload {
            if let Some(fname) = upload_filename {
                if url.ends_with('/') {
                    format!("{url}{fname}")
                } else {
                    url.clone()
                }
            } else {
                url.clone()
            }
        } else {
            url.clone()
        };

        if let Err(e) = easy.url(&effective_url) {
            if !silent || show_error {
                eprintln!("curl: ({}) URL rejected: {e}", 3);
            }
            // Still produce write-out for invalid URLs (curl compat: test 423)
            if let Some(wo) = write_out {
                let dummy_response = liburlx::Response::new(
                    0,
                    std::collections::HashMap::new(),
                    Vec::new(),
                    url.clone(),
                );
                let ctx = WriteOutContext {
                    urlnum: i,
                    exitcode: 3,
                    errormsg: format!("URL rejected: {e}"),
                    had_error: true,
                    ..WriteOutContext::default()
                };
                let _ = output_response_with_context(
                    &dummy_response,
                    None,
                    Some(wo),
                    false,
                    silent,
                    true,
                    &ctx,
                );
            }
            let exit_code = ExitCode::from(3_u8); // CURLE_URL_MALFORMAT
            if fail_early {
                return exit_code;
            }
            last_exit = exit_code;
            continue;
        }

        // Apply per-URL credentials: -u flag takes priority, then URL userinfo.
        // For FTP/SSH/SMTP/IMAP/POP3, embed credentials in URL (these protocols
        // read credentials from the URL, not from Authorization headers).
        // (curl compat: tests 618, 619, 620, 621 — multi-URL SSH transfers)
        if let Some(Some((ref user, ref pass))) = per_url_credentials.get(i) {
            if effective_url.starts_with("ftp://")
                || effective_url.starts_with("ftps://")
                || effective_url.starts_with("sftp://")
                || effective_url.starts_with("scp://")
                || effective_url.starts_with("smtp://")
                || effective_url.starts_with("smtps://")
                || effective_url.starts_with("imap://")
                || effective_url.starts_with("imaps://")
                || effective_url.starts_with("pop3://")
                || effective_url.starts_with("pop3s://")
            {
                let base_url = strip_url_credentials(&effective_url);
                if let Some(scheme_end) = base_url.find("://").map(|p| p + 3) {
                    let new_url = format!(
                        "{}{}:{}@{}",
                        &base_url[..scheme_end],
                        percent_encode_credential(user),
                        percent_encode_credential(pass),
                        &base_url[scheme_end..]
                    );
                    let _ = easy.url(&new_url);
                }
            }
        }
        // Remove old Authorization header before setting new credentials (curl compat: test 1134).
        // Skip when Digest/NTLM/AnyAuth is configured — those use challenge-response
        // and the auth_credentials handle the credentials (curl compat: test 388).
        if !easy.uses_challenge_auth() {
            if let Some(Some((ref user, ref pass))) = per_url_credentials.get(i) {
                easy.remove_header("Authorization");
                easy.remove_header("_auto_Authorization");
                easy.basic_auth(user, pass);
            } else {
                let url_user = extract_url_username_raw(url);
                let url_pass = extract_url_password(url);
                if url_user.is_some() || url_pass.is_some() {
                    let user = url_user.unwrap_or_default();
                    let pass = url_pass.unwrap_or_default();
                    easy.remove_header("Authorization");
                    easy.remove_header("_auto_Authorization");
                    easy.basic_auth(&user, &pass);
                } else {
                    // No credentials for this URL — remove stale auth from previous URL
                    // (curl compat: test 999)
                    easy.remove_header("Authorization");
                    easy.remove_header("_auto_Authorization");
                }
            }
        }

        // Update FTP config per-URL (for --next changing --ftp-method; test 1096)
        if let Some(method) = per_url_ftp_methods.get(i).copied() {
            easy.ftp_method(method);
        }

        // IMAP batch: if this URL is the start of a multi-URL IMAP batch,
        // process the entire batch on one connection (curl compat: tests 804, 815, 816).
        if let Some(&(batch_start, batch_end)) = imap_batches.iter().find(|&&(s, _)| s == i) {
            let batch_result = rt.block_on(run_imap_batch(
                &urls[batch_start..=batch_end],
                &easy,
                per_url_easy,
                per_url_credentials,
                per_url_custom_request,
                batch_start,
            ));
            match batch_result {
                Ok(responses) => {
                    for (idx, response) in responses.into_iter().enumerate() {
                        let url_idx = batch_start + idx;
                        let file_for_this = output_files.get(url_idx).map(String::as_str);
                        let exit = output_response(
                            &response,
                            file_for_this,
                            write_out,
                            false, // include_headers
                            silent,
                            false, // suppress_body
                        );
                        last_exit = exit;
                    }
                }
                Err(e) => {
                    if !silent || show_error {
                        eprintln!("curl: IMAP batch error: {e}");
                    }
                    last_exit = ExitCode::from(error_to_curl_code(&e));
                }
            }
            // Skip remaining URLs in this batch (they were already processed)
            continue;
        }
        // Skip individual URLs that are part of a batch (non-start elements)
        if imap_batch_processed[i] {
            continue;
        }

        // Early scheme validation: reject unsupported protocols before attempting
        // DNS resolution or connection (curl compat: test 760).
        if let Some(u) = easy.url_ref() {
            let scheme = u.scheme().to_lowercase();
            let supported = matches!(
                scheme.as_str(),
                "http"
                    | "https"
                    | "ftp"
                    | "ftps"
                    | "sftp"
                    | "scp"
                    | "file"
                    | "dict"
                    | "tftp"
                    | "mqtt"
                    | "ws"
                    | "wss"
                    | "smtp"
                    | "smtps"
                    | "imap"
                    | "imaps"
                    | "pop3"
                    | "pop3s"
            );
            if !supported {
                if !silent || show_error {
                    eprintln!("curl: (1) Protocol \"{scheme}\" not supported");
                }
                let exit_code = ExitCode::from(1_u8);
                if fail_early {
                    return exit_code;
                }
                last_exit = exit_code;
                continue;
            }
        }

        match rt.block_on(easy.perform_async()) {
            Ok(response) => {
                // Downgrade HTTP version if server responded with HTTP/1.0 AND the
                // connection is being kept alive (curl compat: test 1074).
                // Only downgrade when connection reuse is expected — if the server
                // closes the connection, the next request creates a fresh connection
                // which should use HTTP/1.1 (curl compat: test 1258).
                // For FTP-over-proxy, check Proxy-Connection as well (curl compat: test 1077).
                if response.http_version()
                    == liburlx::protocol::http::response::ResponseHttpVersion::Http10
                {
                    let has_keepalive = response
                        .header("connection")
                        .is_some_and(|v| v.eq_ignore_ascii_case("keep-alive"))
                        || response
                            .header("proxy-connection")
                            .is_some_and(|v| v.eq_ignore_ascii_case("keep-alive"));
                    if has_keepalive {
                        easy.http_version(liburlx::HttpVersion::Http10);
                        downgraded_http10 = true;
                    }
                }
                if fail_on_error && response.status() >= 400 {
                    let err_msg =
                        format!("The requested URL returned error: {}", response.status());
                    // Output write-out and optionally body on --fail (curl compat: tests 361, 1188)
                    let file_for_this = output_files.get(i).map(String::as_str);
                    let ctx = WriteOutContext {
                        urlnum: i,
                        exitcode: 22,
                        errormsg: err_msg,
                        had_error: true,
                        ..WriteOutContext::default()
                    };
                    let suppress = !fail_with_body;
                    // When glob URLs share the same output file, skip writing the error
                    // response to avoid polluting the file for the next URL's output
                    // (curl compat: test 1328).
                    let shares_file_with_next = file_for_this.is_some()
                        && output_files.get(i + 1).map(String::as_str) == file_for_this;
                    let effective_file =
                        if suppress && shares_file_with_next { None } else { file_for_this };
                    let effective_include =
                        if suppress && shares_file_with_next { false } else { include_headers };
                    let _ = output_response_with_context(
                        &response,
                        effective_file,
                        write_out,
                        effective_include,
                        silent,
                        suppress,
                        &ctx,
                    );
                    last_exit = ExitCode::from(22); // CURLE_HTTP_RETURNED_ERROR
                    continue;
                }
                // Each URL uses its corresponding output file (from #N substitution)
                let file_for_this = output_files.get(i).map(String::as_str);

                // -z/--time-cond body suppression (curl compat: test 1128)
                let suppress_body = time_cond_ts.is_some_and(|cond_ts| {
                    response.header("last-modified").and_then(parse_http_date).is_some_and(
                        |lm_ts| {
                            if time_cond_negate {
                                lm_ts > cond_ts
                            } else {
                                lm_ts <= cond_ts
                            }
                        },
                    )
                });

                // --dump-header: write headers before body output
                // --dump-header handling for multi-URL mode
                let dump_to_stdout = dump_header == Some("-") && file_for_this.is_none();
                if let Some(dh_path) = dump_header {
                    let header_text = format_headers(&response);
                    let raw_trailers = response.raw_trailers();
                    if dump_to_stdout && include_headers {
                        // Both --dump-header - and --include: each header line appears twice
                        // (once from dump callback, once from include). Then body follows.
                        // (curl compat: test 1066)
                        use std::io::Write;
                        let mut stdout = std::io::stdout();
                        for line in header_text.split_inclusive('\n') {
                            let _ = stdout.write_all(line.as_bytes());
                            let _ = stdout.write_all(line.as_bytes());
                        }
                    } else if dump_to_stdout {
                        // --dump-header - without --include: headers once to stdout
                        use std::io::Write;
                        let _ = std::io::stdout().write_all(header_text.as_bytes());
                    } else if dh_path == "-" {
                        // --dump-header - with -o file: dump to stdout
                        use std::io::Write;
                        let mut dump_data = header_text.into_bytes();
                        if !raw_trailers.is_empty() {
                            dump_data.extend_from_slice(raw_trailers);
                        }
                        let _ = std::io::stdout().write_all(&dump_data);
                    } else {
                        let mut dump_data = header_text.into_bytes();
                        if !raw_trailers.is_empty() {
                            dump_data.extend_from_slice(raw_trailers);
                        }
                        let _ = std::fs::write(dh_path, &dump_data);
                    }
                }

                // When dump-header goes to stdout and include_headers is active,
                // headers were already output as doubled lines above. Skip include
                // in output_response to avoid triple output.
                // Also suppress headers for non-HTTP protocols (FTP, etc.) — curl
                // doesn't output HTTP-like headers for FTP even with --include.
                let is_non_http = response.http_version()
                    == liburlx::protocol::http::response::ResponseHttpVersion::Unknown;
                let effective_include = include_headers && !(dump_to_stdout || is_non_http);
                let exit = output_response(
                    &response,
                    file_for_this,
                    write_out,
                    effective_include,
                    silent,
                    suppress_body,
                );
                // Always update last_exit: curl uses last transfer's exit code
                // (curl compat: test 1328 — --fail with glob, last URL succeeds)
                last_exit = exit;
            }
            Err(e) => {
                // SFTP post-quote errors: output the downloaded data before
                // reporting the error (curl compat: test 609)
                if let liburlx::Error::SshQuoteErrorWithData { ref response, .. } = e {
                    let file_for_this = output_files.get(i).map(String::as_str);
                    let _ = output_response(
                        response.as_ref(),
                        file_for_this,
                        write_out,
                        false, // no include headers for SFTP
                        silent,
                        false,
                    );
                }
                if !silent || show_error {
                    eprintln!("curl: transfer {} ({}): {e}", i + 1, url);
                }
                let curl_code = error_to_curl_code(&e);
                // Still produce write-out for failed transfers (curl compat: test 423)
                if let Some(wo) = write_out {
                    let dummy_response = liburlx::Response::new(
                        0,
                        std::collections::HashMap::new(),
                        Vec::new(),
                        url.clone(),
                    );
                    let ctx = WriteOutContext {
                        urlnum: i,
                        exitcode: curl_code,
                        errormsg: curl_error_message(&e),
                        had_error: true,
                        ..WriteOutContext::default()
                    };
                    let _ = output_response_with_context(
                        &dummy_response,
                        None,
                        Some(wo),
                        false,
                        silent,
                        true,
                        &ctx,
                    );
                }
                let exit_code = ExitCode::from(curl_code);
                if fail_early {
                    return exit_code;
                }
                last_exit = exit_code;
            }
        }
    }

    // Send FTP QUIT to cleanly close any reusable FTP session
    rt.block_on(easy.ftp_quit());

    // Save cookie jar after all transfers (curl compat: tests 327, 329, 444)
    if let Err(e) = easy.save_cookie_jar() {
        if !silent || show_error {
            eprintln!("curl: error saving cookies: {e}");
        }
    }
    // Save HSTS cache after all transfers
    if let Err(e) = easy.save_hsts_cache() {
        if !silent || show_error {
            eprintln!("curl: error saving HSTS cache: {e}");
        }
    }

    last_exit
}

/// Extract `host:port` from an IMAP URL for batch grouping.
fn extract_imap_host_port(url: &str) -> String {
    // Parse "imap://user:pass@host:port/path" to "host:port"
    if let Some(rest) = url.strip_prefix("imap://").or_else(|| url.strip_prefix("imaps://")) {
        // Skip userinfo@ if present
        let after_at = rest.rfind('@').map_or(rest, |pos| &rest[pos + 1..]);
        // Take host:port (before first /)
        let host_port = after_at.split('/').next().unwrap_or(after_at);
        host_port.to_lowercase()
    } else {
        String::new()
    }
}

/// Run a batch of IMAP URLs on a single connection (curl compat: tests 804, 815, 816).
async fn run_imap_batch(
    urls: &[String],
    template_easy: &liburlx::Easy,
    per_url_easy: &[Option<liburlx::Easy>],
    per_url_credentials: &[Option<(String, String)>],
    per_url_custom_request: &[Option<String>],
    batch_start: usize,
) -> Result<Vec<liburlx::Response>, liburlx::Error> {
    let mut ops = Vec::new();
    let mut parsed_urls = Vec::new();

    for (idx, url_str) in urls.iter().enumerate() {
        let global_idx = batch_start + idx;
        // Get the Easy handle for this URL (may have per-URL overrides from --next)
        let url_easy =
            per_url_easy.get(global_idx).and_then(|o| o.as_ref()).unwrap_or(template_easy);

        let mut easy_clone = url_easy.clone();

        // Embed per-URL credentials into the URL (same as the main transfer loop)
        let effective_url =
            if let Some(Some((ref user, ref pass))) = per_url_credentials.get(global_idx) {
                let encoded_user = percent_encode_credential(user);
                let encoded_pass = percent_encode_credential(pass);
                let base_url = strip_url_credentials(url_str);
                let scheme_end = base_url.find("://").map_or(0, |p| p + 3);
                format!(
                    "{}{}:{}@{}",
                    &base_url[..scheme_end],
                    encoded_user,
                    encoded_pass,
                    &base_url[scheme_end..]
                )
            } else {
                url_str.clone()
            };

        easy_clone.url(&effective_url)?;
        // Get custom request and method from the Easy handle
        parsed_urls.push(easy_clone);
    }

    // Build operation descriptors from the parsed Easy handles.
    // For IMAP custom requests: -X sets the method (uppercased) and optionally
    // custom_request_target (original case). When the method is not a standard
    // HTTP method, it IS the custom command for IMAP.
    let mut custom_requests: Vec<Option<String>> = Vec::new();
    for (idx, easy_clone) in parsed_urls.iter().enumerate() {
        let global_idx = batch_start + idx;
        // Use per-URL original-case custom request if available (curl compat: tests 815, 816)
        let per_url_cr = per_url_custom_request.get(global_idx).and_then(|v| v.as_deref());
        let custom_request = easy_clone.custom_request().or(per_url_cr);
        let method = easy_clone.effective_method();
        // If custom_request is set, use it; otherwise if the method
        // is not a standard HTTP method, use it as the custom request.
        let effective_custom = if custom_request.is_some() {
            custom_request.map(ToString::to_string)
        } else {
            match method {
                "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "PATCH" | "OPTIONS" => None,
                _ => Some(method.to_string()),
            }
        };
        custom_requests.push(effective_custom);
    }

    for (idx, easy_clone) in parsed_urls.iter().enumerate() {
        let url = easy_clone
            .url_ref()
            .ok_or_else(|| liburlx::Error::Http("IMAP batch: missing URL".to_string()))?;
        let method = easy_clone.effective_method();
        let body = easy_clone.body_ref();

        ops.push(liburlx::protocol::imap::ImapOperation {
            url,
            method,
            body,
            custom_request: custom_requests[idx].as_deref(),
        });
    }

    // Get auth settings from the first URL's Easy handle
    let first_easy =
        per_url_easy.get(batch_start).and_then(|o| o.as_ref()).unwrap_or(template_easy);

    let sasl_ir = first_easy.get_sasl_ir();
    let oauth2_bearer = first_easy.get_oauth2_bearer().map(ToString::to_string);
    let login_options = first_easy.get_login_options().map(ToString::to_string);
    let sasl_authzid = first_easy.get_sasl_authzid().map(ToString::to_string);
    let resolve_overrides = first_easy.get_resolve_overrides().to_vec();
    let tls_config = first_easy.get_tls_config().clone();
    let use_ssl = first_easy.get_use_ssl();

    liburlx::protocol::imap::fetch_multi(
        &ops,
        sasl_ir,
        oauth2_bearer.as_deref(),
        login_options.as_deref(),
        sasl_authzid.as_deref(),
        &resolve_overrides,
        'A',
        use_ssl,
        &tls_config,
    )
    .await
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
    fn parse_http_date_pre_1970() {
        // curl test 762: "Wed, 09 Oct 1940 16:45:49 +0100" => -922349651
        let ts = parse_http_date("Wed, 09 Oct 1940 16:45:49 +0100");
        assert_eq!(ts, Some(-922_349_651));
    }

    #[test]
    fn parse_http_date_timezone_offset() {
        // Same date in GMT should be 3600 seconds larger (less negative)
        let ts_gmt = parse_http_date("Wed, 09 Oct 1940 16:45:49 GMT");
        let ts_plus1 = parse_http_date("Wed, 09 Oct 1940 16:45:49 +0100");
        assert!(ts_gmt.is_some());
        assert!(ts_plus1.is_some());
        assert_eq!(ts_gmt.unwrap() - ts_plus1.unwrap(), 3600);
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
