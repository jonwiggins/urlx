//! Cookie jar engine.
//!
//! Stores cookies from `Set-Cookie` response headers and sends matching
//! cookies in `Cookie` request headers per RFC 6265.
//!
//! Supports Netscape cookie file format for persistent storage
//! (compatible with curl's `-b`/`-c` flags).

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A simple cookie jar that stores and retrieves cookies.
///
/// Cookies are indexed by domain for O(1) domain lookup on each request.
/// The domain index maps lowercase domains to indices in the cookie Vec.
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    /// Index from domain to cookie indices for fast lookup.
    domain_index: HashMap<String, Vec<usize>>,
    /// Monotonically increasing counter for cookie creation order.
    next_creation_index: u64,
}

/// `SameSite` cookie attribute (RFC 6265bis).
///
/// Controls when cookies are sent with cross-site requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Cookie is not sent with cross-site requests.
    /// This is the default when no `SameSite` attribute is present (per RFC 6265bis).
    #[default]
    Lax,
    /// Cookie is sent with all requests (requires `Secure` flag).
    None,
    /// Cookie is never sent with cross-site requests.
    Strict,
}

/// A single HTTP cookie.
#[derive(Debug, Clone)]
struct Cookie {
    name: String,
    value: String,
    /// Domain for matching (lowercase, no leading dot).
    domain: String,
    /// Domain as it should appear in jar output (preserves original case and dot prefix).
    domain_display: String,
    path: String,
    expires: Option<SystemTime>,
    secure: bool,
    #[allow(dead_code)] // Stored for future use (e.g., JavaScript cookie access filtering)
    http_only: bool,
    /// `SameSite` attribute controlling cross-site cookie behavior.
    /// Stored for completeness; CLI requests are always top-level navigations.
    #[allow(dead_code)]
    same_site: SameSite,
    /// Monotonically increasing counter for creation order (curl compat sorting).
    creation_index: u64,
    /// Whether the cookie applies to subdomains (TRUE in Netscape format).
    include_subdomains: bool,
}

impl CookieJar {
    /// Create a new empty cookie jar.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // HashMap::new() is not const
    pub fn new() -> Self {
        Self { cookies: Vec::new(), domain_index: HashMap::new(), next_creation_index: 0 }
    }

    /// Parse and store cookies from `Set-Cookie` headers.
    ///
    /// `request_host` and `request_path` are used as defaults when the
    /// cookie doesn't specify domain/path attributes.
    /// `is_secure_origin` indicates whether the request was made over HTTPS;
    /// cookies with the `Secure` attribute are rejected from non-secure origins
    /// (curl compat).
    pub fn store_from_headers(
        &mut self,
        headers: &HashMap<String, String>,
        request_host: &str,
        request_path: &str,
        is_secure_origin: bool,
    ) {
        // Look for set-cookie headers (case-insensitive, already lowercased)
        // Multiple Set-Cookie headers are joined with newline by the parser
        if let Some(set_cookie) = headers.get("set-cookie") {
            for value in set_cookie.split('\n') {
                self.parse_set_cookie(value, request_host, request_path, is_secure_origin);
            }
        }
    }

    /// Parse and store cookies from multiple `Set-Cookie` header values.
    ///
    /// This handles the case where multiple Set-Cookie headers are present
    /// (joined with a separator by the response parser).
    pub fn store_cookies(
        &mut self,
        set_cookie_values: &[&str],
        host: &str,
        path: &str,
        is_secure_origin: bool,
    ) {
        for value in set_cookie_values {
            self.parse_set_cookie(value, host, path, is_secure_origin);
        }
    }

    /// Get the `Cookie` header value for a request to the given URL.
    ///
    /// Returns `None` if no cookies match.
    #[must_use]
    pub fn cookie_header(&self, host: &str, path: &str, is_secure: bool) -> Option<String> {
        const MAX_COOKIE_SEND: usize = 150;
        const MAX_COOKIE_HEADER_LEN: usize = 8190;
        let now = SystemTime::now();
        let host_lower = host.to_ascii_lowercase();

        // Collect candidate domains: exact match + parent domains + wildcard (empty domain)
        let mut candidate_indices: Vec<usize> = Vec::new();

        // Check exact domain match
        if let Some(indices) = self.domain_index.get(&host_lower) {
            candidate_indices.extend(indices);
        }
        // Also check with leading dot (Netscape cookie format)
        let dot_host = format!(".{host_lower}");
        if let Some(indices) = self.domain_index.get(&dot_host) {
            candidate_indices.extend(indices);
        }

        // Check parent domains (e.g., for host "www.example.com", check "example.com")
        let mut dot_pos = 0;
        while let Some(pos) = host_lower[dot_pos..].find('.') {
            let parent = &host_lower[dot_pos + pos + 1..];
            if !parent.is_empty() && parent.contains('.') {
                if let Some(indices) = self.domain_index.get(parent) {
                    candidate_indices.extend(indices);
                }
            }
            dot_pos += pos + 1;
        }

        // Check cookies with empty domain (loaded from files without domain attr, match all)
        if let Some(indices) = self.domain_index.get("") {
            candidate_indices.extend(indices);
        }

        // Filter candidates by expiry, secure, domain match, and path
        let matching: Vec<&Cookie> = candidate_indices
            .iter()
            .filter_map(|&idx| {
                let c = &self.cookies[idx];
                if let Some(expires) = c.expires {
                    if now > expires {
                        return None;
                    }
                }
                if c.secure && !is_secure {
                    return None;
                }
                if !domain_matches(host, &c.domain) {
                    return None;
                }
                if !path_matches(path, &c.path) {
                    return None;
                }
                Some(c)
            })
            .collect();

        if matching.is_empty() {
            return None;
        }

        // Sort matching curl's cookie_sort: path length DESC, domain length DESC,
        // name length DESC, then creation time DESC (newer cookies first).
        let mut matching = matching;
        matching.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then_with(|| b.domain.len().cmp(&a.domain.len()))
                .then_with(|| b.name.len().cmp(&a.name.len()))
                .then_with(|| b.creation_index.cmp(&a.creation_index))
        });

        // curl caps at 150 cookies per request (MAX_COOKIE_SEND_AMOUNT).
        // When over the limit, drop the newest cookies (highest creation_index).
        if matching.len() > MAX_COOKIE_SEND {
            // Sort by creation_index ASC to find oldest, then take first 150
            matching.sort_by(|a, b| a.creation_index.cmp(&b.creation_index));
            matching.truncate(MAX_COOKIE_SEND);
            // Re-sort in curl's output order
            matching.sort_by(|a, b| {
                b.path
                    .len()
                    .cmp(&a.path.len())
                    .then_with(|| b.domain.len().cmp(&a.domain.len()))
                    .then_with(|| b.name.len().cmp(&a.name.len()))
                    .then_with(|| b.creation_index.cmp(&a.creation_index))
            });
        }
        // Build Cookie header, enforcing curl's MAX_COOKIE_HEADER_LEN (8190 bytes).
        // Include cookies in sorted order until adding the next one would exceed the limit.
        let mut cookie_str = String::new();
        for c in &matching {
            let pair = format!("{}={}", c.name, c.value);
            let new_len = if cookie_str.is_empty() {
                pair.len()
            } else {
                cookie_str.len() + 2 + pair.len() // "; " separator
            };
            if new_len > MAX_COOKIE_HEADER_LEN {
                break; // Stop adding cookies to stay within limit
            }
            if !cookie_str.is_empty() {
                cookie_str.push_str("; ");
            }
            cookie_str.push_str(&pair);
        }

        if cookie_str.is_empty() {
            return None;
        }

        Some(cookie_str)
    }

    /// Returns the number of stored cookies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Returns true if the jar is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Remove expired cookies.
    pub fn remove_expired(&mut self) {
        let now = SystemTime::now();
        self.cookies.retain(|c| c.expires.is_none_or(|exp| now <= exp));
        self.rebuild_index();
    }

    /// Load cookies from a Netscape-format cookie file.
    ///
    /// The file format uses tab-separated fields:
    /// `domain\tflag\tpath\tsecure\texpiration\tname\tvalue`
    ///
    /// Lines starting with `#` or empty lines are ignored.
    /// This is compatible with curl's `-b <file>` flag.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be read.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut jar = Self::new();
        jar.load_from_reader(reader)?;
        Ok(jar)
    }

    /// Load cookies from a reader in Netscape cookie file format or HTTP header dump.
    ///
    /// Detects the format automatically:
    /// - Lines with `Set-Cookie:` are parsed as HTTP header dump (curl compat)
    /// - Lines starting with `HTTP/` are skipped (response status line)
    /// - Tab-separated lines with 7+ fields are parsed as Netscape format
    ///
    /// # Errors
    ///
    /// Returns an I/O error if reading fails.
    pub fn load_from_reader<R: BufRead>(&mut self, reader: R) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            // Trim spaces and CR/LF but NOT tabs — tabs are field delimiters
            // in Netscape cookie format and a trailing tab indicates an empty value field.
            let line = line.trim_matches(|c: char| c == ' ' || c == '\r' || c == '\n');

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // HTTP header dump format: parse Set-Cookie lines
            if let Some(value) =
                line.strip_prefix("Set-Cookie:").or_else(|| line.strip_prefix("set-cookie:"))
            {
                // Use empty host/path defaults — the cookie's own domain/path attrs apply.
                // Allow secure cookies from file (they may have been saved from HTTPS).
                self.parse_set_cookie(value.trim(), "", "/", true);
                continue;
            }

            // Skip HTTP response status lines and other headers in header dumps
            if line.starts_with("HTTP/") || line.contains(':') && !line.contains('\t') {
                continue;
            }

            // HttpOnly cookies have #HttpOnly_ prefix on domain
            let (line, http_only_prefix) = if let Some(rest) = line.strip_prefix("#HttpOnly_") {
                (rest, true)
            } else if line.starts_with('#') {
                // Skip comment lines (but not #HttpOnly_ which was handled above)
                continue;
            } else {
                (line, false)
            };

            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 6 {
                continue; // Malformed line — need at least domain, flag, path, secure, expires, name
            }

            let raw_domain = fields[0];
            let domain = raw_domain.strip_prefix('.').unwrap_or(raw_domain).to_lowercase();
            let include_subdomains = fields[1].eq_ignore_ascii_case("TRUE");
            let domain_display = if include_subdomains && !raw_domain.starts_with('.') {
                format!(".{raw_domain}")
            } else {
                raw_domain.to_string()
            };
            let path = fields[2].to_string();
            let secure = fields[3].eq_ignore_ascii_case("TRUE");
            let expires = fields[4].parse::<u64>().ok().and_then(|ts| {
                if ts == 0 {
                    Option::None // Session cookie
                } else {
                    UNIX_EPOCH.checked_add(Duration::from_secs(ts))
                }
            });
            let name = fields[5].to_string();
            // Value is the 7th field (index 6); if missing, treat as empty (curl compat)
            let value = fields.get(6).unwrap_or(&"").to_string();
            let http_only = http_only_prefix;

            // Replace existing cookie with same name+domain+path
            self.cookies.retain(|c| !(c.name == name && c.domain == domain && c.path == path));

            let idx = self.next_creation_index;
            self.next_creation_index += 1;
            self.cookies.push(Cookie {
                name,
                value,
                domain,
                domain_display,
                path,
                expires,
                secure,
                http_only,
                same_site: SameSite::default(),
                creation_index: idx,
                include_subdomains,
            });
        }
        self.rebuild_index();
        Ok(())
    }

    /// Save cookies to a Netscape-format cookie file.
    ///
    /// Session cookies (no expiration) are included with expiration `0`.
    /// This is compatible with curl's `-c <file>` flag.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be written.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = std::io::BufWriter::new(file);
        self.save_to_writer(&mut writer)
    }

    /// Save cookies to a writer in Netscape-format.
    ///
    /// Expired cookies are filtered out (curl compat).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if writing fails.
    pub fn save_to_writer<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writeln!(writer, "# Netscape HTTP Cookie File")?;
        writeln!(writer, "# https://curl.se/docs/http-cookies.html")?;
        writeln!(writer, "# This file was generated by libcurl! Edit at your own risk.")?;
        writeln!(writer)?;

        let now = SystemTime::now();

        // Sort by creation time descending (newest first) to match curl's jar output
        let mut sorted: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                // Filter out expired cookies (curl compat)
                c.expires.is_none_or(|exp| now < exp)
            })
            .collect();
        sorted.sort_by(|a, b| b.creation_index.cmp(&a.creation_index));

        for cookie in sorted {
            let domain_str = if cookie.http_only {
                format!("#HttpOnly_{}", cookie.domain_display)
            } else {
                cookie.domain_display.clone()
            };
            let flag = if cookie.include_subdomains { "TRUE" } else { "FALSE" };
            let secure_str = if cookie.secure { "TRUE" } else { "FALSE" };
            let expires_ts = cookie
                .expires
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());

            writeln!(
                writer,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                domain_str, flag, cookie.path, secure_str, expires_ts, cookie.name, cookie.value
            )?;
        }

        Ok(())
    }

    /// Parse a single Set-Cookie header value and store it.
    ///
    /// `is_secure_origin` controls whether cookies with the `Secure` flag are
    /// accepted. curl rejects `Secure` cookies received over plain HTTP.
    #[allow(clippy::too_many_lines)]
    fn parse_set_cookie(
        &mut self,
        header: &str,
        request_host: &str,
        request_path: &str,
        is_secure_origin: bool,
    ) {
        const MAX_COOKIE_LINE: usize = 4096;
        const MAX_COOKIES_PER_DOMAIN: usize = 50;

        let parts: Vec<&str> = header.splitn(2, ';').collect();
        let name_value = parts[0].trim();

        let Some((name, value)) = name_value.split_once('=') else {
            return; // Invalid cookie
        };

        // Reject cookies with control characters BEFORE trimming (curl compat).
        // Tab (0x09) IS rejected in names and values — tab is the field separator
        // in Netscape cookie format, so allowing it would corrupt the cookie jar.
        let has_control = name.bytes().chain(value.bytes()).any(|b| b < 0x20 || b == 0x7F);
        if has_control {
            return;
        }

        let name = name.trim().to_string();
        let value = value.trim().to_string();

        if name.is_empty() {
            return; // curl rejects empty cookie names
        }

        // Reject cookies where name + value exceeds curl's MAX_COOKIE_LINE_LEN (4096).
        if name.len() + value.len() > MAX_COOKIE_LINE {
            return;
        }

        let mut domain = request_host.to_lowercase();
        let mut path = default_cookie_path(request_path);
        let mut expires: Option<SystemTime> = None;
        let mut secure = false;
        let mut http_only = false;
        let mut same_site = SameSite::default();
        let mut has_explicit_domain = false;

        // Parse attributes
        if parts.len() > 1 {
            for attr in parts[1].split(';') {
                let attr = attr.trim();
                if let Some((attr_name, attr_value)) = attr.split_once('=') {
                    let attr_name = attr_name.trim();
                    let attr_value = attr_value.trim();

                    if attr_name.eq_ignore_ascii_case("domain") {
                        if !attr_value.is_empty() {
                            // Strip leading dot (RFC 6265 §5.2.3)
                            domain =
                                attr_value.strip_prefix('.').unwrap_or(attr_value).to_lowercase();
                            has_explicit_domain = true;
                        }
                    } else if attr_name.eq_ignore_ascii_case("path") {
                        if !attr_value.is_empty() {
                            // Strip surrounding quotes (some servers quote the path)
                            let p = attr_value.strip_prefix('"').unwrap_or(attr_value);
                            let p = p.strip_suffix('"').unwrap_or(p);
                            path = p.to_string();
                        }
                    } else if attr_name.eq_ignore_ascii_case("expires") {
                        // Parse date in various formats (RFC 2616, Netscape, etc.)
                        if let Some(t) = parse_cookie_date(attr_value) {
                            // Only set if max-age hasn't already been set
                            // (max-age takes precedence per RFC 6265 §5.3)
                            if expires.is_none() {
                                expires = Some(cap_cookie_expiry(t));
                            }
                        }
                    } else if attr_name.eq_ignore_ascii_case("max-age") {
                        if let Ok(seconds) = attr_value.parse::<i64>() {
                            if seconds <= 0 {
                                expires = Some(SystemTime::UNIX_EPOCH);
                            } else {
                                #[allow(clippy::cast_sign_loss)]
                                let dur = Duration::from_secs(seconds as u64);
                                expires = SystemTime::now().checked_add(dur);
                            }
                        }
                    } else if attr_name.eq_ignore_ascii_case("samesite") {
                        if attr_value.eq_ignore_ascii_case("strict") {
                            same_site = SameSite::Strict;
                        } else if attr_value.eq_ignore_ascii_case("none") {
                            same_site = SameSite::None;
                        } else {
                            same_site = SameSite::Lax;
                        }
                    }
                } else if attr.eq_ignore_ascii_case("secure") {
                    secure = true;
                } else if attr.eq_ignore_ascii_case("httponly") {
                    http_only = true;
                }
            }
        }

        // SameSite=None requires Secure (RFC 6265bis §5.4.7)
        if same_site == SameSite::None && !secure {
            return; // Reject the cookie
        }

        // Reject Secure cookies received over plain HTTP (curl compat).
        // Secure cookies may only be set by HTTPS origins.
        if secure && !is_secure_origin {
            return;
        }

        // Reject cookies with explicit Domain attribute set to a public suffix
        // (e.g., "com", "co.uk", "github.io") to prevent super-domain cookie attacks.
        // Host-only cookies (no Domain attr) are always allowed.
        if has_explicit_domain && is_public_suffix(&domain) {
            return;
        }

        // Validate domain against request host (RFC 6265 §5.3 step 6):
        // The domain must domain-match the request host.
        if has_explicit_domain && !request_host.is_empty() {
            let req_lower = request_host.to_ascii_lowercase();
            if !domain_matches(&req_lower, &domain) {
                return; // Reject: domain doesn't match request host
            }
        }

        // Build display domain for jar output
        let (domain_display, include_subdomains) = if has_explicit_domain {
            // Preserve the original case from the Set-Cookie header
            let raw = if parts.len() > 1 {
                parts[1]
                    .split(';')
                    .find_map(|attr| {
                        let attr = attr.trim();
                        attr.split_once('=').and_then(|(k, v)| {
                            if k.trim().eq_ignore_ascii_case("domain") {
                                let v = v.trim().strip_prefix('.').unwrap_or_else(|| v.trim());
                                if v.is_empty() {
                                    None
                                } else {
                                    Some(v.to_string())
                                }
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or_else(|| domain.clone())
            } else {
                domain.clone()
            };
            // IP addresses don't have subdomains: no dot prefix, include_subdomains=FALSE
            if is_ip_address(&domain) {
                (raw, false)
            } else {
                // Explicit domain: add dot prefix, set include_subdomains=TRUE
                (format!(".{raw}"), true)
            }
        } else {
            // Host-only: no dot prefix, include_subdomains=FALSE
            (domain.clone(), false)
        };

        // Strip trailing slash from cookie path (curl compat).
        // Root path "/" is kept as-is.
        if path.len() > 1 && path.ends_with('/') {
            path = path.trim_end_matches('/').to_string();
        }

        // Replace existing cookie with same name+domain+path.
        // Normalize paths by stripping trailing slashes for comparison (curl compat:
        // paths "/overwrite/" and "/overwrite" refer to the same cookie).
        let path_normalized = path.trim_end_matches('/');
        let is_replacement = self.cookies.iter().any(|c| {
            let existing_normalized = c.path.trim_end_matches('/');
            c.name == name && c.domain == domain && existing_normalized == path_normalized
        });
        self.cookies.retain(|c| {
            let existing_normalized = c.path.trim_end_matches('/');
            !(c.name == name && c.domain == domain && existing_normalized == path_normalized)
        });

        // Enforce per-domain cookie cap (curl compat: MAX_COOKIE_TOTAL_AMOUNT = 50).
        // If this is a new cookie (not replacement) and domain already at limit, reject.
        if !is_replacement {
            let domain_count = self.cookies.iter().filter(|c| c.domain == domain).count();
            if domain_count >= MAX_COOKIES_PER_DOMAIN {
                self.rebuild_index();
                return; // Reject: too many cookies for this domain
            }
        }

        let idx = self.next_creation_index;
        self.next_creation_index += 1;
        self.cookies.push(Cookie {
            name,
            value,
            domain,
            domain_display,
            path,
            expires,
            secure,
            http_only,
            same_site,
            creation_index: idx,
            include_subdomains,
        });

        // Rebuild the index (retain may have invalidated indices)
        self.rebuild_index();
    }

    /// Rebuild the domain index from scratch.
    fn rebuild_index(&mut self) {
        self.domain_index.clear();
        for (idx, cookie) in self.cookies.iter().enumerate() {
            self.domain_index.entry(cookie.domain.clone()).or_default().push(idx);
        }
    }
}

/// Check if a domain is a public suffix (e.g., "com", "co.uk", "github.io").
///
/// Uses the embedded public suffix list to prevent cookies from being set
/// for top-level domains, which would be a security issue (super-domain
/// cookie attack).
///
/// Unknown domains not in the PSL (e.g., "localhost", "moo") are NOT
/// treated as public suffixes. Only known PSL entries are blocked.
/// This matches curl's behavior of allowing cookies on hostnames like
/// "localhost" (curl compat: tests 331, 392, 1258).
fn is_public_suffix(domain: &str) -> bool {
    use psl::Psl;
    let domain_bytes = domain.as_bytes();
    // psl::List.suffix() returns the public suffix portion of the domain.
    // If the suffix IS the entire domain, then the domain is a public suffix.
    // Only block if the suffix is a "known" entry in the PSL — this allows
    // unknown single-label domains like "localhost" and "moo" (curl compat).
    let Some(suffix) = psl::List.suffix(domain_bytes) else {
        return false;
    };
    suffix.is_known() && suffix.as_bytes().eq_ignore_ascii_case(domain_bytes)
}

/// Check if a request host matches a cookie domain.
///
/// Per RFC 6265 §5.1.3: either exact match or the domain is a suffix
/// of the host preceded by a dot.
fn domain_matches(host: &str, cookie_domain: &str) -> bool {
    // Empty cookie domain matches any host (cookies loaded from file without domain attr)
    if cookie_domain.is_empty() {
        return true;
    }

    // Strip leading dot from cookie domain for matching (Netscape format)
    let cookie_domain_clean = cookie_domain.strip_prefix('.').unwrap_or(cookie_domain);

    if host.eq_ignore_ascii_case(cookie_domain_clean) {
        return true;
    }

    if host.eq_ignore_ascii_case(cookie_domain) {
        return true;
    }

    // IP addresses don't have domain hierarchy — only exact match allowed
    if is_ip_address(host) {
        return false;
    }

    // Host is foo.example.com, domain is example.com
    // Check if host ends with ".{domain}" without allocating
    if host.len() > cookie_domain.len() + 1 {
        let offset = host.len() - cookie_domain.len() - 1;
        host.as_bytes()[offset] == b'.' && host[offset + 1..].eq_ignore_ascii_case(cookie_domain)
    } else {
        false
    }
}

/// Check if a string looks like an IP address (v4 or v6).
fn is_ip_address(s: &str) -> bool {
    // IPv4: all chars are digits or dots
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') && s.contains('.') {
        return true;
    }
    // IPv6: contains colons
    s.contains(':')
}

/// Check if a request path matches a cookie path.
///
/// Per RFC 6265 §5.1.4.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }

    if request_path.starts_with(cookie_path) {
        // Cookie path "/foo" matches request "/foo/bar"
        if cookie_path.ends_with('/') {
            return true;
        }
        // Cookie path "/foo" matches request "/foo/bar" (with separator)
        if request_path.as_bytes().get(cookie_path.len()) == Some(&b'/') {
            return true;
        }
    }

    false
}

/// Get the default cookie path from a request path.
///
/// Per RFC 6265 §5.1.4: take the path up to (but not including) the
/// rightmost `/`. If the result is empty, use `/`.
fn default_cookie_path(request_path: &str) -> String {
    if request_path.is_empty() || !request_path.starts_with('/') {
        return "/".to_string();
    }

    request_path
        .rfind('/')
        .filter(|&pos| pos > 0)
        .map_or_else(|| "/".to_string(), |pos| request_path[..pos].to_string())
}

/// Cap cookie expiry to 400 days from now (RFC 6265bis, curl compat).
///
/// Aligns the capped time to a 60-second boundary for test determinism.
fn cap_cookie_expiry(expires: SystemTime) -> SystemTime {
    const MAX_AGE_SECS: u64 = 400 * 24 * 3600;

    let now = SystemTime::now();
    if let Ok(now_secs) = now.duration_since(UNIX_EPOCH) {
        let cap_secs = now_secs.as_secs() + MAX_AGE_SECS + 30;
        let cap_aligned = (cap_secs / 60) * 60;
        let cap_time = UNIX_EPOCH + Duration::from_secs(cap_aligned);
        if expires > cap_time {
            return cap_time;
        }
    }
    expires
}

/// Parse a cookie date string into a `SystemTime`.
///
/// Handles common date formats used in Set-Cookie headers:
/// - `Fri, 13-Feb-2037 11:56:27 GMT` (Netscape / RFC 2109)
/// - `Fri, 13 Feb 2037 11:56:27 GMT` (RFC 2616)
/// - `Friday, 13-Feb-2037 11:56:27 GMT` (full day name)
fn parse_cookie_date(s: &str) -> Option<SystemTime> {
    // Tokenize: extract day-of-month, month, year, time components
    // per RFC 6265 §5.1.1 (relaxed date parsing)
    let s = s.trim();

    // Replace dashes with spaces for uniform parsing
    let normalized = s.replace('-', " ");
    let tokens: Vec<&str> = normalized.split_whitespace().collect();

    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<u32> = None;
    let mut hour: Option<u32> = None;
    let mut minute: Option<u32> = None;
    let mut second: Option<u32> = None;

    for token in &tokens {
        // Try time (HH:MM:SS)
        if hour.is_none() && token.contains(':') {
            let parts: Vec<&str> = token.split(':').collect();
            if parts.len() >= 3 {
                if let (Ok(h), Ok(m), Ok(s)) =
                    (parts[0].parse::<u32>(), parts[1].parse::<u32>(), parts[2].parse::<u32>())
                {
                    hour = Some(h);
                    minute = Some(m);
                    second = Some(s);
                    continue;
                }
            }
        }

        // Try month name
        if month.is_none() {
            let m = match token.to_ascii_lowercase().get(..3) {
                Some("jan") => Some(1),
                Some("feb") => Some(2),
                Some("mar") => Some(3),
                Some("apr") => Some(4),
                Some("may") => Some(5),
                Some("jun") => Some(6),
                Some("jul") => Some(7),
                Some("aug") => Some(8),
                Some("sep") => Some(9),
                Some("oct") => Some(10),
                Some("nov") => Some(11),
                Some("dec") => Some(12),
                _ => None,
            };
            if m.is_some() {
                month = m;
                continue;
            }
        }

        // Try numeric (could be day or year)
        if let Ok(n) = token.parse::<u32>() {
            if day.is_none() && (1..=31).contains(&n) {
                day = Some(n);
            } else if year.is_none() {
                year = Some(if n < 100 {
                    if n < 70 {
                        n + 2000
                    } else {
                        n + 1900
                    }
                } else {
                    n
                });
            } else if day.is_none() {
                // Year was set first, this must be the day
                day = Some(n);
            }
        }
    }

    let day = day?;
    let month = month?;
    let year = u64::from(year?);
    let hour = u64::from(hour.unwrap_or(0));
    let minute = u64::from(minute.unwrap_or(0));
    let second = u64::from(second.unwrap_or(0));

    // Convert to seconds since epoch (simplified — no leap second handling)
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + minute * 60 + second;

    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Convert a date to days since Unix epoch.
fn days_from_civil(year: u64, month: u32, day: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }

    // Days in each month (non-leap)
    let days_in_months: [u32; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut total_days: u64 = 0;

    // Add days for complete years since 1970
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for complete months in current year
    for m in 1..month {
        total_days += u64::from(days_in_months[m as usize]);
        if m == 2 && is_leap_year(year) {
            total_days += 1;
        }
    }

    // Add remaining days
    total_days += u64::from(day - 1);

    Some(total_days)
}

/// Check if a year is a leap year.
const fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_jar() {
        let jar = CookieJar::new();
        assert!(jar.is_empty());
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn parse_simple_cookie() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value", "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("name=value".to_string()));
    }

    #[test]
    fn parse_cookie_with_attributes() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("sid=abc123; Path=/api; Secure; HttpOnly", "example.com", "/", true);
        assert_eq!(jar.len(), 1);

        // Secure cookie should not match non-secure request
        assert_eq!(jar.cookie_header("example.com", "/api", false), None);
        // Should match secure request
        assert_eq!(jar.cookie_header("example.com", "/api", true), Some("sid=abc123".to_string()));
    }

    #[test]
    fn parse_cookie_with_domain() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=example.com", "www.example.com", "/", true);
        assert_eq!(jar.len(), 1);

        // Should match exact domain
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("name=value".to_string()));
        // Should match subdomain
        assert_eq!(
            jar.cookie_header("www.example.com", "/", false),
            Some("name=value".to_string())
        );
        // Should not match different domain
        assert_eq!(jar.cookie_header("other.com", "/", false), None);
    }

    #[test]
    fn parse_cookie_with_leading_dot_domain() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=.example.com", "www.example.com", "/", true);
        assert_eq!(jar.len(), 1);
        // Leading dot is stripped per RFC 6265
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("name=value".to_string()));
    }

    #[test]
    fn path_matching() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Path=/api", "example.com", "/", true);
        assert_eq!(jar.len(), 1);

        // Exact match
        assert_eq!(jar.cookie_header("example.com", "/api", false), Some("name=value".to_string()));
        // Sub-path match
        assert_eq!(
            jar.cookie_header("example.com", "/api/v1", false),
            Some("name=value".to_string())
        );
        // No match for different path
        assert_eq!(jar.cookie_header("example.com", "/other", false), None);
    }

    #[test]
    fn multiple_cookies() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("a=1", "example.com", "/", true);
        jar.parse_set_cookie("b=2", "example.com", "/", true);
        assert_eq!(jar.len(), 2);

        let header = jar.cookie_header("example.com", "/", false).unwrap();
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
        assert!(header.contains("; "));
    }

    #[test]
    fn cookie_replacement() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=old", "example.com", "/", true);
        jar.parse_set_cookie("name=new", "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("name=new".to_string()));
    }

    #[test]
    fn max_age_zero_expires_cookie() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value", "example.com", "/", true);
        assert_eq!(jar.len(), 1);

        // Max-Age=0 should mark as expired
        jar.parse_set_cookie("name=value; Max-Age=0", "example.com", "/", true);
        jar.remove_expired();
        assert!(jar.is_empty());
    }

    #[test]
    fn max_age_positive() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Max-Age=3600", "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        // Should still be valid (not expired)
        assert!(jar.cookie_header("example.com", "/", false).is_some());
    }

    #[test]
    fn empty_cookie_name_rejected() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("=value", "example.com", "/", true);
        assert!(jar.is_empty());
    }

    #[test]
    fn no_equals_rejected() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("nocookie", "example.com", "/", true);
        assert!(jar.is_empty());
    }

    #[test]
    fn default_cookie_path_computation() {
        assert_eq!(default_cookie_path("/"), "/");
        assert_eq!(default_cookie_path("/api/v1/resource"), "/api/v1");
        assert_eq!(default_cookie_path("/page"), "/");
        assert_eq!(default_cookie_path(""), "/");
    }

    #[test]
    fn domain_match_exact() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn domain_match_subdomain() {
        assert!(domain_matches("www.example.com", "example.com"));
    }

    #[test]
    fn domain_no_match() {
        assert!(!domain_matches("other.com", "example.com"));
        assert!(!domain_matches("notexample.com", "example.com"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Path=/; Max-Age=3600", "example.com", "/", true);
        jar.parse_set_cookie(
            "sid=abc123; Path=/api; Secure; HttpOnly",
            "sub.example.com",
            "/",
            true,
        );

        let mut buf = Vec::new();
        jar.save_to_writer(&mut buf).unwrap();
        let output = String::from_utf8(buf.clone()).unwrap();

        // Verify header
        assert!(output.starts_with("# Netscape HTTP Cookie File"));

        // Load back
        let mut loaded = CookieJar::new();
        loaded.load_from_reader(std::io::Cursor::new(buf)).unwrap();
        assert_eq!(loaded.len(), 2);

        // Verify cookies match
        assert!(loaded.cookie_header("example.com", "/", false).is_some());
        assert!(loaded.cookie_header("sub.example.com", "/api", true).is_some());
    }

    #[test]
    fn load_netscape_format() {
        let data = b"# Netscape HTTP Cookie File\n\
            .example.com\tTRUE\t/\tFALSE\t0\tsession\tval1\n\
            .secure.com\tTRUE\t/api\tTRUE\t9999999999\tsid\tabc\n";

        let mut jar = CookieJar::new();
        jar.load_from_reader(std::io::Cursor::new(data)).unwrap();
        assert_eq!(jar.len(), 2);

        // Session cookie (expires=0)
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("session=val1".to_string()));

        // Secure cookie
        assert_eq!(jar.cookie_header("secure.com", "/api", false), None);
        assert_eq!(jar.cookie_header("secure.com", "/api", true), Some("sid=abc".to_string()));
    }

    #[test]
    fn load_httponly_cookies() {
        let data = b"#HttpOnly_.example.com\tTRUE\t/\tFALSE\t0\tsecret\tval\n";
        let mut jar = CookieJar::new();
        jar.load_from_reader(std::io::Cursor::new(data)).unwrap();
        assert_eq!(jar.len(), 1);
        assert!(jar.cookie_header("example.com", "/", false).is_some());
    }

    #[test]
    fn load_skips_comments_and_empty() {
        let data =
            b"# Comment line\n\n\n.example.com\tTRUE\t/\tFALSE\t0\tname\tval\n# Another comment\n";
        let mut jar = CookieJar::new();
        jar.load_from_reader(std::io::Cursor::new(data)).unwrap();
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn load_skips_malformed_lines() {
        let data = b".example.com\tTRUE\t/\n.ok.com\tTRUE\t/\tFALSE\t0\tname\tval\n";
        let mut jar = CookieJar::new();
        jar.load_from_reader(std::io::Cursor::new(data)).unwrap();
        assert_eq!(jar.len(), 1); // Only the valid line
    }

    #[test]
    fn save_to_file_and_load() {
        let dir = std::env::temp_dir();
        let path = dir.join("urlx_test_cookies.txt");

        let mut jar = CookieJar::new();
        jar.parse_set_cookie("test=123; Path=/; Max-Age=7200", "filetest.com", "/", true);
        jar.save_to_file(&path).unwrap();

        let loaded = CookieJar::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.cookie_header("filetest.com", "/", false), Some("test=123".to_string()));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_format_fields() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("k=v; Path=/p; Secure", "example.com", "/", true);

        let mut buf = Vec::new();
        jar.save_to_writer(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Find the data line (skip header lines)
        let data_line = output.lines().find(|l| !l.starts_with('#') && !l.is_empty()).unwrap();
        let fields: Vec<&str> = data_line.split('\t').collect();
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[0], "example.com"); // domain (curl compat: no dot prefix)
        assert_eq!(fields[1], "FALSE"); // include subdomains
        assert_eq!(fields[2], "/p"); // path
        assert_eq!(fields[3], "TRUE"); // secure
        assert_eq!(fields[5], "k"); // name
        assert_eq!(fields[6], "v"); // value
    }

    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn domain_matches_case_insensitive() {
        assert!(domain_matches("Example.COM", "example.com"));
        assert!(domain_matches("example.com", "Example.COM"));
    }

    #[test]
    fn domain_matches_subdomain() {
        assert!(domain_matches("www.example.com", "example.com"));
        assert!(domain_matches("deep.sub.example.com", "example.com"));
    }

    #[test]
    fn domain_matches_no_partial() {
        // "notexample.com" should NOT match "example.com"
        assert!(!domain_matches("notexample.com", "example.com"));
    }

    #[test]
    fn domain_matches_shorter_host() {
        assert!(!domain_matches("com", "example.com"));
    }

    #[test]
    fn path_matches_exact_and_prefix() {
        assert!(path_matches("/", "/"));
        assert!(path_matches("/foo", "/foo"));
        assert!(path_matches("/foo/bar", "/foo"));
        assert!(path_matches("/foo/bar", "/foo/"));
        assert!(!path_matches("/foobar", "/foo"));
    }

    #[test]
    fn cookie_attr_case_insensitive() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie(
            "k=v; SECURE; HTTPONLY; PATH=/api; DOMAIN=example.com",
            "example.com",
            "/",
            true,
        );
        assert_eq!(jar.len(), 1);
        // SECURE flag should be set
        assert_eq!(jar.cookie_header("example.com", "/api", false), None);
        assert_eq!(jar.cookie_header("example.com", "/api", true), Some("k=v".to_string()));
    }

    #[test]
    fn domain_index_basic() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("a=1", "foo.com", "/", true);
        jar.parse_set_cookie("b=2", "bar.com", "/", true);
        jar.parse_set_cookie("c=3", "foo.com", "/", true);
        // Index should have 2 domains
        assert_eq!(jar.domain_index.len(), 2);
        assert_eq!(jar.domain_index["foo.com"].len(), 2);
        assert_eq!(jar.domain_index["bar.com"].len(), 1);
    }

    #[test]
    fn domain_index_subdomain_lookup() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("k=v; Domain=example.com", "www.example.com", "/", true);
        // Cookie is stored under "example.com"
        assert_eq!(jar.domain_index.len(), 1);
        // Subdomain lookup should find it
        assert_eq!(jar.cookie_header("sub.example.com", "/", false), Some("k=v".to_string()));
        // Non-matching domain should not find it
        assert_eq!(jar.cookie_header("other.com", "/", false), None);
    }

    #[test]
    fn domain_index_after_replacement() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("k=old", "example.com", "/", true);
        jar.parse_set_cookie("k=new", "example.com", "/", true);
        // Should have only 1 cookie (replaced)
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.domain_index["example.com"].len(), 1);
        assert_eq!(jar.cookie_header("example.com", "/", false), Some("k=new".to_string()));
    }

    // --- Public Suffix List tests ---

    #[test]
    fn psl_rejects_cookie_for_tld() {
        // Setting a cookie for ".com" should be rejected
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=com", "example.com", "/", true);
        assert!(jar.is_empty(), "cookie for TLD 'com' should be rejected");
    }

    #[test]
    fn psl_rejects_cookie_for_co_uk() {
        // ".co.uk" is a public suffix
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=co.uk", "example.co.uk", "/", true);
        assert!(jar.is_empty(), "cookie for public suffix 'co.uk' should be rejected");
    }

    #[test]
    fn psl_allows_cookie_for_etld_plus_one() {
        // "example.com" is eTLD+1, should be allowed
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=example.com", "www.example.com", "/", true);
        assert_eq!(jar.len(), 1, "cookie for eTLD+1 should be allowed");
    }

    #[test]
    fn psl_allows_cookie_for_subdomain() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=sub.example.com", "sub.example.com", "/", true);
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn psl_rejects_cookie_for_github_io() {
        // "github.io" is a public suffix (wildcard rule)
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=github.io", "foo.github.io", "/", true);
        assert!(jar.is_empty(), "cookie for public suffix 'github.io' should be rejected");
    }

    #[test]
    fn psl_allows_cookie_for_specific_github_io() {
        // "foo.github.io" is eTLD+1 under the wildcard rule
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=foo.github.io", "foo.github.io", "/", true);
        assert_eq!(jar.len(), 1, "cookie for eTLD+1 under wildcard should be allowed");
    }

    #[test]
    fn psl_allows_cookie_without_domain_attr() {
        // Host-only cookies (no Domain attr) are always allowed
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value", "example.com", "/", true);
        assert_eq!(jar.len(), 1, "host-only cookie should always be allowed");
    }

    #[test]
    fn psl_rejects_cookie_for_org() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=org", "example.org", "/", true);
        assert!(jar.is_empty());
    }

    #[test]
    fn psl_rejects_cookie_for_tokyo_jp() {
        // "tokyo.jp" is a public suffix
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=tokyo.jp", "example.tokyo.jp", "/", true);
        assert!(jar.is_empty());
    }

    #[test]
    fn psl_allows_cookie_for_etld1_tokyo_jp() {
        let mut jar = CookieJar::new();
        jar.parse_set_cookie("name=value; Domain=example.tokyo.jp", "example.tokyo.jp", "/", true);
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn is_public_suffix_basic() {
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("org"));
        assert!(is_public_suffix("net"));
        assert!(is_public_suffix("co.uk"));
        assert!(!is_public_suffix("example.com"));
        assert!(!is_public_suffix("www.example.com"));
    }

    #[test]
    fn domain_index_many_domains() {
        let mut jar = CookieJar::new();
        for i in 0..100 {
            jar.store_cookies(&[&format!("k{i}=v{i}")], &format!("host{i}.com"), "/", true);
        }
        assert_eq!(jar.len(), 100);
        assert_eq!(jar.domain_index.len(), 100);
        // Lookup specific domain
        assert_eq!(jar.cookie_header("host50.com", "/", false), Some("k50=v50".to_string()));
        // No match
        assert_eq!(jar.cookie_header("unknown.com", "/", false), None);
    }

    // ─── SameSite tests ───

    #[test]
    fn samesite_lax_parsed() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=123; SameSite=Lax"], "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies[0].same_site, SameSite::Lax);
    }

    #[test]
    fn samesite_strict_parsed() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=456; SameSite=Strict"], "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies[0].same_site, SameSite::Strict);
    }

    #[test]
    fn samesite_none_with_secure_accepted() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=789; SameSite=None; Secure"], "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies[0].same_site, SameSite::None);
        assert!(jar.cookies[0].secure);
    }

    #[test]
    fn samesite_none_without_secure_rejected() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=bad; SameSite=None"], "example.com", "/", true);
        // SameSite=None without Secure must be rejected
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn samesite_default_is_lax() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=def"], "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies[0].same_site, SameSite::Lax);
    }

    #[test]
    fn samesite_case_insensitive() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["a=1; samesite=STRICT"], "example.com", "/", true);
        assert_eq!(jar.cookies[0].same_site, SameSite::Strict);

        jar.store_cookies(&["b=2; SAMESITE=lax"], "example.com", "/", true);
        assert_eq!(jar.cookies[1].same_site, SameSite::Lax);
    }

    #[test]
    fn samesite_unknown_value_defaults_to_lax() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=x; SameSite=Invalid"], "example.com", "/", true);
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies[0].same_site, SameSite::Lax);
    }

    #[test]
    fn samesite_none_secure_cookie_sent_over_https() {
        let mut jar = CookieJar::new();
        jar.store_cookies(&["id=s; SameSite=None; Secure"], "example.com", "/", true);
        // Secure cookies should be sent over HTTPS
        assert!(jar.cookie_header("example.com", "/", true).is_some());
        // But not over HTTP
        assert!(jar.cookie_header("example.com", "/", false).is_none());
    }

    #[test]
    fn test_329_max_age_zero_deletes() {
        // Simulate test 329
        let mut jar = CookieJar::new();

        // Load cookies from files
        let data1 = b".host.foo.com\tTRUE\t/we/want/\tFALSE\t22147483647\ttest\tno\n";
        let data2 = b".host.foo.com\tTRUE\t/we/want/\tFALSE\t22147483647\ttester\tyes\n";
        jar.load_from_reader(std::io::Cursor::new(data1)).unwrap();
        jar.load_from_reader(std::io::Cursor::new(data2)).unwrap();
        assert_eq!(jar.len(), 2);

        // First request: should send both
        let header = jar.cookie_header("host.foo.com", "/we/want/329", false);
        assert!(header.is_some());
        let h = header.unwrap();
        assert!(h.contains("tester=yes"), "should have tester=yes, got: {h}");
        assert!(h.contains("test=no"), "should have test=no, got: {h}");

        // Server responds with Max-Age=0 for test cookie and Max-Age=-1 for testn1
        jar.parse_set_cookie(
            "testn1=yes; path=/we/want/; domain=.host.foo.com; Max-Age=-1;",
            "host.foo.com",
            "/we/want/329",
            false,
        );
        jar.parse_set_cookie(
            "test=yes; path=/we/want/; domain=.host.foo.com; Max-Age=0;",
            "host.foo.com",
            "/we/want/329",
            false,
        );

        // Second request should only send tester=yes
        let header = jar.cookie_header("host.foo.com", "/we/want/3290002", false);
        assert_eq!(header, Some("tester=yes".to_string()), "Only tester=yes should be sent");
    }
}
