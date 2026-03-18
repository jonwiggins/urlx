//! URL parsing with curl compatibility quirks.
//!
//! Wraps the `url` crate and adds curl-specific behavior for
//! scheme defaults, host normalization, and edge cases.

use crate::error::Error;

/// A parsed URL with curl-compatible behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    inner: url::Url,
    /// Override host for URLs where the `url` crate rejects the hostname
    /// (e.g., `test.80` which WHATWG spec treats as invalid IPv4).
    /// When set, this takes priority over `inner.host_str()`.
    override_host: Option<String>,
    /// Raw input URL before parsing (preserves dot segments for --path-as-is).
    raw_input: Option<String>,
}

impl Url {
    /// Parse a URL string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the URL cannot be parsed.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::UrlParse("empty URL".to_string()));
        }

        let input = Self::maybe_add_scheme(input);

        // Reject URLs with multiple @ in the authority (e.g. http://user@host:80@other).
        // curl treats this as an invalid port number (test 1260).
        if let Some(scheme_end) = input.find("://") {
            let rest = &input[scheme_end + 3..];
            let authority_end = rest.find('/').unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            // Count @ signs in the authority — more than one means ambiguous userinfo/host
            if authority.chars().filter(|&c| c == '@').count() > 1 {
                return Err(Error::UrlParse(
                    "Port number was not a decimal number between 0 and 65535".to_string(),
                ));
            }
        }

        match url::Url::parse(&input) {
            Ok(inner) => {
                // Reject extremely long hostnames (curl returns CURLE_URL_MALFORMAT: test 399).
                // Note: hostnames > 255 chars are allowed here because SOCKS5h proxies may
                // resolve them remotely; the 255-byte SOCKS5 limit is checked at the proxy
                // layer (curl compat: test 728).
                if inner.host_str().is_some_and(|h| h.len() > 65535) {
                    return Err(Error::UrlParse("hostname too long".to_string()));
                }
                Ok(Self { inner, override_host: None, raw_input: Some(input.clone()) })
            }
            Err(e) => {
                // The `url` crate rejects hostnames like "test.80" because the WHATWG URL
                // standard treats a label ending in a number as an IPv4 address attempt.
                // curl treats any non-IP as a hostname, so we work around this by
                // replacing the host with a placeholder, parsing, and storing the
                // original host as an override.
                let err_str = e.to_string();
                if err_str.contains("invalid IPv4 address")
                    || err_str.contains("invalid domain character")
                {
                    if let Some(after_scheme) = input.find("://") {
                        let host_start = after_scheme + 3;
                        let rest = &input[host_start..];
                        // Skip userinfo if present
                        let host_part_start = rest.find('@').map_or(0, |at_pos| {
                            let slash_pos = rest.find('/').unwrap_or(rest.len());
                            if at_pos < slash_pos {
                                at_pos + 1
                            } else {
                                0
                            }
                        });
                        let host_rest = &rest[host_part_start..];
                        // Find end of host (: for port, / for path, ? for query, # for fragment)
                        let host_end =
                            host_rest.find([':', '/', '?', '#']).unwrap_or(host_rest.len());
                        let original_host = &host_rest[..host_end];

                        // Replace with a placeholder hostname that the url crate accepts
                        let placeholder = "urlx-placeholder.invalid";
                        let modified = format!(
                            "{}{}{}",
                            &input[..host_start + host_part_start],
                            placeholder,
                            &host_rest[host_end..],
                        );
                        if let Ok(inner) = url::Url::parse(&modified) {
                            return Ok(Self {
                                inner,
                                override_host: Some(original_host.to_string()),
                                raw_input: Some(input.clone()),
                            });
                        }
                    }
                }
                Err(Error::UrlParse(e.to_string()))
            }
        }
    }

    /// Returns the scheme (e.g., "https", "http").
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    /// Returns the host as a string, if present.
    ///
    /// Uses the override host when the `url` crate couldn't parse the original
    /// hostname (e.g., `test.80`).
    #[must_use]
    pub fn host_str(&self) -> Option<&str> {
        self.override_host.as_deref().or_else(|| self.inner.host_str())
    }

    /// Returns the port, if explicitly specified.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.inner.port()
    }

    /// Returns the effective port (explicit or default for the scheme).
    ///
    /// Supports additional schemes beyond what the `url` crate knows about:
    /// - `ftps://` defaults to port 990
    #[must_use]
    pub fn port_or_default(&self) -> Option<u16> {
        self.inner.port_or_known_default().or_else(|| match self.inner.scheme() {
            "ftps" => Some(990),
            "sftp" | "scp" | "ssh" => Some(22),
            _ => None,
        })
    }

    /// Returns the path component.
    #[must_use]
    pub fn path(&self) -> &str {
        self.inner.path()
    }

    /// Returns the query string, if present.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.inner.query()
    }

    /// Returns the fragment, if present.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.inner.fragment()
    }

    /// Returns the username, if present.
    #[must_use]
    pub fn username(&self) -> &str {
        self.inner.username()
    }

    /// Returns the password, if present.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.inner.password()
    }

    /// Returns user:password credentials if present in the URL.
    ///
    /// Returns `None` if no username is set (empty username counts as not set).
    #[must_use]
    pub fn credentials(&self) -> Option<(&str, &str)> {
        let user = self.inner.username();
        if user.is_empty() {
            return None;
        }
        let pass = self.inner.password().unwrap_or("");
        Some((user, pass))
    }

    /// Returns the full URL as a string.
    ///
    /// When the URL was parsed with a host override (e.g., `test.80`),
    /// this returns a corrected string with the original hostname restored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // For URLs with override_host, the inner URL has a placeholder host.
        // We return the inner string, and callers that need the correct host
        // should use host_str() or host_header_value() instead.
        // In practice this is only used for effective_url in responses and
        // absolute proxy URLs, where we need the real host.
        self.inner.as_str()
    }

    /// Returns the full URL with the original hostname restored.
    ///
    /// For URLs where `override_host` is set, the placeholder is replaced
    /// with the original host. For normal URLs, this is the same as `as_str()`.
    #[must_use]
    pub fn to_full_string(&self) -> String {
        self.override_host.as_ref().map_or_else(
            || self.inner.as_str().to_string(),
            |real_host| self.inner.as_str().replace("urlx-placeholder.invalid", real_host),
        )
    }

    /// Returns the host and port suitable for a TCP connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the URL has no host.
    pub fn host_and_port(&self) -> Result<(String, u16), Error> {
        let host = self
            .host_str()
            .ok_or_else(|| Error::UrlParse("URL has no host".to_string()))?
            .to_string();
        let port = self.port_or_default().ok_or_else(|| {
            Error::UrlParse("URL has no port and no default for scheme".to_string())
        })?;
        Ok((host, port))
    }

    /// Returns the Host header value (includes port if non-default).
    ///
    /// Preserves the original hostname case from the raw input URL so that
    /// `MiXeDcAsE.cOm` stays as-is in the Host header (curl compat: test 1318).
    #[must_use]
    pub fn host_header_value(&self) -> String {
        let host = self.raw_host_str().unwrap_or_else(|| self.host_str().unwrap_or("").to_string());
        match self.inner.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    /// Extract the original-cased hostname from the raw input URL.
    ///
    /// The `url` crate normalizes hostnames to lowercase. This method
    /// recovers the original casing from `raw_input` when available.
    fn raw_host_str(&self) -> Option<String> {
        let raw = self.raw_input.as_deref()?;
        let after_scheme = raw.find("://")?;
        let rest = &raw[after_scheme + 3..];
        // Skip userinfo if present (look for @ before first /)
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        let host_start = rest[..slash_pos].rfind('@').map_or(0, |at| at + 1);
        let host_rest = &rest[host_start..];
        // Find end of host: port separator, path, query, or fragment
        let host_end = host_rest.find([':', '/', '?', '#']).unwrap_or(host_rest.len());
        let raw_host = &host_rest[..host_end];
        // Verify it matches the parsed host (case-insensitively)
        let parsed_host = self.host_str()?;
        if raw_host.eq_ignore_ascii_case(parsed_host) {
            Some(raw_host.to_string())
        } else {
            None
        }
    }

    /// Returns the raw input URL string (before normalization).
    #[must_use]
    pub fn raw_input(&self) -> Option<&str> {
        self.raw_input.as_deref()
    }

    /// Clear the raw input (e.g., for redirect URLs that should use normalized paths).
    pub fn clear_raw_input(&mut self) {
        self.raw_input = None;
    }

    /// Returns the path and query suitable for an HTTP request line.
    ///
    /// In the query portion, `%20` is replaced with `+` (curl-compatible
    /// form-encoded spaces).
    #[must_use]
    pub fn request_target(&self) -> String {
        // Use the raw input path to preserve characters that the url crate normalizes
        // (e.g., `\` to `/`, `{`/`}` to percent-encoded forms). Then normalize dot
        // segments (./ and ../) for security. This matches curl's behavior.
        if let Some(ref raw) = self.raw_input {
            let raw_path = extract_raw_path_and_query(raw);
            return normalize_dot_segments(&raw_path);
        }
        // Fallback: use the parsed URL's path with curl-compat decoding
        let path = self
            .inner
            .path()
            .replace("%22", "\"")
            .replace("%7B", "{")
            .replace("%7D", "}")
            .replace("%5C", "\\");
        match self.inner.query() {
            Some(q) => format!("{path}?{}", q.replace("%20", "+")),
            None => path,
        }
    }

    /// Set the port on the URL.
    ///
    /// Replaces any existing port. Use `None` to remove an explicit port
    /// (reverting to the scheme default).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the URL does not support a port (e.g., `file://`).
    pub fn set_port(&mut self, port: Option<u16>) -> Result<(), Error> {
        self.inner
            .set_port(port)
            .map_err(|()| Error::UrlParse("cannot set port on this URL".to_string()))
    }

    /// Set the scheme on the URL.
    ///
    /// This rebuilds the URL string with the new scheme rather than using
    /// `url::Url::set_scheme`, which rejects transitions between "special"
    /// and "non-special" schemes (e.g., http → socks5).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the resulting URL cannot be parsed.
    pub fn set_scheme(&mut self, scheme: &str) -> Result<(), Error> {
        // Try the native method first (works for same-category scheme changes)
        if self.inner.set_scheme(scheme).is_ok() {
            return Ok(());
        }
        // Fallback: reconstruct the URL string with the new scheme
        let old_str = self.inner.as_str();
        let rest = old_str.find("://").map_or(old_str, |idx| &old_str[idx..]);
        let new_str = format!("{scheme}{rest}");
        self.inner = url::Url::parse(&new_str)
            .map_err(|e| Error::UrlParse(format!("cannot set scheme to '{scheme}': {e}")))?;
        Ok(())
    }

    /// curl defaults to HTTP if no scheme is provided.
    /// Known URL schemes that we recognize without `://`.
    ///
    /// These schemes work with single-colon syntax (e.g., `file:/path`).
    const KNOWN_SCHEMES: &'static [&'static str] = &[
        "file", "ftp", "ftps", "http", "https", "sftp", "scp", "dict", "tftp", "mqtt", "ws", "wss",
        "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "telnet", "ldap", "ldaps", "gopher",
        "gophers",
    ];

    fn maybe_add_scheme(input: &str) -> String {
        if input.contains("://") {
            return input.to_string();
        }
        // Check for scheme:<something> patterns (e.g., file:/path)
        // Only match known URL schemes to avoid confusing hostname:port
        if let Some(colon_pos) = input.find(':') {
            let before_colon = &input[..colon_pos];
            if Self::KNOWN_SCHEMES.iter().any(|s| s.eq_ignore_ascii_case(before_colon)) {
                return input.to_string();
            }
        }
        format!("http://{input}")
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

/// Extract the path and query from a raw URL string (preserving special characters).
/// Strips the fragment if present.
fn extract_raw_path_and_query(url_str: &str) -> String {
    if let Some(scheme_end) = url_str.find("://") {
        let after_scheme = &url_str[scheme_end + 3..];
        // Find the start of path: first `/` or `?` after the authority
        let slash_pos = after_scheme.find('/');
        let query_pos = after_scheme.find('?');
        let path_start = match (slash_pos, query_pos) {
            (Some(s), Some(q)) => Some(s.min(q)),
            (Some(s), None) => Some(s),
            (None, Some(q)) => Some(q),
            (None, None) => None,
        };
        if let Some(start) = path_start {
            let path_and_rest = &after_scheme[start..];
            // If starts with '?' (no explicit path), prepend '/'
            let result = if path_and_rest.starts_with('?') {
                format!("/{path_and_rest}")
            } else {
                path_and_rest.to_string()
            };
            // Strip fragment if present
            if let Some(frag_pos) = result.find('#') {
                return result[..frag_pos].to_string();
            }
            return result;
        }
        return "/".to_string();
    }
    url_str.to_string()
}

/// Normalize dot segments (`.` and `..`) in a path string per RFC 3986 Section 5.2.4.
/// Preserves query string. This handles `/../`, `/./`, trailing `/..` and `/.`.
fn normalize_dot_segments(path_and_query: &str) -> String {
    // Split path from query
    let (path, query) = path_and_query.find('?').map_or((path_and_query, None), |q_pos| {
        (&path_and_query[..q_pos], Some(&path_and_query[q_pos..]))
    });

    // Split into segments
    let mut output_segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "." => {
                // Skip single-dot segments
            }
            ".." => {
                // Pop the last segment (go up one directory)
                let _ = output_segments.pop();
            }
            _ => {
                output_segments.push(segment);
            }
        }
    }

    let normalized = output_segments.join("/");
    // Ensure path starts with /
    let result = if normalized.starts_with('/') {
        normalized
    } else if path.starts_with('/') {
        format!("/{normalized}")
    } else {
        normalized
    };

    match query {
        Some(q) => format!("{result}{q}"),
        None => result,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_https() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
        assert_eq!(url.query(), Some("q=1"));
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn parse_simple_http() {
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port_or_default(), Some(80));
    }

    #[test]
    fn parse_with_port() {
        let url = Url::parse("http://example.com:8080/path").unwrap();
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.port_or_default(), Some(8080));
    }

    #[test]
    fn parse_https_default_port() {
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_default(), Some(443));
    }

    #[test]
    fn parse_with_fragment() {
        let url = Url::parse("https://example.com/page#section").unwrap();
        assert_eq!(url.fragment(), Some("section"));
    }

    #[test]
    fn parse_with_userinfo() {
        let url = Url::parse("http://user:pass@example.com/").unwrap();
        assert_eq!(url.username(), "user");
        assert_eq!(url.password(), Some("pass"));
    }

    #[test]
    fn parse_empty_returns_error() {
        assert!(Url::parse("").is_err());
    }

    #[test]
    fn parse_no_scheme_defaults_to_http() {
        let url = Url::parse("example.com/path").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn host_and_port_http() {
        let url = Url::parse("http://example.com/path").unwrap();
        let (host, port) = url.host_and_port().unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn host_and_port_https() {
        let url = Url::parse("https://secure.example.com/").unwrap();
        let (host, port) = url.host_and_port().unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn host_and_port_custom() {
        let url = Url::parse("http://localhost:3000/api").unwrap();
        let (host, port) = url.host_and_port().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 3000);
    }

    #[test]
    fn request_target_with_query() {
        let url = Url::parse("http://example.com/api?key=value").unwrap();
        assert_eq!(url.request_target(), "/api?key=value");
    }

    #[test]
    fn request_target_without_query() {
        let url = Url::parse("http://example.com/api").unwrap();
        assert_eq!(url.request_target(), "/api");
    }

    #[test]
    fn request_target_root() {
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.request_target(), "/");
    }

    #[test]
    fn display_roundtrip() {
        let input = "https://example.com/path?q=1#frag";
        let url = Url::parse(input).unwrap();
        assert_eq!(url.to_string(), input);
    }

    #[test]
    fn parse_ipv4_host() {
        let url = Url::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn parse_ipv6_host() {
        let url = Url::parse("http://[::1]:8080/").unwrap();
        assert_eq!(url.host_str(), Some("[::1]"));
        assert_eq!(url.port(), Some(8080));
    }

    // --- Edge cases ---

    #[test]
    fn parse_percent_encoded_path() {
        let url = Url::parse("http://example.com/hello%20world").unwrap();
        assert_eq!(url.path(), "/hello%20world");
    }

    #[test]
    fn parse_percent_encoded_query() {
        let url = Url::parse("http://example.com/path?q=hello%20world").unwrap();
        assert_eq!(url.query(), Some("q=hello%20world"));
    }

    #[test]
    fn parse_credentials_in_url() {
        let url = Url::parse("http://admin:secret@example.com/").unwrap();
        let (user, pass) = url.credentials().unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn parse_credentials_username_only() {
        let url = Url::parse("http://admin@example.com/").unwrap();
        let (user, pass) = url.credentials().unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "");
    }

    #[test]
    fn parse_no_credentials() {
        let url = Url::parse("http://example.com/").unwrap();
        assert!(url.credentials().is_none());
    }

    #[test]
    fn parse_ftp_scheme() {
        let url = Url::parse("ftp://files.example.com/pub/readme.txt").unwrap();
        assert_eq!(url.scheme(), "ftp");
        assert_eq!(url.host_str(), Some("files.example.com"));
        assert_eq!(url.path(), "/pub/readme.txt");
        assert_eq!(url.port_or_default(), Some(21));
    }

    #[test]
    fn parse_ftps_scheme() {
        let url = Url::parse("ftps://secure.example.com/data/file.csv").unwrap();
        assert_eq!(url.scheme(), "ftps");
        assert_eq!(url.host_str(), Some("secure.example.com"));
        assert_eq!(url.path(), "/data/file.csv");
        assert_eq!(url.port_or_default(), Some(990));
    }

    #[test]
    fn parse_ftps_custom_port() {
        let url = Url::parse("ftps://secure.example.com:2121/file.txt").unwrap();
        assert_eq!(url.scheme(), "ftps");
        assert_eq!(url.port(), Some(2121));
        assert_eq!(url.port_or_default(), Some(2121));
    }

    #[test]
    fn parse_ftps_with_credentials() {
        let url = Url::parse("ftps://user:pass@ftp.example.com/pub/").unwrap();
        let (user, pass) = url.credentials().unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }

    #[test]
    fn parse_file_url() {
        let url = Url::parse("file:///tmp/test.txt").unwrap();
        assert_eq!(url.scheme(), "file");
        assert_eq!(url.path(), "/tmp/test.txt");
    }

    #[test]
    fn parse_url_with_special_query_chars() {
        let url = Url::parse("http://example.com/search?q=a&b=c&d=e").unwrap();
        assert_eq!(url.query(), Some("q=a&b=c&d=e"));
    }

    #[test]
    fn parse_path_with_dots() {
        let url = Url::parse("http://example.com/a/b/../c").unwrap();
        // URL crate normalizes .. segments
        assert_eq!(url.path(), "/a/c");
    }

    #[test]
    fn parse_trailing_slash() {
        let url = Url::parse("http://example.com/path/").unwrap();
        assert_eq!(url.path(), "/path/");
    }

    #[test]
    fn parse_double_slash_in_path() {
        let url = Url::parse("http://example.com//path").unwrap();
        assert_eq!(url.path(), "//path");
    }

    #[test]
    fn host_header_default_port_omitted() {
        let url = Url::parse("http://example.com/").unwrap();
        assert_eq!(url.host_header_value(), "example.com");
    }

    #[test]
    fn host_header_custom_port_included() {
        let url = Url::parse("http://example.com:8080/").unwrap();
        assert_eq!(url.host_header_value(), "example.com:8080");
    }

    #[test]
    fn parse_long_path() {
        let long_path = "/a".repeat(500);
        let url_str = format!("http://example.com{long_path}");
        let url = Url::parse(&url_str).unwrap();
        assert_eq!(url.path().len(), 1000);
    }

    #[test]
    fn parse_empty_path() {
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.path(), "/");
    }

    #[test]
    fn parse_url_with_port_zero() {
        // Port 0 is technically valid in a URL (means auto-assign)
        let url = Url::parse("http://example.com:0/").unwrap();
        assert_eq!(url.port(), Some(0));
    }

    #[test]
    fn parse_sftp_scheme() {
        let url = Url::parse("sftp://user@host.example.com/path/file.txt").unwrap();
        assert_eq!(url.scheme(), "sftp");
        assert_eq!(url.host_str(), Some("host.example.com"));
        assert_eq!(url.path(), "/path/file.txt");
        assert_eq!(url.port_or_default(), Some(22));
        assert_eq!(url.username(), "user");
    }

    #[test]
    fn parse_scp_scheme() {
        let url = Url::parse("scp://user:pass@host.example.com/remote/file").unwrap();
        assert_eq!(url.scheme(), "scp");
        assert_eq!(url.host_str(), Some("host.example.com"));
        assert_eq!(url.path(), "/remote/file");
        assert_eq!(url.port_or_default(), Some(22));
        let (user, pass) = url.credentials().unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }

    #[test]
    fn parse_sftp_custom_port() {
        let url = Url::parse("sftp://user@host.example.com:2222/file.txt").unwrap();
        assert_eq!(url.port(), Some(2222));
        assert_eq!(url.port_or_default(), Some(2222));
    }

    #[test]
    fn set_port_explicit() {
        let mut url = Url::parse("http://example.com:3128/path").unwrap();
        url.set_port(Some(9999)).unwrap();
        assert_eq!(url.port(), Some(9999));
        assert_eq!(url.as_str(), "http://example.com:9999/path");
    }

    #[test]
    fn set_port_remove() {
        let mut url = Url::parse("http://example.com:3128/path").unwrap();
        url.set_port(None).unwrap();
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_default(), Some(80));
    }

    #[test]
    fn set_scheme_http_to_socks5() {
        let mut url = Url::parse("http://proxy.example.com:8080/").unwrap();
        url.set_scheme("socks5").unwrap();
        assert_eq!(url.scheme(), "socks5");
        assert_eq!(url.host_str(), Some("proxy.example.com"));
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn set_scheme_invalid() {
        let mut url = Url::parse("http://example.com/").unwrap();
        // Empty scheme should fail
        assert!(url.set_scheme("").is_err());
    }
}
