//! URL parsing with curl compatibility quirks.
//!
//! Wraps the `url` crate and adds curl-specific behavior for
//! scheme defaults, host normalization, and edge cases.

use crate::error::Error;

/// A parsed URL with curl-compatible behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    inner: url::Url,
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

        let inner = url::Url::parse(&input).map_err(|e| Error::UrlParse(e.to_string()))?;

        Ok(Self { inner })
    }

    /// Returns the scheme (e.g., "https", "http").
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    /// Returns the host as a string, if present.
    #[must_use]
    pub fn host_str(&self) -> Option<&str> {
        self.inner.host_str()
    }

    /// Returns the port, if explicitly specified.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.inner.port()
    }

    /// Returns the effective port (explicit or default for the scheme).
    #[must_use]
    pub fn port_or_default(&self) -> Option<u16> {
        self.inner.port_or_known_default()
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
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
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
    #[must_use]
    pub fn host_header_value(&self) -> String {
        let host = self.host_str().unwrap_or("");
        self.inner.port().map_or_else(|| host.to_string(), |port| format!("{host}:{port}"))
    }

    /// Returns the path and query suitable for an HTTP request line.
    #[must_use]
    pub fn request_target(&self) -> String {
        self.inner
            .query()
            .map_or_else(|| self.inner.path().to_string(), |q| format!("{}?{q}", self.inner.path()))
    }

    /// curl defaults to HTTP if no scheme is provided.
    fn maybe_add_scheme(input: &str) -> String {
        if input.contains("://") {
            input.to_string()
        } else {
            format!("http://{input}")
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
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
}
