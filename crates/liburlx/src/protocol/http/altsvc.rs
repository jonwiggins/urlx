//! Alt-Svc header parsing (RFC 7838).
//!
//! Parses `Alt-Svc` response headers to discover alternative services
//! (e.g., HTTP/3 via QUIC). Currently provides parsing only; caching
//! and automatic upgrade are planned for future phases.

use std::time::Duration;

/// A single alternative service entry from an `Alt-Svc` header.
///
/// Example: `h3=":443"; ma=2592000` produces an `AltSvc` with
/// `protocol_id = "h3"`, `host = ""`, `port = 443`, and
/// `max_age = Duration::from_secs(2592000)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc {
    /// ALPN protocol identifier (e.g., "h3", "h2", "h3-29").
    pub protocol_id: String,
    /// Alternative hostname (empty string means same as origin).
    pub host: String,
    /// Alternative port number.
    pub port: u16,
    /// Maximum age before the entry expires.
    pub max_age: Duration,
}

/// Default max-age for Alt-Svc entries (24 hours per RFC 7838).
const DEFAULT_MAX_AGE_SECS: u64 = 86400;

/// Parse an `Alt-Svc` header value into a list of alternative service entries.
///
/// Handles the `clear` directive (returns empty vec) and multiple
/// comma-separated alternatives.
///
/// # Examples
///
/// ```
/// use liburlx::protocol::http::altsvc::parse_alt_svc;
///
/// let entries = parse_alt_svc(r#"h3=":443"; ma=2592000, h2=":443""#);
/// assert_eq!(entries.len(), 2);
/// assert_eq!(entries[0].protocol_id, "h3");
/// assert_eq!(entries[0].port, 443);
/// ```
#[must_use]
pub fn parse_alt_svc(value: &str) -> Vec<AltSvc> {
    let trimmed = value.trim();

    // "clear" means the server wants to invalidate all cached Alt-Svc entries
    if trimmed == "clear" {
        return Vec::new();
    }

    let mut results = Vec::new();

    for entry in split_entries(trimmed) {
        if let Some(alt) = parse_single_entry(entry.trim()) {
            results.push(alt);
        }
    }

    results
}

/// Split Alt-Svc header into individual entries, respecting quoted strings.
fn split_entries(value: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, ch) in value.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                entries.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    if start < value.len() {
        entries.push(&value[start..]);
    }

    entries
}

/// Parse a single Alt-Svc entry like `h3=":443"; ma=2592000`.
fn parse_single_entry(entry: &str) -> Option<AltSvc> {
    // Split on first '=' to get protocol_id and authority
    let (proto_id, rest) = entry.split_once('=')?;
    let protocol_id = proto_id.trim().to_string();

    // Parse the rest: "authority"; params...
    let mut parts = rest.splitn(2, ';');
    let authority_str = parts.next()?.trim().trim_matches('"');
    let params_str = parts.next().unwrap_or("");

    // Parse authority (host:port)
    let (host, port) = parse_authority(authority_str)?;

    // Parse parameters
    let max_age = parse_max_age(params_str);

    Some(AltSvc { protocol_id, host, port, max_age })
}

/// Parse an authority string like ":443" or "alt.example.com:443".
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(colon_pos) = authority.rfind(':') {
        let host = authority[..colon_pos].to_string();
        let port: u16 = authority[colon_pos + 1..].parse().ok()?;
        Some((host, port))
    } else {
        // No port — invalid
        None
    }
}

/// Parse the `ma=` parameter from Alt-Svc parameters.
fn parse_max_age(params: &str) -> Duration {
    for param in params.split(';') {
        let param = param.trim();
        if let Some(val) = param.strip_prefix("ma=") {
            if let Ok(secs) = val.trim().parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
    }
    Duration::from_secs(DEFAULT_MAX_AGE_SECS)
}

/// Parse a `Retry-After` response header value.
///
/// The value can be either:
/// - A number of seconds (e.g., `120`)
/// - An HTTP-date (e.g., `Fri, 31 Dec 1999 23:59:59 GMT`) — not yet supported
///
/// Returns `None` if the value cannot be parsed.
///
/// # Examples
///
/// ```
/// use liburlx::protocol::http::altsvc::parse_retry_after;
///
/// assert_eq!(parse_retry_after("120"), Some(std::time::Duration::from_secs(120)));
/// assert_eq!(parse_retry_after("0"), Some(std::time::Duration::from_secs(0)));
/// assert_eq!(parse_retry_after("not a number"), None);
/// ```
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    // Try parsing as seconds first (most common)
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // HTTP-date parsing would go here in a future phase
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_clear() {
        let result = parse_alt_svc("clear");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_single_h3() {
        let result = parse_alt_svc(r#"h3=":443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[0].host, "");
        assert_eq!(result[0].port, 443);
        assert_eq!(result[0].max_age, Duration::from_secs(DEFAULT_MAX_AGE_SECS));
    }

    #[test]
    fn parse_with_max_age() {
        let result = parse_alt_svc(r#"h3=":443"; ma=2592000"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[0].port, 443);
        assert_eq!(result[0].max_age, Duration::from_secs(2_592_000));
    }

    #[test]
    fn parse_multiple_entries() {
        let result = parse_alt_svc(r#"h3=":443"; ma=2592000, h2=":443""#);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].protocol_id, "h3");
        assert_eq!(result[1].protocol_id, "h2");
    }

    #[test]
    fn parse_with_host() {
        let result = parse_alt_svc(r#"h3="alt.example.com:8443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "alt.example.com");
        assert_eq!(result[0].port, 8443);
    }

    #[test]
    fn parse_versioned_protocol() {
        let result = parse_alt_svc(r#"h3-29=":443""#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_id, "h3-29");
    }

    #[test]
    fn parse_empty_string() {
        let result = parse_alt_svc("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_whitespace() {
        let result = parse_alt_svc("   ");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_invalid_port() {
        let result = parse_alt_svc(r#"h3=":notaport""#);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_no_port() {
        let result = parse_alt_svc(r#"h3="noport""#);
        assert!(result.is_empty());
    }

    #[test]
    fn retry_after_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_zero() {
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn retry_after_with_whitespace() {
        assert_eq!(parse_retry_after("  60  "), Some(Duration::from_secs(60)));
    }

    #[test]
    fn retry_after_invalid() {
        assert_eq!(parse_retry_after("not a number"), None);
    }

    #[test]
    fn retry_after_http_date_not_supported() {
        // HTTP-date is not yet supported
        assert_eq!(parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT"), None);
    }

    #[test]
    fn split_entries_basic() {
        let entries = split_entries(r#"h3=":443", h2=":443""#);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn split_entries_with_quoted_comma() {
        // Comma inside quotes should not split
        let entries = split_entries(r#"h3="host,name:443""#);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_authority_basic() {
        let (host, port) = parse_authority(":443").unwrap();
        assert_eq!(host, "");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_authority_with_host() {
        let (host, port) = parse_authority("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }
}
