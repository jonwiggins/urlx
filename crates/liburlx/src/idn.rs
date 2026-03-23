//! Internationalized Domain Name (IDN) support.
//!
//! Converts non-ASCII hostnames to their Punycode (ACE) representation
//! using IDNA 2008 / UTS #46 processing, matching curl's `libidn2` behavior.

use crate::error::Error;

/// Convert a hostname to its ASCII (Punycode) form using IDNA processing.
///
/// If the hostname is already ASCII, it is returned unchanged.
/// Returns an error if the hostname contains invalid characters or
/// labels that cannot be converted.
///
/// # Errors
///
/// Returns [`Error::UrlParse`] if IDNA processing fails (e.g., invalid
/// characters, empty labels after processing, or labels exceeding 63 bytes).
pub fn hostname_to_ascii(host: &str) -> Result<String, Error> {
    // Fast path: if the hostname is pure ASCII, no IDNA processing needed.
    if host.is_ascii() {
        return Ok(host.to_string());
    }

    idna::domain_to_ascii(host)
        .map_err(|_| Error::UrlParse(format!("Failed to convert IDN hostname: {host}")))
}

/// Convert the hostname part of an email address to Punycode.
///
/// Given an address like `user@hö.se`, returns `user@xn--h-1ga.se`.
/// If there is no `@`, the address is returned unchanged.
/// The local part (before `@`) is never modified.
///
/// # Errors
///
/// Returns [`Error::UrlParse`] if the domain part cannot be converted.
pub fn idn_email_address(addr: &str) -> Result<String, Error> {
    if let Some(at_pos) = addr.rfind('@') {
        let local = &addr[..at_pos];
        let domain = &addr[at_pos + 1..];
        if domain.is_empty() {
            return Ok(addr.to_string());
        }
        let ascii_domain = hostname_to_ascii(domain)?;
        Ok(format!("{local}@{ascii_domain}"))
    } else {
        // No @ — return as-is (e.g., just a local part for VRFY)
        Ok(addr.to_string())
    }
}

/// Check if a string contains any non-ASCII characters.
#[must_use]
pub fn has_non_ascii(s: &str) -> bool {
    !s.is_ascii()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_hostname_unchanged() {
        assert_eq!(hostname_to_ascii("example.com").unwrap(), "example.com");
    }

    #[test]
    fn idn_hostname_converted() {
        // åäö.se → xn--4cab6c.se
        assert_eq!(hostname_to_ascii("åäö.se").unwrap(), "xn--4cab6c.se");
    }

    #[test]
    fn idn_with_subdomain() {
        assert_eq!(hostname_to_ascii("www.åäö.se").unwrap(), "www.xn--4cab6c.se");
    }

    #[test]
    fn german_sharp_s() {
        let result = hostname_to_ascii("große.de").unwrap();
        assert!(result.ends_with(".de"));
        assert!(result.starts_with("xn--") || result.contains("xn--"));
    }

    #[test]
    fn email_address_domain_converted() {
        let result = idn_email_address("sender@åäö.se").unwrap();
        assert_eq!(result, "sender@xn--4cab6c.se");
    }

    #[test]
    fn email_address_ascii_unchanged() {
        let result = idn_email_address("sender@example.com").unwrap();
        assert_eq!(result, "sender@example.com");
    }

    #[test]
    fn email_no_at_unchanged() {
        let result = idn_email_address("justuser").unwrap();
        assert_eq!(result, "justuser");
    }

    #[test]
    fn email_preserves_utf8_local_part() {
        let result = idn_email_address("Avsändaren@åäö.se").unwrap();
        assert_eq!(result, "Avsändaren@xn--4cab6c.se");
    }

    #[test]
    fn has_non_ascii_detects_utf8() {
        assert!(has_non_ascii("åäö"));
        assert!(has_non_ascii("Avsändaren"));
        assert!(!has_non_ascii("example.com"));
        assert!(!has_non_ascii("sender@example.com"));
    }
}
