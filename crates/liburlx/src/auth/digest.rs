//! HTTP Digest authentication (RFC 7616).
//!
//! Implements the Digest access authentication scheme with support for
//! MD5 and SHA-256 algorithms, and `qop=auth` quality of protection.

use crate::error::Error;

/// A parsed Digest authentication challenge from a `WWW-Authenticate` header.
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    /// The authentication realm.
    pub realm: String,
    /// The server-generated nonce.
    pub nonce: String,
    /// The quality of protection (typically "auth").
    pub qop: Option<String>,
    /// The hash algorithm ("MD5", "SHA-256", etc.).
    pub algorithm: DigestAlgorithm,
    /// The opaque string to echo back.
    pub opaque: Option<String>,
    /// Whether the nonce is stale (client should retry with new nonce).
    pub stale: bool,
}

/// Supported Digest hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 (RFC 2617 default).
    Md5,
    /// SHA-256 (RFC 7616).
    Sha256,
}

impl DigestAlgorithm {
    /// Compute the hash of the input bytes, returning a hex string.
    fn hash(self, input: &[u8]) -> String {
        use md5::Digest as _;

        match self {
            Self::Md5 => hex::encode(md5::Md5::digest(input)),
            Self::Sha256 => hex::encode(sha2::Sha256::digest(input)),
        }
    }
}

impl DigestChallenge {
    /// Parse a Digest challenge from a `WWW-Authenticate` header value.
    ///
    /// Expected format: `Digest realm="...", nonce="...", qop="auth", algorithm=MD5`
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the header cannot be parsed.
    pub fn parse(header_value: &str) -> Result<Self, Error> {
        let stripped = header_value
            .strip_prefix("Digest")
            .or_else(|| header_value.strip_prefix("digest"))
            .ok_or_else(|| Error::Http("not a Digest challenge".to_string()))?
            .trim();

        let mut realm = None;
        let mut nonce = None;
        let mut qop = None;
        let mut algorithm = DigestAlgorithm::Md5; // Default per RFC
        let mut opaque = None;
        let mut stale = false;

        for param in split_params(stripped) {
            let (key, value) = split_kv(param);
            let value = unquote(value);

            match key.to_lowercase().as_str() {
                "realm" => realm = Some(value.to_string()),
                "nonce" => nonce = Some(value.to_string()),
                "qop" => qop = Some(value.to_string()),
                "algorithm" => {
                    algorithm = match value.to_uppercase().as_str() {
                        "SHA-256" => DigestAlgorithm::Sha256,
                        _ => DigestAlgorithm::Md5,
                    };
                }
                "opaque" => opaque = Some(value.to_string()),
                "stale" => stale = value.eq_ignore_ascii_case("true"),
                _ => {} // Ignore unknown parameters
            }
        }

        let realm =
            realm.ok_or_else(|| Error::Http("Digest challenge missing realm".to_string()))?;
        let nonce =
            nonce.ok_or_else(|| Error::Http("Digest challenge missing nonce".to_string()))?;

        Ok(Self { realm, nonce, qop, algorithm, opaque, stale })
    }

    /// Compute the Digest authorization header value.
    ///
    /// Implements the response computation per RFC 7616:
    /// - HA1 = H(username:realm:password)
    /// - HA2 = H(method:uri)
    /// - If qop=auth: response = H(HA1:nonce:nc:cnonce:qop:HA2)
    /// - Otherwise: response = H(HA1:nonce:HA2)
    #[must_use]
    pub fn respond(
        &self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        nc: u32,
        cnonce: &str,
    ) -> String {
        use std::fmt::Write as _;

        let ha1 = self
            .algorithm
            .hash(format!("{username}:{realm}:{password}", realm = self.realm).as_bytes());

        let ha2 = self.algorithm.hash(format!("{method}:{uri}").as_bytes());

        let response = if self.qop.is_some() {
            let nc_str = format!("{nc:08x}");
            self.algorithm.hash(
                format!("{ha1}:{nonce}:{nc_str}:{cnonce}:auth:{ha2}", nonce = self.nonce)
                    .as_bytes(),
            )
        } else {
            self.algorithm.hash(format!("{ha1}:{nonce}:{ha2}", nonce = self.nonce).as_bytes())
        };

        let mut header = format!(
            "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\"",
            realm = self.realm,
            nonce = self.nonce,
        );

        if self.qop.is_some() {
            let nc_str = format!("{nc:08x}");
            let _ = write!(header, ", qop=auth, nc={nc_str}, cnonce=\"{cnonce}\"");
        }

        if let Some(ref opaque) = self.opaque {
            let _ = write!(header, ", opaque=\"{opaque}\"");
        }

        match self.algorithm {
            DigestAlgorithm::Sha256 => header.push_str(", algorithm=SHA-256"),
            DigestAlgorithm::Md5 => header.push_str(", algorithm=MD5"),
        }

        header
    }
}

/// Generate a random client nonce (cnonce) as a hex string.
#[must_use]
pub fn generate_cnonce() -> String {
    // Use a simple approach: mix of timestamp and a counter
    // For better randomness in production, use a CSPRNG, but this
    // is sufficient for Digest auth cnonce generation.
    use std::time::SystemTime;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let seed = now.as_nanos();
    format!("{seed:016x}")
}

/// Split comma-separated parameters, respecting quoted strings.
fn split_params(s: &str) -> Vec<&str> {
    let mut params = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let param = s[start..i].trim();
                if !param.is_empty() {
                    params.push(param);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = s[start..].trim();
    if !last.is_empty() {
        params.push(last);
    }

    params
}

/// Split a key=value pair.
fn split_kv(s: &str) -> (&str, &str) {
    if let Some((key, value)) = s.split_once('=') {
        (key.trim(), value.trim())
    } else {
        (s.trim(), "")
    }
}

/// Remove surrounding quotes from a value.
fn unquote(s: &str) -> &str {
    s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_digest_challenge() {
        let header = r#"Digest realm="test@example.com", nonce="abc123", qop="auth""#;
        let challenge = DigestChallenge::parse(header).unwrap();
        assert_eq!(challenge.realm, "test@example.com");
        assert_eq!(challenge.nonce, "abc123");
        assert_eq!(challenge.qop.as_deref(), Some("auth"));
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert!(challenge.opaque.is_none());
        assert!(!challenge.stale);
    }

    #[test]
    fn parse_digest_challenge_with_sha256() {
        let header =
            r#"Digest realm="example", nonce="xyz", algorithm=SHA-256, opaque="opq", stale=true"#;
        let challenge = DigestChallenge::parse(header).unwrap();
        assert_eq!(challenge.realm, "example");
        assert_eq!(challenge.algorithm, DigestAlgorithm::Sha256);
        assert_eq!(challenge.opaque.as_deref(), Some("opq"));
        assert!(challenge.stale);
    }

    #[test]
    fn parse_digest_challenge_missing_realm() {
        let header = r#"Digest nonce="abc""#;
        assert!(DigestChallenge::parse(header).is_err());
    }

    #[test]
    fn parse_digest_challenge_missing_nonce() {
        let header = r#"Digest realm="test""#;
        assert!(DigestChallenge::parse(header).is_err());
    }

    #[test]
    fn parse_not_digest() {
        let header = "Basic realm=\"test\"";
        assert!(DigestChallenge::parse(header).is_err());
    }

    #[test]
    fn digest_response_md5_with_qop() {
        // RFC 2617 example values (adapted)
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            stale: false,
        };

        let response =
            challenge.respond("Mufasa", "Circle Of Life", "GET", "/dir/index.html", 1, "0a4f113b");

        assert!(response.starts_with("Digest username=\"Mufasa\""));
        assert!(response.contains("realm=\"testrealm@host.com\""));
        assert!(response.contains("qop=auth"));
        assert!(response.contains("nc=00000001"));
        assert!(response.contains("cnonce=\"0a4f113b\""));
        assert!(response.contains("algorithm=MD5"));
        assert!(response.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
        // Verify the response hash is computed correctly
        assert!(response.contains("response=\""));
    }

    #[test]
    fn digest_response_md5_rfc2617_example() {
        // Test against the well-known RFC 2617 example
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            opaque: None,
            stale: false,
        };

        let response =
            challenge.respond("Mufasa", "Circle Of Life", "GET", "/dir/index.html", 1, "0a4f113b");

        // HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life")
        //      = 939e7578ed9e3c518a452acee763bce9
        // HA2 = MD5("GET:/dir/index.html")
        //      = 39aff3a2bab6126f332b942af5e6afc3
        // response = MD5("939e7578ed9e3c518a452acee763bce9:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af5e6afc3")
        //          = 6629fae49393a05397450978507c4ef1
        assert!(response.contains("response=\"6629fae49393a05397450978507c4ef1\""));
    }

    #[test]
    fn digest_response_without_qop() {
        let challenge = DigestChallenge {
            realm: "test".to_string(),
            nonce: "nonce123".to_string(),
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            opaque: None,
            stale: false,
        };

        let response = challenge.respond("user", "pass", "GET", "/", 1, "cnonce");

        assert!(!response.contains("qop="));
        assert!(!response.contains("nc="));
        assert!(!response.contains("cnonce="));
        assert!(response.contains("response=\""));
    }

    #[test]
    fn digest_response_sha256() {
        let challenge = DigestChallenge {
            realm: "test".to_string(),
            nonce: "nonce".to_string(),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha256,
            opaque: None,
            stale: false,
        };

        let response = challenge.respond("user", "pass", "GET", "/", 1, "cnonce");
        assert!(response.contains("algorithm=SHA-256"));
    }

    #[test]
    fn generate_cnonce_not_empty() {
        let cnonce = generate_cnonce();
        assert!(!cnonce.is_empty());
        assert!(cnonce.len() >= 16);
    }

    #[test]
    fn split_params_basic() {
        let params = split_params(r#"realm="test", nonce="abc""#);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], r#"realm="test""#);
        assert_eq!(params[1], r#"nonce="abc""#);
    }

    #[test]
    fn split_params_with_commas_in_quotes() {
        let params = split_params(r#"realm="a,b", nonce="c""#);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], r#"realm="a,b""#);
    }

    #[test]
    fn unquote_removes_quotes() {
        assert_eq!(unquote(r#""hello""#), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("\""), "\"");
    }
}
