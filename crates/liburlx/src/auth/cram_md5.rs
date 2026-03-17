//! CRAM-MD5 SASL authentication (RFC 2195).
//!
//! Used by SMTP (RFC 4954), IMAP (RFC 3501 AUTHENTICATE), and POP3 (RFC 5034).
//! The mechanism is challenge-response: the server sends a base64 challenge,
//! the client replies with `username HMAC-MD5(password, challenge)` base64-encoded.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use std::fmt::Write;

/// Compute the CRAM-MD5 response for a given challenge.
///
/// Returns the string `"username hex_digest"` suitable for base64 encoding
/// and sending to the server.
///
/// # Algorithm
///
/// ```text
/// digest = HMAC-MD5(key=password, data=challenge)
/// response = "username hex_digest"
/// ```
#[must_use]
pub fn cram_md5_response(username: &str, password: &str, challenge: &str) -> String {
    type HmacMd5 = Hmac<Md5>;

    // HMAC-MD5 accepts any key length; `new_from_slice` only fails for
    // variable-output MACs (which MD5 is not), so this is infallible.
    let Ok(mut mac) = HmacMd5::new_from_slice(password.as_bytes()) else {
        unreachable!("HMAC-MD5 accepts any key length");
    };
    mac.update(challenge.as_bytes());
    let result = mac.finalize();
    let digest = result.into_bytes();

    // Format as "username hex_digest"
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in &digest {
        let _ = write!(hex, "{b:02x}");
    }
    format!("{username} {hex}")
}

/// Compute the POP3 APOP digest.
///
/// APOP uses plain MD5 (not HMAC): `MD5(timestamp + password)`.
///
/// Returns the hex digest string.
#[must_use]
pub fn apop_digest(timestamp: &str, password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 2);
    for b in &result {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cram_md5_known_vector() {
        // From curl test suite: challenge "<1972.987654321@curl>", user "user", pass "secret"
        let response = cram_md5_response("user", "secret", "<1972.987654321@curl>");
        assert_eq!(response, "user 7031725599fdbb5d412689aa323e3e0b");
    }

    #[test]
    fn apop_known_vector() {
        // From curl test 864: timestamp "<1972.987654321@curl>", pass "secret"
        let digest = apop_digest("<1972.987654321@curl>", "secret");
        assert_eq!(digest, "7501b4cdc224d469940e65e7b5e4d6eb");
    }
}
