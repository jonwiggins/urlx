//! SASL SCRAM-SHA-256 authentication (RFC 7677 / RFC 5802).
//!
//! Implements the Salted Challenge Response Authentication Mechanism
//! using SHA-256, commonly used for SMTP, IMAP, and POP3 authentication.

use crate::error::Error;

/// State machine for a SCRAM-SHA-256 client authentication exchange.
#[derive(Debug)]
pub struct ScramClient {
    username: String,
    password: String,
    client_nonce: String,
    /// The full `client-first-message-bare` for binding into `AuthMessage`.
    client_first_bare: String,
}

impl ScramClient {
    /// Create a new SCRAM-SHA-256 client for the given credentials.
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        let client_nonce = generate_nonce();
        let client_first_bare = format!("n={},r={}", saslprep(username), client_nonce);
        Self {
            username: username.to_string(),
            password: password.to_string(),
            client_nonce,
            client_first_bare,
        }
    }

    /// Build the `client-first-message` (sent to the server to start auth).
    ///
    /// Format: `n,,n=<user>,r=<nonce>`
    #[must_use]
    pub fn client_first(&self) -> String {
        // GS2 header "n,," = no channel binding
        format!("n,,{}", self.client_first_bare)
    }

    /// Process the `server-first-message` and produce the `client-final-message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Auth`] if the server message is malformed or contains
    /// an invalid nonce.
    pub fn client_final(&self, server_first: &str) -> Result<(String, [u8; 32]), Error> {
        use base64::Engine as _;

        let parsed = parse_server_first(server_first)?;

        // Verify the combined nonce starts with our client nonce
        if !parsed.nonce.starts_with(&self.client_nonce) {
            return Err(Error::Auth("SCRAM nonce mismatch".to_string()));
        }

        let salted_password = hi(&self.password, &parsed.salt, parsed.iteration_count);
        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key = sha256(&client_key);

        // channel-binding = "biws" = base64("n,,")
        let client_final_without_proof = format!("c=biws,r={}", parsed.nonce);
        let auth_message =
            format!("{},{},{}", self.client_first_bare, server_first, client_final_without_proof);

        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut client_proof = [0u8; 32];
        for i in 0..32 {
            client_proof[i] = client_key[i] ^ client_signature[i];
        }

        let server_key = hmac_sha256(&salted_password, b"Server Key");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());

        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(client_proof);
        let client_final = format!("{client_final_without_proof},p={proof_b64}");

        Ok((client_final, server_signature))
    }

    /// Verify the `server-final-message` using the expected server signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Auth`] if the server signature does not match.
    pub fn verify_server_final(
        server_final: &str,
        expected_signature: &[u8; 32],
    ) -> Result<(), Error> {
        use base64::Engine as _;

        let verifier = server_final
            .strip_prefix("v=")
            .ok_or_else(|| Error::Auth("SCRAM server-final missing v= prefix".to_string()))?;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(verifier.trim())
            .map_err(|e| Error::Auth(format!("SCRAM server signature decode failed: {e}")))?;

        if decoded.len() != 32 {
            return Err(Error::Auth(format!(
                "SCRAM server signature wrong length: {}",
                decoded.len()
            )));
        }

        let mut sig = [0u8; 32];
        sig.copy_from_slice(&decoded);

        if sig != *expected_signature {
            return Err(Error::Auth("SCRAM server signature verification failed".to_string()));
        }

        Ok(())
    }

    /// Returns the username used for this exchange.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// Parsed fields from a `server-first-message`.
struct ServerFirst {
    nonce: String,
    salt: Vec<u8>,
    iteration_count: u32,
}

/// Parse a `server-first-message`: `r=<nonce>,s=<salt>,i=<iterations>`.
fn parse_server_first(msg: &str) -> Result<ServerFirst, Error> {
    use base64::Engine as _;

    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;

    for part in msg.split(',') {
        if let Some(val) = part.strip_prefix("r=") {
            nonce = Some(val.to_string());
        } else if let Some(val) = part.strip_prefix("s=") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(val)
                .map_err(|e| Error::Auth(format!("SCRAM salt decode failed: {e}")))?;
            salt = Some(decoded);
        } else if let Some(val) = part.strip_prefix("i=") {
            let count: u32 = val
                .parse()
                .map_err(|e| Error::Auth(format!("SCRAM iteration count invalid: {e}")))?;
            if count == 0 {
                return Err(Error::Auth("SCRAM iteration count must be > 0".to_string()));
            }
            iterations = Some(count);
        }
    }

    Ok(ServerFirst {
        nonce: nonce.ok_or_else(|| Error::Auth("SCRAM server-first missing r=".to_string()))?,
        salt: salt.ok_or_else(|| Error::Auth("SCRAM server-first missing s=".to_string()))?,
        iteration_count: iterations
            .ok_or_else(|| Error::Auth("SCRAM server-first missing i=".to_string()))?,
    })
}

/// PBKDF2-HMAC-SHA256 key derivation (`Hi` in RFC 5802).
fn hi(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    // U1 = HMAC(password, salt + INT(1))
    let mut salt_plus_one = Vec::with_capacity(salt.len() + 4);
    salt_plus_one.extend_from_slice(salt);
    salt_plus_one.extend_from_slice(&1u32.to_be_bytes());

    // HMAC-SHA256 accepts any key length — new_from_slice cannot fail.
    #[allow(clippy::expect_used)]
    let u1 = {
        let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(&salt_plus_one);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    };

    let mut result = u1;
    let mut prev = u1;

    for _ in 1..iterations {
        // HMAC-SHA256 accepts any key length — new_from_slice cannot fail.
        #[allow(clippy::expect_used)]
        let next = {
            let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes())
                .expect("HMAC-SHA256 accepts any key length");
            mac.update(&prev);
            let r = mac.finalize().into_bytes();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };
        for j in 0..32 {
            result[j] ^= next[j];
        }
        prev = next;
    }

    result
}

/// HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    // HMAC-SHA256 accepts any key length — new_from_slice cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// SHA-256 hash.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Generate a random nonce for SCRAM (24 bytes, base64-encoded).
fn generate_nonce() -> String {
    use base64::Engine as _;
    use rand::Rng as _;

    let mut rng = rand::rng();
    let mut bytes = [0u8; 24];
    rng.fill(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Minimal `SASLprep` — strips leading/trailing whitespace.
///
/// A full `SASLprep` (RFC 4013) implementation would normalize Unicode.
/// For the common case of ASCII usernames, this suffices.
fn saslprep(s: &str) -> &str {
    s.trim()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn client_first_format() {
        let client = ScramClient::new("user", "pencil");
        let first = client.client_first();
        assert!(first.starts_with("n,,n=user,r="));
    }

    #[test]
    fn client_first_bare_excludes_gs2() {
        let client = ScramClient::new("user", "pencil");
        assert!(client.client_first_bare.starts_with("n=user,r="));
        assert!(!client.client_first_bare.starts_with("n,,"));
    }

    #[test]
    fn parse_server_first_valid() {
        use base64::Engine as _;
        let salt = base64::engine::general_purpose::STANDARD.encode(b"salt value");
        let msg = format!("r=clientnonceservernonce,s={salt},i=4096");
        let parsed = parse_server_first(&msg).unwrap();
        assert_eq!(parsed.nonce, "clientnonceservernonce");
        assert_eq!(parsed.salt, b"salt value");
        assert_eq!(parsed.iteration_count, 4096);
    }

    #[test]
    fn parse_server_first_missing_nonce() {
        use base64::Engine as _;
        let salt = base64::engine::general_purpose::STANDARD.encode(b"salt");
        let msg = format!("s={salt},i=4096");
        assert!(parse_server_first(&msg).is_err());
    }

    #[test]
    fn parse_server_first_zero_iterations() {
        use base64::Engine as _;
        let salt = base64::engine::general_purpose::STANDARD.encode(b"salt");
        let msg = format!("r=nonce,s={salt},i=0");
        assert!(parse_server_first(&msg).is_err());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        use base64::Engine as _;
        let client = ScramClient::new("user", "pencil");
        let salt = base64::engine::general_purpose::STANDARD.encode(b"salt");
        // Server nonce that doesn't start with client nonce
        let server_first = format!("r=completely_different_nonce,s={salt},i=4096");
        assert!(client.client_final(&server_first).is_err());
    }

    #[test]
    fn full_exchange_roundtrip() {
        use base64::Engine as _;

        let client = ScramClient::new("user", "pencil");
        let first = client.client_first();
        assert!(first.starts_with("n,,"));

        // Simulate server response with proper nonce prefix
        let nonce = &client.client_first_bare["n=user,r=".len()..];
        let combined_nonce = format!("{nonce}servernonce123");
        let salt = base64::engine::general_purpose::STANDARD.encode(b"mysalt");
        let server_first = format!("r={combined_nonce},s={salt},i=4096");

        let (client_final, server_sig) = client.client_final(&server_first).unwrap();
        assert!(client_final.starts_with("c=biws,r="));
        assert!(client_final.contains(",p="));

        // Verify server signature can be validated
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(server_sig);
        let server_final = format!("v={sig_b64}");
        ScramClient::verify_server_final(&server_final, &server_sig).unwrap();
    }

    #[test]
    fn server_final_bad_signature() {
        use base64::Engine as _;
        let expected = [0xAA; 32];
        let wrong = base64::engine::general_purpose::STANDARD.encode([0xBB; 32]);
        let server_final = format!("v={wrong}");
        assert!(ScramClient::verify_server_final(&server_final, &expected).is_err());
    }

    #[test]
    fn server_final_missing_prefix() {
        let expected = [0xAA; 32];
        assert!(ScramClient::verify_server_final("bad", &expected).is_err());
    }

    #[test]
    fn hi_deterministic() {
        let r1 = hi("password", b"salt", 1);
        let r2 = hi("password", b"salt", 1);
        assert_eq!(r1, r2);
    }

    #[test]
    fn hi_different_iterations() {
        let r1 = hi("password", b"salt", 1);
        let r2 = hi("password", b"salt", 2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn hmac_sha256_deterministic() {
        let h1 = hmac_sha256(b"key", b"data");
        let h2 = hmac_sha256(b"key", b"data");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn sha256_known() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }

    #[test]
    fn nonce_is_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
        // Base64 of 24 bytes = 32 chars
        assert_eq!(n1.len(), 32);
    }

    #[test]
    fn saslprep_trims() {
        assert_eq!(saslprep("  user  "), "user");
        assert_eq!(saslprep("user"), "user");
    }

    #[test]
    fn username_accessor() {
        let client = ScramClient::new("testuser", "pass");
        assert_eq!(client.username(), "testuser");
    }
}
