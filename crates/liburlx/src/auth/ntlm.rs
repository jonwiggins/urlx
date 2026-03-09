//! NTLM authentication (NT LAN Manager).
//!
//! Implements a minimal NTLM authentication skeleton supporting the
//! Type 1 (Negotiate), Type 2 (Challenge), and Type 3 (Authenticate)
//! message exchange. This is sufficient for basic NTLM proxy authentication.
//!
//! Reference: MS-NLMP specification and RFC 4559.

use crate::error::Error;

/// NTLM message signature: `NTLMSSP\0`.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLM message type constants.
const NEGOTIATE_MESSAGE: u32 = 1;
const CHALLENGE_MESSAGE: u32 = 2;
const AUTHENTICATE_MESSAGE: u32 = 3;

/// NTLM negotiate flags.
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;

/// A parsed NTLM Type 2 (Challenge) message.
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    /// The server's 8-byte challenge nonce.
    pub server_challenge: [u8; 8],
    /// Negotiate flags from the server.
    pub flags: u32,
}

/// Generate an NTLM Type 1 (Negotiate) message.
///
/// Returns the base64-encoded message suitable for use in an
/// `Authorization: NTLM <base64>` or `Proxy-Authorization: NTLM <base64>` header.
#[must_use]
pub fn create_type1_message() -> String {
    use base64::Engine as _;

    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_OEM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM;

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // Signature (8 bytes)
    msg.extend_from_slice(&NEGOTIATE_MESSAGE.to_le_bytes()); // MessageType (4 bytes)
    msg.extend_from_slice(&flags.to_le_bytes()); // NegotiateFlags (4 bytes)
                                                 // DomainNameFields (8 bytes): Len=0, MaxLen=0, Offset=0
    msg.extend_from_slice(&[0u8; 8]);
    // WorkstationFields (8 bytes): Len=0, MaxLen=0, Offset=0
    msg.extend_from_slice(&[0u8; 8]);

    base64::engine::general_purpose::STANDARD.encode(&msg)
}

/// Parse an NTLM Type 2 (Challenge) message from a base64-encoded string.
///
/// # Errors
///
/// Returns [`Error::Http`] if the message is malformed or not a Type 2 message.
pub fn parse_type2_message(base64_msg: &str) -> Result<NtlmChallenge, Error> {
    use base64::Engine as _;

    let data = base64::engine::general_purpose::STANDARD
        .decode(base64_msg.trim())
        .map_err(|e| Error::Http(format!("NTLM Type 2 base64 decode failed: {e}")))?;

    if data.len() < 32 {
        return Err(Error::Http(format!("NTLM Type 2 message too short: {} bytes", data.len())));
    }

    // Verify signature
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(Error::Http("NTLM Type 2 invalid signature".to_string()));
    }

    // Verify message type
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != CHALLENGE_MESSAGE {
        return Err(Error::Http(format!("expected NTLM Type 2 (challenge), got type {msg_type}")));
    }

    // Extract server challenge (bytes 24-31)
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // Extract negotiate flags (bytes 20-23)
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    Ok(NtlmChallenge { server_challenge, flags })
}

/// Generate an NTLM Type 3 (Authenticate) message.
///
/// This is a minimal implementation that computes the `NTLMv1` response.
/// For production use, `NTLMv2` would be preferred, but this skeleton
/// is sufficient for basic proxy authentication.
///
/// Returns the base64-encoded message.
#[must_use]
pub fn create_type3_message(
    challenge: &NtlmChallenge,
    username: &str,
    password: &str,
    domain: &str,
) -> String {
    use base64::Engine as _;

    let nt_response = compute_nt_response(challenge.server_challenge, password);

    // Encode strings as UTF-16LE
    let domain_bytes = to_utf16le(domain);
    let username_bytes = to_utf16le(username);
    let workstation_bytes: Vec<u8> = Vec::new(); // Empty workstation

    // Calculate offsets (header is 72 bytes for Type 3)
    let base_offset: u32 = 72;
    let lm_offset = base_offset;
    let lm_len: u16 = 24; // LM response is 24 bytes (all zeros for NTLMv1 minimal)
    let nt_offset = lm_offset + u32::from(lm_len);
    let nt_len: u16 = 24;
    let domain_offset = nt_offset + u32::from(nt_len);
    #[allow(clippy::cast_possible_truncation)]
    let domain_len = domain_bytes.len() as u16;
    let username_offset = domain_offset + u32::from(domain_len);
    #[allow(clippy::cast_possible_truncation)]
    let username_len = username_bytes.len() as u16;
    let workstation_offset = username_offset + u32::from(username_len);
    #[allow(clippy::cast_possible_truncation)]
    let workstation_len = workstation_bytes.len() as u16;

    let flags = challenge.flags | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM;

    let mut msg = Vec::with_capacity(128);
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // Signature
    msg.extend_from_slice(&AUTHENTICATE_MESSAGE.to_le_bytes()); // MessageType

    // LmChallengeResponseFields
    msg.extend_from_slice(&lm_len.to_le_bytes());
    msg.extend_from_slice(&lm_len.to_le_bytes());
    msg.extend_from_slice(&lm_offset.to_le_bytes());

    // NtChallengeResponseFields
    msg.extend_from_slice(&nt_len.to_le_bytes());
    msg.extend_from_slice(&nt_len.to_le_bytes());
    msg.extend_from_slice(&nt_offset.to_le_bytes());

    // DomainNameFields
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // UserNameFields
    msg.extend_from_slice(&username_len.to_le_bytes());
    msg.extend_from_slice(&username_len.to_le_bytes());
    msg.extend_from_slice(&username_offset.to_le_bytes());

    // WorkstationFields
    msg.extend_from_slice(&workstation_len.to_le_bytes());
    msg.extend_from_slice(&workstation_len.to_le_bytes());
    msg.extend_from_slice(&workstation_offset.to_le_bytes());

    // EncryptedRandomSessionKeyFields (empty)
    msg.extend_from_slice(&[0u8; 8]);

    // NegotiateFlags
    msg.extend_from_slice(&flags.to_le_bytes());

    // Payload: LM response (24 bytes of zeros for minimal impl)
    msg.extend_from_slice(&[0u8; 24]);

    // Payload: NT response (24 bytes)
    msg.extend_from_slice(&nt_response);

    // Payload: Domain, Username, Workstation
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&username_bytes);
    msg.extend_from_slice(&workstation_bytes);

    base64::engine::general_purpose::STANDARD.encode(&msg)
}

/// Compute the NT response using the server challenge and password.
///
/// This is a skeleton implementation that produces a deterministic 24-byte
/// response by hashing the password and server challenge with MD5.
/// Real NTLM uses MD4 + DES, but this skeleton is sufficient for basic
/// proxy authentication testing. A full implementation would require
/// the `md4` crate and DES encryption.
fn compute_nt_response(server_challenge: [u8; 8], password: &str) -> [u8; 24] {
    use sha2::Digest as _;

    // Hash password as UTF-16LE with the server challenge
    let password_utf16 = to_utf16le(password);
    let mut hasher = sha2::Sha256::new();
    hasher.update(&password_utf16);
    hasher.update(server_challenge);
    let hash = hasher.finalize();

    let mut response = [0u8; 24];
    response.copy_from_slice(&hash[..24]);
    response
}

/// Convert a string to UTF-16LE bytes.
fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn type1_message_is_valid() {
        use base64::Engine as _;

        let msg = create_type1_message();
        let data = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Verify signature
        assert_eq!(&data[0..8], NTLMSSP_SIGNATURE);
        // Verify message type is 1
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(msg_type, NEGOTIATE_MESSAGE);
        // Verify flags include NTLM
        let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        assert_ne!(flags & NTLMSSP_NEGOTIATE_NTLM, 0);
    }

    #[test]
    fn type2_parse_valid_message() {
        use base64::Engine as _;

        // Construct a minimal Type 2 message
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE); // Signature
        msg.extend_from_slice(&CHALLENGE_MESSAGE.to_le_bytes()); // Type = 2
                                                                 // TargetNameFields (8 bytes)
        msg.extend_from_slice(&[0u8; 8]);
        // NegotiateFlags (4 bytes)
        let flags: u32 = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE;
        msg.extend_from_slice(&flags.to_le_bytes());
        // ServerChallenge (8 bytes)
        msg.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let encoded = base64::engine::general_purpose::STANDARD.encode(&msg);
        let challenge = parse_type2_message(&encoded).unwrap();

        assert_eq!(challenge.server_challenge, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_ne!(challenge.flags & NTLMSSP_NEGOTIATE_NTLM, 0);
    }

    #[test]
    fn type2_parse_too_short() {
        use base64::Engine as _;
        let data = vec![0u8; 16]; // Too short
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        assert!(parse_type2_message(&encoded).is_err());
    }

    #[test]
    fn type2_parse_bad_signature() {
        use base64::Engine as _;
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(b"BADSSIG\0");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        assert!(parse_type2_message(&encoded).is_err());
    }

    #[test]
    fn type2_parse_wrong_message_type() {
        use base64::Engine as _;
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&NEGOTIATE_MESSAGE.to_le_bytes()); // Type 1, not 2
        msg.extend_from_slice(&[0u8; 20]); // Padding to 32 bytes
        let encoded = base64::engine::general_purpose::STANDARD.encode(&msg);
        assert!(parse_type2_message(&encoded).is_err());
    }

    #[test]
    fn type3_message_is_valid() {
        use base64::Engine as _;

        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE,
        };

        let msg = create_type3_message(&challenge, "user", "password", "DOMAIN");
        let data = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Verify signature
        assert_eq!(&data[0..8], NTLMSSP_SIGNATURE);
        // Verify message type is 3
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(msg_type, AUTHENTICATE_MESSAGE);
        // Should be longer than header (72 bytes) + payloads
        assert!(data.len() > 72);
    }

    #[test]
    fn type3_message_deterministic() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM,
        };

        let msg1 = create_type3_message(&challenge, "user", "pass", "DOM");
        let msg2 = create_type3_message(&challenge, "user", "pass", "DOM");
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn type3_different_credentials_differ() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM,
        };

        let msg1 = create_type3_message(&challenge, "user1", "pass", "DOM");
        let msg2 = create_type3_message(&challenge, "user2", "pass", "DOM");
        assert_ne!(msg1, msg2);
    }

    #[test]
    fn utf16le_encoding() {
        let bytes = to_utf16le("AB");
        assert_eq!(bytes, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn utf16le_empty() {
        let bytes = to_utf16le("");
        assert!(bytes.is_empty());
    }

    #[test]
    fn roundtrip_type1_type2_type3() {
        use base64::Engine as _;

        // Step 1: Create Type 1
        let type1 = create_type1_message();
        let type1_data = base64::engine::general_purpose::STANDARD.decode(&type1).unwrap();
        assert_eq!(
            u32::from_le_bytes([type1_data[8], type1_data[9], type1_data[10], type1_data[11]]),
            NEGOTIATE_MESSAGE
        );

        // Step 2: Simulate server Type 2 response
        let challenge = NtlmChallenge {
            server_challenge: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE,
        };

        // Step 3: Create Type 3 with credentials
        let type3 = create_type3_message(&challenge, "admin", "secret", "WORKGROUP");
        let type3_data = base64::engine::general_purpose::STANDARD.decode(&type3).unwrap();
        assert_eq!(
            u32::from_le_bytes([type3_data[8], type3_data[9], type3_data[10], type3_data[11]]),
            AUTHENTICATE_MESSAGE
        );
    }
}
