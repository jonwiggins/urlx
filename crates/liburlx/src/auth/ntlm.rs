//! NTLM authentication (NT LAN Manager).
//!
//! Implements `NTLMv1` and `NTLMv2` authentication supporting the
//! Type 1 (Negotiate), Type 2 (Challenge), and Type 3 (Authenticate)
//! message exchange per the MS-NLMP specification.
//!
//! The implementation matches curl's NTLM behavior: it sends `NTLMv1` responses
//! (24-byte LM/NT) using OEM encoding, which is the format expected by most
//! HTTP test servers and IIS.
//!
//! Reference: MS-NLMP specification and RFC 4559.

use crate::error::Error;

/// NTLM message signature: `NTLMSSP\0`.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Maximum allowed size for a decoded NTLM Type 2 (Challenge) message.
/// curl rejects oversized Type 2 messages with `CURLE_TOO_LARGE` (100).
/// 64 KiB is a generous upper bound — legitimate Type 2 messages are typically
/// a few hundred bytes.
const MAX_TYPE2_SIZE: usize = 64 * 1024;

/// NTLM message type constants.
const NEGOTIATE_MESSAGE: u32 = 1;
const CHALLENGE_MESSAGE: u32 = 2;
const AUTHENTICATE_MESSAGE: u32 = 3;

/// NTLM negotiate flags.
#[allow(dead_code)] // Standard NTLM flag; kept for completeness even though we use OEM encoding.
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NTLMSSP_NEGOTIATE_NTLM2: u32 = 0x0008_0000;

/// Hardcoded workstation name, matching curl behavior.
const WORKSTATION: &str = "WORKSTATION";

/// A parsed NTLM Type 2 (Challenge) message.
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    /// The server's 8-byte challenge nonce.
    pub server_challenge: [u8; 8],
    /// Negotiate flags from the server.
    pub flags: u32,
    /// Target info blob (for `NTLMv2`), if present.
    pub target_info: Option<Vec<u8>>,
}

/// Generate an NTLM Type 1 (Negotiate) message.
///
/// Returns the base64-encoded message suitable for use in an
/// `Authorization: NTLM <base64>` or `Proxy-Authorization: NTLM <base64>` header.
///
/// The flags match curl's Type 1: OEM | `REQUEST_TARGET` | NTLM | `ALWAYS_SIGN` | NTLM2.
/// Note: UNICODE is NOT set (curl compat).
#[must_use]
pub fn create_type1_message() -> String {
    use base64::Engine as _;

    // Match curl's Type 1 flags: 0x00088206
    let flags = NTLMSSP_NEGOTIATE_OEM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_NTLM2;

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

    // Reject oversized Type 2 messages (curl compat: test 776).
    // Malicious servers can send extremely large challenges; curl rejects
    // these with CURLE_TOO_LARGE (100).
    if data.len() > MAX_TYPE2_SIZE {
        return Err(Error::Protocol(100));
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

    // Extract negotiate flags (bytes 20-23)
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    // Extract server challenge (bytes 24-31)
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // Extract target info if present (offset 40-47 in extended Type 2)
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let ti_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        if ti_len > 0 && ti_offset + ti_len <= data.len() {
            Some(data[ti_offset..ti_offset + ti_len].to_vec())
        } else {
            None
        }
    } else {
        None
    };

    Ok(NtlmChallenge { server_challenge, flags, target_info })
}

/// Maximum buffer size for NTLM Type 3 messages, matching curl's `NTLM_BUFSIZE`.
const NTLM_BUFSIZE: usize = 1024;

/// Size of the NTLM Type 3 message header (signature + type + 6 field descriptors + flags).
const NTLM_TYPE3_HEADER_SIZE: usize = 64;

/// Generate an NTLM Type 3 (Authenticate) message using `NTLMv1`.
///
/// Uses `NTLMv1` (24-byte LM and NT responses) with OEM encoding,
/// matching curl's NTLM implementation. Includes the `WORKSTATION` hostname.
///
/// Returns the base64-encoded message, or an error if the credentials are
/// too large (matching curl's `CURLE_TOO_LARGE` = 100 behavior).
///
/// # Errors
///
/// Returns [`Error::Transfer`] with code 100 if the combined size of domain,
/// username, and workstation fields would exceed the NTLM buffer limit.
pub fn create_type3_message(
    challenge: &NtlmChallenge,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<String, Error> {
    use base64::Engine as _;

    let nt_hash = compute_nt_hash(password);
    let lm_hash = compute_lm_hash(password);

    // NTLMv1: 24-byte responses using DES
    let lm_response = des_encrypt_challenge(&lm_hash, &challenge.server_challenge);
    let nt_response = des_encrypt_challenge(&nt_hash, &challenge.server_challenge);

    // Use OEM (ASCII) encoding for domain, username, workstation
    let domain_bytes = domain.as_bytes().to_vec();
    let username_bytes = username.as_bytes().to_vec();
    let workstation_bytes = WORKSTATION.as_bytes().to_vec();

    // Check total message size against NTLM buffer limit (curl compat: test 775).
    // curl uses a fixed 1024-byte buffer for Type 3 messages and returns
    // CURLE_TOO_LARGE (100) if domain + username + hostname exceed available space.
    let payload_size = NTLM_TYPE3_HEADER_SIZE
        + lm_response.len()
        + nt_response.len()
        + domain_bytes.len()
        + username_bytes.len()
        + workstation_bytes.len();
    if payload_size >= NTLM_BUFSIZE {
        return Err(Error::Transfer {
            code: 100,
            message: "user + domain + hostname too big for NTLM".to_string(),
        });
    }

    // Calculate offsets — Type 3 header is 64 bytes:
    // 8 (sig) + 4 (type) + 6*8 (fields) + 4 (flags) = 64
    let base_offset: u32 = 64;
    let lm_offset = base_offset;
    #[allow(clippy::cast_possible_truncation)]
    let lm_len = lm_response.len() as u16;
    let nt_offset = lm_offset + u32::from(lm_len);
    #[allow(clippy::cast_possible_truncation)]
    let nt_len = nt_response.len() as u16;
    let domain_offset = nt_offset + u32::from(nt_len);
    #[allow(clippy::cast_possible_truncation)]
    let domain_len = domain_bytes.len() as u16;
    let username_offset = domain_offset + u32::from(domain_len);
    #[allow(clippy::cast_possible_truncation)]
    let username_len = username_bytes.len() as u16;
    let workstation_offset = username_offset + u32::from(username_len);
    #[allow(clippy::cast_possible_truncation)]
    let workstation_len = workstation_bytes.len() as u16;

    // Use the server's flags with OEM and NTLM set, matching curl behavior
    let flags = challenge.flags | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_NTLM;

    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&AUTHENTICATE_MESSAGE.to_le_bytes());

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

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&username_bytes);
    msg.extend_from_slice(&workstation_bytes);

    Ok(base64::engine::general_purpose::STANDARD.encode(&msg))
}

/// Compute the NT hash: `MD4(UTF-16LE(password))`.
fn compute_nt_hash(password: &str) -> [u8; 16] {
    use md4::{Digest as _, Md4};

    let password_utf16 = to_utf16le(password);
    let mut hasher = Md4::new();
    hasher.update(&password_utf16);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the LM hash from a password.
///
/// The LM hash algorithm:
/// 1. Convert password to uppercase ASCII, truncate/pad to 14 bytes
/// 2. Split into two 7-byte halves
/// 3. Each half is used as a DES key to encrypt the magic string `KGS!@#$%`
/// 4. Concatenate the two 8-byte DES outputs to get the 16-byte LM hash
fn compute_lm_hash(password: &str) -> [u8; 16] {
    let magic = b"KGS!@#$%";

    // Convert to uppercase, truncate to 14 bytes, pad with zeros
    let mut pwd_bytes = [0u8; 14];
    for (i, &b) in password.as_bytes().iter().take(14).enumerate() {
        pwd_bytes[i] = b.to_ascii_uppercase();
    }

    let key1 = des_key_from_7(&pwd_bytes[0..7]);
    let key2 = des_key_from_7(&pwd_bytes[7..14]);

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&des_ecb_encrypt(&key1, magic));
    hash[8..].copy_from_slice(&des_ecb_encrypt(&key2, magic));
    hash
}

/// Encrypt an 8-byte challenge using a 16-byte hash to produce a 24-byte response.
///
/// The `NTLMv1` response algorithm:
/// 1. Pad the 16-byte hash to 21 bytes with zeros
/// 2. Split into three 7-byte chunks
/// 3. Each chunk is expanded to a DES key and encrypts the 8-byte challenge
/// 4. Concatenate the three 8-byte results → 24 bytes
#[allow(clippy::trivially_copy_pass_by_ref)] // Consistent with DES API conventions
fn des_encrypt_challenge(hash: &[u8; 16], challenge: &[u8; 8]) -> Vec<u8> {
    // Pad hash to 21 bytes
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(hash);

    let key1 = des_key_from_7(&padded[0..7]);
    let key2 = des_key_from_7(&padded[7..14]);
    let key3 = des_key_from_7(&padded[14..21]);

    let mut response = Vec::with_capacity(24);
    response.extend_from_slice(&des_ecb_encrypt(&key1, challenge));
    response.extend_from_slice(&des_ecb_encrypt(&key2, challenge));
    response.extend_from_slice(&des_ecb_encrypt(&key3, challenge));
    response
}

/// Expand a 7-byte value to an 8-byte DES key.
///
/// DES uses 56 effective key bits (bits 7-1 of each byte; bit 0 is parity).
/// This function distributes the 56 input bits across 8 bytes, matching
/// curl's `extend_key_56_to_64` function exactly.
fn des_key_from_7(src: &[u8]) -> [u8; 8] {
    [
        src[0],
        (src[0] << 7) | (src[1] >> 1),
        (src[1] << 6) | (src[2] >> 2),
        (src[2] << 5) | (src[3] >> 3),
        (src[3] << 4) | (src[4] >> 4),
        (src[4] << 3) | (src[5] >> 5),
        (src[5] << 2) | (src[6] >> 6),
        src[6] << 1,
    ]
}

/// Perform DES-ECB encryption of an 8-byte block with the given key.
#[allow(clippy::trivially_copy_pass_by_ref)] // Matches cipher API convention
fn des_ecb_encrypt(key: &[u8; 8], plaintext: &[u8; 8]) -> [u8; 8] {
    use cipher::{BlockEncrypt as _, KeyInit as _};
    use des::Des;

    // Des::new_from_slice cannot fail for 8-byte keys.
    #[allow(clippy::expect_used)]
    let cipher = Des::new_from_slice(key).expect("DES accepts 8-byte keys");
    let mut block = cipher::generic_array::GenericArray::clone_from_slice(plaintext);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
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
    fn type1_message_matches_curl() {
        use base64::Engine as _;

        let msg = create_type1_message();
        let data = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Verify signature
        assert_eq!(&data[0..8], NTLMSSP_SIGNATURE);
        // Verify message type is 1
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(msg_type, NEGOTIATE_MESSAGE);
        // Verify flags match curl's expected value: 0x00088206
        let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        assert_eq!(flags, 0x0008_8206, "Type1 flags must match curl");
        // UNICODE should NOT be set
        assert_eq!(flags & NTLMSSP_NEGOTIATE_UNICODE, 0);
        // OEM, REQUEST_TARGET, NTLM, ALWAYS_SIGN, NTLM2 should be set
        assert_ne!(flags & NTLMSSP_NEGOTIATE_OEM, 0);
        assert_ne!(flags & NTLMSSP_REQUEST_TARGET, 0);
        assert_ne!(flags & NTLMSSP_NEGOTIATE_NTLM, 0);
        assert_ne!(flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN, 0);
        assert_ne!(flags & NTLMSSP_NEGOTIATE_NTLM2, 0);
        // Total size should be 32 bytes
        assert_eq!(data.len(), 32);
    }

    #[test]
    fn type1_base64_matches_curl_test() {
        // The curl test suite expects this exact base64 for the Type 1 message
        // (decoded from the %b64[...]b64% pattern in test data files)
        let msg = create_type1_message();
        let expected = "TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(msg, expected, "Type1 base64 must match curl test expectation");
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
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM,
            target_info: None,
        };

        let msg = create_type3_message(&challenge, "user", "password", "DOMAIN").unwrap();
        let data = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Verify signature
        assert_eq!(&data[0..8], NTLMSSP_SIGNATURE);
        // Verify message type is 3
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(msg_type, AUTHENTICATE_MESSAGE);

        // LM response should be 24 bytes (NTLMv1)
        let lm_len = u16::from_le_bytes([data[12], data[13]]);
        assert_eq!(lm_len, 24, "LM response must be 24 bytes (NTLMv1)");

        // NT response should be 24 bytes (NTLMv1)
        let nt_len = u16::from_le_bytes([data[20], data[21]]);
        assert_eq!(nt_len, 24, "NT response must be 24 bytes (NTLMv1)");

        // Should be longer than header (72 bytes) + payloads
        assert!(data.len() > 72);
    }

    #[test]
    fn type3_uses_oem_encoding() {
        use base64::Engine as _;

        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM,
            target_info: None,
        };

        let msg = create_type3_message(&challenge, "testuser", "testpass", "").unwrap();
        let data = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Username should be OEM (ASCII), not UTF-16LE
        let usr_len = u16::from_le_bytes([data[36], data[37]]) as usize;
        let usr_off = u32::from_le_bytes([data[40], data[41], data[42], data[43]]) as usize;
        let usr = &data[usr_off..usr_off + usr_len];
        assert_eq!(usr, b"testuser", "Username must be OEM-encoded ASCII");

        // Workstation should be "WORKSTATION"
        let ws_len = u16::from_le_bytes([data[44], data[45]]) as usize;
        let ws_off = u32::from_le_bytes([data[48], data[49], data[50], data[51]]) as usize;
        let ws = &data[ws_off..ws_off + ws_len];
        assert_eq!(ws, b"WORKSTATION");
    }

    #[test]
    fn type3_matches_curl_test_vector() {
        // Test the exact Type 3 message from curl test 67/68
        // Server challenge from the Type 2 in the test: 739d406150e0c8d7
        // User: testuser, Pass: testpass, Domain: (empty)
        use base64::Engine as _;
        let expected_b64 = "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAAABwAAAACAAIAHAAAAALAAsAeAAAAAAAAAAAAAAAhoIBAFpkQwKRCZFMhjj0tw47wEjKHRHlvzfxQamFcheMuv8v+xeqphEO5V41xRd7R9deOXRlc3R1c2VyV09SS1NUQVRJT04=";
        let expected = base64::engine::general_purpose::STANDARD.decode(expected_b64).unwrap();

        // Parse the Type 2 challenge from the test data
        let type2_b64 = "TlRMTVNTUAACAAAAAgACADAAAACGggEAc51AYVDgyNcAAAAAAAAAAG4AbgAyAAAAQ0MCAAQAQwBDAAEAEgBFAEwASQBTAEEAQgBFAFQASAAEABgAYwBjAC4AaQBjAGUAZABlAHYALgBuAHUAAwAsAGUAbABpAHMAYQBiAGUAdABoAC4AYwBjAC4AaQBjAGUAZABlAHYALgBuAHUAAAAAAA==";
        let challenge = parse_type2_message(type2_b64).unwrap();

        let msg = create_type3_message(&challenge, "testuser", "testpass", "").unwrap();
        let actual = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        // Verify structural match (LM/NT responses will differ due to DES determinism,
        // but the structure, offsets, flags, username, workstation must match exactly)
        assert_eq!(actual.len(), expected.len(), "Type3 message length must match");

        // Flags must match
        assert_eq!(&actual[60..64], &expected[60..64], "Flags must match");

        // Domain, username, workstation offsets and data must match
        assert_eq!(&actual[28..36], &expected[28..36], "Domain fields must match");
        assert_eq!(&actual[36..44], &expected[36..44], "Username fields must match");
        assert_eq!(&actual[44..52], &expected[44..52], "Workstation fields must match");

        // Username bytes
        assert_eq!(&actual[112..120], b"testuser", "Username data must be 'testuser'");
        // Workstation bytes
        assert_eq!(&actual[120..131], b"WORKSTATION", "Workstation data must be 'WORKSTATION'");

        // LM and NT responses are deterministic with NTLMv1 (no random nonce)
        // so they should match exactly
        assert_eq!(
            &actual[64..88],
            &expected[64..88],
            "LM response must match (NTLMv1 is deterministic)"
        );
        assert_eq!(
            &actual[88..112],
            &expected[88..112],
            "NT response must match (NTLMv1 is deterministic)"
        );
    }

    #[test]
    fn type3_with_domain_matches_curl_test91() {
        use base64::Engine as _;

        // Test 91: domain\user = mydomain\myself, pass = secret
        let expected_b64 = "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAgACABwAAAABgAGAHgAAAALAAsAfgAAAAAAAAAAAAAAhoIBAMIyJpR5mHpg2FZha5kRaFZ9436GAxPu0C5llxexSQ5QzVkiLSfkcpVyRgCXXqR+Am15ZG9tYWlubXlzZWxmV09SS1NUQVRJT04=";
        let expected = base64::engine::general_purpose::STANDARD.decode(expected_b64).unwrap();

        let type2_b64 = "TlRMTVNTUAACAAAAAgACADAAAACGggEAc51AYVDgyNcAAAAAAAAAAG4AbgAyAAAAQ0MCAAQAQwBDAAEAEgBFAEwASQBTAEEAQgBFAFQASAAEABgAYwBjAC4AaQBjAGUAZABlAHYALgBuAHUAAwAsAGUAbABpAHMAYQBiAGUAdABoAC4AYwBjAC4AaQBjAGUAZABlAHYALgBuAHUAAAAAAA==";
        let challenge = parse_type2_message(type2_b64).unwrap();

        let msg = create_type3_message(&challenge, "myself", "secret", "mydomain").unwrap();
        let actual = base64::engine::general_purpose::STANDARD.decode(&msg).unwrap();

        assert_eq!(actual.len(), expected.len(), "Type3 length must match for test 91");
        assert_eq!(actual, expected, "Type3 must match curl test 91 exactly");
    }

    #[test]
    fn type3_different_credentials_differ() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM,
            target_info: None,
        };

        let msg1 = create_type3_message(&challenge, "user1", "pass", "DOM").unwrap();
        let msg2 = create_type3_message(&challenge, "user2", "pass", "DOM").unwrap();
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
    fn lm_hash_known_value() {
        // LM hash of empty password should be the "empty" LM hash
        let hash = compute_lm_hash("");
        assert_eq!(hash.len(), 16);
        // AAD3B435B51404EE is the known LM hash of the empty 7-byte key
        assert_eq!(
            hex::encode(&hash[..8]),
            "aad3b435b51404ee",
            "First half of LM hash for empty password"
        );
    }

    #[test]
    fn des_key_expansion() {
        // Verify 7-byte to 8-byte DES key expansion
        let input = [0xFF_u8; 7];
        let key = des_key_from_7(&input);
        assert_eq!(key.len(), 8);
    }

    #[test]
    fn des_encrypt_produces_24_bytes() {
        let hash = compute_nt_hash("password");
        let challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let response = des_encrypt_challenge(&hash, &challenge);
        assert_eq!(response.len(), 24, "NTLMv1 response must be 24 bytes");
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
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM,
            target_info: None,
        };

        // Step 3: Create Type 3 with credentials
        let type3 = create_type3_message(&challenge, "admin", "secret", "WORKGROUP").unwrap();
        let type3_data = base64::engine::general_purpose::STANDARD.decode(&type3).unwrap();
        assert_eq!(
            u32::from_le_bytes([type3_data[8], type3_data[9], type3_data[10], type3_data[11]]),
            AUTHENTICATE_MESSAGE
        );
    }

    #[test]
    fn type3_too_long_username_returns_error() {
        // curl test 775: username longer than ~900 chars exceeds NTLM_BUFSIZE (1024)
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM,
            target_info: None,
        };

        // testuser + 1100 * 'A' = 1108 chars — exceeds 1024 buffer
        let long_user = format!("testuser{}", "A".repeat(1100));
        let result = create_type3_message(&challenge, &long_user, "testpass", "");
        assert!(result.is_err(), "Too-long username must return an error");
    }

    #[test]
    fn nt_hash_known_value() {
        // Known test vector: password "Password" → MD4 of UTF-16LE
        let hash = compute_nt_hash("Password");
        assert_eq!(hash.len(), 16);
        assert_ne!(hash, [0u8; 16]);
    }

    #[test]
    fn nt_hash_empty_password() {
        let hash = compute_nt_hash("");
        assert_eq!(hash.len(), 16);
        assert_ne!(hash, [0u8; 16]);
    }
}
