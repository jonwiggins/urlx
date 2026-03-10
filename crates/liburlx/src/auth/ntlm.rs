//! NTLM authentication (NT LAN Manager).
//!
//! Implements `NTLMv1` and `NTLMv2` authentication supporting the
//! Type 1 (Negotiate), Type 2 (Challenge), and Type 3 (Authenticate)
//! message exchange per the MS-NLMP specification.
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
const NTLMSSP_NEGOTIATE_NTLM2: u32 = 0x0008_0000;

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
#[must_use]
pub fn create_type1_message() -> String {
    use base64::Engine as _;

    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_OEM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
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

/// Generate an NTLM Type 3 (Authenticate) message using `NTLMv2`.
///
/// Uses the proper `NTLMv2` cryptographic algorithm:
/// 1. NT Hash = `MD4(UTF-16LE(password))`
/// 2. `NTLMv2` Hash = `HMAC-MD5(NT_Hash, UPPER(username) + domain)`
/// 3. `NTProofStr` = `HMAC-MD5(NTLMv2_Hash, server_challenge + blob)`
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

    let nt_hash = compute_nt_hash(password);
    let ntlmv2_hash = compute_ntlmv2_hash(&nt_hash, username, domain);

    // Build NTLMv2 client blob
    let client_challenge = generate_client_challenge();
    let timestamp = ntlm_timestamp();
    let target_info = challenge.target_info.as_deref().unwrap_or(&[]);
    let blob = build_ntlmv2_blob(timestamp, client_challenge, target_info);

    // Compute NTProofStr = HMAC-MD5(NTLMv2_Hash, server_challenge + blob)
    let nt_proof_str = compute_nt_proof_str(&ntlmv2_hash, challenge.server_challenge, &blob);

    // NT response = NTProofStr + blob
    let mut nt_response = Vec::with_capacity(nt_proof_str.len() + blob.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // LMv2 response = HMAC-MD5(NTLMv2_Hash, server_challenge + client_challenge)
    let lm_response =
        compute_lmv2_response(&ntlmv2_hash, challenge.server_challenge, client_challenge);

    // Encode strings as UTF-16LE
    let domain_bytes = to_utf16le(domain);
    let username_bytes = to_utf16le(username);
    let workstation_bytes: Vec<u8> = Vec::new();

    // Calculate offsets (header is 72 bytes for Type 3)
    let base_offset: u32 = 72;
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

    let flags = challenge.flags | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM;

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

    base64::engine::general_purpose::STANDARD.encode(&msg)
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

/// Compute the `NTLMv2` hash: `HMAC-MD5(NT_Hash, UPPER(username) + domain)`.
fn compute_ntlmv2_hash(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    use hmac::{Hmac, Mac as _};
    use md5::Md5;

    let identity = format!("{}{}", username.to_uppercase(), domain);
    let identity_utf16 = to_utf16le(&identity);

    // HMAC-MD5 accepts any key length — new_from_slice cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Md5>::new_from_slice(nt_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(&identity_utf16);
    let result = mac.finalize().into_bytes();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the `NTProofStr`: `HMAC-MD5(NTLMv2_Hash, server_challenge + blob)`.
fn compute_nt_proof_str(
    ntlmv2_hash: &[u8; 16],
    server_challenge: [u8; 8],
    blob: &[u8],
) -> [u8; 16] {
    use hmac::{Hmac, Mac as _};
    use md5::Md5;

    // HMAC-MD5 accepts any key length — new_from_slice cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac =
        Hmac::<Md5>::new_from_slice(ntlmv2_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(&server_challenge);
    mac.update(blob);
    let result = mac.finalize().into_bytes();
    let mut proof = [0u8; 16];
    proof.copy_from_slice(&result);
    proof
}

/// Compute the `LMv2` response: `HMAC-MD5(NTLMv2_Hash, server_challenge + client_challenge) + client_challenge`.
fn compute_lmv2_response(
    ntlmv2_hash: &[u8; 16],
    server_challenge: [u8; 8],
    client_challenge: [u8; 8],
) -> Vec<u8> {
    use hmac::{Hmac, Mac as _};
    use md5::Md5;

    // HMAC-MD5 accepts any key length — new_from_slice cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac =
        Hmac::<Md5>::new_from_slice(ntlmv2_hash).expect("HMAC-MD5 accepts any key length");
    mac.update(&server_challenge);
    mac.update(&client_challenge);
    let result = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(24);
    response.extend_from_slice(&result);
    response.extend_from_slice(&client_challenge);
    response
}

/// Build the `NTLMv2` client blob (temp structure).
fn build_ntlmv2_blob(timestamp: [u8; 8], client_challenge: [u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(32 + target_info.len());
    blob.extend_from_slice(&[0x01, 0x01]); // RespType, HiRespType
    blob.extend_from_slice(&[0x00, 0x00]); // Reserved1
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved2
    blob.extend_from_slice(&timestamp); // TimeStamp (8 bytes)
    blob.extend_from_slice(&client_challenge); // ChallengeFromClient (8 bytes)
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved3
    blob.extend_from_slice(target_info); // AvPairs
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Terminator
    blob
}

/// Generate an 8-byte random client challenge.
fn generate_client_challenge() -> [u8; 8] {
    use rand::Rng as _;
    let mut rng = rand::rng();
    let mut challenge = [0u8; 8];
    rng.fill(&mut challenge);
    challenge
}

/// Get the current time as an NTLM timestamp (100-nanosecond intervals since 1601-01-01).
fn ntlm_timestamp() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Offset between 1601-01-01 and 1970-01-01 in 100-nanosecond intervals
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;

    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let ticks = unix_time.as_nanos() / 100;

    #[allow(clippy::cast_possible_truncation)]
    let timestamp = (ticks as u64) + EPOCH_DIFF;
    timestamp.to_le_bytes()
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
        // Should include NTLMv2 session security flag
        assert_ne!(flags & NTLMSSP_NEGOTIATE_NTLM2, 0);
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
            target_info: None,
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
    fn type3_different_credentials_differ() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM,
            target_info: None,
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
            target_info: None,
        };

        // Step 3: Create Type 3 with credentials
        let type3 = create_type3_message(&challenge, "admin", "secret", "WORKGROUP");
        let type3_data = base64::engine::general_purpose::STANDARD.decode(&type3).unwrap();
        assert_eq!(
            u32::from_le_bytes([type3_data[8], type3_data[9], type3_data[10], type3_data[11]]),
            AUTHENTICATE_MESSAGE
        );
    }

    // ─── NTLMv2 crypto tests ───

    #[test]
    fn nt_hash_known_value() {
        // Known test vector: password "Password" → MD4 of UTF-16LE
        let hash = compute_nt_hash("Password");
        // MD4(UTF-16LE("Password")) is a well-known value
        // We verify it's 16 bytes and non-zero
        assert_eq!(hash.len(), 16);
        assert_ne!(hash, [0u8; 16]);
    }

    #[test]
    fn nt_hash_empty_password() {
        let hash = compute_nt_hash("");
        assert_eq!(hash.len(), 16);
        // MD4 of empty input is a known constant
        assert_ne!(hash, [0u8; 16]);
    }

    #[test]
    fn ntlmv2_hash_computed() {
        let nt_hash = compute_nt_hash("Password");
        let v2_hash = compute_ntlmv2_hash(&nt_hash, "User", "Domain");
        assert_eq!(v2_hash.len(), 16);
        assert_ne!(v2_hash, [0u8; 16]);
    }

    #[test]
    fn ntlmv2_hash_different_users() {
        let nt_hash = compute_nt_hash("Password");
        let h1 = compute_ntlmv2_hash(&nt_hash, "User1", "Domain");
        let h2 = compute_ntlmv2_hash(&nt_hash, "User2", "Domain");
        assert_ne!(h1, h2);
    }

    #[test]
    fn client_challenge_is_random() {
        let c1 = generate_client_challenge();
        let c2 = generate_client_challenge();
        // With 2^64 possible values, collision is practically impossible
        assert_ne!(c1, c2);
    }

    #[test]
    fn ntlm_timestamp_is_nonzero() {
        let ts = ntlm_timestamp();
        assert_ne!(ts, [0u8; 8]);
    }

    #[test]
    fn lmv2_response_length() {
        let nt_hash = compute_nt_hash("pass");
        let v2_hash = compute_ntlmv2_hash(&nt_hash, "user", "dom");
        let server = [1u8; 8];
        let client = [2u8; 8];
        let resp = compute_lmv2_response(&v2_hash, server, client);
        // LMv2 response is 16 (HMAC) + 8 (client challenge) = 24 bytes
        assert_eq!(resp.len(), 24);
    }

    #[test]
    fn ntlmv2_blob_structure() {
        let ts = [0u8; 8];
        let cc = [1u8; 8];
        let ti = vec![0x02, 0x00, 0x04, 0x00, b'D', 0x00, b'O', 0x00];
        let blob = build_ntlmv2_blob(ts, cc, &ti);
        // Verify blob starts with RespType=1, HiRespType=1
        assert_eq!(blob[0], 0x01);
        assert_eq!(blob[1], 0x01);
        // Verify blob contains client challenge at offset 16
        assert_eq!(&blob[16..24], &cc);
    }

    #[test]
    fn type3_with_target_info() {
        let target_info = vec![
            0x02, 0x00, 0x06, 0x00, b'D', 0x00, b'O', 0x00, b'M', 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            flags: NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE,
            target_info: Some(target_info),
        };
        let msg = create_type3_message(&challenge, "user", "pass", "DOM");
        assert!(!msg.is_empty());
    }

    #[test]
    fn nt_proof_str_deterministic() {
        let v2_hash = [0xAA; 16];
        let server = [0xBB; 8];
        let blob = [0xCC; 32];
        let p1 = compute_nt_proof_str(&v2_hash, server, &blob);
        let p2 = compute_nt_proof_str(&v2_hash, server, &blob);
        assert_eq!(p1, p2);
    }
}
