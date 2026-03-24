//! SMB/SMBS protocol handler.
//!
//! Implements `SMBv1` (Server Message Block) for file download and upload,
//! matching curl's SMB behavior. Supports both plaintext (`smb://`) and
//! TLS-encrypted (`smbs://`) connections.
//!
//! URL format: `smb://[domain%5Cuser:password@]server[:port]/share/path/to/file`
//!
//! The first path component is the share name; the remainder is the file path
//! within that share. Authentication uses NTLM (matching curl's SMB behavior).

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

// ── SMB1 command codes ──────────────────────────────────────────────────────

/// Close file.
const SMB_COM_CLOSE: u8 = 0x04;
/// Read with `AndX` chaining.
const SMB_COM_READ_ANDX: u8 = 0x2E;
/// Write with `AndX` chaining.
const SMB_COM_WRITE_ANDX: u8 = 0x2F;
/// Disconnect from tree (share).
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
/// Protocol negotiation.
const SMB_COM_NEGOTIATE: u8 = 0x72;
/// Session setup (authentication).
const SMB_COM_SESSION_SETUP_ANDX: u8 = 0x73;
/// Tree (share) connection.
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
/// NT-style file create/open.
const SMB_COM_NT_CREATE_ANDX: u8 = 0xA2;
/// No further chained (`AndX`) command.
const SMB_COM_NO_ANDX: u8 = 0xFF;

// ── SMB header constants ────────────────────────────────────────────────────

/// SMB1 header length (32 bytes).
const SMB_HEADER_LEN: usize = 32;
/// SMB protocol magic bytes: `\xFFSMB`.
const SMB_MAGIC: [u8; 4] = [0xFF, b'S', b'M', b'B'];

// ── SMB flags ───────────────────────────────────────────────────────────────

/// Case-insensitive pathnames.
const SMB_FLAGS_CASELESS: u8 = 0x08;
/// Canonicalized pathnames.
const SMB_FLAGS_CANONICAL: u8 = 0x10;

/// Client understands long file names.
const SMB_FLAGS2_LONG_NAMES: u16 = 0x0001;
/// Long name used in request.
const SMB_FLAGS2_IS_LONG_NAME: u16 = 0x0040;
/// NT-style 32-bit error codes.
const SMB_FLAGS2_ERR_STATUS: u16 = 0x4000;
/// Unicode strings in SMB messages.
const SMB_FLAGS2_UNICODE: u16 = 0x8000;

// ── NT_CREATE_ANDX constants ────────────────────────────────────────────────

/// Read data from file.
const FILE_READ_DATA: u32 = 0x0000_0001;
/// Write data to file.
const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// Read extended attributes.
const FILE_READ_EA: u32 = 0x0000_0008;
/// Write extended attributes.
const FILE_WRITE_EA: u32 = 0x0000_0010;
/// Read file attributes.
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Write file attributes.
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

/// Share read access with other openers.
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// Share write access with other openers.
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

/// Open existing file (fail if not found).
const FILE_OPEN: u32 = 0x0000_0001;
/// Create or overwrite.
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

/// Security impersonation level.
const SECURITY_IMPERSONATION: u32 = 0x0000_0002;

// ── Transfer size limits ────────────────────────────────────────────────────

/// Maximum bytes per Read `AndX` request (~60 KB).
const MAX_READ_SIZE: u16 = 60_000;
/// Maximum bytes per Write `AndX` request (~60 KB).
const MAX_WRITE_SIZE: usize = 60_000;

/// Capability flag: extended security negotiation (SPNEGO).
const CAP_EXTENDED_SECURITY: u32 = 0x8000_0000;

/// Maximum allowed SMB message size (256 KB).
const MAX_SMB_MSG_SIZE: usize = 256 * 1024;

// ── Little-endian helpers ───────────────────────────────────────────────────

/// Read a `u16` from `buf` at `offset` in little-endian byte order.
fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a `u32` from `buf` at `offset` in little-endian byte order.
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

/// Read a `u64` from `buf` at `offset` in little-endian byte order.
fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Append a `u16` in little-endian byte order.
fn write_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Append a `u32` in little-endian byte order.
fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Append a `u64` in little-endian byte order.
fn write_u64_le(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

// ── NTLM authentication (raw bytes for SMB, mirrors auth/ntlm.rs) ──────────

/// Compute the NT hash: `MD4(UTF-16LE(password))`.
fn compute_nt_hash(password: &str) -> [u8; 16] {
    use md4::{Digest as _, Md4};

    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the LM hash from a password (DES-based).
fn compute_lm_hash(password: &str) -> [u8; 16] {
    let magic = b"KGS!@#$%";
    let mut pwd = [0u8; 14];
    for (i, &b) in password.as_bytes().iter().take(14).enumerate() {
        pwd[i] = b.to_ascii_uppercase();
    }
    let key1 = des_key_from_7(&pwd[0..7]);
    let key2 = des_key_from_7(&pwd[7..14]);
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&des_ecb_encrypt(&key1, magic));
    hash[8..].copy_from_slice(&des_ecb_encrypt(&key2, magic));
    hash
}

/// Encrypt an 8-byte challenge with a 16-byte hash → 24-byte `NTLMv1` response.
#[allow(clippy::trivially_copy_pass_by_ref)] // Consistent with DES API conventions
fn ntlm_response(hash: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(hash);
    let key1 = des_key_from_7(&padded[0..7]);
    let key2 = des_key_from_7(&padded[7..14]);
    let key3 = des_key_from_7(&padded[14..21]);
    let mut resp = [0u8; 24];
    resp[..8].copy_from_slice(&des_ecb_encrypt(&key1, challenge));
    resp[8..16].copy_from_slice(&des_ecb_encrypt(&key2, challenge));
    resp[16..].copy_from_slice(&des_ecb_encrypt(&key3, challenge));
    resp
}

/// Expand 7 bytes to an 8-byte DES key (parity-bit expansion).
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

/// DES-ECB encrypt an 8-byte block.
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

// ── NetBIOS session service framing ─────────────────────────────────────────

/// Wrap an SMB message in a `NetBIOS` session service frame (type 0x00).
fn nb_frame(smb_msg: &[u8]) -> Vec<u8> {
    let len = smb_msg.len();
    let mut frame = Vec::with_capacity(4 + len);
    frame.push(0x00); // Session message type
                      // 3-byte big-endian length
    #[allow(clippy::cast_possible_truncation)]
    {
        frame.push(((len >> 16) & 0xFF) as u8);
        frame.push(((len >> 8) & 0xFF) as u8);
        frame.push((len & 0xFF) as u8);
    }
    frame.extend_from_slice(smb_msg);
    frame
}

/// Read a complete NetBIOS-framed SMB message.
///
/// # Errors
///
/// Returns an error if the stream closes, the message is too large, or the
/// SMB magic bytes are missing.
async fn recv_nb_message<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    let _ = stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::Http(format!("SMB read error: {e}")))?;

    let msg_len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
    if msg_len > MAX_SMB_MSG_SIZE {
        return Err(Error::Http(format!("SMB message too large: {msg_len}")));
    }

    let mut buf = vec![0u8; msg_len];
    let _ = stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Http(format!("SMB read error: {e}")))?;

    // Validate SMB magic
    if buf.len() < SMB_HEADER_LEN || buf[0..4] != SMB_MAGIC {
        return Err(Error::Http("SMB invalid response: bad magic".to_string()));
    }

    Ok(buf)
}

// ── SMB header builder ──────────────────────────────────────────────────────

/// Build a 32-byte SMB1 header.
fn build_smb_header(command: u8, flags2: u16, tid: u16, uid: u16, mid: u16) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(SMB_HEADER_LEN);
    hdr.extend_from_slice(&SMB_MAGIC); // Protocol (4)
    hdr.push(command); // Command (1)
    hdr.extend_from_slice(&[0u8; 4]); // Status (4)
    hdr.push(SMB_FLAGS_CASELESS | SMB_FLAGS_CANONICAL); // Flags (1)
    write_u16_le(&mut hdr, flags2); // Flags2 (2)
    write_u16_le(&mut hdr, 0); // PID High (2)
    hdr.extend_from_slice(&[0u8; 8]); // Signature (8)
    write_u16_le(&mut hdr, 0); // Reserved (2)
    write_u16_le(&mut hdr, tid); // TID (2)
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut hdr, std::process::id() as u16); // PID Low (2)
    write_u16_le(&mut hdr, uid); // UID (2)
    write_u16_le(&mut hdr, mid); // MID (2)
    debug_assert_eq!(hdr.len(), SMB_HEADER_LEN);
    hdr
}

/// Flags2 for commands that use OEM (ASCII) strings.
const FLAGS2_OEM: u16 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ERR_STATUS;
/// Flags2 for commands that use Unicode strings.
const FLAGS2_UNICODE: u16 = FLAGS2_OEM | SMB_FLAGS2_UNICODE;

/// Check SMB response NT Status (header bytes 5–8). Zero means success.
///
/// # Errors
///
/// Returns an error with the NT Status hex value if non-zero.
fn check_smb_status(resp: &[u8]) -> Result<(), Error> {
    let status = read_u32_le(resp, 5);
    if status != 0 {
        Err(Error::Http(format!("SMB error: NT Status 0x{status:08X}")))
    } else {
        Ok(())
    }
}

// ── Negotiate ───────────────────────────────────────────────────────────────

/// Result of a successful SMB Negotiate exchange.
struct NegotiateResult {
    /// Server's 8-byte NTLM challenge nonce.
    challenge: [u8; 8],
    /// Session key from server (echoed in Session Setup).
    session_key: u32,
    /// Server capability flags.
    capabilities: u32,
    /// Maximum buffer size the server supports.
    max_buffer_size: u32,
}

/// Send an `SMB_COM_NEGOTIATE` and parse the response.
///
/// Offers the `NT LM 0.12` dialect (`SMBv1`). Rejects servers that require
/// extended security (SPNEGO), as curl's SMB implementation uses the simpler
/// non-extended-security authentication path.
///
/// # Errors
///
/// Returns an error if the server rejects the dialect, requires extended
/// security, or returns an unexpected response format.
async fn smb_negotiate<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Result<NegotiateResult, Error> {
    let mut msg = build_smb_header(SMB_COM_NEGOTIATE, FLAGS2_OEM, 0, 0, 0);
    msg.push(0); // WordCount = 0

    // Dialect string: buffer format 0x02 + null-terminated "NT LM 0.12"
    let dialect = b"\x02NT LM 0.12\0";
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, dialect.len() as u16); // ByteCount
    msg.extend_from_slice(dialect);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    if resp.len() < SMB_HEADER_LEN + 1 {
        return Err(Error::Http("SMB negotiate response too short".to_string()));
    }

    let word_count = resp[SMB_HEADER_LEN] as usize;
    if word_count < 17 {
        return Err(Error::Http(format!("SMB negotiate: unexpected word count {word_count}")));
    }

    let params_start = SMB_HEADER_LEN + 1;
    let params = &resp[params_start..];
    if params.len() < 34 + 2 {
        return Err(Error::Http("SMB negotiate response params too short".to_string()));
    }

    // DialectIndex at offset 0 (should be 0 for our single offered dialect)
    let dialect_index = read_u16_le(params, 0);
    if dialect_index == 0xFFFF {
        return Err(Error::Http("SMB negotiate: server rejected all dialects".to_string()));
    }

    let max_buffer_size = read_u32_le(params, 7);
    let session_key = read_u32_le(params, 15);
    let capabilities = read_u32_le(params, 19);
    let challenge_len = params[33] as usize;

    if capabilities & CAP_EXTENDED_SECURITY != 0 {
        return Err(Error::Http(
            "SMB server requires extended security (not supported)".to_string(),
        ));
    }

    // Data section: ByteCount at params_start + word_count*2, then challenge bytes
    let byte_count_offset = params_start + word_count * 2;
    if resp.len() < byte_count_offset + 2 {
        return Err(Error::Http("SMB negotiate: missing byte count".to_string()));
    }

    let data_start = byte_count_offset + 2;
    if challenge_len != 8 || resp.len() < data_start + 8 {
        return Err(Error::Http(format!(
            "SMB negotiate: unexpected challenge length {challenge_len}"
        )));
    }

    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&resp[data_start..data_start + 8]);

    Ok(NegotiateResult { challenge, session_key, capabilities, max_buffer_size })
}

// ── Session Setup ───────────────────────────────────────────────────────────

/// Authenticate with the SMB server using `NTLMv1`.
///
/// Sends LM and NT responses computed from the negotiate challenge.
/// Returns the UID assigned by the server.
///
/// # Errors
///
/// Returns an error if authentication fails.
async fn smb_session_setup<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    negotiate: &NegotiateResult,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<u16, Error> {
    let nt_hash = compute_nt_hash(password);
    let lm_hash = compute_lm_hash(password);
    let lm_resp = ntlm_response(&lm_hash, &negotiate.challenge);
    let nt_resp = ntlm_response(&nt_hash, &negotiate.challenge);

    // Use OEM flags for Session Setup (strings are ASCII)
    let mut msg = build_smb_header(SMB_COM_SESSION_SETUP_ANDX, FLAGS2_OEM, 0, 0, 1);

    // Parameters (WordCount = 13, 26 bytes)
    msg.push(13);
    msg.push(SMB_COM_NO_ANDX); // AndXCommand
    msg.push(0); // AndXReserved
    write_u16_le(&mut msg, 0); // AndXOffset
    #[allow(clippy::cast_possible_truncation)]
    let max_buf = negotiate.max_buffer_size.min(65535) as u16;
    write_u16_le(&mut msg, max_buf); // MaxBufferSize
    write_u16_le(&mut msg, 1); // MaxMpxCount
    write_u16_le(&mut msg, 0); // VcNumber
    write_u32_le(&mut msg, negotiate.session_key); // SessionKey
    write_u16_le(&mut msg, 24); // OEMPasswordLen (LM response)
    write_u16_le(&mut msg, 24); // UnicodePasswordLen (NT response)
    write_u32_le(&mut msg, 0); // Reserved
    write_u32_le(&mut msg, negotiate.capabilities & !CAP_EXTENDED_SECURITY); // Capabilities

    // Data: LM response + NT response + ASCII null-terminated strings
    let mut data = Vec::new();
    data.extend_from_slice(&lm_resp);
    data.extend_from_slice(&nt_resp);
    data.extend_from_slice(username.as_bytes());
    data.push(0);
    data.extend_from_slice(domain.as_bytes());
    data.push(0);
    data.extend_from_slice(b"urlx\0"); // NativeOS
    data.extend_from_slice(b"urlx\0"); // NativeLanMan

    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, data.len() as u16); // ByteCount
    msg.extend_from_slice(&data);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    // UID is in the SMB header at offset 28
    let uid = read_u16_le(&resp, 28);
    Ok(uid)
}

// ── Tree Connect ────────────────────────────────────────────────────────────

/// Connect to an SMB share (tree connect).
///
/// `share_path` should be in UNC format: `\\server\share`.
/// Returns the TID assigned by the server.
///
/// # Errors
///
/// Returns an error if the share is not accessible.
async fn smb_tree_connect<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    uid: u16,
    share_path: &str,
) -> Result<u16, Error> {
    let mut msg = build_smb_header(SMB_COM_TREE_CONNECT_ANDX, FLAGS2_UNICODE, 0, uid, 2);

    // Parameters (WordCount = 4, 8 bytes)
    msg.push(4);
    msg.push(SMB_COM_NO_ANDX); // AndXCommand
    msg.push(0); // AndXReserved
    write_u16_le(&mut msg, 0); // AndXOffset
    write_u16_le(&mut msg, 0); // Flags
    write_u16_le(&mut msg, 1); // PasswordLength

    // Data: password (1 null byte) + pad + Unicode path + ASCII service
    let mut data = Vec::new();
    data.push(0); // Password (null)

    // Pad for Unicode alignment: position from SMB header start is
    // 32 (hdr) + 1 (wc) + 8 (params) + 2 (bc) + 1 (password) = 44 (even) → no pad needed

    // Path in Unicode (UCS-2LE), null-terminated
    let path_unicode: Vec<u8> = share_path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&path_unicode);
    data.extend_from_slice(&[0, 0]); // Unicode null terminator

    // Service type (ASCII, null-terminated)
    data.extend_from_slice(b"?????\0");

    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, data.len() as u16); // ByteCount
    msg.extend_from_slice(&data);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    // TID is in the SMB header at offset 24
    let tid = read_u16_le(&resp, 24);
    Ok(tid)
}

// ── NT Create AndX (open/create file) ───────────────────────────────────────

/// Result of a successful NT Create `AndX`.
struct FileHandle {
    /// File ID for subsequent read/write/close operations.
    fid: u16,
    /// File size in bytes (from `EndOfFile` field).
    file_size: u64,
}

/// Open or create a file on the SMB share.
///
/// For downloads (`for_write = false`), opens the file for reading.
/// For uploads (`for_write = true`), creates or overwrites the file.
///
/// # Errors
///
/// Returns an error if the file cannot be opened/created.
async fn smb_nt_create<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    tid: u16,
    uid: u16,
    filename: &str,
    for_write: bool,
) -> Result<FileHandle, Error> {
    // Filename in Unicode (UCS-2LE)
    let name_unicode: Vec<u8> = filename.encode_utf16().flat_map(u16::to_le_bytes).collect();

    let (access_mask, share_access, disposition) = if for_write {
        (
            FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
            0u32,
            FILE_OVERWRITE_IF,
        )
    } else {
        (
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
        )
    };

    let mut msg = build_smb_header(SMB_COM_NT_CREATE_ANDX, FLAGS2_UNICODE, tid, uid, 3);

    // Parameters (WordCount = 24, 48 bytes)
    msg.push(24);
    msg.push(SMB_COM_NO_ANDX); // AndXCommand
    msg.push(0); // AndXReserved
    write_u16_le(&mut msg, 0); // AndXOffset
    msg.push(0); // Reserved
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, name_unicode.len() as u16); // NameLength (in bytes)
    write_u32_le(&mut msg, 0); // Flags
    write_u32_le(&mut msg, 0); // RootDirectoryFID
    write_u32_le(&mut msg, access_mask); // DesiredAccess
    write_u64_le(&mut msg, 0); // AllocationSize
    write_u32_le(&mut msg, 0); // ExtFileAttributes (normal)
    write_u32_le(&mut msg, share_access); // ShareAccess
    write_u32_le(&mut msg, disposition); // CreateDisposition
    write_u32_le(&mut msg, 0); // CreateOptions
    write_u32_le(&mut msg, SECURITY_IMPERSONATION); // ImpersonationLevel
    msg.push(0); // SecurityFlags

    // Data: pad byte (for Unicode alignment) + Unicode filename + null terminator
    // Position from SMB header start: 32 + 1 + 48 + 2 = 83 (odd) → pad needed
    let mut data = Vec::new();
    data.push(0); // Pad
    data.extend_from_slice(&name_unicode);
    data.extend_from_slice(&[0, 0]); // Unicode null terminator

    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, data.len() as u16); // ByteCount
    msg.extend_from_slice(&data);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    // Parse NT Create AndX response (WordCount = 34, 68 bytes of params)
    if resp.len() < SMB_HEADER_LEN + 1 {
        return Err(Error::Http("SMB NT Create response too short".to_string()));
    }

    let word_count = resp[SMB_HEADER_LEN] as usize;
    let params = &resp[SMB_HEADER_LEN + 1..];
    if word_count < 34 || params.len() < 68 {
        return Err(Error::Http(format!("SMB NT Create: unexpected word count {word_count}")));
    }

    // FID at params offset 5 (2 bytes), EndOfFile at params offset 55 (8 bytes)
    let fid = read_u16_le(params, 5);
    let file_size = read_u64_le(params, 55);

    Ok(FileHandle { fid, file_size })
}

// ── Read AndX ───────────────────────────────────────────────────────────────

/// Read a chunk of data from an open file.
///
/// # Errors
///
/// Returns an error if the read fails or the response is malformed.
async fn smb_read<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    tid: u16,
    uid: u16,
    fid: u16,
    offset: u64,
    max_count: u16,
    mid: u16,
) -> Result<Vec<u8>, Error> {
    let mut msg = build_smb_header(SMB_COM_READ_ANDX, FLAGS2_UNICODE, tid, uid, mid);

    // Parameters (WordCount = 12, 24 bytes)
    msg.push(12);
    msg.push(SMB_COM_NO_ANDX); // AndXCommand
    msg.push(0); // AndXReserved
    write_u16_le(&mut msg, 0); // AndXOffset
    write_u16_le(&mut msg, fid); // FID
    #[allow(clippy::cast_possible_truncation)]
    write_u32_le(&mut msg, offset as u32); // Offset (low 32 bits)
    write_u16_le(&mut msg, max_count); // MaxCountOfBytesToReturn
    write_u16_le(&mut msg, 0); // MinCountOfBytesToReturn
    write_u32_le(&mut msg, 0); // Timeout / MaxCountHigh + Reserved
    write_u16_le(&mut msg, 0); // Remaining
    #[allow(clippy::cast_possible_truncation)]
    write_u32_le(&mut msg, (offset >> 32) as u32); // OffsetHigh

    // ByteCount = 0
    write_u16_le(&mut msg, 0);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    // Parse Read AndX response (WordCount = 12, 24 bytes of params)
    if resp.len() < SMB_HEADER_LEN + 1 {
        return Err(Error::Http("SMB Read response too short".to_string()));
    }

    let params = &resp[SMB_HEADER_LEN + 1..];
    if params.len() < 24 {
        return Err(Error::Http("SMB Read response params too short".to_string()));
    }

    // DataLength at params offset 10 (2 bytes)
    // DataOffset at params offset 12 (2 bytes) — relative to SMB header start
    // DataLengthHigh at params offset 14 (2 bytes)
    let data_length = read_u16_le(params, 10) as usize;
    let data_offset = read_u16_le(params, 12) as usize;
    let data_length_high = read_u16_le(params, 14) as usize;
    let total_length = data_length | (data_length_high << 16);

    if data_offset + total_length > resp.len() {
        return Err(Error::Http("SMB Read response data out of bounds".to_string()));
    }

    Ok(resp[data_offset..data_offset + total_length].to_vec())
}

// ── Write AndX ──────────────────────────────────────────────────────────────

/// Write a chunk of data to an open file.
///
/// Returns the number of bytes the server acknowledged writing.
///
/// # Errors
///
/// Returns an error if the write fails.
async fn smb_write<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    tid: u16,
    uid: u16,
    fid: u16,
    offset: u64,
    data: &[u8],
    mid: u16,
) -> Result<u32, Error> {
    let mut msg = build_smb_header(SMB_COM_WRITE_ANDX, FLAGS2_UNICODE, tid, uid, mid);

    // Parameters (WordCount = 14, 28 bytes)
    msg.push(14);
    msg.push(SMB_COM_NO_ANDX); // AndXCommand
    msg.push(0); // AndXReserved
    write_u16_le(&mut msg, 0); // AndXOffset
    write_u16_le(&mut msg, fid); // FID
    #[allow(clippy::cast_possible_truncation)]
    write_u32_le(&mut msg, offset as u32); // Offset (low 32)
    write_u32_le(&mut msg, 0); // Reserved
    write_u16_le(&mut msg, 0); // WriteMode
    write_u16_le(&mut msg, 0); // Remaining
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, (data.len() >> 16) as u16); // DataLengthHigh
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, data.len() as u16); // DataLength

    // DataOffset: from SMB header start to start of write data
    // 32 (hdr) + 1 (wc) + 28 (params) + 2 (bc) + 1 (pad) = 64
    let data_offset = msg.len() + 2 + 1; // +2 ByteCount, +1 pad
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, data_offset as u16); // DataOffset
    #[allow(clippy::cast_possible_truncation)]
    write_u32_le(&mut msg, (offset >> 32) as u32); // OffsetHigh

    // Data: pad + write data
    let byte_count = 1 + data.len();
    #[allow(clippy::cast_possible_truncation)]
    write_u16_le(&mut msg, byte_count as u16); // ByteCount
    msg.push(0); // Pad
    msg.extend_from_slice(data);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;

    // Parse Write AndX response (WordCount = 6, 12 bytes of params)
    let params = &resp[SMB_HEADER_LEN + 1..];
    if params.len() < 12 {
        return Err(Error::Http("SMB Write response params too short".to_string()));
    }

    // Count at params offset 4 (2 bytes), CountHigh at offset 8 (2 bytes)
    let count = u32::from(read_u16_le(params, 4));
    let count_high = u32::from(read_u16_le(params, 8));
    Ok(count | (count_high << 16))
}

// ── Close ───────────────────────────────────────────────────────────────────

/// Close an open file handle.
///
/// # Errors
///
/// Returns an error if the close fails.
async fn smb_close<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    tid: u16,
    uid: u16,
    fid: u16,
) -> Result<(), Error> {
    let mut msg = build_smb_header(SMB_COM_CLOSE, FLAGS2_UNICODE, tid, uid, 4);

    // Parameters (WordCount = 3, 6 bytes)
    msg.push(3);
    write_u16_le(&mut msg, fid); // FID
    write_u32_le(&mut msg, 0xFFFF_FFFF); // LastTimeModified (let server decide)

    // ByteCount = 0
    write_u16_le(&mut msg, 0);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;
    Ok(())
}

// ── Tree Disconnect ─────────────────────────────────────────────────────────

/// Disconnect from an SMB share.
///
/// # Errors
///
/// Returns an error if the disconnect fails.
async fn smb_tree_disconnect<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    tid: u16,
    uid: u16,
) -> Result<(), Error> {
    let mut msg = build_smb_header(SMB_COM_TREE_DISCONNECT, FLAGS2_UNICODE, tid, uid, 5);

    // WordCount = 0, ByteCount = 0
    msg.push(0);
    write_u16_le(&mut msg, 0);

    let frame = nb_frame(&msg);
    stream.write_all(&frame).await.map_err(|e| Error::Http(format!("SMB write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("SMB flush error: {e}")))?;

    let resp = recv_nb_message(stream).await?;
    check_smb_status(&resp)?;
    Ok(())
}

// ── URL parsing ─────────────────────────────────────────────────────────────

/// Parsed components of an SMB URL.
struct SmbUrlParts {
    host: String,
    port: u16,
    share: String,
    file_path: String,
    username: String,
    password: String,
    domain: String,
}

/// Parse an SMB URL into its component parts.
///
/// URL format: `smb://[domain%5Cuser:password@]server[:port]/share/path`
///
/// # Errors
///
/// Returns an error if the URL is missing the host or share name.
fn parse_smb_url(url: &crate::url::Url) -> Result<SmbUrlParts, Error> {
    let (host, port) = url.host_and_port()?;
    let raw_path = url.path();

    // Path format: /share/path/to/file
    let path = raw_path.trim_start_matches('/');
    let (share, file_path) =
        path.find('/').map_or((path, ""), |idx| (&path[..idx], &path[idx + 1..]));

    if share.is_empty() {
        return Err(Error::Http("SMB URL missing share name".to_string()));
    }

    // Extract credentials; handle domain\user or domain%5Cuser format
    let (username, password, domain) = if let Some((user, pass)) = url.credentials() {
        let decoded_user = percent_decode(user);
        let decoded_pass = percent_decode(pass);
        if let Some(idx) = decoded_user.find('\\') {
            (decoded_user[idx + 1..].to_string(), decoded_pass, decoded_user[..idx].to_string())
        } else {
            (decoded_user, decoded_pass, String::new())
        }
    } else {
        (String::new(), String::new(), String::new())
    };

    Ok(SmbUrlParts {
        host,
        port,
        share: share.to_string(),
        file_path: file_path.to_string(),
        username,
        password,
        domain,
    })
}

/// Percent-decode a URL component.
fn percent_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// Convert a hex ASCII character to its numeric value.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Core transfer logic ─────────────────────────────────────────────────────

/// Execute the full SMB protocol flow on an established stream.
///
/// Steps: Negotiate → Session Setup → Tree Connect → NT Create →
/// Read/Write → Close → Tree Disconnect.
async fn smb_transfer_on_stream<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    parts: &SmbUrlParts,
    upload_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    // 1. Negotiate
    let negotiate = smb_negotiate(stream).await?;

    // 2. Session Setup (NTLM auth)
    let uid =
        smb_session_setup(stream, &negotiate, &parts.username, &parts.password, &parts.domain)
            .await?;

    // 3. Tree Connect
    let share_path = format!("\\\\{}\\{}", parts.host, parts.share);
    let tid = smb_tree_connect(stream, uid, &share_path).await?;

    // Convert forward slashes to backslashes for SMB file path
    let smb_path = parts.file_path.replace('/', "\\");

    // 4. NT Create (open/create file)
    let for_write = upload_data.is_some();
    let handle = smb_nt_create(stream, tid, uid, &smb_path, for_write).await?;

    let result = if let Some(data) = upload_data {
        // Upload: write in chunks
        let mut offset = 0u64;
        let mut mid = 10u16;
        while offset < data.len() as u64 {
            #[allow(clippy::cast_possible_truncation)] // Upload data fits in memory
            let off = offset as usize;
            let chunk_end = (off + MAX_WRITE_SIZE).min(data.len());
            let chunk = &data[off..chunk_end];
            let written = smb_write(stream, tid, uid, handle.fid, offset, chunk, mid).await?;
            offset += u64::from(written);
            mid = mid.wrapping_add(1);
        }
        Vec::new()
    } else {
        // Download: read in chunks
        let mut body = Vec::with_capacity(handle.file_size.min(10 * 1024 * 1024) as usize);
        let mut offset = 0u64;
        let mut mid = 10u16;
        while offset < handle.file_size {
            let chunk = smb_read(stream, tid, uid, handle.fid, offset, MAX_READ_SIZE, mid).await?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            body.extend_from_slice(&chunk);
            mid = mid.wrapping_add(1);
        }
        body
    };

    // 5. Close
    smb_close(stream, tid, uid, handle.fid).await?;

    // 6. Tree Disconnect
    smb_tree_disconnect(stream, tid, uid).await?;

    Ok(result)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Perform an SMB/SMBS file transfer.
///
/// Downloads a file from an SMB share (default) or uploads data to it
/// (when `upload_data` is `Some`). For `smbs://` URLs, the TCP connection
/// is wrapped in TLS.
///
/// # URL format
///
/// `smb://[domain%5Cuser:password@]server[:port]/share/path/to/file`
///
/// # Errors
///
/// Returns an error if the connection, authentication, or transfer fails.
pub async fn transfer(
    url: &crate::url::Url,
    tls_config: &crate::tls::TlsConfig,
    use_tls: bool,
    upload_data: Option<&[u8]>,
) -> Result<Response, Error> {
    let parts = parse_smb_url(url)?;
    let addr = format!("{}:{}", parts.host, parts.port);

    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    let body = if use_tls {
        let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
        let (mut tls_stream, _alpn) = connector.connect(tcp, &parts.host).await?;
        smb_transfer_on_stream(&mut tls_stream, &parts, upload_data).await?
    } else {
        let mut tcp = tcp;
        smb_transfer_on_stream(&mut tcp, &parts, upload_data).await?
    };

    let mut headers = HashMap::new();
    let _ = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── URL parsing tests ───────────────────────────────────────────────

    #[test]
    fn parse_smb_url_basic() {
        let url = crate::url::Url::parse("smb://server/share/path/to/file.txt").unwrap();
        let parts = parse_smb_url(&url).unwrap();
        assert_eq!(parts.host, "server");
        assert_eq!(parts.port, 445);
        assert_eq!(parts.share, "share");
        assert_eq!(parts.file_path, "path/to/file.txt");
        assert!(parts.username.is_empty());
        assert!(parts.password.is_empty());
        assert!(parts.domain.is_empty());
    }

    #[test]
    fn parse_smb_url_with_credentials() {
        let url = crate::url::Url::parse("smb://user:pass@server/share/file").unwrap();
        let parts = parse_smb_url(&url).unwrap();
        assert_eq!(parts.username, "user");
        assert_eq!(parts.password, "pass");
        assert!(parts.domain.is_empty());
    }

    #[test]
    fn parse_smb_url_with_domain() {
        let url = crate::url::Url::parse("smb://DOMAIN%5Cuser:pass@server/share/file.txt").unwrap();
        let parts = parse_smb_url(&url).unwrap();
        assert_eq!(parts.domain, "DOMAIN");
        assert_eq!(parts.username, "user");
        assert_eq!(parts.password, "pass");
    }

    #[test]
    fn parse_smb_url_custom_port() {
        let url = crate::url::Url::parse("smb://server:8445/share/file").unwrap();
        let parts = parse_smb_url(&url).unwrap();
        assert_eq!(parts.port, 8445);
    }

    #[test]
    fn parse_smb_url_share_only() {
        let url = crate::url::Url::parse("smb://server/share").unwrap();
        let parts = parse_smb_url(&url).unwrap();
        assert_eq!(parts.share, "share");
        assert!(parts.file_path.is_empty());
    }

    #[test]
    fn parse_smb_url_missing_share() {
        let url = crate::url::Url::parse("smb://server/").unwrap();
        assert!(parse_smb_url(&url).is_err());
    }

    // ── NTLM hash tests ────────────────────────────────────────────────

    #[test]
    fn nt_hash_known_value() {
        // "Password" → known NT hash
        let hash = compute_nt_hash("Password");
        let hex_hash = hex::encode(hash);
        assert_eq!(hex_hash, "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn lm_hash_known_value() {
        // "Password" → known LM hash
        let hash = compute_lm_hash("Password");
        let hex_hash = hex::encode(hash);
        assert_eq!(hex_hash, "e52cac67419a9a224a3b108f3fa6cb6d");
    }

    #[test]
    fn ntlm_response_length() {
        let hash = compute_nt_hash("test");
        let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        let resp = ntlm_response(&hash, &challenge);
        assert_eq!(resp.len(), 24);
    }

    // ── Message building tests ──────────────────────────────────────────

    #[test]
    fn smb_header_magic() {
        let hdr = build_smb_header(SMB_COM_NEGOTIATE, FLAGS2_OEM, 0, 0, 0);
        assert_eq!(hdr.len(), SMB_HEADER_LEN);
        assert_eq!(&hdr[0..4], &SMB_MAGIC);
        assert_eq!(hdr[4], SMB_COM_NEGOTIATE);
    }

    #[test]
    fn smb_header_tid_uid_mid() {
        let hdr = build_smb_header(SMB_COM_CLOSE, FLAGS2_UNICODE, 42, 7, 99);
        assert_eq!(read_u16_le(&hdr, 24), 42); // TID
        assert_eq!(read_u16_le(&hdr, 28), 7); // UID
        assert_eq!(read_u16_le(&hdr, 30), 99); // MID
    }

    #[test]
    fn smb_header_flags() {
        let hdr = build_smb_header(SMB_COM_NEGOTIATE, FLAGS2_UNICODE, 0, 0, 0);
        let flags = hdr[9];
        assert_ne!(flags & SMB_FLAGS_CASELESS, 0);
        assert_ne!(flags & SMB_FLAGS_CANONICAL, 0);
        let flags2 = read_u16_le(&hdr, 10);
        assert_ne!(flags2 & SMB_FLAGS2_UNICODE, 0);
        assert_ne!(flags2 & SMB_FLAGS2_ERR_STATUS, 0);
    }

    #[test]
    fn nb_frame_structure() {
        let payload = vec![0xFF, b'S', b'M', b'B', 0x72]; // minimal "SMB" prefix + command
        let frame = nb_frame(&payload);
        assert_eq!(frame[0], 0x00); // Session message type
        let len = ((frame[1] as usize) << 16) | ((frame[2] as usize) << 8) | (frame[3] as usize);
        assert_eq!(len, payload.len());
        assert_eq!(&frame[4..], &payload);
    }

    #[test]
    fn nb_frame_large_message() {
        let payload = vec![0u8; 70_000];
        let frame = nb_frame(&payload);
        let len = ((frame[1] as usize) << 16) | ((frame[2] as usize) << 8) | (frame[3] as usize);
        assert_eq!(len, 70_000);
    }

    #[test]
    fn check_status_success() {
        let mut resp = vec![0u8; SMB_HEADER_LEN];
        resp[0..4].copy_from_slice(&SMB_MAGIC);
        // Status bytes 5-8 are already zero (success)
        assert!(check_smb_status(&resp).is_ok());
    }

    #[test]
    fn check_status_error() {
        let mut resp = vec![0u8; SMB_HEADER_LEN];
        resp[0..4].copy_from_slice(&SMB_MAGIC);
        // Set status to ACCESS_DENIED (0xC0000022)
        resp[5] = 0x22;
        resp[6] = 0x00;
        resp[7] = 0x00;
        resp[8] = 0xC0;
        let err = check_smb_status(&resp).unwrap_err();
        assert!(err.to_string().contains("0xC0000022"));
    }

    // ── Percent decoding tests ──────────────────────────────────────────

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("%5C"), "\\");
    }

    #[test]
    fn percent_decode_domain_backslash() {
        assert_eq!(percent_decode("DOMAIN%5Cuser"), "DOMAIN\\user");
    }

    #[test]
    fn percent_decode_incomplete() {
        assert_eq!(percent_decode("test%2"), "test%2");
        assert_eq!(percent_decode("test%"), "test%");
    }

    // ── LE helper tests ─────────────────────────────────────────────────

    #[test]
    fn le_roundtrip_u16() {
        let mut buf = Vec::new();
        write_u16_le(&mut buf, 0x1234);
        assert_eq!(read_u16_le(&buf, 0), 0x1234);
    }

    #[test]
    fn le_roundtrip_u32() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 0x1234_5678);
        assert_eq!(read_u32_le(&buf, 0), 0x1234_5678);
    }

    #[test]
    fn le_roundtrip_u64() {
        let mut buf = Vec::new();
        write_u64_le(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(read_u64_le(&buf, 0), 0x0102_0304_0506_0708);
    }

    // ── recv_nb_message tests ───────────────────────────────────────────

    #[tokio::test]
    async fn recv_nb_message_valid() {
        // Build a minimal valid SMB response: NetBIOS frame + SMB header
        let mut smb_msg = vec![0u8; SMB_HEADER_LEN];
        smb_msg[0..4].copy_from_slice(&SMB_MAGIC);
        smb_msg[4] = SMB_COM_NEGOTIATE; // command
        let frame = nb_frame(&smb_msg);

        let mut cursor = std::io::Cursor::new(frame);
        let result = recv_nb_message(&mut cursor).await.unwrap();
        assert_eq!(&result[0..4], &SMB_MAGIC);
    }

    #[tokio::test]
    async fn recv_nb_message_bad_magic() {
        let mut smb_msg = vec![0u8; SMB_HEADER_LEN];
        smb_msg[0..4].copy_from_slice(b"BAD!"); // Wrong magic
        let frame = nb_frame(&smb_msg);

        let mut cursor = std::io::Cursor::new(frame);
        assert!(recv_nb_message(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn recv_nb_message_too_large() {
        // Craft a frame header claiming a very large message
        let frame = vec![0x00, 0x10, 0x00, 0x00]; // 1MB message
        let mut cursor = std::io::Cursor::new(frame);
        assert!(recv_nb_message(&mut cursor).await.is_err());
    }
}
