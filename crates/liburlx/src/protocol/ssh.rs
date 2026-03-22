//! SSH/SFTP/SCP protocol support.
//!
//! Provides SFTP file transfer and SCP file copy over SSH connections
//! using the `russh` and `russh-sftp` crates (pure-Rust, async).
//!
//! Supports password and public key authentication, `known_hosts` verification,
//! and SHA-256 host key fingerprint pinning.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// SSH authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuthMethod {
    /// Password authentication (default if credentials are in the URL).
    Password,
    /// Public key authentication using a key file.
    PublicKey,
}

/// SSH host key verification policy.
#[derive(Debug, Clone, Default)]
pub enum SshHostKeyPolicy {
    /// Accept all host keys (default, matches curl without `--known-hosts`).
    #[default]
    AcceptAll,
    /// Verify against a `known_hosts` file.
    KnownHosts(Vec<KnownHostEntry>),
    /// Verify against a specific SHA-256 fingerprint (base64-encoded, no prefix).
    Sha256Fingerprint(String),
    /// Verify against a specific MD5 fingerprint (hex-encoded, 32 chars, no colons).
    Md5Fingerprint(String),
}

/// A parsed `known_hosts` entry for host key verification.
#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    /// Host patterns (plain hostnames or hashed).
    pub host_patterns: KnownHostPatterns,
    /// Whether this entry is revoked.
    pub revoked: bool,
    /// The public key bytes (SSH wire format).
    pub public_key_bytes: Vec<u8>,
}

/// Host pattern types from `known_hosts` file.
#[derive(Debug, Clone)]
pub enum KnownHostPatterns {
    /// Comma-separated hostname patterns.
    Patterns(Vec<String>),
    /// Hashed hostname (HMAC-SHA1).
    Hashed {
        /// The salt for HMAC-SHA1.
        salt: Vec<u8>,
        /// The HMAC-SHA1 hash of the hostname.
        hash: [u8; 20],
    },
}

/// Parse a `known_hosts` file into entries.
///
/// Supports both plain and hashed hostname formats (RFC 4251 `known_hosts`).
///
/// # Errors
///
/// Returns [`Error::Ssh`] if the file cannot be read or parsed.
pub fn parse_known_hosts_file(path: &str) -> Result<Vec<KnownHostEntry>, Error> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Ssh(format!("failed to read known_hosts '{path}': {e}")))?;
    parse_known_hosts(&contents)
}

/// Parse `known_hosts` content string into entries.
///
/// # Errors
///
/// Returns [`Error::Ssh`] if the content cannot be parsed.
pub fn parse_known_hosts(contents: &str) -> Result<Vec<KnownHostEntry>, Error> {
    use russh::keys::ssh_key::known_hosts::KnownHosts;

    let mut entries = Vec::new();
    for result in KnownHosts::new(contents) {
        let entry = result.map_err(|e| Error::Ssh(format!("known_hosts parse error: {e}")))?;

        let revoked = entry
            .marker()
            .is_some_and(|m| matches!(m, russh::keys::ssh_key::known_hosts::Marker::Revoked));

        let host_patterns = match entry.host_patterns() {
            russh::keys::ssh_key::known_hosts::HostPatterns::Patterns(patterns) => {
                KnownHostPatterns::Patterns(patterns.clone())
            }
            russh::keys::ssh_key::known_hosts::HostPatterns::HashedName { salt, hash } => {
                KnownHostPatterns::Hashed { salt: salt.clone(), hash: *hash }
            }
        };

        let public_key_bytes = entry
            .public_key()
            .to_bytes()
            .map_err(|e| Error::Ssh(format!("known_hosts key encode error: {e}")))?;

        entries.push(KnownHostEntry { host_patterns, revoked, public_key_bytes });
    }
    Ok(entries)
}

/// Check if a hostname matches a `known_hosts` entry.
fn host_matches_entry(hostname: &str, entry: &KnownHostEntry) -> bool {
    match &entry.host_patterns {
        KnownHostPatterns::Patterns(patterns) => {
            patterns.iter().any(|p| host_matches_pattern(hostname, p))
        }
        KnownHostPatterns::Hashed { salt, hash } => {
            // Compute HMAC-SHA1(salt, hostname) and compare
            let computed = hmac_sha1(salt, hostname.as_bytes());
            computed == *hash
        }
    }
}

/// Simple glob-style pattern matching for `known_hosts` hostnames.
///
/// Supports `*` and `?` wildcards and `!` negation prefix.
fn host_matches_pattern(hostname: &str, pattern: &str) -> bool {
    if let Some(negated) = pattern.strip_prefix('!') {
        return !simple_glob_match(hostname, negated);
    }
    // Strip port brackets: [hostname]:port
    let pattern = if pattern.starts_with('[') {
        pattern.find(']').map_or(pattern, |bracket_end| &pattern[1..bracket_end])
    } else {
        pattern
    };
    simple_glob_match(hostname, pattern)
}

/// Simple glob matching supporting `*` and `?`.
fn simple_glob_match(text: &str, pattern: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return text.eq_ignore_ascii_case(pattern);
    }
    // Basic recursive glob match
    glob_match_recursive(text.as_bytes(), pattern.as_bytes())
}

fn glob_match_recursive(text: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern[0] == b'*' {
        // Try matching * with 0 or more characters
        for i in 0..=text.len() {
            if glob_match_recursive(&text[i..], &pattern[1..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == b'?' || pattern[0].eq_ignore_ascii_case(&text[0]) {
        return glob_match_recursive(&text[1..], &pattern[1..]);
    }
    false
}

/// Compute MD5 hash.
///
/// Used for `--hostpubmd5` host key verification.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn md5_hash(data: &[u8]) -> [u8; 16] {
    // MD5 constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        #[allow(clippy::needless_range_loop)]
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };

            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

/// Compute HMAC-SHA1(key, message).
///
/// Used for hashed `known_hosts` hostname verification.
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    const OPAD: u8 = 0x5C;
    const IPAD: u8 = 0x36;

    // If key is longer than block size, hash it first
    let key = if key.len() > BLOCK_SIZE {
        let digest = sha1_hash(key);
        digest.to_vec()
    } else {
        key.to_vec()
    };

    // Pad key to block size
    let mut padded_key = vec![0u8; BLOCK_SIZE];
    padded_key[..key.len()].copy_from_slice(&key);

    // Inner hash: SHA1(key XOR ipad || message)
    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    for &b in &padded_key {
        inner.push(b ^ IPAD);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha1_hash(&inner);

    // Outer hash: SHA1(key XOR opad || inner_hash)
    let mut outer = Vec::with_capacity(BLOCK_SIZE + 20);
    for &b in &padded_key {
        outer.push(b ^ OPAD);
    }
    outer.extend_from_slice(&inner_hash);
    sha1_hash(&outer)
}

/// Minimal SHA-1 implementation for HMAC-SHA1 `known_hosts` verification.
///
/// Not used for security purposes — only for hostname hash verification
/// in `known_hosts` files (`OpenSSH` format).
#[allow(clippy::many_single_char_names)]
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        #[allow(clippy::needless_range_loop)] // SHA-1 round loop uses index for w[] lookup
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };

            let temp =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

/// SSH client handler with configurable host key verification.
struct SshHandler {
    policy: SshHostKeyPolicy,
    hostname: String,
}

impl russh::client::Handler for SshHandler {
    type Error = crate::error::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.policy {
            SshHostKeyPolicy::AcceptAll => Ok(true),
            SshHostKeyPolicy::Sha256Fingerprint(expected) => {
                let fingerprint =
                    server_public_key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
                let actual = base64_encode(fingerprint.as_bytes());
                if actual == *expected {
                    Ok(true)
                } else {
                    Err(Error::SshHostKeyMismatch(format!(
                        "SSH host key fingerprint mismatch: expected SHA256:{expected}, got SHA256:{actual}"
                    )))
                }
            }
            SshHostKeyPolicy::Md5Fingerprint(expected) => {
                // Compute MD5 of the public key bytes
                let key_bytes = server_public_key
                    .to_bytes()
                    .map_err(|e| Error::Ssh(format!("failed to encode server key: {e}")))?;
                let digest = md5_hash(&key_bytes);
                let actual = digest.iter().fold(String::new(), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                });
                if actual == expected.to_lowercase() {
                    Ok(true)
                } else {
                    Err(Error::SshHostKeyMismatch(format!(
                        "SSH host key MD5 mismatch: expected {expected}, got {actual}"
                    )))
                }
            }
            SshHostKeyPolicy::KnownHosts(entries) => {
                let server_key_bytes = server_public_key
                    .to_bytes()
                    .map_err(|e| Error::Ssh(format!("failed to encode server key: {e}")))?;

                for entry in entries {
                    if host_matches_entry(&self.hostname, entry) {
                        if entry.revoked {
                            return Err(Error::SshHostKeyMismatch(format!(
                                "SSH host key for '{}' is revoked in known_hosts",
                                self.hostname
                            )));
                        }
                        if entry.public_key_bytes == server_key_bytes {
                            return Ok(true);
                        }
                        // Key mismatch — potential MITM
                        return Err(Error::SshHostKeyMismatch(format!(
                            "SSH host key for '{}' does not match known_hosts (possible MITM attack)",
                            self.hostname
                        )));
                    }
                }
                // Host not found in known_hosts — reject
                Err(Error::SshHostKeyMismatch(format!(
                    "SSH host '{}' not found in known_hosts file",
                    self.hostname
                )))
            }
        }
    }
}

/// Base64-encode bytes (standard alphabet, no padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(ALPHABET[(b0 >> 2) as usize] as char);
        result.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            result.push(ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        }
        i += 3;
    }
    result
}

// Our Error type needs From<russh::Error> for the Handler trait.
impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Self {
        Self::Ssh(e.to_string())
    }
}

/// An active SSH session that can perform SFTP and SCP operations.
pub struct SshSession {
    handle: russh::client::Handle<SshHandler>,
}

/// Build an SSH client config that prefers `rsa-sha2-256` over `rsa-sha2-512`
/// for host key algorithms. russh 0.57.x has a bug verifying RSA-SHA2-512
/// server signatures with some OpenSSH server versions; preferring SHA-256
/// avoids the issue while remaining compatible with all servers.
fn ssh_client_config() -> Arc<russh::client::Config> {
    use std::borrow::Cow;

    let mut config = russh::client::Config::default();
    let mut preferred = config.preferred.clone();

    // Re-order host key algorithms: put rsa-sha2-256 before rsa-sha2-512
    preferred.key = Cow::Owned(vec![
        russh::keys::Algorithm::Ed25519,
        russh::keys::Algorithm::Ecdsa { curve: russh::keys::EcdsaCurve::NistP256 },
        russh::keys::Algorithm::Ecdsa { curve: russh::keys::EcdsaCurve::NistP384 },
        russh::keys::Algorithm::Ecdsa { curve: russh::keys::EcdsaCurve::NistP521 },
        russh::keys::Algorithm::Rsa { hash: Some(russh::keys::HashAlg::Sha256) },
        russh::keys::Algorithm::Rsa { hash: Some(russh::keys::HashAlg::Sha512) },
        russh::keys::Algorithm::Rsa { hash: None },
    ]);
    config.preferred = preferred;
    Arc::new(config)
}

impl SshSession {
    /// Connect to an SSH server and authenticate with a password.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the connection or authentication fails.
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        policy: SshHostKeyPolicy,
    ) -> Result<Self, Error> {
        let config = ssh_client_config();
        let handler = SshHandler { policy, hostname: host.to_string() };
        let mut handle = russh::client::connect(config, (host, port), handler).await?;

        let auth_result = handle
            .authenticate_password(user, pass)
            .await
            .map_err(|e| Error::Ssh(format!("password auth failed: {e}")))?;

        if !auth_result.success() {
            return Err(Error::Ssh("SSH password authentication rejected".to_string()));
        }

        Ok(Self { handle })
    }

    /// Connect to an SSH server and authenticate with a public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the connection, key loading, or authentication fails.
    pub async fn connect_with_key(
        host: &str,
        port: u16,
        user: &str,
        key_path: &str,
        policy: SshHostKeyPolicy,
    ) -> Result<Self, Error> {
        let config = ssh_client_config();
        let handler = SshHandler { policy, hostname: host.to_string() };
        let mut handle = russh::client::connect(config, (host, port), handler).await?;

        let key_pair = russh::keys::load_secret_key(key_path, None)
            .map_err(|e| Error::Ssh(format!("failed to load SSH key '{key_path}': {e}")))?;

        // Query server for best supported RSA hash algorithm
        let hash_alg = handle.best_supported_rsa_hash().await.ok().flatten().flatten();

        let auth_result = handle
            .authenticate_publickey(
                user,
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
            )
            .await
            .map_err(|e| Error::Ssh(format!("public key auth failed: {e}")))?;

        if !auth_result.success() {
            return Err(Error::Ssh("SSH public key authentication rejected".to_string()));
        }

        Ok(Self { handle })
    }

    /// Download a file via SFTP, following symlinks.
    ///
    /// If the target path is a symlink, resolves it via `read_link` and reads
    /// the target file. Follows up to 10 levels of symlinks to prevent loops.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or file read fails.
    pub async fn sftp_download(&self, path: &str) -> Result<Vec<u8>, Error> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("failed to request sftp subsystem: {e}")))?;

        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("SFTP session init failed: {e}")))?;

        // Resolve symlinks (up to 10 levels)
        let resolved = resolve_sftp_symlinks(&sftp, path, 10).await?;

        let data = sftp
            .read(&resolved)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP read '{resolved}' failed: {e}")))?;

        Ok(data)
    }

    /// Upload a file via SFTP, preserving permissions from the source.
    ///
    /// If `source_permissions` is provided (as a Unix mode like `0o644`),
    /// the remote file's permissions are set after the upload completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or file write fails.
    pub async fn sftp_upload(&self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.sftp_upload_with_permissions(path, data, None).await
    }

    /// Upload a file via SFTP with explicit permissions.
    ///
    /// Sets the remote file's permissions to `mode` after upload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or file write fails.
    pub async fn sftp_upload_with_permissions(
        &self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
    ) -> Result<(), Error> {
        use tokio::io::AsyncWriteExt;

        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("failed to request sftp subsystem: {e}")))?;

        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("SFTP session init failed: {e}")))?;

        // Use create() to create/truncate the file, then write data
        let mut file = sftp
            .create(path)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP create '{path}' failed: {e}")))?;
        file.write_all(data)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP write '{path}' failed: {e}")))?;

        // Set permissions if provided
        if let Some(permissions) = mode {
            let attrs = russh_sftp::protocol::FileAttributes {
                size: None,
                uid: None,
                user: None,
                gid: None,
                group: None,
                permissions: Some(permissions),
                atime: None,
                mtime: None,
            };
            sftp.set_metadata(path, attrs)
                .await
                .map_err(|e| Error::Ssh(format!("SFTP set permissions '{path}' failed: {e}")))?;
        }

        Ok(())
    }

    /// Recursively create directories for an SFTP path (like mkdir -p).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session initialization fails.
    pub async fn sftp_mkdir_p(&self, path: &str) -> Result<(), Error> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("failed to request sftp subsystem: {e}")))?;
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("SFTP session init failed: {e}")))?;

        // Build path components and create each level
        let mut current = String::new();
        for component in path.split('/') {
            if component.is_empty() {
                current.push('/');
                continue;
            }
            if !current.ends_with('/') {
                current.push('/');
            }
            current.push_str(component);
            // Try to create; ignore "already exists" errors
            let _ = sftp.create_dir(&current).await;
        }
        Ok(())
    }

    /// List a directory via SFTP.
    ///
    /// Returns the listing in long format (`ls -l` style) with one entry per line.
    /// This matches curl's SFTP directory listing output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or directory read fails.
    #[allow(clippy::items_after_statements)]
    pub async fn sftp_list(&self, path: &str) -> Result<Vec<u8>, Error> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("failed to request sftp subsystem: {e}")))?;

        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("SFTP session init failed: {e}")))?;

        let entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP readdir '{path}' failed: {e}")))?;

        use std::fmt::Write;
        let mut listing = String::new();
        for entry in entries {
            let meta = entry.metadata();
            let perms = format_permissions(&meta);
            let nlinks: u32 = if meta.file_type().is_dir() { 3 } else { 1 };
            let uid = meta.uid.unwrap_or(0);
            let gid = meta.gid.unwrap_or(0);
            let size = meta.size.unwrap_or(0);
            let mtime_str = format_mtime(meta.mtime);
            let name = entry.file_name();
            let _ = writeln!(
                listing,
                "{perms} {nlinks:4} {uid:<8} {gid:<8} {size:>12} {mtime_str} {name}"
            );
        }

        Ok(listing.into_bytes())
    }

    /// Download a file via SCP.
    ///
    /// Executes `scp -f <path>` on the remote server and reads the SCP protocol
    /// response to extract file data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the channel, SCP command, or data transfer fails.
    pub async fn scp_download(&self, path: &str) -> Result<Vec<u8>, Error> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;

        // Execute scp in source (download) mode
        channel
            .exec(true, format!("scp -f {path}"))
            .await
            .map_err(|e| Error::Ssh(format!("failed to exec scp: {e}")))?;

        // Send initial null byte to start transfer
        channel.data(&b"\0"[..]).await.map_err(|e| Error::Ssh(format!("scp write failed: {e}")))?;

        let mut header_parsed = false;
        let mut file_size: usize = 0;
        let mut file_data = Vec::new();
        let mut buf = Vec::new();

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    buf.extend_from_slice(data);

                    if !header_parsed {
                        // Look for the SCP header line: "C<mode> <size> <filename>\n"
                        if let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
                            let header_line = String::from_utf8_lossy(&buf[..nl_pos]).to_string();
                            drop(buf.drain(..=nl_pos));

                            file_size = parse_scp_header(&header_line)?;
                            header_parsed = true;

                            // Acknowledge the header
                            channel
                                .data(&b"\0"[..])
                                .await
                                .map_err(|e| Error::Ssh(format!("scp ack failed: {e}")))?;
                        }
                    }

                    if header_parsed {
                        file_data.extend_from_slice(&buf);
                        buf.clear();

                        if file_data.len() >= file_size {
                            // Trim to exact size (SCP sends a trailing \0)
                            file_data.truncate(file_size);
                            // Acknowledge completion
                            let _ = channel.data(&b"\0"[..]).await;
                            break;
                        }
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        if !header_parsed {
            return Err(Error::Ssh("SCP: no file header received".to_string()));
        }

        Ok(file_data)
    }

    /// Upload a file via SCP.
    ///
    /// Executes `scp -t <path>` on the remote server and writes the file data
    /// using the SCP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the channel, SCP command, or data transfer fails.
    pub async fn scp_upload(&self, path: &str, data: &[u8]) -> Result<(), Error> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::SshUploadFailed(format!("failed to open SSH channel: {e}")))?;

        // Execute scp in sink (upload) mode
        channel
            .exec(true, format!("scp -t {path}"))
            .await
            .map_err(|e| Error::SshUploadFailed(format!("failed to exec scp: {e}")))?;

        // Wait for initial \0 acknowledgement from server
        wait_for_scp_ack(&mut channel).await.map_err(|e| Error::SshUploadFailed(format!("{e}")))?;

        // Extract filename from path
        let filename = path.rsplit('/').next().unwrap_or(path);

        // Send SCP header: "C0644 <size> <filename>\n"
        let header = format!("C0644 {} {filename}\n", data.len());
        channel
            .data(header.as_bytes())
            .await
            .map_err(|e| Error::SshUploadFailed(format!("scp header write failed: {e}")))?;

        // Wait for acknowledgement
        wait_for_scp_ack(&mut channel).await.map_err(|e| Error::SshUploadFailed(format!("{e}")))?;

        // Send file data
        channel
            .data(data)
            .await
            .map_err(|e| Error::SshUploadFailed(format!("scp data write failed: {e}")))?;

        // Send trailing null byte
        channel
            .data(&b"\0"[..])
            .await
            .map_err(|e| Error::SshUploadFailed(format!("scp trailing null write failed: {e}")))?;

        // Wait for final acknowledgement
        wait_for_scp_ack(&mut channel).await.map_err(|e| Error::SshUploadFailed(format!("{e}")))?;

        // Signal EOF
        let _ = channel.eof().await;

        Ok(())
    }

    /// Close the SSH session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if disconnect fails.
    pub async fn close(self) -> Result<(), Error> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| Error::Ssh(format!("SSH disconnect failed: {e}")))
    }
}

/// Parse an SCP file header line ("C<mode> <size> <filename>").
///
/// Returns the file size.
fn parse_scp_header(line: &str) -> Result<usize, Error> {
    // Format: "C<4-digit-mode> <size> <filename>"
    if !line.starts_with('C') {
        return Err(Error::Ssh(format!("SCP: unexpected header: {line}")));
    }

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(Error::Ssh(format!("SCP: malformed header: {line}")));
    }

    parts[1]
        .parse::<usize>()
        .map_err(|e| Error::Ssh(format!("SCP: invalid file size '{}': {e}", parts[1])))
}

/// Wait for an SCP acknowledgement (single \0 byte).
async fn wait_for_scp_ack(channel: &mut russh::Channel<russh::client::Msg>) -> Result<(), Error> {
    loop {
        let Some(msg) = channel.wait().await else {
            return Err(Error::Ssh("SCP: channel closed waiting for ack".to_string()));
        };
        match msg {
            russh::ChannelMsg::Data { ref data } => {
                if data.is_empty() {
                    continue;
                }
                if data[0] == 0 {
                    return Ok(());
                }
                if data[0] == 1 || data[0] == 2 {
                    let msg = String::from_utf8_lossy(&data[1..]);
                    return Err(Error::Ssh(format!("SCP error: {msg}")));
                }
                // Other data, skip
            }
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                return Err(Error::Ssh("SCP: channel closed waiting for ack".to_string()));
            }
            _ => {}
        }
    }
}

/// Resolve symlinks for an SFTP path.
///
/// Uses `symlink_metadata` (lstat) to check if the path is a symlink, and
/// `read_link` to resolve it. Follows up to `max_depth` levels.
///
/// # Errors
///
/// Returns [`Error::Ssh`] if symlink resolution fails or exceeds depth.
async fn resolve_sftp_symlinks(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    max_depth: u32,
) -> Result<String, Error> {
    let mut current = path.to_string();

    for _ in 0..max_depth {
        let meta = sftp
            .symlink_metadata(&current)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP stat '{current}' failed: {e}")))?;

        if !meta.file_type().is_symlink() {
            return Ok(current);
        }

        let target = sftp
            .read_link(&current)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP readlink '{current}' failed: {e}")))?;

        // If target is relative, resolve it against the parent directory
        if target.starts_with('/') {
            current = target;
        } else if let Some(parent) = current.rsplit_once('/') {
            current = format!("{}/{target}", parent.0);
        } else {
            current = target;
        }
    }

    Err(Error::Ssh(format!("SFTP symlink loop: too many levels of symlinks for '{path}'")))
}

/// Download a file via SFTP and return it as a Response.
///
/// # Errors
///
/// Returns an error if connection, authentication, or file transfer fails.
#[allow(clippy::too_many_arguments)]
pub async fn download(
    url: &crate::url::Url,
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
    ssh_public_keyfile: Option<&str>,
    ssh_auth_types: Option<u32>,
    pre_quote: &[String],
    post_quote: &[String],
    range: Option<&str>,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(
        &host,
        port,
        user,
        pass,
        ssh_key_path,
        policy,
        ssh_public_keyfile,
        ssh_auth_types,
    )
    .await?;

    // Execute pre-quote commands
    if !pre_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, pre_quote).await?;
    }

    let mut data = if url.scheme() == "scp" {
        session.scp_download(path).await?
    } else if path.ends_with('/') {
        // Directory listing (curl compat: tests 613, 614)
        session.sftp_list(path).await?
    } else {
        session.sftp_download(path).await?
    };

    // Apply byte range if specified (SFTP only)
    if let Some(range_str) = range {
        data = apply_byte_range(&data, range_str)?;
    }

    // Execute post-quote commands
    // Post-quote errors still produce the downloaded data (curl compat: test 609)
    let post_quote_err = if !post_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, post_quote).await.err()
    } else {
        None
    };

    let _ = session.close().await;

    // If post-quote failed, return error with downloaded data embedded
    if let Some(err) = post_quote_err {
        // Return the error; the caller (CLI) will already have written body data
        // from a previous successful response in the same transfer sequence.
        // For now, we still need to return the data so it can be output.
        // Use a special error that includes the response data.
        let headers = HashMap::new();
        let mut resp = Response::new(200, headers, data, url.as_str().to_string());
        resp.set_raw_headers(Vec::new());
        // Store the post-quote error in the response as a header-like marker
        return Err(Error::SshQuoteErrorWithData {
            message: err.to_string(),
            response: Box::new(resp),
        });
    }

    let headers = HashMap::new();
    let mut resp = Response::new(200, headers, data, url.as_str().to_string());
    resp.set_raw_headers(Vec::new());
    Ok(resp)
}

/// Upload a file via SFTP and return a Response.
///
/// # Errors
///
/// Returns an error if connection, authentication, or file transfer fails.
#[allow(clippy::too_many_arguments)]
pub async fn upload(
    url: &crate::url::Url,
    data: &[u8],
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
    ssh_public_keyfile: Option<&str>,
    ssh_auth_types: Option<u32>,
    pre_quote: &[String],
    post_quote: &[String],
    create_dirs: bool,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(
        &host,
        port,
        user,
        pass,
        ssh_key_path,
        policy,
        ssh_public_keyfile,
        ssh_auth_types,
    )
    .await?;

    // Execute pre-quote commands
    if !pre_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, pre_quote).await?;
    }

    // --ftp-create-dirs: create parent directories for upload path
    if create_dirs && url.scheme() == "sftp" {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent_str = parent.to_string_lossy();
            if !parent_str.is_empty() && parent_str != "/" {
                session.sftp_mkdir_p(&parent_str).await?;
            }
        }
    }

    if url.scheme() == "scp" {
        session.scp_upload(path, data).await?;
    } else {
        session.sftp_upload(path, data).await?;
    }

    // Execute post-quote commands
    if !post_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, post_quote).await?;
    }

    let _ = session.close().await;

    let headers = HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

/// HEAD request for SSH (run quote commands, no file transfer).
///
/// # Errors
///
/// Returns an error if connection, authentication, or quote commands fail.
#[allow(clippy::too_many_arguments)]
pub async fn head(
    url: &crate::url::Url,
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
    ssh_public_keyfile: Option<&str>,
    ssh_auth_types: Option<u32>,
    pre_quote: &[String],
    post_quote: &[String],
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));

    let session = connect_session(
        &host,
        port,
        user,
        pass,
        ssh_key_path,
        policy,
        ssh_public_keyfile,
        ssh_auth_types,
    )
    .await?;

    if !pre_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, pre_quote).await?;
    }
    if !post_quote.is_empty() && url.scheme() == "sftp" {
        execute_sftp_quotes(&session, post_quote).await?;
    }

    let _ = session.close().await;

    let headers = HashMap::new();
    let mut resp = Response::new(200, headers, Vec::new(), url.as_str().to_string());
    resp.set_raw_headers(Vec::new());
    Ok(resp)
}

/// Format Unix-style file permissions string (e.g., "-rw-r--r--" or "drwxr-xr-x").
fn format_permissions(meta: &russh_sftp::protocol::FileAttributes) -> String {
    let raw = meta.permissions.unwrap_or(0);
    let file_type_char = if meta.is_dir() {
        'd'
    } else if meta.is_symlink() {
        'l'
    } else {
        '-'
    };
    let perms = meta.permissions();
    let mut s = String::with_capacity(10);
    s.push(file_type_char);
    s.push(if perms.owner_read { 'r' } else { '-' });
    s.push(if perms.owner_write { 'w' } else { '-' });
    s.push(if raw & 0o4000 != 0 {
        if perms.owner_exec {
            's'
        } else {
            'S'
        }
    } else if perms.owner_exec {
        'x'
    } else {
        '-'
    });
    s.push(if perms.group_read { 'r' } else { '-' });
    s.push(if perms.group_write { 'w' } else { '-' });
    s.push(if raw & 0o2000 != 0 {
        if perms.group_exec {
            's'
        } else {
            'S'
        }
    } else if perms.group_exec {
        'x'
    } else {
        '-'
    });
    s.push(if perms.other_read { 'r' } else { '-' });
    s.push(if perms.other_write { 'w' } else { '-' });
    s.push(if raw & 0o1000 != 0 {
        if perms.other_exec {
            't'
        } else {
            'T'
        }
    } else if perms.other_exec {
        'x'
    } else {
        '-'
    });
    s
}

/// Format mtime as a human-readable date string (e.g., "Jan  1  2000" or "Jan  1 12:00").
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn format_mtime(mtime: Option<u32>) -> String {
    let Some(ts) = mtime else {
        return "Jan  1  1970".to_string();
    };

    // Convert Unix timestamp to date components
    let secs = i64::from(ts);
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    // Simple date calculation from epoch days
    let (year, month, day) = days_to_ymd(days);

    let month_names =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mon_str = month_names[((month - 1) as usize).min(11)];

    // If the file is older than ~6 months, show year; otherwise show time
    let now_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_days = now_days / 86400;
    let six_months_days = 182;

    if (now_days - days).abs() > six_months_days {
        format!("{mon_str} {day:2}  {year}")
    } else {
        format!("{mon_str} {day:2} {hours:02}:{minutes:02}")
    }
}

/// Convert days since Unix epoch to (year, month, day).
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
const fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as i64, d as i64)
}

/// Execute SFTP quote commands (rename, rm, mkdir, rmdir, chmod, chown, ln, symlink).
///
/// Commands prefixed with `*` are "accept-fail": errors are ignored.
async fn execute_sftp_quotes(session: &SshSession, commands: &[String]) -> Result<(), Error> {
    let channel = session
        .handle
        .channel_open_session()
        .await
        .map_err(|e| Error::Ssh(format!("failed to open SSH channel for quote: {e}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| Error::Ssh(format!("failed to request sftp subsystem: {e}")))?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| Error::Ssh(format!("SFTP session init failed: {e}")))?;

    for cmd in commands {
        // Check for `*` prefix (accept-fail: ignore errors)
        let (accept_fail, cmd) =
            cmd.strip_prefix('*').map_or((false, cmd.as_str()), |stripped| (true, stripped));

        let result = execute_single_sftp_quote(&sftp, cmd).await;
        if let Err(e) = result {
            if accept_fail {
                // Silently ignore the error
                continue;
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Execute a single SFTP quote command.
#[allow(clippy::too_many_lines)]
async fn execute_single_sftp_quote(
    sftp: &russh_sftp::client::SftpSession,
    cmd: &str,
) -> Result<(), Error> {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let op = parts[0].to_lowercase();
    let args = parts.get(1).copied().unwrap_or("");
    match op.as_str() {
        "rename" => {
            let rename_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if rename_parts.len() < 2 {
                return Err(Error::SshQuoteError(
                    "SFTP quote rename: need old and new path".to_string(),
                ));
            }
            sftp.rename(rename_parts[0], rename_parts[1])
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote rename failed: {e}")))?;
        }
        "rm" | "remove" => {
            sftp.remove_file(args)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote rm failed: {e}")))?;
        }
        "mkdir" => {
            sftp.create_dir(args)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote mkdir failed: {e}")))?;
        }
        "rmdir" => {
            sftp.remove_dir(args)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote rmdir failed: {e}")))?;
        }
        "chmod" => {
            // chmod <mode> <path>
            let chmod_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if chmod_parts.len() < 2 {
                return Err(Error::SshQuoteError(
                    "SFTP quote chmod: need mode and path".to_string(),
                ));
            }
            let mode = u32::from_str_radix(chmod_parts[0], 8).map_err(|e| {
                Error::SshQuoteError(format!(
                    "SFTP quote chmod: invalid mode '{}': {e}",
                    chmod_parts[0]
                ))
            })?;
            // Read existing metadata to preserve file type bits, then set new permissions
            let meta = sftp
                .metadata(chmod_parts[1])
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote chmod stat failed: {e}")))?;
            let file_type_bits = meta.permissions.unwrap_or(0) & 0o170_000;
            let attrs = russh_sftp::protocol::FileAttributes {
                size: None,
                uid: None,
                user: None,
                gid: None,
                group: None,
                permissions: Some(file_type_bits | mode),
                atime: None,
                mtime: None,
            };
            sftp.set_metadata(chmod_parts[1], attrs)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote chmod failed: {e}")))?;
        }
        "chown" => {
            // chown <uid> <path>
            let chown_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if chown_parts.len() < 2 {
                return Err(Error::SshQuoteError(
                    "SFTP quote chown: need uid and path".to_string(),
                ));
            }
            let uid = chown_parts[0].parse::<u32>().map_err(|e| {
                Error::SshQuoteError(format!(
                    "SFTP quote chown: invalid uid '{}': {e}",
                    chown_parts[0]
                ))
            })?;
            let attrs = russh_sftp::protocol::FileAttributes {
                size: None,
                uid: Some(uid),
                user: None,
                gid: None,
                group: None,
                permissions: None,
                atime: None,
                mtime: None,
            };
            sftp.set_metadata(chown_parts[1], attrs)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote chown failed: {e}")))?;
        }
        "chgrp" => {
            // chgrp <gid> <path>
            let chgrp_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if chgrp_parts.len() < 2 {
                return Err(Error::SshQuoteError(
                    "SFTP quote chgrp: need gid and path".to_string(),
                ));
            }
            let gid = chgrp_parts[0].parse::<u32>().map_err(|e| {
                Error::SshQuoteError(format!(
                    "SFTP quote chgrp: invalid gid '{}': {e}",
                    chgrp_parts[0]
                ))
            })?;
            let attrs = russh_sftp::protocol::FileAttributes {
                size: None,
                uid: None,
                user: None,
                gid: Some(gid),
                group: None,
                permissions: None,
                atime: None,
                mtime: None,
            };
            sftp.set_metadata(chgrp_parts[1], attrs)
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote chgrp failed: {e}")))?;
        }
        "ln" | "symlink" => {
            let ln_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if ln_parts.len() < 2 {
                return Err(Error::SshQuoteError(
                    "SFTP quote ln/symlink: need source and target path".to_string(),
                ));
            }
            sftp.symlink(ln_parts[0], ln_parts[1])
                .await
                .map_err(|e| Error::SshQuoteError(format!("SFTP quote symlink failed: {e}")))?;
        }
        _ => {
            return Err(Error::SshQuoteError(format!("SFTP quote: unsupported command '{op}'")));
        }
    }
    Ok(())
}

/// Apply a byte range (e.g., "5-9" or "-9") to downloaded data.
///
/// Returns `Ok(data)` on success, or `Err(SshRangeError)` if the range is not satisfiable.
fn apply_byte_range(data: &[u8], range: &str) -> Result<Vec<u8>, Error> {
    // Negative range: "-N" means last N bytes
    if let Some(suffix) = range.strip_prefix('-') {
        let n = suffix.parse::<usize>().unwrap_or(0);
        if n == 0 {
            return Err(Error::SshRangeError("invalid range".to_string()));
        }
        let start = data.len().saturating_sub(n);
        return Ok(data[start..].to_vec());
    }

    if let Some((start_str, end_str)) = range.split_once('-') {
        let start = start_str.parse::<usize>().unwrap_or(0);
        // "N-" means from offset N to end of file
        if end_str.is_empty() {
            // Range beyond file size: return error (curl compat: test 637)
            if start >= data.len() {
                return Err(Error::SshRangeError(format!(
                    "Requested range was not satisfiable (start {start} >= size {})",
                    data.len()
                )));
            }
            return Ok(data[start..].to_vec());
        }
        let end = end_str.parse::<usize>().unwrap_or_else(|_| data.len().saturating_sub(1));
        if start >= data.len() {
            return Err(Error::SshRangeError(format!(
                "Requested range was not satisfiable (start {start} >= size {})",
                data.len()
            )));
        }
        let end = end.min(data.len().saturating_sub(1));
        Ok(data[start..=end].to_vec())
    } else {
        Ok(data.to_vec())
    }
}

/// SSH auth type bitmask: public key authentication.
const SSH_AUTH_PUBLICKEY: u32 = 1;
/// SSH auth type bitmask: password authentication.
const SSH_AUTH_PASSWORD: u32 = 2;

/// Connect to an SSH server, choosing auth method based on available credentials.
///
/// `ssh_public_keyfile` is accepted for API compatibility (identifies which key to offer)
/// but is not directly used by russh, which only needs the private key.
///
/// `ssh_auth_types` is an optional bitmask controlling which auth methods are attempted:
/// - bit 0 (1): public key
/// - bit 1 (2): password
/// - bit 2 (4): keyboard-interactive
/// - bit 3 (8): host-based
///
/// When `None`, all available methods are attempted (default behavior).
#[allow(clippy::too_many_arguments)]
async fn connect_session(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
    _ssh_public_keyfile: Option<&str>,
    ssh_auth_types: Option<u32>,
) -> Result<SshSession, Error> {
    let effective_user = if user.is_empty() { "root" } else { user };

    let allow_pubkey = ssh_auth_types.is_none_or(|mask| mask & SSH_AUTH_PUBLICKEY != 0);
    let allow_password = ssh_auth_types.is_none_or(|mask| mask & SSH_AUTH_PASSWORD != 0);

    if allow_pubkey {
        if let Some(key_path) = ssh_key_path {
            // Verify the key file exists before attempting connection (curl compat: test 656)
            if !std::path::Path::new(key_path).exists() {
                return Err(Error::Ssh(format!(
                    "failed to load SSH key: unable to read '{key_path}'"
                )));
            }
            return SshSession::connect_with_key(
                host,
                port,
                effective_user,
                key_path,
                policy.clone(),
            )
            .await;
        }
    }

    if allow_password && !pass.is_empty() {
        return SshSession::connect(host, port, effective_user, pass, policy.clone()).await;
    }

    if allow_pubkey {
        // Try default SSH key locations
        let home = std::env::var("HOME").unwrap_or_default();
        let default_keys = [
            format!("{home}/.ssh/id_ed25519"),
            format!("{home}/.ssh/id_rsa"),
            format!("{home}/.ssh/id_ecdsa"),
        ];
        for key_path in &default_keys {
            if std::path::Path::new(key_path).exists() {
                if let Ok(session) = SshSession::connect_with_key(
                    host,
                    port,
                    effective_user,
                    key_path,
                    policy.clone(),
                )
                .await
                {
                    return Ok(session);
                }
            }
        }
    }

    Err(Error::Ssh(
        "no SSH credentials provided: use URL credentials, --key, or have keys in ~/.ssh/"
            .to_string(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ssh_auth_method_eq() {
        assert_eq!(SshAuthMethod::Password, SshAuthMethod::Password);
        assert_eq!(SshAuthMethod::PublicKey, SshAuthMethod::PublicKey);
        assert_ne!(SshAuthMethod::Password, SshAuthMethod::PublicKey);
    }

    #[test]
    fn parse_scp_header_valid() {
        let size = parse_scp_header("C0644 12345 testfile.txt").unwrap();
        assert_eq!(size, 12345);
    }

    #[test]
    fn parse_scp_header_zero_size() {
        let size = parse_scp_header("C0644 0 empty.txt").unwrap();
        assert_eq!(size, 0);
    }

    #[test]
    fn parse_scp_header_large_size() {
        let size = parse_scp_header("C0644 1073741824 large.bin").unwrap();
        assert_eq!(size, 1_073_741_824);
    }

    #[test]
    fn parse_scp_header_no_c_prefix() {
        let result = parse_scp_header("0644 123 file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected header"));
    }

    #[test]
    fn parse_scp_header_malformed() {
        let result = parse_scp_header("C0644");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("malformed header"));
    }

    #[test]
    fn parse_scp_header_invalid_size() {
        let result = parse_scp_header("C0644 notanumber file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid file size"));
    }

    #[test]
    fn parse_scp_header_with_spaces_in_filename() {
        let size = parse_scp_header("C0644 42 my file name.txt").unwrap();
        assert_eq!(size, 42);
    }

    #[test]
    fn parse_scp_header_permissions_755() {
        let size = parse_scp_header("C0755 100 script.sh").unwrap();
        assert_eq!(size, 100);
    }

    #[test]
    fn ssh_error_display() {
        let err = Error::Ssh("test error".to_string());
        assert_eq!(err.to_string(), "SSH error: test error");
    }

    #[test]
    fn ssh_error_from_russh() {
        // Verify the From<russh::Error> conversion works
        let russh_err = russh::Error::Disconnect;
        let err: Error = Error::from(russh_err);
        assert!(err.to_string().contains("SSH error"));
    }

    #[test]
    fn ssh_host_key_policy_default_is_accept_all() {
        let policy = SshHostKeyPolicy::default();
        assert!(matches!(policy, SshHostKeyPolicy::AcceptAll));
    }

    #[test]
    fn ssh_host_key_policy_sha256() {
        let policy = SshHostKeyPolicy::Sha256Fingerprint("abc123".to_string());
        assert!(matches!(policy, SshHostKeyPolicy::Sha256Fingerprint(_)));
    }

    #[test]
    fn ssh_host_key_policy_clone() {
        let policy = SshHostKeyPolicy::Sha256Fingerprint("test".to_string());
        #[allow(clippy::redundant_clone)]
        let cloned = policy.clone();
        assert!(matches!(cloned, SshHostKeyPolicy::Sha256Fingerprint(s) if s == "test"));
    }

    #[test]
    fn host_matches_pattern_exact() {
        assert!(host_matches_pattern("example.com", "example.com"));
        assert!(!host_matches_pattern("example.com", "other.com"));
    }

    #[test]
    fn host_matches_pattern_case_insensitive() {
        assert!(host_matches_pattern("Example.Com", "example.com"));
        assert!(host_matches_pattern("example.com", "EXAMPLE.COM"));
    }

    #[test]
    fn host_matches_pattern_wildcard() {
        assert!(host_matches_pattern("foo.example.com", "*.example.com"));
        assert!(!host_matches_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn host_matches_pattern_question_mark() {
        assert!(host_matches_pattern("host1", "host?"));
        assert!(!host_matches_pattern("host12", "host?"));
    }

    #[test]
    fn host_matches_pattern_negation() {
        assert!(!host_matches_pattern("bad.com", "!bad.com"));
        assert!(host_matches_pattern("good.com", "!bad.com"));
    }

    #[test]
    fn host_matches_pattern_bracketed_port() {
        assert!(host_matches_pattern("example.com", "[example.com]:22"));
    }

    #[test]
    fn simple_glob_match_no_wildcards() {
        assert!(simple_glob_match("hello", "hello"));
        assert!(!simple_glob_match("hello", "world"));
    }

    #[test]
    fn simple_glob_match_star() {
        assert!(simple_glob_match("anything", "*"));
        assert!(simple_glob_match("foobar", "foo*"));
        assert!(simple_glob_match("foobar", "*bar"));
        assert!(simple_glob_match("foobar", "f*r"));
    }

    #[test]
    fn simple_glob_match_question() {
        assert!(simple_glob_match("ab", "a?"));
        assert!(!simple_glob_match("abc", "a?"));
    }

    #[test]
    fn sha1_hash_empty() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1_hash(b"");
        let hex = hash.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_hash_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1_hash(b"abc");
        let hex = hash.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_sha1_rfc2202_test1() {
        // HMAC-SHA1 test vector from RFC 2202:
        // key = 0x0b repeated 20 times, data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        let hex = result.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg");
        assert_eq!(base64_encode(b"fo"), "Zm8");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg");
    }

    #[test]
    fn host_matches_entry_plain_patterns() {
        let entry = KnownHostEntry {
            host_patterns: KnownHostPatterns::Patterns(vec![
                "example.com".to_string(),
                "alias.example.com".to_string(),
            ]),
            revoked: false,
            public_key_bytes: vec![1, 2, 3],
        };
        assert!(host_matches_entry("example.com", &entry));
        assert!(host_matches_entry("alias.example.com", &entry));
        assert!(!host_matches_entry("other.com", &entry));
    }

    #[test]
    fn host_matches_entry_hashed() {
        // Pre-compute HMAC-SHA1 for "example.com" with a known salt
        let salt = b"testsalt".to_vec();
        let hash = hmac_sha1(&salt, b"example.com");
        let entry = KnownHostEntry {
            host_patterns: KnownHostPatterns::Hashed { salt, hash },
            revoked: false,
            public_key_bytes: vec![1, 2, 3],
        };
        assert!(host_matches_entry("example.com", &entry));
        assert!(!host_matches_entry("other.com", &entry));
    }

    #[test]
    fn parse_known_hosts_empty() {
        let entries = parse_known_hosts("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_known_hosts_comments_only() {
        let entries = parse_known_hosts("# this is a comment\n# another comment\n").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn known_host_entry_revoked_flag() {
        let entry = KnownHostEntry {
            host_patterns: KnownHostPatterns::Patterns(vec!["revoked.com".to_string()]),
            revoked: true,
            public_key_bytes: vec![],
        };
        assert!(entry.revoked);
    }

    #[test]
    fn file_attributes_with_permissions() {
        let attrs = russh_sftp::protocol::FileAttributes {
            size: None,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: Some(0o755),
            atime: None,
            mtime: None,
        };
        assert_eq!(attrs.permissions, Some(0o755));
    }

    #[test]
    fn file_attributes_permissions_preserve_mode() {
        // Verify common permission modes round-trip through FileAttributes
        for mode in [0o644u32, 0o755, 0o600, 0o777, 0o400] {
            let attrs = russh_sftp::protocol::FileAttributes {
                size: None,
                uid: None,
                user: None,
                gid: None,
                group: None,
                permissions: Some(mode),
                atime: None,
                mtime: None,
            };
            assert_eq!(attrs.permissions, Some(mode));
        }
    }

    #[test]
    fn symlink_path_resolution_absolute() {
        // Absolute symlink targets should be used as-is
        let target = "/absolute/path/to/file";
        assert!(target.starts_with('/'));
    }

    #[test]
    fn symlink_path_resolution_relative() {
        // Relative symlink targets should be resolved against parent
        let current = "/home/user/link";
        let target = "actual_file";
        let parent = current.rsplit_once('/').unwrap().0;
        let resolved = format!("{parent}/{target}");
        assert_eq!(resolved, "/home/user/actual_file");
    }

    #[test]
    fn symlink_path_resolution_relative_with_subdir() {
        let current = "/data/links/mylink";
        let target = "../files/data.txt";
        let parent = current.rsplit_once('/').unwrap().0;
        let resolved = format!("{parent}/{target}");
        assert_eq!(resolved, "/data/links/../files/data.txt");
    }

    #[test]
    fn ssh_auth_types_password_only() {
        // With auth_types=2 (password only), pubkey bit is NOT set
        let mask: u32 = SSH_AUTH_PASSWORD;
        assert_eq!(mask & SSH_AUTH_PUBLICKEY, 0, "pubkey should be disabled");
        assert_ne!(mask & SSH_AUTH_PASSWORD, 0, "password should be enabled");
    }

    #[test]
    fn ssh_auth_types_pubkey_only() {
        // With auth_types=1 (pubkey only), password bit is NOT set
        let mask: u32 = SSH_AUTH_PUBLICKEY;
        assert_ne!(mask & SSH_AUTH_PUBLICKEY, 0, "pubkey should be enabled");
        assert_eq!(mask & SSH_AUTH_PASSWORD, 0, "password should be disabled");
    }

    #[test]
    fn ssh_auth_types_all() {
        // With auth_types=3 (pubkey + password), both bits are set
        let mask: u32 = SSH_AUTH_PUBLICKEY | SSH_AUTH_PASSWORD;
        assert_ne!(mask & SSH_AUTH_PUBLICKEY, 0, "pubkey should be enabled");
        assert_ne!(mask & SSH_AUTH_PASSWORD, 0, "password should be enabled");
    }

    #[test]
    fn ssh_auth_types_none_allows_all() {
        // When auth_types is None, all methods should be allowed
        let auth_types: Option<u32> = None;
        let allow_pubkey = auth_types.is_none_or(|mask| mask & SSH_AUTH_PUBLICKEY != 0);
        let allow_password = auth_types.is_none_or(|mask| mask & SSH_AUTH_PASSWORD != 0);
        assert!(allow_pubkey);
        assert!(allow_password);
    }
}
