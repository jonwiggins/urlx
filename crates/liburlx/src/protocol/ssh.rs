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
        if let Some(bracket_end) = pattern.find(']') {
            &pattern[1..bracket_end]
        } else {
            pattern
        }
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
                    Err(Error::Ssh(format!(
                        "SSH host key fingerprint mismatch: expected SHA256:{expected}, got SHA256:{actual}"
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
                            return Err(Error::Ssh(format!(
                                "SSH host key for '{}' is revoked in known_hosts",
                                self.hostname
                            )));
                        }
                        if entry.public_key_bytes == server_key_bytes {
                            return Ok(true);
                        }
                        // Key mismatch — potential MITM
                        return Err(Error::Ssh(format!(
                            "SSH host key for '{}' does not match known_hosts (possible MITM attack)",
                            self.hostname
                        )));
                    }
                }
                // Host not found in known_hosts — reject
                Err(Error::Ssh(format!(
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
        let config = Arc::new(russh::client::Config::default());
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
        let config = Arc::new(russh::client::Config::default());
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

    /// Download a file via SFTP.
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

        let data = sftp
            .read(path)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP read '{path}' failed: {e}")))?;

        Ok(data)
    }

    /// Upload a file via SFTP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or file write fails.
    pub async fn sftp_upload(&self, path: &str, data: &[u8]) -> Result<(), Error> {
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

        sftp.write(path, data)
            .await
            .map_err(|e| Error::Ssh(format!("SFTP write '{path}' failed: {e}")))?;

        Ok(())
    }

    /// List a directory via SFTP.
    ///
    /// Returns the listing as UTF-8 text with one entry per line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ssh`] if the SFTP session or directory read fails.
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

        let mut listing = String::new();
        for entry in entries {
            listing.push_str(&entry.file_name());
            listing.push('\n');
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
            .map_err(|e| Error::Ssh(format!("failed to open SSH channel: {e}")))?;

        // Execute scp in sink (upload) mode
        channel
            .exec(true, format!("scp -t {path}"))
            .await
            .map_err(|e| Error::Ssh(format!("failed to exec scp: {e}")))?;

        // Wait for initial \0 acknowledgement from server
        wait_for_scp_ack(&mut channel).await?;

        // Extract filename from path
        let filename = path.rsplit('/').next().unwrap_or(path);

        // Send SCP header: "C0644 <size> <filename>\n"
        let header = format!("C0644 {} {filename}\n", data.len());
        channel
            .data(header.as_bytes())
            .await
            .map_err(|e| Error::Ssh(format!("scp header write failed: {e}")))?;

        // Wait for acknowledgement
        wait_for_scp_ack(&mut channel).await?;

        // Send file data
        channel.data(data).await.map_err(|e| Error::Ssh(format!("scp data write failed: {e}")))?;

        // Send trailing null byte
        channel
            .data(&b"\0"[..])
            .await
            .map_err(|e| Error::Ssh(format!("scp trailing null write failed: {e}")))?;

        // Wait for final acknowledgement
        wait_for_scp_ack(&mut channel).await?;

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

/// Download a file via SFTP and return it as a Response.
///
/// # Errors
///
/// Returns an error if connection, authentication, or file transfer fails.
pub async fn download(
    url: &crate::url::Url,
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(&host, port, user, pass, ssh_key_path, policy).await?;

    let data = if url.scheme() == "scp" {
        session.scp_download(path).await?
    } else {
        session.sftp_download(path).await?
    };
    let _ = session.close().await;

    let mut headers = HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Upload a file via SFTP and return a Response.
///
/// # Errors
///
/// Returns an error if connection, authentication, or file transfer fails.
pub async fn upload(
    url: &crate::url::Url,
    data: &[u8],
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(&host, port, user, pass, ssh_key_path, policy).await?;

    if url.scheme() == "scp" {
        session.scp_upload(path, data).await?;
    } else {
        session.sftp_upload(path, data).await?;
    }
    let _ = session.close().await;

    let headers = HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

/// Connect to an SSH server, choosing auth method based on available credentials.
async fn connect_session(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    ssh_key_path: Option<&str>,
    policy: &SshHostKeyPolicy,
) -> Result<SshSession, Error> {
    let effective_user = if user.is_empty() { "root" } else { user };

    if let Some(key_path) = ssh_key_path {
        SshSession::connect_with_key(host, port, effective_user, key_path, policy.clone()).await
    } else if !pass.is_empty() {
        SshSession::connect(host, port, effective_user, pass, policy.clone()).await
    } else {
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
        Err(Error::Ssh(
            "no SSH credentials provided: use URL credentials, --key, or have keys in ~/.ssh/"
                .to_string(),
        ))
    }
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
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_hash_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1_hash(b"abc");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_sha1_rfc2202_test1() {
        // HMAC-SHA1 test vector from RFC 2202:
        // key = 0x0b repeated 20 times, data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
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
}
