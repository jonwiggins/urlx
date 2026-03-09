//! SSH/SFTP/SCP protocol support.
//!
//! Provides SFTP file transfer and SCP file copy over SSH connections
//! using the `russh` and `russh-sftp` crates (pure-Rust, async).
//!
//! Supports password and public key authentication.

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

/// Minimal SSH client handler.
///
/// Accepts all server host keys by default (matching curl's default behavior
/// without `--known-hosts`). A future phase can add `known_hosts` checking.
struct SshHandler;

impl russh::client::Handler for SshHandler {
    type Error = crate::error::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all server keys (matches curl default without known_hosts).
        // TODO: Add known_hosts verification in a future phase.
        Ok(true)
    }
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
    pub async fn connect(host: &str, port: u16, user: &str, pass: &str) -> Result<Self, Error> {
        let config = Arc::new(russh::client::Config::default());
        let handler = SshHandler;
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
    ) -> Result<Self, Error> {
        let config = Arc::new(russh::client::Config::default());
        let handler = SshHandler;
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
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(&host, port, user, pass, ssh_key_path).await?;

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
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (user, pass) = url.credentials().unwrap_or(("", ""));
    let path = url.path();

    let session = connect_session(&host, port, user, pass, ssh_key_path).await?;

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
) -> Result<SshSession, Error> {
    let effective_user = if user.is_empty() { "root" } else { user };

    if let Some(key_path) = ssh_key_path {
        SshSession::connect_with_key(host, port, effective_user, key_path).await
    } else if !pass.is_empty() {
        SshSession::connect(host, port, effective_user, pass).await
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
                if let Ok(session) =
                    SshSession::connect_with_key(host, port, effective_user, key_path).await
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
}
