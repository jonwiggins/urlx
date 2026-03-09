//! FTP protocol handler.
//!
//! Implements the File Transfer Protocol (RFC 959) for downloading and
//! uploading files, directory listing, and file management.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::io::{ReadHalf, WriteHalf};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// An FTP response from the server.
#[derive(Debug, Clone)]
pub struct FtpResponse {
    /// The 3-digit status code.
    pub code: u16,
    /// The response text (may be multi-line).
    pub message: String,
}

impl FtpResponse {
    /// Check if this is a positive preliminary response (1xx).
    #[must_use]
    pub const fn is_preliminary(&self) -> bool {
        self.code >= 100 && self.code < 200
    }

    /// Check if this is a positive completion response (2xx).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// Check if this is a positive intermediate response (3xx).
    #[must_use]
    pub const fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

/// Transfer mode for FTP data connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// ASCII text mode (TYPE A).
    Ascii,
    /// Binary/image mode (TYPE I).
    Binary,
}

/// Server capabilities discovered via FEAT.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct FtpFeatures {
    /// Whether the server supports EPSV (Extended Passive Mode).
    pub epsv: bool,
    /// Whether the server supports MLST/MLSD (RFC 3659).
    pub mlst: bool,
    /// Whether the server supports REST STREAM (resume).
    pub rest_stream: bool,
    /// Whether the server supports SIZE.
    pub size: bool,
    /// Whether the server supports UTF8.
    pub utf8: bool,
    /// Raw feature list.
    pub raw: Vec<String>,
}

/// An active FTP session with an established control connection.
///
/// Handles login, passive mode, and data transfer operations.
pub struct FtpSession {
    reader: BufReader<ReadHalf<tokio::net::TcpStream>>,
    writer: WriteHalf<tokio::net::TcpStream>,
    features: Option<FtpFeatures>,
}

impl FtpSession {
    /// Connect to an FTP server and log in.
    ///
    /// # Errors
    ///
    /// Returns an error if connection, login, or greeting fails.
    pub async fn connect(host: &str, port: u16, user: &str, pass: &str) -> Result<Self, Error> {
        let addr = format!("{host}:{port}");
        let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
        let (reader, writer) = tokio::io::split(tcp);
        let mut reader = BufReader::new(reader);

        // Read server greeting
        let greeting = read_response(&mut reader).await?;
        if !greeting.is_complete() {
            return Err(Error::Http(format!(
                "FTP server rejected connection: {} {}",
                greeting.code, greeting.message
            )));
        }

        let mut session = Self { reader, writer, features: None };

        // Login
        session.login(user, pass).await?;

        Ok(session)
    }

    /// Login with USER/PASS sequence.
    async fn login(&mut self, user: &str, pass: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("USER {user}")).await?;
        let user_resp = read_response(&mut self.reader).await?;

        if user_resp.is_intermediate() {
            send_command(&mut self.writer, &format!("PASS {pass}")).await?;
            let pass_resp = read_response(&mut self.reader).await?;
            if !pass_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP login failed: {} {}",
                    pass_resp.code, pass_resp.message
                )));
            }
        } else if !user_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP USER rejected: {} {}",
                user_resp.code, user_resp.message
            )));
        }

        Ok(())
    }

    /// Send FEAT command and parse server capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error on communication failure. If the server doesn't
    /// support FEAT, returns default (empty) features without error.
    pub async fn feat(&mut self) -> Result<&FtpFeatures, Error> {
        send_command(&mut self.writer, "FEAT").await?;
        let resp = read_response(&mut self.reader).await?;

        let features = if resp.is_complete() {
            parse_feat_response(&resp.message)
        } else {
            // If FEAT returns 5xx (not supported), use empty defaults
            FtpFeatures::default()
        };

        self.features = Some(features);
        // features was just inserted, so get_or_insert_with won't allocate
        Ok(self.features.get_or_insert_with(FtpFeatures::default))
    }

    /// Set the transfer type (ASCII or Binary).
    ///
    /// # Errors
    ///
    /// Returns an error if the TYPE command fails.
    pub async fn set_type(&mut self, transfer_type: TransferType) -> Result<(), Error> {
        let type_cmd = match transfer_type {
            TransferType::Ascii => "TYPE A",
            TransferType::Binary => "TYPE I",
        };
        send_command(&mut self.writer, type_cmd).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP TYPE failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Enter passive mode and open a data connection.
    ///
    /// # Errors
    ///
    /// Returns an error if PASV fails or data connection cannot be established.
    async fn open_data_connection(&mut self) -> Result<tokio::net::TcpStream, Error> {
        send_command(&mut self.writer, "PASV").await?;
        let pasv_resp = read_response(&mut self.reader).await?;
        if pasv_resp.code != 227 {
            return Err(Error::Http(format!(
                "FTP PASV failed: {} {}",
                pasv_resp.code, pasv_resp.message
            )));
        }
        let (data_host, data_port) = parse_pasv_response(&pasv_resp.message)?;
        let data_addr = format!("{data_host}:{data_port}");
        let data_stream = tokio::net::TcpStream::connect(&data_addr)
            .await
            .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;
        Ok(data_stream)
    }

    /// Download a file from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn download(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("RETR {path}")).await?;
        let retr_resp = read_response(&mut self.reader).await?;
        if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RETR failed: {} {}",
                retr_resp.code, retr_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Download a file with resume from a byte offset (REST + RETR).
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support REST or the transfer fails.
    pub async fn download_resume(&mut self, path: &str, offset: u64) -> Result<Vec<u8>, Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        // Send REST to set the starting offset
        send_command(&mut self.writer, &format!("REST {offset}")).await?;
        let rest_resp = read_response(&mut self.reader).await?;
        if !rest_resp.is_intermediate() {
            return Err(Error::Http(format!(
                "FTP REST failed: {} {}",
                rest_resp.code, rest_resp.message
            )));
        }

        send_command(&mut self.writer, &format!("RETR {path}")).await?;
        let retr_resp = read_response(&mut self.reader).await?;
        if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RETR failed: {} {}",
                retr_resp.code, retr_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Upload a file to the server (STOR).
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn upload(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("STOR {path}")).await?;
        let stor_resp = read_response(&mut self.reader).await?;
        if !stor_resp.is_preliminary() && !stor_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP STOR failed: {} {}",
                stor_resp.code, stor_resp.message
            )));
        }

        data_stream
            .write_all(data)
            .await
            .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        data_stream
            .shutdown()
            .await
            .map_err(|e| Error::Http(format!("FTP data shutdown error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP upload failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(())
    }

    /// Append data to a file on the server (APPE).
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn append(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("APPE {path}")).await?;
        let appe_resp = read_response(&mut self.reader).await?;
        if !appe_resp.is_preliminary() && !appe_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP APPE failed: {} {}",
                appe_resp.code, appe_resp.message
            )));
        }

        data_stream
            .write_all(data)
            .await
            .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        data_stream
            .shutdown()
            .await
            .map_err(|e| Error::Http(format!("FTP data shutdown error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP append failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(())
    }

    /// List directory contents (LIST).
    ///
    /// # Errors
    ///
    /// Returns an error if the listing fails.
    pub async fn list(&mut self, path: Option<&str>) -> Result<Vec<u8>, Error> {
        if let Some(dir) = path {
            if !dir.is_empty() && dir != "/" {
                send_command(&mut self.writer, &format!("CWD {dir}")).await?;
                let cwd_resp = read_response(&mut self.reader).await?;
                if !cwd_resp.is_complete() {
                    return Err(Error::Http(format!(
                        "FTP CWD failed: {} {}",
                        cwd_resp.code, cwd_resp.message
                    )));
                }
            }
        }

        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, "LIST").await?;
        let list_resp = read_response(&mut self.reader).await?;
        if !list_resp.is_preliminary() && !list_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP LIST failed: {} {}",
                list_resp.code, list_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Machine-readable listing (MLSD, RFC 3659).
    ///
    /// # Errors
    ///
    /// Returns an error if MLSD is not supported or fails.
    pub async fn mlsd(&mut self, path: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut data_stream = self.open_data_connection().await?;

        let cmd = path.map_or_else(|| "MLSD".to_string(), |p| format!("MLSD {p}"));
        send_command(&mut self.writer, &cmd).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_preliminary() && !resp.is_complete() {
            return Err(Error::Http(format!("FTP MLSD failed: {} {}", resp.code, resp.message)));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP MLSD transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Get file size (SIZE command).
    ///
    /// # Errors
    ///
    /// Returns an error if SIZE is not supported or fails.
    pub async fn size(&mut self, path: &str) -> Result<u64, Error> {
        send_command(&mut self.writer, &format!("SIZE {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP SIZE failed: {} {}", resp.code, resp.message)));
        }
        resp.message
            .trim()
            .parse::<u64>()
            .map_err(|e| Error::Http(format!("FTP SIZE parse error: {e}")))
    }

    /// Create a directory (MKD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub async fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("MKD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP MKD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Remove a directory (RMD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be removed.
    pub async fn rmdir(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("RMD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP RMD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Delete a file (DELE).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be deleted.
    pub async fn delete(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("DELE {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP DELE failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Rename a file or directory (RNFR + RNTO).
    ///
    /// # Errors
    ///
    /// Returns an error if the rename fails.
    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("RNFR {from}")).await?;
        let rnfr_resp = read_response(&mut self.reader).await?;
        if !rnfr_resp.is_intermediate() {
            return Err(Error::Http(format!(
                "FTP RNFR failed: {} {}",
                rnfr_resp.code, rnfr_resp.message
            )));
        }

        send_command(&mut self.writer, &format!("RNTO {to}")).await?;
        let rnto_resp = read_response(&mut self.reader).await?;
        if !rnto_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RNTO failed: {} {}",
                rnto_resp.code, rnto_resp.message
            )));
        }
        Ok(())
    }

    /// Send a SITE command.
    ///
    /// # Errors
    ///
    /// Returns an error if the SITE command fails.
    pub async fn site(&mut self, command: &str) -> Result<FtpResponse, Error> {
        send_command(&mut self.writer, &format!("SITE {command}")).await?;
        read_response(&mut self.reader).await
    }

    /// Print the current working directory (PWD).
    ///
    /// # Errors
    ///
    /// Returns an error if the PWD command fails.
    pub async fn pwd(&mut self) -> Result<String, Error> {
        send_command(&mut self.writer, "PWD").await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP PWD failed: {} {}", resp.code, resp.message)));
        }
        // PWD returns: 257 "/current/dir"
        // Extract the path from between quotes
        if let Some(start) = resp.message.find('"') {
            if let Some(end) = resp.message[start + 1..].find('"') {
                return Ok(resp.message[start + 1..start + 1 + end].to_string());
            }
        }
        Ok(resp.message)
    }

    /// Change working directory (CWD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory change fails.
    pub async fn cwd(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("CWD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP CWD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Close the FTP session (QUIT).
    ///
    /// # Errors
    ///
    /// Returns an error if sending the QUIT command fails.
    pub async fn quit(mut self) -> Result<(), Error> {
        send_command(&mut self.writer, "QUIT").await?;
        // Don't wait for QUIT response — some servers are slow
        Ok(())
    }
}

/// Read an FTP response (potentially multi-line) from the control connection.
///
/// Multi-line responses start with `code-` and end with `code ` (space).
///
/// # Errors
///
/// Returns an error if the response is malformed or the connection drops.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<FtpResponse, Error> {
    let mut full_message = String::new();
    let mut final_code: Option<u16> = None;

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("FTP read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("FTP connection closed unexpectedly".to_string()));
        }

        let line = line.trim_end_matches('\n').trim_end_matches('\r');

        if line.len() < 4 {
            // Lines shorter than "NNN " aren't valid FTP responses
            full_message.push_str(line);
            full_message.push('\n');
            continue;
        }

        let code_str = &line[..3];
        let separator = line.as_bytes().get(3).copied();

        if let Ok(code) = code_str.parse::<u16>() {
            match separator {
                Some(b' ') => {
                    // Final line of response
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    final_code = Some(code);
                    break;
                }
                Some(b'-') => {
                    // Multi-line response continues
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    full_message.push('\n');
                    if final_code.is_none() {
                        final_code = Some(code);
                    }
                }
                _ => {
                    // Not a code line, just accumulate
                    full_message.push_str(line);
                    full_message.push('\n');
                }
            }
        } else {
            // Not a code line, just accumulate
            full_message.push_str(line);
            full_message.push('\n');
        }
    }

    let code =
        final_code.ok_or_else(|| Error::Http("FTP response has no status code".to_string()))?;

    Ok(FtpResponse { code, message: full_message })
}

/// Send an FTP command on the control connection.
///
/// # Errors
///
/// Returns an error if the write fails.
pub async fn send_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    command: &str,
) -> Result<(), Error> {
    let cmd = format!("{command}\r\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("FTP write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("FTP flush error: {e}")))?;
    Ok(())
}

/// Parse PASV response to extract IP and port.
///
/// PASV response format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
///
/// # Errors
///
/// Returns an error if the response cannot be parsed.
pub fn parse_pasv_response(message: &str) -> Result<(String, u16), Error> {
    // Find the parenthesized address
    let start = message
        .find('(')
        .ok_or_else(|| Error::Http("PASV response missing address".to_string()))?;
    let end = message
        .find(')')
        .ok_or_else(|| Error::Http("PASV response missing closing paren".to_string()))?;

    let nums: Vec<u16> =
        message[start + 1..end].split(',').filter_map(|s| s.trim().parse().ok()).collect();

    if nums.len() != 6 {
        return Err(Error::Http(format!("PASV response has {} numbers, expected 6", nums.len())));
    }

    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = nums[4] * 256 + nums[5];

    Ok((host, port))
}

/// Parse EPSV response to extract port.
///
/// EPSV response format: `229 Entering Extended Passive Mode (|||port|)`
///
/// # Errors
///
/// Returns an error if the response cannot be parsed.
pub fn parse_epsv_response(message: &str) -> Result<u16, Error> {
    // Find the port between ||| and |
    let start = message
        .find("|||")
        .ok_or_else(|| Error::Http("EPSV response missing port delimiter".to_string()))?;
    let rest = &message[start + 3..];
    let end = rest
        .find('|')
        .ok_or_else(|| Error::Http("EPSV response missing closing delimiter".to_string()))?;

    rest[..end].parse::<u16>().map_err(|e| Error::Http(format!("EPSV port parse error: {e}")))
}

/// Parse FEAT response into feature list.
///
/// # Errors
///
/// Returns an error if parsing fails.
#[must_use]
pub fn parse_feat_response(message: &str) -> FtpFeatures {
    let mut features = FtpFeatures::default();
    for line in message.lines() {
        let feature = line.trim().to_uppercase();
        if feature.starts_with("EPSV") {
            features.epsv = true;
        } else if feature.starts_with("MLST") {
            features.mlst = true;
        } else if feature.starts_with("REST") && feature.contains("STREAM") {
            features.rest_stream = true;
        } else if feature.starts_with("SIZE") {
            features.size = true;
        } else if feature.starts_with("UTF8") {
            features.utf8 = true;
        }
        if !feature.is_empty() {
            features.raw.push(line.trim().to_string());
        }
    }
    features
}

/// Perform an FTP download and return the file contents as a Response.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or the file cannot be retrieved.
#[allow(clippy::too_many_lines)]
pub async fn download(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = FtpSession::connect(&host, port, user, pass).await?;
    let data = session.download(path).await?;
    let _ = session.quit().await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Perform an FTP directory listing and return it as a Response.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or listing fails.
#[allow(clippy::too_many_lines)]
pub async fn list(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = FtpSession::connect(&host, port, user, pass).await?;
    let path_opt = if path.is_empty() || path == "/" { None } else { Some(path) };
    let data = session.list(path_opt).await?;
    let _ = session.quit().await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Perform an FTP upload.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or the upload fails.
pub async fn upload(url: &crate::url::Url, data: &[u8]) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = FtpSession::connect(&host, port, user, pass).await?;
    session.upload(path, data).await?;
    let _ = session.quit().await;

    let headers = std::collections::HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_simple_response() {
        let data = b"220 Welcome to FTP\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.message, "Welcome to FTP");
    }

    #[tokio::test]
    async fn read_multiline_response() {
        let data = b"220-Welcome\r\n220-to the\r\n220 FTP server\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 220);
        assert!(resp.message.contains("Welcome"));
        assert!(resp.message.contains("FTP server"));
    }

    #[tokio::test]
    async fn read_response_connection_closed() {
        let data = b"";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let result = read_response(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn parse_pasv_simple() {
        let msg = "Entering Passive Mode (192,168,1,1,4,1)";
        let (host, port) = parse_pasv_response(msg).unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 1025); // 4*256 + 1
    }

    #[test]
    fn parse_pasv_high_port() {
        let msg = "Entering Passive Mode (127,0,0,1,200,100)";
        let (host, port) = parse_pasv_response(msg).unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 51300); // 200*256 + 100
    }

    #[test]
    fn parse_epsv_simple() {
        let msg = "Entering Extended Passive Mode (|||12345|)";
        let port = parse_epsv_response(msg).unwrap();
        assert_eq!(port, 12345);
    }

    #[test]
    fn ftp_response_status_categories() {
        let preliminary = FtpResponse { code: 150, message: String::new() };
        assert!(preliminary.is_preliminary());
        assert!(!preliminary.is_complete());

        let complete = FtpResponse { code: 226, message: String::new() };
        assert!(complete.is_complete());
        assert!(!complete.is_intermediate());

        let intermediate = FtpResponse { code: 331, message: String::new() };
        assert!(intermediate.is_intermediate());
        assert!(!intermediate.is_complete());
    }

    #[test]
    fn parse_feat_response_full() {
        let message =
            "Extensions supported:\n EPSV\n MLST size*;modify*;type*\n REST STREAM\n SIZE\n UTF8";
        let features = parse_feat_response(message);
        assert!(features.epsv);
        assert!(features.mlst);
        assert!(features.rest_stream);
        assert!(features.size);
        assert!(features.utf8);
    }

    #[test]
    fn parse_feat_response_minimal() {
        let message = "SIZE\nREST STREAM";
        let features = parse_feat_response(message);
        assert!(features.size);
        assert!(features.rest_stream);
        assert!(!features.epsv);
        assert!(!features.mlst);
    }

    #[test]
    fn parse_feat_response_empty() {
        let features = parse_feat_response("");
        assert!(!features.epsv);
        assert!(!features.mlst);
        assert!(!features.rest_stream);
        assert!(!features.size);
        assert!(!features.utf8);
        assert!(features.raw.is_empty());
    }

    #[test]
    fn transfer_type_equality() {
        assert_eq!(TransferType::Ascii, TransferType::Ascii);
        assert_eq!(TransferType::Binary, TransferType::Binary);
        assert_ne!(TransferType::Ascii, TransferType::Binary);
    }

    #[test]
    fn ftp_features_default() {
        let features = FtpFeatures::default();
        assert!(!features.epsv);
        assert!(!features.mlst);
        assert!(!features.rest_stream);
        assert!(!features.size);
        assert!(!features.utf8);
        assert!(features.raw.is_empty());
    }
}
