//! FTP protocol handler.
//!
//! Implements the File Transfer Protocol (RFC 959) for downloading and
//! uploading files, directory listing, and file management.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

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

/// Perform an FTP download and return the file contents as a Response.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or the file cannot be retrieved.
#[allow(clippy::too_many_lines)]
pub async fn download(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();

    // Extract credentials from URL or use anonymous
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    // Connect to FTP server
    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    // Read server greeting
    let greeting = read_response(&mut reader).await?;
    if !greeting.is_complete() {
        return Err(Error::Http(format!(
            "FTP server rejected connection: {} {}",
            greeting.code, greeting.message
        )));
    }

    // Login
    send_command(&mut writer, &format!("USER {user}")).await?;
    let user_resp = read_response(&mut reader).await?;

    if user_resp.is_intermediate() {
        // Server wants password
        send_command(&mut writer, &format!("PASS {pass}")).await?;
        let pass_resp = read_response(&mut reader).await?;
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

    // Set binary mode
    send_command(&mut writer, "TYPE I").await?;
    let type_resp = read_response(&mut reader).await?;
    if !type_resp.is_complete() {
        return Err(Error::Http(format!(
            "FTP TYPE failed: {} {}",
            type_resp.code, type_resp.message
        )));
    }

    // Enter passive mode
    send_command(&mut writer, "PASV").await?;
    let pasv_resp = read_response(&mut reader).await?;
    if pasv_resp.code != 227 {
        return Err(Error::Http(format!(
            "FTP PASV failed: {} {}",
            pasv_resp.code, pasv_resp.message
        )));
    }
    let (data_host, data_port) = parse_pasv_response(&pasv_resp.message)?;

    // Open data connection
    let data_addr = format!("{data_host}:{data_port}");
    let mut data_stream = tokio::net::TcpStream::connect(&data_addr)
        .await
        .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;

    // Request file
    send_command(&mut writer, &format!("RETR {path}")).await?;
    let retr_resp = read_response(&mut reader).await?;
    if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
        return Err(Error::Http(format!(
            "FTP RETR failed: {} {}",
            retr_resp.code, retr_resp.message
        )));
    }

    // Read data
    let mut data = Vec::new();
    let _n = data_stream
        .read_to_end(&mut data)
        .await
        .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
    drop(data_stream);

    // Read transfer complete response
    let complete_resp = read_response(&mut reader).await?;
    if !complete_resp.is_complete() {
        return Err(Error::Http(format!(
            "FTP transfer failed: {} {}",
            complete_resp.code, complete_resp.message
        )));
    }

    // Quit
    send_command(&mut writer, "QUIT").await?;
    // Don't wait for QUIT response — some servers are slow

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

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    // Read greeting
    let greeting = read_response(&mut reader).await?;
    if !greeting.is_complete() {
        return Err(Error::Http(format!(
            "FTP server rejected: {} {}",
            greeting.code, greeting.message
        )));
    }

    // Login
    send_command(&mut writer, &format!("USER {user}")).await?;
    let user_resp = read_response(&mut reader).await?;
    if user_resp.is_intermediate() {
        send_command(&mut writer, &format!("PASS {pass}")).await?;
        let pass_resp = read_response(&mut reader).await?;
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

    // Change to directory if path specified
    if !path.is_empty() && path != "/" {
        send_command(&mut writer, &format!("CWD {path}")).await?;
        let cwd_resp = read_response(&mut reader).await?;
        if !cwd_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP CWD failed: {} {}",
                cwd_resp.code, cwd_resp.message
            )));
        }
    }

    // Enter passive mode
    send_command(&mut writer, "PASV").await?;
    let pasv_resp = read_response(&mut reader).await?;
    if pasv_resp.code != 227 {
        return Err(Error::Http(format!(
            "FTP PASV failed: {} {}",
            pasv_resp.code, pasv_resp.message
        )));
    }
    let (data_host, data_port) = parse_pasv_response(&pasv_resp.message)?;

    // Open data connection
    let data_addr = format!("{data_host}:{data_port}");
    let mut data_stream = tokio::net::TcpStream::connect(&data_addr)
        .await
        .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;

    // Request listing
    send_command(&mut writer, "LIST").await?;
    let list_resp = read_response(&mut reader).await?;
    if !list_resp.is_preliminary() && !list_resp.is_complete() {
        return Err(Error::Http(format!(
            "FTP LIST failed: {} {}",
            list_resp.code, list_resp.message
        )));
    }

    // Read listing data
    let mut data = Vec::new();
    let _n = data_stream
        .read_to_end(&mut data)
        .await
        .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
    drop(data_stream);

    // Read complete response
    let complete_resp = read_response(&mut reader).await?;
    if !complete_resp.is_complete() {
        return Err(Error::Http(format!(
            "FTP transfer failed: {} {}",
            complete_resp.code, complete_resp.message
        )));
    }

    // Quit
    send_command(&mut writer, "QUIT").await?;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
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
}
