//! SOCKS4/SOCKS5 proxy protocol implementation.
//!
//! Implements the SOCKS4 (RFC 1928) and SOCKS5 proxy handshakes for
//! tunneling TCP connections through a SOCKS proxy.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Error;

/// Create a SOCKS proxy error (maps to `CURLE_PROXY`, exit code 97).
const fn proxy_err(msg: String) -> Error {
    Error::Transfer { code: 97, message: msg }
}

/// Connect to a target host through a SOCKS5 proxy.
///
/// Performs the SOCKS5 handshake with optional username/password authentication,
/// then requests a connection to the target host and port.
///
/// # Errors
///
/// Returns an error if the handshake fails, authentication is rejected,
/// or the connection request is denied.
#[allow(clippy::too_many_lines)]
pub async fn connect_socks5(
    mut proxy_stream: TcpStream,
    target_host: &str,
    target_port: u16,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream, Error> {
    // Step 1: Send greeting with supported auth methods
    let methods = if auth.is_some() {
        vec![0x05, 0x02, 0x00, 0x02] // version, 2 methods: no-auth + user/pass
    } else {
        vec![0x05, 0x01, 0x00] // version, 1 method: no-auth
    };

    proxy_stream
        .write_all(&methods)
        .await
        .map_err(|e| proxy_err(format!("SOCKS5 greeting write error: {e}")))?;

    // Step 2: Read server's chosen method
    let mut response = [0u8; 2];
    let _n = proxy_stream
        .read_exact(&mut response)
        .await
        .map_err(|e| proxy_err(format!("SOCKS5 greeting read error: {e}")))?;

    if response[0] != 0x05 {
        return Err(proxy_err(format!("SOCKS5 unexpected version: {:#x}", response[0])));
    }

    match response[1] {
        0x00 => {
            // No authentication required
        }
        0x02 => {
            // Username/password authentication (RFC 1929)
            let (user, pass) = auth.ok_or_else(|| {
                proxy_err("SOCKS5 server requires auth but none provided".to_string())
            })?;

            let mut auth_request = Vec::new();
            auth_request.push(0x01); // auth version

            #[allow(clippy::cast_possible_truncation)]
            {
                auth_request.push(user.len() as u8);
            }
            auth_request.extend_from_slice(user.as_bytes());

            #[allow(clippy::cast_possible_truncation)]
            {
                auth_request.push(pass.len() as u8);
            }
            auth_request.extend_from_slice(pass.as_bytes());

            proxy_stream
                .write_all(&auth_request)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 auth write error: {e}")))?;

            let mut auth_response = [0u8; 2];
            let _n = proxy_stream
                .read_exact(&mut auth_response)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 auth read error: {e}")))?;

            if auth_response[1] != 0x00 {
                return Err(proxy_err("SOCKS5 authentication failed".to_string()));
            }
        }
        0xFF => {
            return Err(proxy_err("SOCKS5 no acceptable auth method".to_string()));
        }
        method => {
            return Err(proxy_err(format!("SOCKS5 unsupported auth method: {method:#x}")));
        }
    }

    // Step 3: Send connection request
    // 0x05 = SOCKS5, 0x01 = CONNECT, 0x00 = reserved, 0x03 = domain address type
    let mut connect_request = vec![0x05, 0x01, 0x00, 0x03];
    #[allow(clippy::cast_possible_truncation)]
    {
        connect_request.push(target_host.len() as u8);
    }
    connect_request.extend_from_slice(target_host.as_bytes());
    connect_request.extend_from_slice(&target_port.to_be_bytes());

    proxy_stream
        .write_all(&connect_request)
        .await
        .map_err(|e| proxy_err(format!("SOCKS5 connect write error: {e}")))?;

    // Step 4: Read connection response
    let mut connect_response = [0u8; 4];
    let _n = proxy_stream
        .read_exact(&mut connect_response)
        .await
        .map_err(|e| proxy_err(format!("SOCKS5 connect read error: {e}")))?;

    if connect_response[0] != 0x05 {
        return Err(proxy_err(format!(
            "SOCKS5 unexpected version in response: {:#x}",
            connect_response[0]
        )));
    }

    if connect_response[1] != 0x00 {
        let reason = match connect_response[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(proxy_err(format!(
            "SOCKS5 connection failed: {reason} (code {:#x})",
            connect_response[1]
        )));
    }

    // Skip the bound address (we don't need it)
    match connect_response[3] {
        0x01 => {
            // IPv4 (4 bytes) + port (2 bytes)
            let mut skip = [0u8; 6];
            let _n = proxy_stream
                .read_exact(&mut skip)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 skip addr error: {e}")))?;
        }
        0x03 => {
            // Domain: 1 byte length + domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            let _n = proxy_stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 skip domain len error: {e}")))?;
            let mut skip = vec![0u8; usize::from(len_buf[0]) + 2];
            let _n = proxy_stream
                .read_exact(&mut skip)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 skip domain error: {e}")))?;
        }
        0x04 => {
            // IPv6 (16 bytes) + port (2 bytes)
            let mut skip = [0u8; 18];
            let _n = proxy_stream
                .read_exact(&mut skip)
                .await
                .map_err(|e| proxy_err(format!("SOCKS5 skip ipv6 error: {e}")))?;
        }
        addr_type => {
            return Err(proxy_err(format!("SOCKS5 unknown address type: {addr_type:#x}")));
        }
    }

    Ok(proxy_stream)
}

/// Connect to a target host through a SOCKS4 proxy.
///
/// SOCKS4 only supports IPv4 addresses, not domain names.
/// For domain name resolution, use `SOCKS4a` (by passing the hostname).
///
/// # Errors
///
/// Returns an error if the handshake fails or the connection is denied.
pub async fn connect_socks4(
    mut proxy_stream: TcpStream,
    target_host: &str,
    target_port: u16,
    user_id: &str,
) -> Result<TcpStream, Error> {
    let mut request = Vec::new();
    request.push(0x04); // SOCKS4 version
    request.push(0x01); // CONNECT command
    request.extend_from_slice(&target_port.to_be_bytes());

    // Try to parse as IPv4, otherwise use SOCKS4a
    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(user_id.as_bytes());
    } else {
        // SOCKS4a: set IP to 0.0.0.x (x != 0) and append hostname
        request.extend_from_slice(&[0, 0, 0, 1]);
        request.extend_from_slice(user_id.as_bytes());
        request.push(0x00); // null-terminate user ID
        request.extend_from_slice(target_host.as_bytes());
    }
    request.push(0x00); // null-terminate last field

    proxy_stream
        .write_all(&request)
        .await
        .map_err(|e| proxy_err(format!("SOCKS4 write error: {e}")))?;

    let mut response = [0u8; 8];
    let _n = proxy_stream
        .read_exact(&mut response)
        .await
        .map_err(|e| proxy_err(format!("SOCKS4 read error: {e}")))?;

    if response[1] != 0x5A {
        let reason = match response[1] {
            0x5B => "request rejected or failed",
            0x5C => "request failed because client is not running identd",
            0x5D => "request failed because client's identd could not confirm the user ID",
            _ => "unknown error",
        };
        return Err(proxy_err(format!(
            "SOCKS4 connection failed: {reason} (code {:#x})",
            response[1]
        )));
    }

    Ok(proxy_stream)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks5_no_auth_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read greeting
            let mut buf = [0u8; 3];
            let _n = stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0x05, 0x01, 0x00]); // v5, 1 method, no-auth

            // Send response: use no-auth
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // Read connect request
            let mut header = [0u8; 4];
            let _n = stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x05); // version
            assert_eq!(header[1], 0x01); // CONNECT
            assert_eq!(header[3], 0x03); // domain address type

            // Read domain
            let mut len_buf = [0u8; 1];
            let _n = stream.read_exact(&mut len_buf).await.unwrap();
            let mut domain = vec![0u8; usize::from(len_buf[0])];
            let _n = stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(String::from_utf8(domain).unwrap(), "example.com");

            // Read port
            let mut port_buf = [0u8; 2];
            let _n = stream.read_exact(&mut port_buf).await.unwrap();
            assert_eq!(u16::from_be_bytes(port_buf), 80);

            // Send success response (with IPv4 address 0.0.0.0:0)
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let proxy_stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let result = connect_socks5(proxy_stream, "example.com", 80, None).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_auth_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read greeting
            let mut buf = [0u8; 4];
            let _n = stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05); // version

            // Require username/password auth
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            // Read auth request
            let mut version = [0u8; 1];
            let _n = stream.read_exact(&mut version).await.unwrap();
            assert_eq!(version[0], 0x01);

            let mut user_len = [0u8; 1];
            let _n = stream.read_exact(&mut user_len).await.unwrap();
            let mut user = vec![0u8; usize::from(user_len[0])];
            let _n = stream.read_exact(&mut user).await.unwrap();
            assert_eq!(String::from_utf8(user).unwrap(), "testuser");

            let mut pass_len = [0u8; 1];
            let _n = stream.read_exact(&mut pass_len).await.unwrap();
            let mut pass = vec![0u8; usize::from(pass_len[0])];
            let _n = stream.read_exact(&mut pass).await.unwrap();
            assert_eq!(String::from_utf8(pass).unwrap(), "testpass");

            // Auth success
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            // Read connect request
            let mut header = [0u8; 4];
            let _n = stream.read_exact(&mut header).await.unwrap();

            // Read domain
            let mut len_buf = [0u8; 1];
            let _n = stream.read_exact(&mut len_buf).await.unwrap();
            let mut skip = vec![0u8; usize::from(len_buf[0]) + 2]; // domain + port
            let _n = stream.read_exact(&mut skip).await.unwrap();

            // Send success
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let proxy_stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let result =
            connect_socks5(proxy_stream, "example.com", 443, Some(("testuser", "testpass"))).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_auth_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read greeting
            let mut buf = [0u8; 4];
            let _n = stream.read_exact(&mut buf).await.unwrap();

            // Require auth
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            // Read auth
            let mut auth = vec![0u8; 32];
            let _n = stream.read(&mut auth).await.unwrap();

            // Reject auth
            stream.write_all(&[0x01, 0x01]).await.unwrap();
        });

        let proxy_stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let result = connect_socks5(proxy_stream, "example.com", 80, Some(("bad", "creds"))).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication failed"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read request
            let mut buf = vec![0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            let request = &buf[..n];

            assert_eq!(request[0], 0x04); // SOCKS4
            assert_eq!(request[1], 0x01); // CONNECT

            // Send success
            stream.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let proxy_stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let result = connect_socks4(proxy_stream, "127.0.0.1", 80, "").await;
        assert!(result.is_ok());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_connection_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut buf = vec![0u8; 64];
            let _n = stream.read(&mut buf).await.unwrap();

            // Reject connection
            stream.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let proxy_stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let result = connect_socks4(proxy_stream, "127.0.0.1", 80, "").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));

        server.await.unwrap();
    }
}
