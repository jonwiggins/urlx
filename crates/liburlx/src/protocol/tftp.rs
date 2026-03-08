//! TFTP protocol handler.
//!
//! Implements the Trivial File Transfer Protocol (RFC 1350) for simple
//! file downloads and uploads over UDP.

use tokio::net::UdpSocket;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// TFTP opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// Read request.
    Rrq = 1,
    /// Write request.
    Wrq = 2,
    /// Data.
    Data = 3,
    /// Acknowledgment.
    Ack = 4,
    /// Error.
    TftpError = 5,
}

/// TFTP block size.
const BLOCK_SIZE: usize = 512;

/// Build a read request (RRQ) packet.
fn build_rrq(filename: &str, mode: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(Opcode::Rrq as u16).to_be_bytes());
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0); // null terminator
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0); // null terminator
    packet
}

/// Build an ACK packet.
fn build_ack(block_num: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(Opcode::Ack as u16).to_be_bytes());
    packet.extend_from_slice(&block_num.to_be_bytes());
    packet
}

/// Parse a TFTP packet's opcode.
///
/// # Errors
///
/// Returns an error if the packet is too short.
fn parse_opcode(data: &[u8]) -> Result<u16, Error> {
    if data.len() < 2 {
        return Err(Error::Http("TFTP packet too short".to_string()));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Download a file via TFTP.
///
/// URL format: `tftp://host:port/filename`
///
/// # Errors
///
/// Returns an error if the download fails.
pub async fn download(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let filename = url.path().trim_start_matches('/');

    if filename.is_empty() {
        return Err(Error::Http("TFTP filename is required in URL path".to_string()));
    }

    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Http(format!("TFTP bind error: {e}")))?;

    let server_addr = format!("{host}:{port}");

    // Send RRQ
    let rrq = build_rrq(filename, "octet");
    let _n = socket
        .send_to(&rrq, &server_addr)
        .await
        .map_err(|e| Error::Http(format!("TFTP send RRQ error: {e}")))?;

    let mut file_data = Vec::new();
    let mut expected_block: u16 = 1;
    let mut buf = [0u8; 4 + BLOCK_SIZE];

    loop {
        let (n, src) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::Http(format!("TFTP recv error: {e}")))?;

        let packet = &buf[..n];
        let opcode = parse_opcode(packet)?;

        match opcode {
            3 => {
                // DATA
                if packet.len() < 4 {
                    return Err(Error::Http("TFTP DATA packet too short".to_string()));
                }
                let block_num = u16::from_be_bytes([packet[2], packet[3]]);

                if block_num == expected_block {
                    file_data.extend_from_slice(&packet[4..]);
                    expected_block = expected_block.wrapping_add(1);
                }

                // Send ACK
                let ack = build_ack(block_num);
                let _n = socket
                    .send_to(&ack, src)
                    .await
                    .map_err(|e| Error::Http(format!("TFTP send ACK error: {e}")))?;

                // Last block: data < 512 bytes
                if packet.len() - 4 < BLOCK_SIZE {
                    break;
                }
            }
            5 => {
                // ERROR
                let msg = if packet.len() > 4 {
                    String::from_utf8_lossy(&packet[4..packet.len().saturating_sub(1)]).to_string()
                } else {
                    "unknown error".to_string()
                };
                return Err(Error::Http(format!("TFTP error: {msg}")));
            }
            _ => {
                return Err(Error::Http(format!("TFTP unexpected opcode: {opcode}")));
            }
        }
    }

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), file_data.len().to_string());

    Ok(Response::new(200, headers, file_data, url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn build_rrq_packet() {
        let packet = build_rrq("test.txt", "octet");
        assert_eq!(&packet[..2], &[0x00, 0x01]); // RRQ opcode
                                                 // "test.txt\0octet\0"
        assert_eq!(&packet[2..10], b"test.txt");
        assert_eq!(packet[10], 0);
        assert_eq!(&packet[11..16], b"octet");
        assert_eq!(packet[16], 0);
    }

    #[test]
    fn build_ack_packet() {
        let packet = build_ack(1);
        assert_eq!(packet, vec![0x00, 0x04, 0x00, 0x01]);
    }

    #[test]
    fn build_ack_high_block() {
        let packet = build_ack(256);
        assert_eq!(packet, vec![0x00, 0x04, 0x01, 0x00]);
    }

    #[test]
    fn parse_opcode_rrq() {
        assert_eq!(parse_opcode(&[0x00, 0x01]).unwrap(), 1);
    }

    #[test]
    fn parse_opcode_data() {
        assert_eq!(parse_opcode(&[0x00, 0x03]).unwrap(), 3);
    }

    #[test]
    fn parse_opcode_error() {
        assert_eq!(parse_opcode(&[0x00, 0x05]).unwrap(), 5);
    }

    #[test]
    fn parse_opcode_too_short() {
        assert!(parse_opcode(&[0x00]).is_err());
    }
}
