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

/// Default TFTP block size.
const DEFAULT_BLOCK_SIZE: usize = 512;

/// Maximum TFTP block size (RFC 2348).
const MAX_BLOCK_SIZE: usize = 65464;

/// OACK opcode (RFC 2347).
const OACK_OPCODE: u16 = 6;

/// Build a read request (RRQ) packet.
fn build_rrq(filename: &str, mode: &str, blksize: Option<u16>) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(Opcode::Rrq as u16).to_be_bytes());
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0); // null terminator
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    // RFC 2348: blksize option negotiation
    if let Some(bs) = blksize {
        packet.extend_from_slice(b"blksize");
        packet.push(0);
        packet.extend_from_slice(bs.to_string().as_bytes());
        packet.push(0);
    }
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
/// `blksize` sets the TFTP block size option (RFC 2348). If `None`, default 512 is used.
/// `no_options` disables OACK option negotiation (RFC 2347).
///
/// # Errors
///
/// Returns an error if the download fails.
pub async fn download(
    url: &crate::url::Url,
    blksize: Option<u16>,
    no_options: bool,
) -> Result<Response, Error> {
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

    // Only negotiate blksize if options are allowed
    let negotiate_blksize = if no_options { None } else { blksize };

    // Send RRQ
    let rrq = build_rrq(filename, "octet", negotiate_blksize);
    let _n = socket
        .send_to(&rrq, &server_addr)
        .await
        .map_err(|e| Error::Http(format!("TFTP send RRQ error: {e}")))?;

    // Effective block size — may be updated by OACK
    let mut effective_blksize = DEFAULT_BLOCK_SIZE;
    let mut file_data = Vec::new();
    let mut expected_block: u16 = 1;
    let mut buf = vec![0u8; 4 + MAX_BLOCK_SIZE];

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

                // Last block: data < block_size bytes
                if packet.len() - 4 < effective_blksize {
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
            o if o == OACK_OPCODE => {
                // OACK — parse negotiated options
                let options_data = &packet[2..];
                let mut parts = options_data.split(|&b| b == 0).filter(|s| !s.is_empty());
                while let Some(key) = parts.next() {
                    if let Some(val) = parts.next() {
                        if key.eq_ignore_ascii_case(b"blksize") {
                            if let Ok(bs) = String::from_utf8_lossy(val).parse::<usize>() {
                                effective_blksize = bs;
                            }
                        }
                    }
                }
                // ACK the OACK with block 0
                let ack = build_ack(0);
                let _n = socket
                    .send_to(&ack, src)
                    .await
                    .map_err(|e| Error::Http(format!("TFTP send OACK ACK error: {e}")))?;
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
        let packet = build_rrq("test.txt", "octet", None);
        assert_eq!(&packet[..2], &[0x00, 0x01]); // RRQ opcode
                                                 // "test.txt\0octet\0"
        assert_eq!(&packet[2..10], b"test.txt");
        assert_eq!(packet[10], 0);
        assert_eq!(&packet[11..16], b"octet");
        assert_eq!(packet[16], 0);
    }

    #[test]
    fn build_rrq_with_blksize() {
        let packet = build_rrq("file.bin", "octet", Some(1024));
        assert_eq!(&packet[..2], &[0x00, 0x01]);
        // After filename\0mode\0, we have blksize\01024\0
        let rest = &packet[2..];
        assert!(rest.windows(7).any(|w| w == b"blksize"));
        assert!(rest.windows(4).any(|w| w == b"1024"));
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
