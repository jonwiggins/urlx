//! TFTP protocol handler.
//!
//! Implements the Trivial File Transfer Protocol (RFC 1350) for simple
//! file downloads and uploads over UDP, with options negotiation
//! (RFC 2347/2348/2349).

use std::time::{Duration, Instant};

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

/// TFTP error codes (RFC 1350, Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpErrorCode {
    /// Not defined, see error message.
    NotDefined = 0,
    /// File not found.
    FileNotFound = 1,
    /// Access violation.
    AccessViolation = 2,
    /// Disk full or allocation exceeded.
    DiskFull = 3,
    /// Illegal TFTP operation.
    IllegalOperation = 4,
    /// Unknown transfer ID.
    UnknownTransferId = 5,
    /// File already exists.
    FileAlreadyExists = 6,
    /// No such user.
    NoSuchUser = 7,
}

impl TftpErrorCode {
    /// Convert a raw error code to a `TftpErrorCode`.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::FileNotFound,
            2 => Self::AccessViolation,
            3 => Self::DiskFull,
            4 => Self::IllegalOperation,
            5 => Self::UnknownTransferId,
            6 => Self::FileAlreadyExists,
            7 => Self::NoSuchUser,
            _ => Self::NotDefined,
        }
    }

    /// Human-readable description of the error code.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::NotDefined => "not defined",
            Self::FileNotFound => "file not found",
            Self::AccessViolation => "access violation",
            Self::DiskFull => "disk full or allocation exceeded",
            Self::IllegalOperation => "illegal TFTP operation",
            Self::UnknownTransferId => "unknown transfer ID",
            Self::FileAlreadyExists => "file already exists",
            Self::NoSuchUser => "no such user",
        }
    }

    /// Map TFTP error code to curl-compatible exit code.
    #[must_use]
    pub const fn to_curl_code(self) -> u32 {
        match self {
            Self::FileNotFound => 68,
            Self::AccessViolation => 69,
            Self::DiskFull => 70,
            Self::IllegalOperation | Self::NotDefined => 71,
            Self::UnknownTransferId => 72,
            Self::FileAlreadyExists | Self::NoSuchUser => 73,
        }
    }

    /// curl-compatible error message for this TFTP error code.
    #[must_use]
    pub const fn curl_message(self) -> &'static str {
        match self {
            Self::FileNotFound => "TFTP: File Not Found",
            Self::AccessViolation => "TFTP: Access Violation",
            Self::DiskFull => "TFTP: Disk full or allocation exceeded",
            Self::IllegalOperation | Self::NotDefined => "TFTP: Illegal operation",
            Self::UnknownTransferId => "TFTP: Unknown transfer ID",
            Self::FileAlreadyExists => "TFTP: File already exists",
            Self::NoSuchUser => "TFTP: No such user",
        }
    }
}

const DEFAULT_BLOCK_SIZE: usize = 512;
const MAX_BLOCK_SIZE: usize = 65464;
/// Maximum TFTP filename length.
const _MAX_TFTP_FILENAME: usize = 512;
const OACK_OPCODE: u16 = 6;
const DEFAULT_TFTP_TIMEOUT: u16 = 6;
const TFTP_RETRY_COUNT: u64 = 50;

fn build_request(
    opcode: Opcode,
    filename: &str,
    mode: &str,
    blksize: u16,
    tsize: u64,
    no_options: bool,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(opcode as u16).to_be_bytes());
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    if !no_options {
        packet.extend_from_slice(b"tsize\0");
        packet.extend_from_slice(tsize.to_string().as_bytes());
        packet.push(0);
        packet.extend_from_slice(b"blksize\0");
        packet.extend_from_slice(blksize.to_string().as_bytes());
        packet.push(0);
    }
    packet
}

fn build_ack(block_num: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(Opcode::Ack as u16).to_be_bytes());
    p.extend_from_slice(&block_num.to_be_bytes());
    p
}

fn build_data(block_num: u16, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + data.len());
    p.extend_from_slice(&(Opcode::Data as u16).to_be_bytes());
    p.extend_from_slice(&block_num.to_be_bytes());
    p.extend_from_slice(data);
    p
}

fn parse_opcode(data: &[u8]) -> Result<u16, Error> {
    if data.len() < 2 {
        return Err(Error::Http("TFTP packet too short".to_string()));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

fn parse_tftp_error(packet: &[u8]) -> Error {
    let error_code = if packet.len() >= 4 {
        TftpErrorCode::from_code(u16::from_be_bytes([packet[2], packet[3]]))
    } else {
        TftpErrorCode::NotDefined
    };
    let _msg = if packet.len() > 5 {
        let end = if packet[packet.len() - 1] == 0 { packet.len() - 1 } else { packet.len() };
        String::from_utf8_lossy(&packet[4..end]).to_string()
    } else {
        error_code.description().to_string()
    };
    Error::Transfer {
        code: error_code.to_curl_code(),
        message: error_code.curl_message().to_string(),
    }
}

fn parse_tftp_path(url: &crate::url::Url) -> (String, String) {
    let raw = url.path();
    let path = raw.strip_prefix('/').unwrap_or(raw);
    path.find(";mode=").map_or_else(
        || (path.to_string(), "octet".to_string()),
        |idx| (path[..idx].to_string(), path[idx + 6..].to_string()),
    )
}

async fn bind_socket(interface: Option<&str>, local_port: Option<u16>) -> Result<UdpSocket, Error> {
    let ip = interface.unwrap_or("0.0.0.0");
    let port = local_port.unwrap_or(0);
    UdpSocket::bind(format!("{ip}:{port}"))
        .await
        .map_err(|e| Error::Http(format!("TFTP bind error: {e}")))
}

fn compute_tftp_timeout(ct: Option<u64>) -> u16 {
    match ct {
        Some(s) if s > 0 => {
            #[allow(clippy::cast_possible_truncation)]
            let v = (s / (TFTP_RETRY_COUNT + 1)).clamp(1, 255) as u16;
            v
        }
        _ => DEFAULT_TFTP_TIMEOUT,
    }
}

/// Download a file via TFTP.
///
/// # Errors
///
/// Returns an error if the download fails.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn download(
    url: &crate::url::Url,
    blksize: Option<u16>,
    no_options: bool,
    interface: Option<&str>,
    local_port: Option<u16>,
    low_speed_limit: Option<u32>,
    low_speed_time: Option<Duration>,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (filename, mode) = parse_tftp_path(url);
    if filename.is_empty() {
        return Err(Error::Http("TFTP filename is required in URL path".to_string()));
    }
    // DEFAULT_BLOCK_SIZE (512) always fits in u16
    #[allow(clippy::cast_possible_truncation)]
    let bs = blksize.unwrap_or(DEFAULT_BLOCK_SIZE as u16);
    // Check filename length BEFORE attempting connection (curl compat: test 1453)
    // curl's check: filename_len + mode_len + 4 > blksize
    if filename.len() + mode.len() + 4 > bs as usize {
        return Err(Error::Transfer { code: 71, message: "TFTP filename too long".to_string() });
    }
    let socket = bind_socket(interface, local_port).await?;
    let addr = format!("{host}:{port}");
    let rrq = build_request(Opcode::Rrq, &filename, &mode, bs, 0, no_options);
    let _ = socket
        .send_to(&rrq, &addr)
        .await
        .map_err(|e| Error::Http(format!("TFTP send RRQ error: {e}")))?;
    let mut eff_bs = DEFAULT_BLOCK_SIZE;
    let mut data = Vec::new();
    let mut exp_block: u16 = 1;
    let mut buf = vec![0u8; 4 + MAX_BLOCK_SIZE];
    let start = Instant::now();
    let sl = u64::from(low_speed_limit.unwrap_or(0));
    let st = low_speed_time.unwrap_or(Duration::ZERO);
    let chk = sl > 0 && !st.is_zero();
    loop {
        let r = if chk {
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await
        } else {
            Ok(socket.recv_from(&mut buf).await)
        };
        let (n, src) = match r {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(Error::Http(format!("TFTP recv error: {e}"))),
            Err(_) => {
                let el = start.elapsed();
                if el >= st {
                    let sp = if el.as_secs() > 0 {
                        data.len() as u64 / el.as_secs()
                    } else {
                        data.len() as u64
                    };
                    if sp < sl {
                        return Err(Error::SpeedLimit { speed: sp, limit: sl, duration: el });
                    }
                }
                continue;
            }
        };
        if chk {
            let el = start.elapsed();
            if el >= st {
                let sp = if el.as_secs() > 0 {
                    data.len() as u64 / el.as_secs()
                } else {
                    data.len() as u64
                };
                if sp < sl {
                    return Err(Error::SpeedLimit { speed: sp, limit: sl, duration: el });
                }
            }
        }
        let pkt = &buf[..n];
        let op = parse_opcode(pkt)?;
        match op {
            3 => {
                if pkt.len() < 4 {
                    return Err(Error::Http("TFTP DATA packet too short".to_string()));
                }
                let bn = u16::from_be_bytes([pkt[2], pkt[3]]);
                if bn == exp_block {
                    data.extend_from_slice(&pkt[4..]);
                    exp_block = exp_block.wrapping_add(1);
                }
                let _ = socket
                    .send_to(&build_ack(bn), src)
                    .await
                    .map_err(|e| Error::Http(format!("TFTP send ACK error: {e}")))?;
                if pkt.len() - 4 < eff_bs {
                    break;
                }
            }
            5 => {
                return Err(parse_tftp_error(pkt));
            }
            o if o == OACK_OPCODE => {
                let od = &pkt[2..];
                let mut ps = od.split(|&b| b == 0).filter(|s| !s.is_empty());
                while let Some(k) = ps.next() {
                    if let Some(v) = ps.next() {
                        if k.eq_ignore_ascii_case(b"blksize") {
                            if let Ok(b) = String::from_utf8_lossy(v).parse::<usize>() {
                                eff_bs = b;
                            }
                        }
                    }
                }
                let _ = socket
                    .send_to(&build_ack(0), src)
                    .await
                    .map_err(|e| Error::Http(format!("TFTP send OACK ACK error: {e}")))?;
            }
            _ => {
                return Err(Error::Http(format!("TFTP unexpected opcode: {op}")));
            }
        }
    }
    let mut h = std::collections::HashMap::new();
    let _ = h.insert("content-length".to_string(), data.len().to_string());
    Ok(Response::new(200, h, data, url.as_str().to_string()))
}

/// Upload a file via TFTP.
///
/// # Errors
///
/// Returns an error if the upload fails.
#[allow(clippy::too_many_arguments)]
pub async fn upload(
    url: &crate::url::Url,
    data: &[u8],
    blksize: Option<u16>,
    no_options: bool,
    interface: Option<&str>,
    local_port: Option<u16>,
    connect_timeout_secs: Option<u64>,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let (filename, mode) = parse_tftp_path(url);
    if filename.is_empty() {
        return Err(Error::Http("TFTP filename is required in URL path".to_string()));
    }
    // DEFAULT_BLOCK_SIZE (512) always fits in u16
    #[allow(clippy::cast_possible_truncation)]
    let bs = blksize.unwrap_or(DEFAULT_BLOCK_SIZE as u16);
    // Check filename length BEFORE attempting connection (curl compat: test 1453)
    // curl's check: filename_len + mode_len + 4 > blksize
    if filename.len() + mode.len() + 4 > bs as usize {
        return Err(Error::Transfer { code: 71, message: "TFTP filename too long".to_string() });
    }
    let socket = bind_socket(interface, local_port).await?;
    let addr = format!("{host}:{port}");
    let mut wrq = build_request(Opcode::Wrq, &filename, &mode, bs, data.len() as u64, no_options);
    if !no_options {
        let t = compute_tftp_timeout(connect_timeout_secs);
        wrq.extend_from_slice(b"timeout\0");
        wrq.extend_from_slice(t.to_string().as_bytes());
        wrq.push(0);
    }
    let _ = socket
        .send_to(&wrq, &addr)
        .await
        .map_err(|e| Error::Http(format!("TFTP send WRQ error: {e}")))?;
    let mut eff_bs = DEFAULT_BLOCK_SIZE;
    let mut buf = vec![0u8; 4 + MAX_BLOCK_SIZE];
    let (n, src) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|e| Error::Http(format!("TFTP recv error: {e}")))?;
    let pkt = &buf[..n];
    let op = parse_opcode(pkt)?;
    let peer = match op {
        4 => src,
        o if o == OACK_OPCODE => {
            let od = &pkt[2..];
            let mut ps = od.split(|&b| b == 0).filter(|s| !s.is_empty());
            while let Some(k) = ps.next() {
                if let Some(v) = ps.next() {
                    if k.eq_ignore_ascii_case(b"blksize") {
                        if let Ok(b) = String::from_utf8_lossy(v).parse::<usize>() {
                            eff_bs = b;
                        }
                    }
                }
            }
            src
        }
        5 => {
            return Err(parse_tftp_error(pkt));
        }
        _ => {
            return Err(Error::Http(format!("TFTP unexpected opcode: {op}")));
        }
    };
    let mut bn: u16 = 1;
    let mut off = 0;
    loop {
        let end = std::cmp::min(off + eff_bs, data.len());
        let chunk = &data[off..end];
        let _ = socket
            .send_to(&build_data(bn, chunk), peer)
            .await
            .map_err(|e| Error::Http(format!("TFTP send DATA error: {e}")))?;
        let (n2, _) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::Http(format!("TFTP recv ACK error: {e}")))?;
        if parse_opcode(&buf[..n2])? == 5 {
            return Err(parse_tftp_error(&buf[..n2]));
        }
        off = end;
        bn = bn.wrapping_add(1);
        if chunk.len() < eff_bs {
            break;
        }
        if off == data.len() {
            let _ = socket
                .send_to(&build_data(bn, &[]), peer)
                .await
                .map_err(|e| Error::Http(format!("TFTP send final error: {e}")))?;
            let _ = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| Error::Http(format!("TFTP recv final error: {e}")))?;
            break;
        }
    }
    let mut h = std::collections::HashMap::new();
    let _ = h.insert("content-length".to_string(), "0".to_string());
    Ok(Response::new(200, h, Vec::new(), url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn build_request_rrq() {
        let p = build_request(Opcode::Rrq, "/t", "octet", 512, 0, false);
        assert_eq!(&p[..2], &[0, 1]);
        assert!(p.windows(5).any(|w| w == b"tsize"));
    }

    #[test]
    fn build_request_wrq() {
        let p = build_request(Opcode::Wrq, "/t", "octet", 512, 10, false);
        assert_eq!(&p[..2], &[0, 2]);
    }

    #[test]
    fn ack() {
        assert_eq!(build_ack(1), vec![0, 4, 0, 1]);
    }

    #[test]
    fn opcode_parse() {
        assert_eq!(parse_opcode(&[0, 1]).unwrap(), 1);
        assert!(parse_opcode(&[0]).is_err());
    }

    #[test]
    fn err_codes() {
        assert_eq!(TftpErrorCode::from_code(2), TftpErrorCode::AccessViolation);
        assert_eq!(TftpErrorCode::from_code(99), TftpErrorCode::NotDefined);
    }

    #[test]
    fn path_simple() {
        let u = crate::url::Url::parse("tftp://h/f.txt").unwrap();
        let (p, m) = parse_tftp_path(&u);
        assert_eq!(p, "f.txt");
        assert_eq!(m, "octet");
    }

    #[test]
    fn path_mode() {
        let u = crate::url::Url::parse("tftp://h//f;mode=netascii").unwrap();
        let (p, m) = parse_tftp_path(&u);
        assert_eq!(p, "/f");
        assert_eq!(m, "netascii");
    }

    #[test]
    fn path_dslash() {
        let u = crate::url::Url::parse("tftp://h//271").unwrap();
        let (p, _) = parse_tftp_path(&u);
        assert_eq!(p, "/271");
    }

    #[test]
    fn timeout_default() {
        assert_eq!(compute_tftp_timeout(None), 6);
    }

    #[test]
    fn timeout_549() {
        assert_eq!(compute_tftp_timeout(Some(549)), 10);
    }
}
