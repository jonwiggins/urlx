//! Telnet protocol handler.
//!
//! Implements the TELNET protocol (RFC 854) for raw bidirectional TCP
//! connections with optional negotiation. Supports upload via `--upload-file`
//! and timeout via `--max-time`.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Telnet IAC (Interpret As Command) byte.
const IAC: u8 = 255;
/// Telnet WILL command.
const WILL: u8 = 251;
/// Telnet WONT command.
const WONT: u8 = 252;
/// Telnet DO command.
const DO: u8 = 253;
/// Telnet DONT command.
const DONT: u8 = 254;
/// Telnet SB (subnegotiation begin) command.
const SB: u8 = 250;
/// Telnet SE (subnegotiation end) command.
const SE: u8 = 240;

/// IAC parser state machine.
enum IacState {
    /// Normal data mode.
    Data,
    /// Received IAC byte, waiting for command.
    Iac,
    /// Received IAC + WILL/WONT/DO/DONT, waiting for option byte.
    Negotiation(u8),
    /// Inside subnegotiation (IAC SB ... IAC SE).
    Subnegotiation,
    /// Received IAC inside subnegotiation (might be SE or escaped IAC).
    SubnegotiationIac,
}

/// Escape IAC bytes in outgoing data.
///
/// Per RFC 854, any literal `0xFF` byte in the data stream must be
/// doubled to `IAC IAC` to distinguish it from telnet commands.
fn iac_escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b == IAC {
            out.push(IAC);
        }
        out.push(b);
    }
    out
}

/// Process received data through the IAC state machine.
///
/// Strips telnet command sequences, handles subnegotiation, and generates
/// negotiation responses (refuse all options).
///
/// Returns `(clean_data, responses_to_send)`.
fn process_received(data: &[u8], state: &mut IacState) -> (Vec<u8>, Vec<u8>) {
    let mut clean = Vec::new();
    let mut responses = Vec::new();

    for &b in data {
        match state {
            IacState::Data => {
                if b == IAC {
                    *state = IacState::Iac;
                } else {
                    clean.push(b);
                }
            }
            IacState::Iac => match b {
                IAC => {
                    // IAC IAC → literal 0xFF
                    clean.push(IAC);
                    *state = IacState::Data;
                }
                WILL | WONT | DO | DONT => {
                    *state = IacState::Negotiation(b);
                }
                SB => {
                    *state = IacState::Subnegotiation;
                }
                _ => {
                    // Other IAC command (e.g. GA, NOP), ignore
                    *state = IacState::Data;
                }
            },
            IacState::Negotiation(cmd) => {
                let cmd = *cmd;
                // Refuse all negotiation: respond WONT to DO/DONT, DONT to WILL/WONT
                match cmd {
                    DO | DONT => {
                        responses.extend_from_slice(&[IAC, WONT, b]);
                    }
                    WILL | WONT => {
                        responses.extend_from_slice(&[IAC, DONT, b]);
                    }
                    _ => {}
                }
                *state = IacState::Data;
            }
            IacState::Subnegotiation => {
                if b == IAC {
                    *state = IacState::SubnegotiationIac;
                }
                // Skip subnegotiation data
            }
            IacState::SubnegotiationIac => {
                if b == SE {
                    // End of subnegotiation
                    *state = IacState::Data;
                } else if b == IAC {
                    // Escaped IAC inside subnegotiation, stay in sub-IAC state
                    *state = IacState::Subnegotiation;
                } else {
                    // Other byte after IAC in subnegotiation
                    *state = IacState::Subnegotiation;
                }
            }
        }
    }

    (clean, responses)
}

/// Perform a telnet transfer.
///
/// Connects to the server via TCP, optionally sends upload data (with IAC
/// escaping), reads server response (with IAC stripping and negotiation
/// handling), and returns the received data.
///
/// # Errors
///
/// Returns an error on connection failure, I/O errors, or timeout.
pub async fn transfer(
    url: &crate::url::Url,
    body: Option<&[u8]>,
    deadline: Option<tokio::time::Instant>,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let addr = format!("{host}:{port}");

    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (mut reader, mut writer) = tokio::io::split(tcp);

    let mut output = Vec::new();
    let mut iac_state = IacState::Data;
    let mut read_buf = [0u8; 4096];

    // Send upload data immediately if present (IAC-escaped).
    // For telnet, --upload-file sets method=PUT and body contains the data.
    if let Some(data) = body {
        let escaped = iac_escape(data);
        let send_result = if let Some(dl) = deadline {
            tokio::time::timeout_at(dl, writer.write_all(&escaped)).await
        } else {
            Ok(writer.write_all(&escaped).await)
        };
        match send_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(Error::Http(format!("telnet write error: {e}"))),
            Err(_) => {
                return Err(Error::Timeout(Duration::from_secs(0)));
            }
        }
        // Shut down write side to signal EOF to the server
        let _ = writer.shutdown().await;
    }

    // Read response from server until EOF or timeout
    loop {
        let read_result = if let Some(dl) = deadline {
            tokio::time::timeout_at(dl, reader.read(&mut read_buf)).await
        } else {
            Ok(reader.read(&mut read_buf).await)
        };

        match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                let (clean, responses) = process_received(&read_buf[..n], &mut iac_state);
                output.extend_from_slice(&clean);
                // Send negotiation responses (best-effort, write side may be shut down)
                if !responses.is_empty() {
                    let _ = writer.write_all(&responses).await;
                }
            }
            Ok(Err(e)) => {
                // Read error — if we already have some output, return it
                if output.is_empty() {
                    return Err(Error::Http(format!("telnet read error: {e}")));
                }
                break;
            }
            Err(_) => {
                // Timeout
                if body.is_none() {
                    // No upload data case (test 1548): timeout is the expected outcome
                    return Err(Error::Timeout(Duration::from_secs(0)));
                }
                // Had upload data but timed out reading response
                break;
            }
        }
    }

    let headers = HashMap::new();
    Ok(Response::new(200, headers, output, url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn iac_escape_no_iac() {
        let data = b"hello world";
        assert_eq!(iac_escape(data), b"hello world");
    }

    #[test]
    fn iac_escape_with_iac() {
        let data = [0x41, 0xFF, 0x42];
        assert_eq!(iac_escape(&data), vec![0x41, 0xFF, 0xFF, 0x42]);
    }

    #[test]
    fn iac_escape_all_iac() {
        let data = [0xFF, 0xFF];
        assert_eq!(iac_escape(&data), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn process_received_plain_data() {
        let mut state = IacState::Data;
        let (clean, responses) = process_received(b"hello", &mut state);
        assert_eq!(clean, b"hello");
        assert!(responses.is_empty());
    }

    #[test]
    fn process_received_iac_iac() {
        let mut state = IacState::Data;
        let data = [0x41, IAC, IAC, 0x42];
        let (clean, responses) = process_received(&data, &mut state);
        assert_eq!(clean, vec![0x41, 0xFF, 0x42]);
        assert!(responses.is_empty());
    }

    #[test]
    fn process_received_do_negotiation() {
        let mut state = IacState::Data;
        // Server sends: IAC DO 39 (NEW_ENVIRON)
        let data = [IAC, DO, 39];
        let (clean, responses) = process_received(&data, &mut state);
        assert!(clean.is_empty());
        // Should respond: IAC WONT 39
        assert_eq!(responses, vec![IAC, WONT, 39]);
    }

    #[test]
    fn process_received_will_negotiation() {
        let mut state = IacState::Data;
        // Server sends: IAC WILL 39
        let data = [IAC, WILL, 39];
        let (clean, responses) = process_received(&data, &mut state);
        assert!(clean.is_empty());
        // Should respond: IAC DONT 39
        assert_eq!(responses, vec![IAC, DONT, 39]);
    }

    #[test]
    fn process_received_mixed_negotiation_and_data() {
        let mut state = IacState::Data;
        // Server sends: IAC DO 39, IAC WILL 39, IAC DONT 31, IAC WONT 31, then "test"
        let mut data = Vec::new();
        data.extend_from_slice(&[IAC, DO, 39]);
        data.extend_from_slice(&[IAC, WILL, 39]);
        data.extend_from_slice(&[IAC, DONT, 31]);
        data.extend_from_slice(&[IAC, WONT, 31]);
        data.extend_from_slice(b"test1452");

        let (clean, responses) = process_received(&data, &mut state);
        assert_eq!(clean, b"test1452");
        // 4 negotiation sequences, each generating a 3-byte response
        assert_eq!(responses.len(), 12);
    }

    #[test]
    fn process_received_subnegotiation() {
        let mut state = IacState::Data;
        // IAC SB 24 <data> IAC SE then "hello"
        let mut data = Vec::new();
        data.extend_from_slice(&[IAC, SB, 24, 0x01, 0x02, IAC, SE]);
        data.extend_from_slice(b"hello");

        let (clean, responses) = process_received(&data, &mut state);
        assert_eq!(clean, b"hello");
        assert!(responses.is_empty());
    }

    #[test]
    fn process_received_split_across_calls() {
        let mut state = IacState::Data;

        // First chunk: IAC
        let (clean1, resp1) = process_received(&[IAC], &mut state);
        assert!(clean1.is_empty());
        assert!(resp1.is_empty());

        // Second chunk: DO 39
        let (clean2, resp2) = process_received(&[DO, 39], &mut state);
        assert!(clean2.is_empty());
        assert_eq!(resp2, vec![IAC, WONT, 39]);
    }
}
