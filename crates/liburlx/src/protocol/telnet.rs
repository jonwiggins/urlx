//! Telnet protocol handler.
//!
//! Implements a basic telnet client (RFC 854) for raw TCP connections.
//! Supports sending upload data and reading the server response, with
//! telnet option negotiation handled transparently.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Telnet IAC (Interpret As Command) byte.
const IAC: u8 = 255;
/// Telnet WILL option negotiation.
const WILL: u8 = 251;
/// Telnet WONT option negotiation.
const WONT: u8 = 252;
/// Telnet DO option negotiation.
const DO: u8 = 253;
/// Telnet DONT option negotiation.
const DONT: u8 = 254;
/// Telnet sub-negotiation begin.
const SB: u8 = 250;
/// Telnet sub-negotiation end.
const SE: u8 = 240;

/// Strip telnet IAC sequences from raw data and return only payload bytes.
///
/// Handles WILL/WONT/DO/DONT (3-byte sequences) and sub-negotiation
/// SB...SE blocks. Literal 0xFF in the data stream is represented as
/// IAC IAC (two 0xFF bytes) per RFC 854.
fn strip_telnet_commands(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 1 < data.len() {
            match data[i + 1] {
                WILL | WONT | DO | DONT => {
                    // 3-byte command: IAC + verb + option
                    i += 3;
                }
                SB => {
                    // Sub-negotiation: skip until IAC SE
                    i += 2;
                    while i + 1 < data.len() {
                        if data[i] == IAC && data[i + 1] == SE {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                IAC => {
                    // Escaped 0xFF — emit one 0xFF byte
                    result.push(IAC);
                    i += 2;
                }
                _ => {
                    // Unknown 2-byte command, skip
                    i += 2;
                }
            }
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    result
}

/// Build telnet negotiation responses: refuse all DO with WONT, refuse all WILL with DONT.
///
/// This makes us a "dumb" telnet client that refuses all option negotiations,
/// which is sufficient for basic data transfer (matching curl's behavior for
/// simple telnet transfers).
fn build_negotiation_responses(data: &[u8]) -> Vec<u8> {
    let mut responses = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 2 < data.len() {
            match data[i + 1] {
                DO => {
                    // Server asks us to DO something — respond WONT
                    responses.extend_from_slice(&[IAC, WONT, data[i + 2]]);
                    i += 3;
                }
                WILL => {
                    // Server offers to WILL something — respond DONT
                    responses.extend_from_slice(&[IAC, DONT, data[i + 2]]);
                    i += 3;
                }
                WONT | DONT => {
                    // Acknowledgment, no response needed
                    i += 3;
                }
                SB => {
                    // Sub-negotiation: skip until IAC SE
                    i += 2;
                    while i + 1 < data.len() {
                        if data[i] == IAC && data[i + 1] == SE {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                _ => {
                    i += 2;
                }
            }
        } else {
            i += 1;
        }
    }
    responses
}

/// Perform a telnet transfer.
///
/// Opens a raw TCP connection to the given host and port. If upload `body`
/// data is provided (via `-T` / `--upload-file`), it is sent to the server.
/// The server's response is read until the connection closes.
///
/// Telnet option negotiation (IAC sequences) is handled transparently:
/// all server DO requests are refused with WONT, and all WILL offers are
/// refused with DONT. IAC sequences are stripped from the returned data.
///
/// # Errors
///
/// Returns an error if the connection or transfer fails.
pub async fn transfer(url: &crate::url::Url, body: Option<&[u8]>) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let addr = format!("{host}:{port}");

    let mut tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    // If we have upload data, send it to the server
    if let Some(data) = body {
        tcp.write_all(data).await.map_err(|e| Error::Http(format!("Telnet write error: {e}")))?;
        tcp.flush().await.map_err(|e| Error::Http(format!("Telnet flush error: {e}")))?;
        // Signal end of writing so the server knows we're done sending
        let _result = tcp.shutdown().await;
    }

    // Read all data from the server
    let mut raw_data = Vec::new();
    let _n = tcp
        .read_to_end(&mut raw_data)
        .await
        .map_err(|e| Error::Http(format!("Telnet read error: {e}")))?;

    // Send negotiation responses if there were any IAC commands
    // (In practice, for simple transfers the server often closes before
    // we'd need to respond, but we handle it for correctness.)
    let negotiation = build_negotiation_responses(&raw_data);
    if !negotiation.is_empty() {
        // Best-effort: connection may already be closing
        let _result = tcp.write_all(&negotiation).await;
    }

    // Strip telnet IAC sequences from the response
    let body = strip_telnet_commands(&raw_data);

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn strip_telnet_commands_no_iac() {
        let data = b"hello world";
        assert_eq!(strip_telnet_commands(data), b"hello world");
    }

    #[test]
    fn strip_telnet_commands_will_do() {
        // IAC WILL ECHO, then "hi"
        let data = [IAC, WILL, 1, b'h', b'i'];
        assert_eq!(strip_telnet_commands(&data), b"hi");
    }

    #[test]
    fn strip_telnet_commands_do_wont() {
        // IAC DO ECHO, IAC WONT ECHO, then "ok"
        let data = [IAC, DO, 1, IAC, WONT, 1, b'o', b'k'];
        assert_eq!(strip_telnet_commands(&data), b"ok");
    }

    #[test]
    fn strip_telnet_commands_subnegotiation() {
        // IAC SB <option> <data> IAC SE, then "test"
        let data = [IAC, SB, 24, 0, b'V', b'T', IAC, SE, b't', b'e', b's', b't'];
        assert_eq!(strip_telnet_commands(&data), b"test");
    }

    #[test]
    fn strip_telnet_commands_escaped_iac() {
        // IAC IAC should produce one 0xFF byte
        let data = [IAC, IAC, b'A'];
        let result = strip_telnet_commands(&data);
        assert_eq!(result, vec![0xFF, b'A']);
    }

    #[test]
    fn build_responses_do_becomes_wont() {
        let data = [IAC, DO, 1]; // Server: DO ECHO
        let resp = build_negotiation_responses(&data);
        assert_eq!(resp, vec![IAC, WONT, 1]); // Client: WONT ECHO
    }

    #[test]
    fn build_responses_will_becomes_dont() {
        let data = [IAC, WILL, 3]; // Server: WILL SGA
        let resp = build_negotiation_responses(&data);
        assert_eq!(resp, vec![IAC, DONT, 3]); // Client: DONT SGA
    }

    #[test]
    fn build_responses_wont_dont_no_reply() {
        let data = [IAC, WONT, 1, IAC, DONT, 3];
        let resp = build_negotiation_responses(&data);
        assert!(resp.is_empty());
    }

    #[test]
    fn build_responses_mixed() {
        let data = [IAC, DO, 1, IAC, WILL, 3, b'x'];
        let resp = build_negotiation_responses(&data);
        assert_eq!(resp, vec![IAC, WONT, 1, IAC, DONT, 3]);
    }

    #[tokio::test]
    async fn transfer_to_echo_server() {
        // Start a simple TCP server that echoes data back
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let _n = tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buf).await.unwrap();
            let _result = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        });

        let url = crate::url::Url::parse(&format!("telnet://127.0.0.1:{}", addr.port())).unwrap();
        let body = b"hello telnet";
        let response = transfer(&url, Some(body)).await.unwrap();
        assert_eq!(response.body(), b"hello telnet");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn transfer_no_upload_reads_server() {
        // Start a TCP server that sends data and closes
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"server says hi\n").await.unwrap();
            let _result = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        });

        let url = crate::url::Url::parse(&format!("telnet://127.0.0.1:{}", addr.port())).unwrap();
        let response = transfer(&url, None).await.unwrap();
        assert_eq!(response.body(), b"server says hi\n");

        server.await.unwrap();
    }
}
