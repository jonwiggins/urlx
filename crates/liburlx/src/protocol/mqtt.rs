//! MQTT protocol handler.
//!
//! Implements a basic MQTT 3.1.1 client (OASIS standard) for publishing
//! and subscribing to topics. Supports CONNECT, PUBLISH, SUBSCRIBE,
//! and DISCONNECT packets.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// MQTT packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Client request to connect to server.
    Connect = 1,
    /// Connect acknowledgment.
    Connack = 2,
    /// Publish message.
    Publish = 3,
    /// Publish acknowledgment.
    Puback = 4,
    /// Subscribe to topics.
    Subscribe = 8,
    /// Subscribe acknowledgment.
    Suback = 9,
    /// Disconnect notification.
    Disconnect = 14,
}

/// Encode the remaining length using MQTT's variable-length encoding.
fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if len == 0 {
            break;
        }
    }
    bytes
}

/// Decode a variable-length encoded remaining length.
///
/// Returns (length, `bytes_consumed`).
///
/// # Errors
///
/// Returns an error if the encoding is malformed.
fn decode_remaining_length(data: &[u8]) -> Result<(usize, usize), Error> {
    let mut multiplier: usize = 1;
    let mut value: usize = 0;

    for (i, &byte) in data.iter().enumerate() {
        value += usize::from(byte & 0x7F) * multiplier;
        if multiplier > 128 * 128 * 128 {
            return Err(Error::Http("MQTT remaining length overflow".to_string()));
        }
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        multiplier *= 128;
    }

    Err(Error::Http("MQTT remaining length incomplete".to_string()))
}

/// Build a CONNECT packet.
fn build_connect_packet(client_id: &str) -> Vec<u8> {
    let client_id_bytes = client_id.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let client_id_len = client_id_bytes.len() as u16;

    // Variable header: protocol name + level + flags + keepalive
    let mut variable_header = Vec::new();
    // Protocol Name: "MQTT"
    variable_header.extend_from_slice(&[0x00, 0x04]);
    variable_header.extend_from_slice(b"MQTT");
    // Protocol Level: 4 (MQTT 3.1.1)
    variable_header.push(0x04);
    // Connect Flags: clean session
    variable_header.push(0x02);
    // Keep Alive: 60 seconds
    variable_header.extend_from_slice(&60_u16.to_be_bytes());

    // Payload: client ID
    let mut payload = Vec::new();
    payload.extend_from_slice(&client_id_len.to_be_bytes());
    payload.extend_from_slice(client_id_bytes);

    let remaining_len = variable_header.len() + payload.len();

    let mut packet = vec![0x10]; // CONNECT type
    packet.extend_from_slice(&encode_remaining_length(remaining_len));
    packet.extend_from_slice(&variable_header);
    packet.extend_from_slice(&payload);

    packet
}

/// Build a PUBLISH packet.
fn build_publish_packet(topic: &str, payload: &[u8]) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let topic_len = topic_bytes.len() as u16;

    let remaining_len = 2 + topic_bytes.len() + payload.len();

    let mut packet = vec![0x30]; // PUBLISH, QoS 0, no retain
    packet.extend_from_slice(&encode_remaining_length(remaining_len));
    packet.extend_from_slice(&topic_len.to_be_bytes());
    packet.extend_from_slice(topic_bytes);
    packet.extend_from_slice(payload);

    packet
}

/// Build a SUBSCRIBE packet.
fn build_subscribe_packet(topic: &str, packet_id: u16) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let topic_len = topic_bytes.len() as u16;

    // 2 bytes packet ID + 2 bytes topic len + topic + 1 byte QoS
    let remaining_len = 2 + 2 + topic_bytes.len() + 1;

    let mut packet = vec![0x82]; // SUBSCRIBE with QoS 1 header flag
    packet.extend_from_slice(&encode_remaining_length(remaining_len));
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.extend_from_slice(&topic_len.to_be_bytes());
    packet.extend_from_slice(topic_bytes);
    packet.push(0x00); // QoS 0

    packet
}

/// Build a DISCONNECT packet.
fn build_disconnect_packet() -> Vec<u8> {
    vec![0xE0, 0x00]
}

/// Read an MQTT packet from the stream.
///
/// Returns (`packet_type`, flags, payload).
///
/// # Errors
///
/// Returns an error if the packet is malformed or connection drops.
async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, u8, Vec<u8>), Error> {
    // Read fixed header byte
    let mut header = [0u8; 1];
    let _n = stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::Http(format!("MQTT read header error: {e}")))?;

    let packet_type = header[0] >> 4;
    let flags = header[0] & 0x0F;

    // Read remaining length (up to 4 bytes)
    let mut len_bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let _n = stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::Http(format!("MQTT read length error: {e}")))?;
        len_bytes.push(byte[0]);
        if byte[0] & 0x80 == 0 || len_bytes.len() >= 4 {
            break;
        }
    }

    let (remaining_len, _) = decode_remaining_length(&len_bytes)?;

    // Read payload
    let mut payload = vec![0u8; remaining_len];
    if remaining_len > 0 {
        let _n = stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| Error::Http(format!("MQTT read payload error: {e}")))?;
    }

    Ok((packet_type, flags, payload))
}

/// Publish a message to an MQTT broker.
///
/// URL format: `mqtt://host:port/topic`
///
/// # Errors
///
/// Returns an error if connection or publishing fails.
pub async fn publish(url: &crate::url::Url, payload: &[u8]) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let topic = url.path().trim_start_matches('/');

    if topic.is_empty() {
        return Err(Error::Http("MQTT topic is required in URL path".to_string()));
    }

    let addr = format!("{host}:{port}");
    let mut tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    // CONNECT
    let connect = build_connect_packet("urlx-client");
    tcp.write_all(&connect)
        .await
        .map_err(|e| Error::Http(format!("MQTT connect write error: {e}")))?;

    // Read CONNACK
    let (ptype, _, connack_payload) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Connack as u8 {
        return Err(Error::Http(format!("MQTT expected CONNACK, got type {ptype}")));
    }
    if connack_payload.len() >= 2 && connack_payload[1] != 0 {
        return Err(Error::Http(format!("MQTT connection refused: code {}", connack_payload[1])));
    }

    // PUBLISH
    let publish_pkt = build_publish_packet(topic, payload);
    tcp.write_all(&publish_pkt)
        .await
        .map_err(|e| Error::Http(format!("MQTT publish write error: {e}")))?;

    // DISCONNECT
    tcp.write_all(&build_disconnect_packet())
        .await
        .map_err(|e| Error::Http(format!("MQTT disconnect write error: {e}")))?;

    let headers = std::collections::HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

/// Subscribe to an MQTT topic and read one message.
///
/// URL format: `mqtt://host:port/topic`
///
/// # Errors
///
/// Returns an error if connection or subscription fails.
pub async fn subscribe(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let topic = url.path().trim_start_matches('/');

    if topic.is_empty() {
        return Err(Error::Http("MQTT topic is required in URL path".to_string()));
    }

    let addr = format!("{host}:{port}");
    let mut tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    // CONNECT
    let connect = build_connect_packet("urlx-subscriber");
    tcp.write_all(&connect)
        .await
        .map_err(|e| Error::Http(format!("MQTT connect write error: {e}")))?;

    // Read CONNACK
    let (ptype, _, connack_payload) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Connack as u8 {
        return Err(Error::Http(format!("MQTT expected CONNACK, got type {ptype}")));
    }
    if connack_payload.len() >= 2 && connack_payload[1] != 0 {
        return Err(Error::Http(format!("MQTT connection refused: code {}", connack_payload[1])));
    }

    // SUBSCRIBE
    let subscribe_pkt = build_subscribe_packet(topic, 1);
    tcp.write_all(&subscribe_pkt)
        .await
        .map_err(|e| Error::Http(format!("MQTT subscribe write error: {e}")))?;

    // Read SUBACK
    let (ptype, _, _) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Suback as u8 {
        return Err(Error::Http(format!("MQTT expected SUBACK, got type {ptype}")));
    }

    // Read one PUBLISH message
    let (ptype, _, payload) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Publish as u8 {
        return Err(Error::Http(format!("MQTT expected PUBLISH, got type {ptype}")));
    }

    // Parse PUBLISH: 2 bytes topic length + topic + payload
    if payload.len() < 2 {
        return Err(Error::Http("MQTT PUBLISH packet too short".to_string()));
    }
    let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let message_start = 2 + topic_len;
    let message =
        if message_start <= payload.len() { payload[message_start..].to_vec() } else { Vec::new() };

    // DISCONNECT
    tcp.write_all(&build_disconnect_packet())
        .await
        .map_err(|e| Error::Http(format!("MQTT disconnect write error: {e}")))?;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), message.len().to_string());

    Ok(Response::new(200, headers, message, url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_remaining_length_small() {
        assert_eq!(encode_remaining_length(0), vec![0]);
        assert_eq!(encode_remaining_length(127), vec![127]);
    }

    #[test]
    fn encode_remaining_length_two_bytes() {
        // 128 = 0x00, 0x01
        assert_eq!(encode_remaining_length(128), vec![0x80, 0x01]);
    }

    #[test]
    fn encode_remaining_length_large() {
        // 16383 = 0xFF, 0x7F
        assert_eq!(encode_remaining_length(16383), vec![0xFF, 0x7F]);
    }

    #[test]
    fn decode_remaining_length_small() {
        let (len, consumed) = decode_remaining_length(&[64]).unwrap();
        assert_eq!(len, 64);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn decode_remaining_length_two_bytes() {
        let (len, consumed) = decode_remaining_length(&[0x80, 0x01]).unwrap();
        assert_eq!(len, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn roundtrip_remaining_length() {
        for &value in &[0, 1, 127, 128, 255, 16383, 16384, 2_097_151] {
            let encoded = encode_remaining_length(value);
            let (decoded, _) = decode_remaining_length(&encoded).unwrap();
            assert_eq!(decoded, value, "roundtrip failed for {value}");
        }
    }

    #[test]
    fn connect_packet_structure() {
        let packet = build_connect_packet("test");
        assert_eq!(packet[0], 0x10); // CONNECT type
                                     // Variable header starts with protocol name "MQTT"
        let rl_end = 2; // 1 byte type + 1 byte remaining length (small)
        assert_eq!(&packet[rl_end..rl_end + 2], &[0x00, 0x04]); // length
        assert_eq!(&packet[rl_end + 2..rl_end + 6], b"MQTT");
        assert_eq!(packet[rl_end + 6], 0x04); // protocol level
    }

    #[test]
    fn publish_packet_structure() {
        let packet = build_publish_packet("test/topic", b"hello");
        assert_eq!(packet[0], 0x30); // PUBLISH, QoS 0
    }

    #[test]
    fn subscribe_packet_structure() {
        let packet = build_subscribe_packet("test/#", 1);
        assert_eq!(packet[0], 0x82); // SUBSCRIBE
    }

    #[test]
    fn disconnect_packet() {
        let packet = build_disconnect_packet();
        assert_eq!(packet, vec![0xE0, 0x00]);
    }

    #[tokio::test]
    async fn read_connack_packet() {
        // CONNACK: type 2, remaining length 2, session present=0, return code=0
        let data = vec![0x20, 0x02, 0x00, 0x00];
        let mut cursor = std::io::Cursor::new(data);
        let (ptype, flags, payload) = read_packet(&mut cursor).await.unwrap();
        assert_eq!(ptype, PacketType::Connack as u8);
        assert_eq!(flags, 0);
        assert_eq!(payload, vec![0x00, 0x00]);
    }
}
