//! MQTT protocol handler.
//!
//! Implements an MQTT 3.1.1 client (OASIS standard) for publishing
//! and subscribing to topics. Supports `QoS` 0, 1, and 2 delivery
//! semantics with `PUBACK`, `PUBREC`/`PUBREL`/`PUBCOMP` flows.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// MQTT Quality of Service levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum QoS {
    /// At most once delivery (fire and forget).
    #[default]
    AtMostOnce = 0,
    /// At least once delivery (acknowledged).
    AtLeastOnce = 1,
    /// Exactly once delivery (four-step handshake).
    ExactlyOnce = 2,
}

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
    /// Publish acknowledgment (`QoS` 1).
    Puback = 4,
    /// Publish received (`QoS` 2, step 1).
    Pubrec = 5,
    /// Publish release (`QoS` 2, step 2).
    Pubrel = 6,
    /// Publish complete (`QoS` 2, step 3).
    Pubcomp = 7,
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

/// Build a PUBLISH packet with a specified `QoS` level.
fn build_publish_packet(topic: &str, payload: &[u8], qos: QoS, packet_id: u16) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let topic_len = topic_bytes.len() as u16;

    // QoS 1 and 2 include a 2-byte packet identifier
    let id_len = if qos == QoS::AtMostOnce { 0 } else { 2 };
    let remaining_len = 2 + topic_bytes.len() + id_len + payload.len();

    // Fixed header: type 3 + flags (QoS in bits 1-2)
    let flags = (qos as u8) << 1;
    let mut packet = vec![0x30 | flags];
    packet.extend_from_slice(&encode_remaining_length(remaining_len));
    packet.extend_from_slice(&topic_len.to_be_bytes());
    packet.extend_from_slice(topic_bytes);
    if qos != QoS::AtMostOnce {
        packet.extend_from_slice(&packet_id.to_be_bytes());
    }
    packet.extend_from_slice(payload);

    packet
}

/// Build a `PUBACK` packet (`QoS` 1 acknowledgment).
fn build_puback_packet(packet_id: u16) -> Vec<u8> {
    let mut packet = vec![0x40, 0x02]; // PUBACK, remaining length 2
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet
}

/// Build a `PUBREC` packet (`QoS` 2, step 1 response).
fn build_pubrec_packet(packet_id: u16) -> Vec<u8> {
    let mut packet = vec![0x50, 0x02]; // PUBREC, remaining length 2
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet
}

/// Build a PUBREL packet (`QoS` 2, step 2).
fn build_pubrel_packet(packet_id: u16) -> Vec<u8> {
    let mut packet = vec![0x62, 0x02]; // PUBREL (type 6, flags 0x02), remaining length 2
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet
}

/// Build a PUBCOMP packet (`QoS` 2, step 3 response).
fn build_pubcomp_packet(packet_id: u16) -> Vec<u8> {
    let mut packet = vec![0x70, 0x02]; // PUBCOMP, remaining length 2
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet
}

/// Build a SUBSCRIBE packet with a requested `QoS` level.
fn build_subscribe_packet(topic: &str, packet_id: u16, qos: QoS) -> Vec<u8> {
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
    packet.push(qos as u8);

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
/// Uses `QoS` 0 (at most once) by default. For `QoS` 1 or 2, use [`publish_qos`].
///
/// # Errors
///
/// Returns an error if connection or publishing fails.
pub async fn publish(url: &crate::url::Url, payload: &[u8]) -> Result<Response, Error> {
    publish_qos(url, payload, QoS::AtMostOnce).await
}

/// Publish a message to an MQTT broker with a specified `QoS` level.
///
/// URL format: `mqtt://host:port/topic`
///
/// - `QoS` 0: Fire and forget (no acknowledgment).
/// - `QoS` 1: At least once. Waits for `PUBACK` from broker.
/// - `QoS` 2: Exactly once. Performs `PUBLISH` → `PUBREC` → `PUBREL` → `PUBCOMP` handshake.
///
/// # Errors
///
/// Returns an error if connection, publishing, or the `QoS` handshake fails.
pub async fn publish_qos(
    url: &crate::url::Url,
    payload: &[u8],
    qos: QoS,
) -> Result<Response, Error> {
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
    let packet_id: u16 = 1;
    let publish_pkt = build_publish_packet(topic, payload, qos, packet_id);
    tcp.write_all(&publish_pkt)
        .await
        .map_err(|e| Error::Http(format!("MQTT publish write error: {e}")))?;

    // Handle QoS acknowledgment flow
    match qos {
        QoS::AtMostOnce => {} // No acknowledgment needed
        QoS::AtLeastOnce => {
            // Wait for PUBACK
            let (ptype, _, ack_payload) = read_packet(&mut tcp).await?;
            if ptype != PacketType::Puback as u8 {
                return Err(Error::Http(format!("MQTT expected PUBACK, got type {ptype}")));
            }
            if ack_payload.len() >= 2 {
                let ack_id = u16::from_be_bytes([ack_payload[0], ack_payload[1]]);
                if ack_id != packet_id {
                    return Err(Error::Http(format!(
                        "MQTT PUBACK packet ID mismatch: expected {packet_id}, got {ack_id}"
                    )));
                }
            }
        }
        QoS::ExactlyOnce => {
            // Step 1: Wait for PUBREC
            let (ptype, _, rec_payload) = read_packet(&mut tcp).await?;
            if ptype != PacketType::Pubrec as u8 {
                return Err(Error::Http(format!("MQTT expected PUBREC, got type {ptype}")));
            }
            if rec_payload.len() >= 2 {
                let rec_id = u16::from_be_bytes([rec_payload[0], rec_payload[1]]);
                if rec_id != packet_id {
                    return Err(Error::Http(format!(
                        "MQTT PUBREC packet ID mismatch: expected {packet_id}, got {rec_id}"
                    )));
                }
            }

            // Step 2: Send PUBREL
            let pubrel = build_pubrel_packet(packet_id);
            tcp.write_all(&pubrel)
                .await
                .map_err(|e| Error::Http(format!("MQTT PUBREL write error: {e}")))?;

            // Step 3: Wait for PUBCOMP
            let (ptype, _, comp_payload) = read_packet(&mut tcp).await?;
            if ptype != PacketType::Pubcomp as u8 {
                return Err(Error::Http(format!("MQTT expected PUBCOMP, got type {ptype}")));
            }
            if comp_payload.len() >= 2 {
                let comp_id = u16::from_be_bytes([comp_payload[0], comp_payload[1]]);
                if comp_id != packet_id {
                    return Err(Error::Http(format!(
                        "MQTT PUBCOMP packet ID mismatch: expected {packet_id}, got {comp_id}"
                    )));
                }
            }
        }
    }

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
/// Uses `QoS` 0 by default. For `QoS` 1 or 2, use [`subscribe_qos`].
///
/// # Errors
///
/// Returns an error if connection or subscription fails.
pub async fn subscribe(url: &crate::url::Url) -> Result<Response, Error> {
    subscribe_qos(url, QoS::AtMostOnce).await
}

/// Subscribe to an MQTT topic with a specified `QoS` level and read one message.
///
/// URL format: `mqtt://host:port/topic`
///
/// When receiving a `QoS` 1 message, sends `PUBACK`. When receiving a `QoS` 2
/// message, performs the `PUBREC` → `PUBREL` → `PUBCOMP` handshake.
///
/// # Errors
///
/// Returns an error if connection, subscription, or the `QoS` handshake fails.
pub async fn subscribe_qos(url: &crate::url::Url, qos: QoS) -> Result<Response, Error> {
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
    let subscribe_pkt = build_subscribe_packet(topic, 1, qos);
    tcp.write_all(&subscribe_pkt)
        .await
        .map_err(|e| Error::Http(format!("MQTT subscribe write error: {e}")))?;

    // Read SUBACK
    let (ptype, _, _) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Suback as u8 {
        return Err(Error::Http(format!("MQTT expected SUBACK, got type {ptype}")));
    }

    // Read one PUBLISH message
    let (ptype, flags, payload) = read_packet(&mut tcp).await?;
    if ptype != PacketType::Publish as u8 {
        return Err(Error::Http(format!("MQTT expected PUBLISH, got type {ptype}")));
    }

    // Parse QoS from PUBLISH flags
    let recv_qos = (flags >> 1) & 0x03;

    // Parse PUBLISH: 2 bytes topic length + topic + [2 bytes packet ID if QoS>0] + payload
    if payload.len() < 2 {
        return Err(Error::Http("MQTT PUBLISH packet too short".to_string()));
    }
    let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;

    let (message_start, recv_packet_id) = if recv_qos > 0 {
        // QoS 1 or 2: packet ID follows topic
        let id_offset = 2 + topic_len;
        if payload.len() < id_offset + 2 {
            return Err(Error::Http("MQTT PUBLISH packet too short for QoS ID".to_string()));
        }
        let pid = u16::from_be_bytes([payload[id_offset], payload[id_offset + 1]]);
        (id_offset + 2, Some(pid))
    } else {
        (2 + topic_len, None)
    };

    let message =
        if message_start <= payload.len() { payload[message_start..].to_vec() } else { Vec::new() };

    // Handle received message QoS acknowledgment
    if let Some(pid) = recv_packet_id {
        if recv_qos == 1 {
            // QoS 1: Send PUBACK
            let puback = build_puback_packet(pid);
            tcp.write_all(&puback)
                .await
                .map_err(|e| Error::Http(format!("MQTT PUBACK write error: {e}")))?;
        } else if recv_qos == 2 {
            // QoS 2: Send PUBREC, wait for PUBREL, send PUBCOMP
            let pubrec = build_pubrec_packet(pid);
            tcp.write_all(&pubrec)
                .await
                .map_err(|e| Error::Http(format!("MQTT PUBREC write error: {e}")))?;

            let (ptype, _, _) = read_packet(&mut tcp).await?;
            if ptype != PacketType::Pubrel as u8 {
                return Err(Error::Http(format!("MQTT expected PUBREL, got type {ptype}")));
            }

            let pubcomp = build_pubcomp_packet(pid);
            tcp.write_all(&pubcomp)
                .await
                .map_err(|e| Error::Http(format!("MQTT PUBCOMP write error: {e}")))?;
        }
    }

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
    fn publish_packet_qos0() {
        let packet = build_publish_packet("test/topic", b"hello", QoS::AtMostOnce, 0);
        assert_eq!(packet[0], 0x30); // PUBLISH, QoS 0
                                     // No packet ID for QoS 0
    }

    #[test]
    fn publish_packet_qos1() {
        let packet = build_publish_packet("test/topic", b"hello", QoS::AtLeastOnce, 42);
        assert_eq!(packet[0] & 0x06, 0x02); // QoS 1 in bits 1-2
                                            // Packet ID should be present after topic
        let topic_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let id_offset = 2 + 2 + topic_len; // topic_len_bytes + topic
        let packet_id = u16::from_be_bytes([packet[id_offset], packet[id_offset + 1]]);
        assert_eq!(packet_id, 42);
    }

    #[test]
    fn publish_packet_qos2() {
        let packet = build_publish_packet("t", b"x", QoS::ExactlyOnce, 1);
        assert_eq!(packet[0] & 0x06, 0x04); // QoS 2 in bits 1-2
    }

    #[test]
    fn puback_packet_structure() {
        let packet = build_puback_packet(42);
        assert_eq!(packet[0], 0x40); // PUBACK type
        assert_eq!(packet[1], 0x02); // remaining length
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 42);
    }

    #[test]
    fn pubrec_packet_structure() {
        let packet = build_pubrec_packet(7);
        assert_eq!(packet[0], 0x50); // PUBREC type
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 7);
    }

    #[test]
    fn pubrel_packet_structure() {
        let packet = build_pubrel_packet(99);
        assert_eq!(packet[0], 0x62); // PUBREL type + flags
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 99);
    }

    #[test]
    fn pubcomp_packet_structure() {
        let packet = build_pubcomp_packet(100);
        assert_eq!(packet[0], 0x70); // PUBCOMP type
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 100);
    }

    #[test]
    fn subscribe_packet_qos0() {
        let packet = build_subscribe_packet("test/#", 1, QoS::AtMostOnce);
        assert_eq!(packet[0], 0x82); // SUBSCRIBE
                                     // Last byte is QoS level
        assert_eq!(*packet.last().unwrap(), 0x00);
    }

    #[test]
    fn subscribe_packet_qos2() {
        let packet = build_subscribe_packet("test/#", 1, QoS::ExactlyOnce);
        assert_eq!(*packet.last().unwrap(), 0x02);
    }

    #[test]
    fn disconnect_packet() {
        let packet = build_disconnect_packet();
        assert_eq!(packet, vec![0xE0, 0x00]);
    }

    #[test]
    fn qos_default_is_at_most_once() {
        assert_eq!(QoS::default(), QoS::AtMostOnce);
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

    #[tokio::test]
    async fn read_puback_packet() {
        // PUBACK: type 4, remaining length 2, packet ID = 1
        let data = vec![0x40, 0x02, 0x00, 0x01];
        let mut cursor = std::io::Cursor::new(data);
        let (ptype, _, payload) = read_packet(&mut cursor).await.unwrap();
        assert_eq!(ptype, PacketType::Puback as u8);
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1);
    }

    #[tokio::test]
    async fn read_pubrec_packet() {
        let data = vec![0x50, 0x02, 0x00, 0x05];
        let mut cursor = std::io::Cursor::new(data);
        let (ptype, _, payload) = read_packet(&mut cursor).await.unwrap();
        assert_eq!(ptype, PacketType::Pubrec as u8);
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 5);
    }

    #[tokio::test]
    async fn read_pubcomp_packet() {
        let data = vec![0x70, 0x02, 0x00, 0x0A];
        let mut cursor = std::io::Cursor::new(data);
        let (ptype, _, payload) = read_packet(&mut cursor).await.unwrap();
        assert_eq!(ptype, PacketType::Pubcomp as u8);
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 10);
    }
}
