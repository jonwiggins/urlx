//! WebSocket protocol handler.
//!
//! Implements the WebSocket handshake (RFC 6455) and frame encoding/decoding
//! for text, binary, ping, pong, and close frames.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Error;

/// WebSocket opcode values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Continuation frame.
    Continuation = 0x0,
    /// Text frame (UTF-8 encoded).
    Text = 0x1,
    /// Binary frame.
    Binary = 0x2,
    /// Connection close.
    Close = 0x8,
    /// Ping.
    Ping = 0x9,
    /// Pong.
    Pong = 0xA,
}

impl Opcode {
    /// Parse an opcode from a raw byte value.
    const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }
}

/// A WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this is the final fragment.
    pub fin: bool,
    /// The frame opcode.
    pub opcode: Opcode,
    /// The frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a text frame.
    #[must_use]
    pub fn text(data: &str) -> Self {
        Self { fin: true, opcode: Opcode::Text, payload: data.as_bytes().to_vec() }
    }

    /// Create a binary frame.
    #[must_use]
    pub fn binary(data: &[u8]) -> Self {
        Self { fin: true, opcode: Opcode::Binary, payload: data.to_vec() }
    }

    /// Create a close frame.
    #[must_use]
    pub const fn close() -> Self {
        Self { fin: true, opcode: Opcode::Close, payload: Vec::new() }
    }

    /// Create a ping frame.
    #[must_use]
    pub fn ping(data: &[u8]) -> Self {
        Self { fin: true, opcode: Opcode::Ping, payload: data.to_vec() }
    }

    /// Create a pong frame.
    #[must_use]
    pub fn pong(data: &[u8]) -> Self {
        Self { fin: true, opcode: Opcode::Pong, payload: data.to_vec() }
    }

    /// Get the payload as a UTF-8 string (for text frames).
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not valid UTF-8.
    pub fn as_text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.payload)
            .map_err(|e| Error::Http(format!("invalid UTF-8 in WebSocket text frame: {e}")))
    }

    /// Encode this frame into bytes for sending.
    ///
    /// Client frames are always masked per RFC 6455.
    #[must_use]
    pub fn encode(&self, mask: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        // First byte: FIN bit + opcode
        let first = if self.fin { 0x80 } else { 0x00 } | (self.opcode as u8);
        buf.push(first);

        // Second byte: MASK bit + payload length
        let mask_bit: u8 = if mask { 0x80 } else { 0x00 };
        let len = self.payload.len();

        if len < 126 {
            #[allow(clippy::cast_possible_truncation)]
            buf.push(mask_bit | len as u8);
        } else if len <= 65535 {
            buf.push(mask_bit | 0x7E);
            #[allow(clippy::cast_possible_truncation)]
            {
                buf.push((len >> 8) as u8);
                buf.push(len as u8);
            }
        } else {
            buf.push(mask_bit | 0x7F);
            for i in (0..8).rev() {
                #[allow(clippy::cast_possible_truncation)]
                buf.push((len >> (i * 8)) as u8);
            }
        }

        if mask {
            // Generate masking key from a simple source
            let mask_key = generate_mask_key();
            buf.extend_from_slice(&mask_key);

            // XOR payload with mask
            for (i, &byte) in self.payload.iter().enumerate() {
                buf.push(byte ^ mask_key[i % 4]);
            }
        } else {
            buf.extend_from_slice(&self.payload);
        }

        buf
    }
}

/// Read a WebSocket frame from a stream.
///
/// # Errors
///
/// Returns an error if the frame is malformed or the stream closes unexpectedly.
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Frame, Error> {
    let mut header = [0u8; 2];
    let _n = stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;

    let fin = header[0] & 0x80 != 0;
    let opcode_val = header[0] & 0x0F;
    let opcode = Opcode::from_u8(opcode_val)
        .ok_or_else(|| Error::Http(format!("unknown WebSocket opcode: {opcode_val:#x}")))?;

    let masked = header[1] & 0x80 != 0;
    let payload_len = match header[1] & 0x7F {
        126 => {
            let mut ext = [0u8; 2];
            let _n = stream
                .read_exact(&mut ext)
                .await
                .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;
            u64::from(u16::from_be_bytes(ext))
        }
        127 => {
            let mut ext = [0u8; 8];
            let _n = stream
                .read_exact(&mut ext)
                .await
                .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;
            u64::from_be_bytes(ext)
        }
        len => u64::from(len),
    };

    let mask_key = if masked {
        let mut key = [0u8; 4];
        let _n = stream
            .read_exact(&mut key)
            .await
            .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;
        Some(key)
    } else {
        None
    };

    #[allow(clippy::cast_possible_truncation)]
    let mut payload = vec![0u8; payload_len as usize];
    let _n = stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;

    // Unmask if needed
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }

    Ok(Frame { fin, opcode, payload })
}

/// Write a WebSocket frame to a stream (client-side, always masked).
///
/// # Errors
///
/// Returns an error if the write fails.
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &Frame,
) -> Result<(), Error> {
    let encoded = frame.encode(true); // Client frames are always masked
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| Error::Http(format!("WebSocket write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("WebSocket flush error: {e}")))?;
    Ok(())
}

/// Generate the WebSocket handshake key.
#[must_use]
pub fn generate_ws_key() -> String {
    use base64::Engine;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    #[allow(clippy::cast_possible_truncation)]
    let bytes: [u8; 16] = {
        let mut buf = [0u8; 16];
        // Mix timestamp into first 8 bytes
        for (i, b) in buf[..8].iter_mut().enumerate() {
            *b = ((nanos >> (i * 8)) & 0xFF) as u8;
        }
        // Mix counter into last 8 bytes for uniqueness within the same nanosecond
        for (i, b) in buf[8..].iter_mut().enumerate() {
            *b = ((count >> (i * 8)) & 0xFF) as u8;
        }
        buf
    };

    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Compute the expected `Sec-WebSocket-Accept` value from a key.
///
/// Per RFC 6455, concatenate the key with the magic GUID and SHA-1 hash it.
/// We use a minimal SHA-1 implementation to avoid adding a dependency.
#[must_use]
pub fn compute_accept_key(key: &str) -> String {
    use base64::Engine;

    let mut input = key.to_string();
    input.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    let hash = sha1_hash(input.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Generate a masking key for client frames.
fn generate_mask_key() -> [u8; 4] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();

    #[allow(clippy::cast_possible_truncation)]
    [
        (nanos & 0xFF) as u8,
        ((nanos >> 8) & 0xFF) as u8,
        ((nanos >> 16) & 0xFF) as u8,
        ((nanos >> 24) & 0xFF) as u8,
    ]
}

/// Minimal SHA-1 implementation (RFC 3174).
///
/// Used only for WebSocket accept key computation. Not for security purposes.
#[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process 512-bit blocks
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1_u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC_u32),
                _ => (b ^ c ^ d, 0xCA62_C1D6_u32),
            };

            let temp =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn frame_text_encode_decode() {
        let frame = Frame::text("hello");
        let encoded = frame.encode(false);

        // First byte: FIN=1, opcode=1 (text)
        assert_eq!(encoded[0], 0x81);
        // Second byte: no mask, length=5
        assert_eq!(encoded[1], 5);
        assert_eq!(&encoded[2..], b"hello");
    }

    #[test]
    fn frame_binary_encode() {
        let data = vec![1, 2, 3, 4];
        let frame = Frame::binary(&data);
        let encoded = frame.encode(false);

        assert_eq!(encoded[0], 0x82); // FIN + binary opcode
        assert_eq!(encoded[1], 4);
        assert_eq!(&encoded[2..], &[1, 2, 3, 4]);
    }

    #[test]
    fn frame_close_encode() {
        let frame = Frame::close();
        let encoded = frame.encode(false);

        assert_eq!(encoded[0], 0x88); // FIN + close opcode
        assert_eq!(encoded[1], 0); // empty payload
    }

    #[test]
    fn frame_masked_encode() {
        let frame = Frame::text("hi");
        let encoded = frame.encode(true);

        // Second byte should have mask bit set
        assert_eq!(encoded[1] & 0x80, 0x80);
        // Payload length
        assert_eq!(encoded[1] & 0x7F, 2);
        // 4 bytes of mask key after the length byte
        assert_eq!(encoded.len(), 2 + 4 + 2);
    }

    #[test]
    fn frame_medium_length() {
        let data = vec![0u8; 200];
        let frame = Frame::binary(&data);
        let encoded = frame.encode(false);

        assert_eq!(encoded[1], 126); // Extended 16-bit length
        assert_eq!(encoded[2], 0); // 200 in big-endian
        assert_eq!(encoded[3], 200);
        assert_eq!(encoded.len(), 4 + 200);
    }

    #[tokio::test]
    async fn read_frame_text() {
        let frame = Frame::text("test");
        let data = frame.encode(false);
        let mut cursor = std::io::Cursor::new(data);

        let decoded = read_frame(&mut cursor).await.unwrap();
        assert!(decoded.fin);
        assert_eq!(decoded.opcode, Opcode::Text);
        assert_eq!(decoded.as_text().unwrap(), "test");
    }

    #[tokio::test]
    async fn read_frame_masked() {
        let frame = Frame::text("masked");
        let data = frame.encode(true);
        let mut cursor = std::io::Cursor::new(data);

        let decoded = read_frame(&mut cursor).await.unwrap();
        assert_eq!(decoded.as_text().unwrap(), "masked");
    }

    #[test]
    fn sha1_known_vector() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1_hash(b"abc");
        assert_eq!(
            hash,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn compute_accept_key_known_value() {
        // RFC 6455 Section 4.2.2 example
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn opcode_roundtrip() {
        assert_eq!(Opcode::from_u8(0x1), Some(Opcode::Text));
        assert_eq!(Opcode::from_u8(0x2), Some(Opcode::Binary));
        assert_eq!(Opcode::from_u8(0x8), Some(Opcode::Close));
        assert_eq!(Opcode::from_u8(0x9), Some(Opcode::Ping));
        assert_eq!(Opcode::from_u8(0xA), Some(Opcode::Pong));
        assert_eq!(Opcode::from_u8(0xF), None);
    }

    #[test]
    fn frame_as_text_invalid_utf8() {
        let frame = Frame { fin: true, opcode: Opcode::Text, payload: vec![0xFF, 0xFE] };
        assert!(frame.as_text().is_err());
    }
}
