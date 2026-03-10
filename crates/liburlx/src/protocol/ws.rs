//! WebSocket protocol handler.
//!
//! Implements the WebSocket handshake (RFC 6455) and frame encoding/decoding
//! for text, binary, ping, pong, and close frames. Provides a higher-level
//! [`WebSocketStream`] that handles control frames (auto-pong, close with
//! status codes) and reassembles fragmented messages.

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

/// WebSocket close status codes (RFC 6455 Section 7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseCode {
    /// Normal closure (1000).
    Normal = 1000,
    /// Endpoint going away (1001).
    GoingAway = 1001,
    /// Protocol error (1002).
    ProtocolError = 1002,
    /// Unsupported data type (1003).
    Unsupported = 1003,
    /// No status code present (1005) — must not be sent in a frame.
    NoStatus = 1005,
    /// Abnormal closure (1006) — must not be sent in a frame.
    Abnormal = 1006,
    /// Invalid payload data (1007).
    InvalidPayload = 1007,
    /// Policy violation (1008).
    PolicyViolation = 1008,
    /// Message too big (1009).
    MessageTooBig = 1009,
    /// Missing expected extension (1010).
    MissingExtension = 1010,
    /// Internal server error (1011).
    InternalError = 1011,
}

impl CloseCode {
    /// Convert a raw u16 to a `CloseCode`, returning `None` for unknown codes.
    #[must_use]
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            1000 => Some(Self::Normal),
            1001 => Some(Self::GoingAway),
            1002 => Some(Self::ProtocolError),
            1003 => Some(Self::Unsupported),
            1005 => Some(Self::NoStatus),
            1006 => Some(Self::Abnormal),
            1007 => Some(Self::InvalidPayload),
            1008 => Some(Self::PolicyViolation),
            1009 => Some(Self::MessageTooBig),
            1010 => Some(Self::MissingExtension),
            1011 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Returns the numeric code value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// A high-level WebSocket message (reassembled from frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A text message (UTF-8).
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A close message with optional status code and reason.
    Close(Option<u16>, Option<String>),
    /// A ping message.
    Ping(Vec<u8>),
    /// A pong message.
    Pong(Vec<u8>),
}

/// A WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this is the final fragment.
    pub fin: bool,
    /// RSV1 bit (used by permessage-deflate extension).
    pub rsv1: bool,
    /// The frame opcode.
    pub opcode: Opcode,
    /// The frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a text frame.
    #[must_use]
    pub fn text(data: &str) -> Self {
        Self { fin: true, rsv1: false, opcode: Opcode::Text, payload: data.as_bytes().to_vec() }
    }

    /// Create a binary frame.
    #[must_use]
    pub fn binary(data: &[u8]) -> Self {
        Self { fin: true, rsv1: false, opcode: Opcode::Binary, payload: data.to_vec() }
    }

    /// Create a close frame with no status code.
    #[must_use]
    pub const fn close() -> Self {
        Self { fin: true, rsv1: false, opcode: Opcode::Close, payload: Vec::new() }
    }

    /// Create a close frame with a status code and optional reason.
    #[must_use]
    pub fn close_with_code(code: u16, reason: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        Self { fin: true, rsv1: false, opcode: Opcode::Close, payload }
    }

    /// Create a ping frame.
    #[must_use]
    pub fn ping(data: &[u8]) -> Self {
        Self { fin: true, rsv1: false, opcode: Opcode::Ping, payload: data.to_vec() }
    }

    /// Create a pong frame.
    #[must_use]
    pub fn pong(data: &[u8]) -> Self {
        Self { fin: true, rsv1: false, opcode: Opcode::Pong, payload: data.to_vec() }
    }

    /// Extract the close status code from a close frame payload.
    ///
    /// Returns `None` if the payload is too short (< 2 bytes) or this is not a close frame.
    #[must_use]
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode != Opcode::Close || self.payload.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
    }

    /// Extract the close reason string from a close frame payload.
    ///
    /// Returns `None` if the payload has no reason text or this is not a close frame.
    #[must_use]
    pub fn close_reason(&self) -> Option<&str> {
        if self.opcode != Opcode::Close || self.payload.len() <= 2 {
            return None;
        }
        std::str::from_utf8(&self.payload[2..]).ok()
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

        // First byte: FIN bit + RSV1 + opcode
        let mut first = if self.fin { 0x80 } else { 0x00 } | (self.opcode as u8);
        if self.rsv1 {
            first |= 0x40;
        }
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

/// Configuration for the `permessage-deflate` WebSocket extension (RFC 7692).
#[cfg(feature = "decompression")]
#[derive(Debug, Clone)]
pub struct DeflateConfig {
    /// Whether compression is enabled.
    pub enabled: bool,
    /// Whether to take over the client compression context between messages.
    /// When true, the deflate state persists across messages for better compression.
    /// When false, each message is compressed independently.
    pub client_no_context_takeover: bool,
    /// Whether to take over the server compression context between messages.
    pub server_no_context_takeover: bool,
    /// Maximum server window bits (9-15). Default is 15.
    pub server_max_window_bits: u8,
    /// Maximum client window bits (9-15). Default is 15.
    pub client_max_window_bits: u8,
}

#[cfg(feature = "decompression")]
impl Default for DeflateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_no_context_takeover: false,
            server_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
        }
    }
}

#[cfg(feature = "decompression")]
impl DeflateConfig {
    /// Parse a `permessage-deflate` extension offer from a `Sec-WebSocket-Extensions` header.
    ///
    /// Returns `None` if the header does not contain a `permessage-deflate` offer.
    #[must_use]
    pub fn from_header(header: &str) -> Option<Self> {
        let mut config = Self { enabled: true, ..Self::default() };

        let parts: Vec<&str> = header.split(';').map(str::trim).collect();
        if parts.is_empty() || !parts[0].eq_ignore_ascii_case("permessage-deflate") {
            return None;
        }

        for param in &parts[1..] {
            let param = param.trim();
            if param.eq_ignore_ascii_case("client_no_context_takeover") {
                config.client_no_context_takeover = true;
            } else if param.eq_ignore_ascii_case("server_no_context_takeover") {
                config.server_no_context_takeover = true;
            } else if let Some(val) = param.strip_prefix("server_max_window_bits=") {
                if let Ok(bits) = val.trim().parse::<u8>() {
                    if (9..=15).contains(&bits) {
                        config.server_max_window_bits = bits;
                    }
                }
            } else if let Some(val) = param.strip_prefix("client_max_window_bits=") {
                if let Ok(bits) = val.trim().parse::<u8>() {
                    if (9..=15).contains(&bits) {
                        config.client_max_window_bits = bits;
                    }
                }
            }
        }

        Some(config)
    }

    /// Format this config as a `Sec-WebSocket-Extensions` header value for an offer.
    #[must_use]
    pub fn to_header(&self) -> String {
        let mut s = String::from("permessage-deflate");
        if self.client_no_context_takeover {
            s.push_str("; client_no_context_takeover");
        }
        if self.server_no_context_takeover {
            s.push_str("; server_no_context_takeover");
        }
        if self.server_max_window_bits != 15 {
            use std::fmt::Write as _;
            let _ = write!(s, "; server_max_window_bits={}", self.server_max_window_bits);
        }
        if self.client_max_window_bits != 15 {
            use std::fmt::Write as _;
            let _ = write!(s, "; client_max_window_bits={}", self.client_max_window_bits);
        }
        s
    }
}

#[cfg(feature = "decompression")]
/// Compressor/decompressor for `permessage-deflate`.
///
/// Handles the raw DEFLATE compression with the trailing 4-byte sync marker
/// stripping required by RFC 7692. Each compress/decompress call creates a
/// fresh context (equivalent to `no_context_takeover` mode).
struct DeflateCodec;

#[cfg(feature = "decompression")]
impl DeflateCodec {
    const fn new(_config: &DeflateConfig, _is_client: bool) -> Self {
        Self
    }

    fn compress(data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut compress = flate2::Compress::new(flate2::Compression::default(), false);
        // Allocate generous output buffer
        let mut output = vec![0u8; data.len() + 64];
        let status = compress
            .compress(data, &mut output, flate2::FlushCompress::Sync)
            .map_err(|e| Error::Http(format!("WebSocket deflate compress error: {e}")))?;

        // If output buffer was too small, grow and retry
        if status == flate2::Status::BufError {
            output.resize(data.len() * 2 + 256, 0);
            compress.reset();
            let _status = compress
                .compress(data, &mut output, flate2::FlushCompress::Sync)
                .map_err(|e| Error::Http(format!("WebSocket deflate compress error: {e}")))?;
        }

        #[allow(clippy::cast_possible_truncation)]
        let written = compress.total_out() as usize;
        output.truncate(written);

        // RFC 7692: Remove trailing 0x00 0x00 0xFF 0xFF sync marker
        if output.len() >= 4 && output[output.len() - 4..] == [0x00, 0x00, 0xFF, 0xFF] {
            output.truncate(output.len() - 4);
        }

        Ok(output)
    }

    fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
        // RFC 7692: Append 0x00 0x00 0xFF 0xFF before decompressing
        let mut input = Vec::with_capacity(data.len() + 4);
        input.extend_from_slice(data);
        input.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);

        let mut decompress = flate2::Decompress::new(false);
        let mut output = Vec::with_capacity(data.len() * 3);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;

        loop {
            #[allow(clippy::cast_possible_truncation)]
            let before_out = decompress.total_out() as usize;

            let status = decompress
                .decompress(&input[input_pos..], &mut buf, flate2::FlushDecompress::Sync)
                .map_err(|e| Error::Http(format!("WebSocket deflate decompress error: {e}")))?;

            #[allow(clippy::cast_possible_truncation)]
            let produced = decompress.total_out() as usize - before_out;
            #[allow(clippy::cast_possible_truncation)]
            {
                input_pos = decompress.total_in() as usize;
            }

            output.extend_from_slice(&buf[..produced]);

            match status {
                flate2::Status::Ok => {
                    if produced == 0 && input_pos >= input.len() {
                        break;
                    }
                }
                flate2::Status::StreamEnd | flate2::Status::BufError => break,
            }
        }

        Ok(output)
    }
}

/// A WebSocket stream that handles control frames and message reassembly.
///
/// Wraps a raw `AsyncRead + AsyncWrite` stream and provides:
/// - Automatic pong responses to ping frames
/// - Close frame status code handling
/// - Fragmented message reassembly (continuation frames)
/// - Optional `permessage-deflate` compression (RFC 7692)
pub struct WebSocketStream<S> {
    stream: S,
    /// Whether we have sent a close frame.
    close_sent: bool,
    /// Whether we have received a close frame.
    close_received: bool,
    /// Whether this is a client (frames are masked) or server.
    is_client: bool,
    /// Buffer for reassembling fragmented messages.
    fragment_buf: Vec<u8>,
    /// Opcode of the first fragment in a fragmented message.
    fragment_opcode: Option<Opcode>,
    /// Deflate codec for permessage-deflate, if negotiated.
    #[cfg(feature = "decompression")]
    deflate: Option<DeflateCodec>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    /// Create a new client-side WebSocket stream.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_client(stream: S) -> Self {
        Self {
            stream,
            close_sent: false,
            close_received: false,
            is_client: true,
            fragment_buf: Vec::new(),
            fragment_opcode: None,
            #[cfg(feature = "decompression")]
            deflate: None,
        }
    }

    /// Create a new server-side WebSocket stream (unmasked frames).
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_server(stream: S) -> Self {
        Self {
            stream,
            close_sent: false,
            close_received: false,
            is_client: false,
            fragment_buf: Vec::new(),
            fragment_opcode: None,
            #[cfg(feature = "decompression")]
            deflate: None,
        }
    }

    /// Create a new client-side WebSocket stream with `permessage-deflate` enabled.
    #[cfg(feature = "decompression")]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_client_deflate(stream: S, config: &DeflateConfig) -> Self {
        Self {
            stream,
            close_sent: false,
            close_received: false,
            is_client: true,
            fragment_buf: Vec::new(),
            fragment_opcode: None,
            deflate: Some(DeflateCodec::new(config, true)),
        }
    }

    /// Create a new server-side WebSocket stream with `permessage-deflate` enabled.
    #[cfg(feature = "decompression")]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_server_deflate(stream: S, config: &DeflateConfig) -> Self {
        Self {
            stream,
            close_sent: false,
            close_received: false,
            is_client: false,
            fragment_buf: Vec::new(),
            fragment_opcode: None,
            deflate: Some(DeflateCodec::new(config, false)),
        }
    }

    /// Returns true if a close frame has been received.
    #[must_use]
    pub const fn is_close_received(&self) -> bool {
        self.close_received
    }

    /// Returns true if a close frame has been sent.
    #[must_use]
    pub const fn is_close_sent(&self) -> bool {
        self.close_sent
    }

    /// Returns true if the connection is fully closed (both sides sent close).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.close_sent && self.close_received
    }

    /// Read the next application-level message.
    ///
    /// Control frames (ping, pong, close) are handled automatically:
    /// - Ping frames are answered with a pong
    /// - Close frames trigger a close response
    /// - Pong frames are returned as `Message::Pong`
    /// - Fragmented messages are reassembled before returning
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or protocol violation.
    pub async fn read_message(&mut self) -> Result<Message, Error> {
        loop {
            let frame = read_frame(&mut self.stream).await?;

            match frame.opcode {
                Opcode::Ping => {
                    // Auto-respond with pong carrying the same payload
                    let pong = Frame::pong(&frame.payload);
                    write_frame_masked(&mut self.stream, &pong, self.is_client).await?;
                    return Ok(Message::Ping(frame.payload));
                }
                Opcode::Pong => {
                    return Ok(Message::Pong(frame.payload));
                }
                Opcode::Close => {
                    self.close_received = true;
                    let code = frame.close_code();
                    let reason = frame.close_reason().map(String::from);

                    // If we haven't sent a close yet, echo the close back
                    if !self.close_sent {
                        let reply =
                            code.map_or_else(Frame::close, |c| Frame::close_with_code(c, ""));
                        write_frame_masked(&mut self.stream, &reply, self.is_client).await?;
                        self.close_sent = true;
                    }

                    return Ok(Message::Close(code, reason));
                }
                Opcode::Text | Opcode::Binary => {
                    if frame.fin {
                        // Decompress if RSV1 is set (permessage-deflate)
                        #[cfg(feature = "decompression")]
                        let payload = if frame.rsv1 {
                            if self.deflate.is_some() {
                                DeflateCodec::decompress(&frame.payload)?
                            } else {
                                frame.payload
                            }
                        } else {
                            frame.payload
                        };
                        #[cfg(not(feature = "decompression"))]
                        let payload = frame.payload;
                        // Complete single-frame message
                        return if frame.opcode == Opcode::Text {
                            let text = String::from_utf8(payload).map_err(|e| {
                                Error::Http(format!("invalid UTF-8 in WebSocket text frame: {e}"))
                            })?;
                            Ok(Message::Text(text))
                        } else {
                            Ok(Message::Binary(payload))
                        };
                    }
                    // Start of a fragmented message
                    self.fragment_opcode = Some(frame.opcode);
                    self.fragment_buf = frame.payload;
                }
                Opcode::Continuation => {
                    if self.fragment_opcode.is_none() {
                        return Err(Error::Http(
                            "received continuation frame without initial fragment".to_string(),
                        ));
                    }
                    self.fragment_buf.extend_from_slice(&frame.payload);

                    if frame.fin {
                        // Reassemble complete message
                        let opcode = self.fragment_opcode.take();
                        let data = std::mem::take(&mut self.fragment_buf);
                        return match opcode {
                            Some(Opcode::Text) => {
                                let text = String::from_utf8(data).map_err(|e| {
                                    Error::Http(format!(
                                        "invalid UTF-8 in WebSocket text message: {e}"
                                    ))
                                })?;
                                Ok(Message::Text(text))
                            }
                            Some(Opcode::Binary) => Ok(Message::Binary(data)),
                            _ => Err(Error::Http("unexpected fragment opcode".to_string())),
                        };
                    }
                }
            }
        }
    }

    /// Send a text message.
    ///
    /// If `permessage-deflate` is negotiated, the payload is compressed
    /// and the RSV1 bit is set on the frame.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or compression failure.
    pub async fn send_text(&mut self, data: &str) -> Result<(), Error> {
        #[cfg(feature = "decompression")]
        let frame = if self.deflate.is_some() {
            let compressed = DeflateCodec::compress(data.as_bytes())?;
            Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: compressed }
        } else {
            Frame::text(data)
        };
        #[cfg(not(feature = "decompression"))]
        let frame = Frame::text(data);
        write_frame_masked(&mut self.stream, &frame, self.is_client).await
    }

    /// Send a binary message.
    ///
    /// If `permessage-deflate` is negotiated, the payload is compressed
    /// and the RSV1 bit is set on the frame.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or compression failure.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
        #[cfg(feature = "decompression")]
        let frame = if self.deflate.is_some() {
            let compressed = DeflateCodec::compress(data)?;
            Frame { fin: true, rsv1: true, opcode: Opcode::Binary, payload: compressed }
        } else {
            Frame::binary(data)
        };
        #[cfg(not(feature = "decompression"))]
        let frame = Frame::binary(data);
        write_frame_masked(&mut self.stream, &frame, self.is_client).await
    }

    /// Send a ping frame.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure.
    pub async fn send_ping(&mut self, data: &[u8]) -> Result<(), Error> {
        let frame = Frame::ping(data);
        write_frame_masked(&mut self.stream, &frame, self.is_client).await
    }

    /// Send a close frame with an optional status code and reason.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure.
    pub async fn send_close(&mut self, code: Option<u16>, reason: &str) -> Result<(), Error> {
        let frame = code.map_or_else(Frame::close, |c| Frame::close_with_code(c, reason));
        write_frame_masked(&mut self.stream, &frame, self.is_client).await?;
        self.close_sent = true;
        Ok(())
    }

    /// Get a reference to the underlying stream.
    pub const fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream.
    pub const fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consume the `WebSocketStream` and return the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
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
    let rsv1 = header[0] & 0x40 != 0;
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

    Ok(Frame { fin, rsv1, opcode, payload })
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
    write_frame_masked(stream, frame, true).await
}

/// Write a WebSocket frame to a stream with configurable masking.
///
/// # Errors
///
/// Returns an error if the write fails.
async fn write_frame_masked<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &Frame,
    mask: bool,
) -> Result<(), Error> {
    let encoded = frame.encode(mask);
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

/// Perform a WebSocket handshake and return the upgrade response.
///
/// Connects to the server at the given URL (ws:// or wss://), sends an HTTP
/// upgrade request, and returns a response with the server's handshake reply.
/// The response body is empty; the connection status is reported via the HTTP
/// status code (101 = success).
///
/// # Errors
///
/// Returns an error if the connection fails, TLS negotiation fails, or the
/// server rejects the upgrade.
pub async fn connect(
    url: &crate::url::Url,
    headers: &[(String, String)],
    tls_config: &crate::tls::TlsConfig,
) -> Result<crate::protocol::http::response::Response, Error> {
    let (host, port) = url.host_and_port()?;
    let is_tls = url.scheme() == "wss";

    // Build the WebSocket key
    let ws_key = generate_ws_key();
    let expected_accept = compute_accept_key(&ws_key);

    // Build the HTTP upgrade request
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let query = url.query().map_or(String::new(), |q| format!("?{q}"));

    let mut request = format!(
        "GET {path}{query} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );
    for (key, val) in headers {
        use std::fmt::Write;
        let _ = write!(request, "{key}: {val}\r\n");
    }
    request.push_str("\r\n");

    // Connect via TCP
    let tcp_stream = tokio::net::TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| Error::Http(format!("WebSocket connect error: {e}")))?;

    if is_tls {
        let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
        let (mut tls_stream, _alpn) = connector.connect(tcp_stream, &host).await?;

        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, request.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("WebSocket write error: {e}")))?;
        tokio::io::AsyncWriteExt::flush(&mut tls_stream)
            .await
            .map_err(|e| Error::Http(format!("WebSocket flush error: {e}")))?;

        parse_upgrade_response(&mut tls_stream, &expected_accept, url.as_str()).await
    } else {
        let mut tcp_stream = tcp_stream;
        tokio::io::AsyncWriteExt::write_all(&mut tcp_stream, request.as_bytes())
            .await
            .map_err(|e| Error::Http(format!("WebSocket write error: {e}")))?;
        tokio::io::AsyncWriteExt::flush(&mut tcp_stream)
            .await
            .map_err(|e| Error::Http(format!("WebSocket flush error: {e}")))?;

        parse_upgrade_response(&mut tcp_stream, &expected_accept, url.as_str()).await
    }
}

/// Parse the HTTP upgrade response from the server.
async fn parse_upgrade_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    expected_accept: &str,
    url_str: &str,
) -> Result<crate::protocol::http::response::Response, Error> {
    // Read response bytes until we see \r\n\r\n
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut byte = [0u8; 1];
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| Error::Http(format!("WebSocket read error: {e}")))?;
        if n == 0 {
            return Err(Error::Http("WebSocket: connection closed during handshake".to_string()));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            return Err(Error::Http("WebSocket: handshake response too large".to_string()));
        }
    }

    let response_str = String::from_utf8_lossy(&buf);

    // Parse status line
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| Error::Http("WebSocket: empty response".to_string()))?;

    let status_code: u16 =
        status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Parse headers
    let mut resp_headers = std::collections::HashMap::new();
    for line in response_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, val)) = line.split_once(':') {
            let _old = resp_headers.insert(key.trim().to_ascii_lowercase(), val.trim().to_string());
        }
    }

    // Validate the accept key for 101 responses
    if status_code == 101 {
        if let Some(accept) = resp_headers.get("sec-websocket-accept") {
            if accept != expected_accept {
                return Err(Error::Http(format!(
                    "WebSocket: invalid Sec-WebSocket-Accept (got {accept}, expected {expected_accept})"
                )));
            }
        }
    }

    Ok(crate::protocol::http::response::Response::new(
        status_code,
        resp_headers,
        Vec::new(),
        url_str.to_string(),
    ))
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
        let frame =
            Frame { fin: true, rsv1: false, opcode: Opcode::Text, payload: vec![0xFF, 0xFE] };
        assert!(frame.as_text().is_err());
    }

    // --- Close frame status codes ---

    #[test]
    fn close_frame_with_code() {
        let frame = Frame::close_with_code(1000, "normal closure");
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.close_code(), Some(1000));
        assert_eq!(frame.close_reason(), Some("normal closure"));
    }

    #[test]
    fn close_frame_with_code_no_reason() {
        let frame = Frame::close_with_code(1001, "");
        assert_eq!(frame.close_code(), Some(1001));
        assert_eq!(frame.close_reason(), None); // empty reason → None
    }

    #[test]
    fn close_frame_empty_no_code() {
        let frame = Frame::close();
        assert_eq!(frame.close_code(), None);
        assert_eq!(frame.close_reason(), None);
    }

    #[test]
    fn close_code_on_non_close_frame() {
        let frame = Frame::text("hello");
        assert_eq!(frame.close_code(), None);
    }

    #[test]
    fn close_code_roundtrip_encode_decode() {
        let frame = Frame::close_with_code(1002, "protocol error");
        let encoded = frame.encode(false);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let decoded = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(encoded);
            read_frame(&mut cursor).await.unwrap()
        });
        assert_eq!(decoded.close_code(), Some(1002));
        assert_eq!(decoded.close_reason(), Some("protocol error"));
    }

    #[test]
    fn close_code_enum_roundtrip() {
        assert_eq!(CloseCode::from_u16(1000), Some(CloseCode::Normal));
        assert_eq!(CloseCode::from_u16(1001), Some(CloseCode::GoingAway));
        assert_eq!(CloseCode::from_u16(1007), Some(CloseCode::InvalidPayload));
        assert_eq!(CloseCode::from_u16(1011), Some(CloseCode::InternalError));
        assert_eq!(CloseCode::from_u16(9999), None);
        assert_eq!(CloseCode::Normal.as_u16(), 1000);
    }

    // --- RSV1 bit ---

    #[test]
    fn rsv1_bit_encoded() {
        let mut frame = Frame::text("hi");
        frame.rsv1 = true;
        let encoded = frame.encode(false);
        // First byte: FIN(0x80) + RSV1(0x40) + opcode(0x01) = 0xC1
        assert_eq!(encoded[0], 0xC1);
    }

    #[tokio::test]
    async fn rsv1_bit_decoded() {
        let mut frame = Frame::text("hi");
        frame.rsv1 = true;
        let encoded = frame.encode(false);
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert!(decoded.rsv1);
        assert_eq!(decoded.as_text().unwrap(), "hi");
    }

    // --- WebSocketStream ---

    #[tokio::test]
    async fn ws_stream_text_roundtrip() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::new_client(client_stream);
        let mut server = WebSocketStream::new_server(server_stream);

        client.send_text("hello").await.unwrap();
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Text("hello".to_string()));
    }

    #[tokio::test]
    async fn ws_stream_binary_roundtrip() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::new_client(client_stream);
        let mut server = WebSocketStream::new_server(server_stream);

        client.send_binary(b"\x00\x01\x02").await.unwrap();
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Binary(vec![0, 1, 2]));
    }

    #[tokio::test]
    async fn ws_stream_ping_auto_pong() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::new_client(client_stream);
        let mut server = WebSocketStream::new_server(server_stream);

        // Server sends ping to client
        let outgoing = Frame::ping(b"heartbeat");
        write_frame_masked(&mut server.stream, &outgoing, false).await.unwrap();

        // Client reads message → gets Ping, auto-sends Pong
        let msg = client.read_message().await.unwrap();
        assert_eq!(msg, Message::Ping(b"heartbeat".to_vec()));

        // Server reads the auto-pong
        let response = read_frame(&mut server.stream).await.unwrap();
        assert_eq!(response.opcode, Opcode::Pong);
        assert_eq!(response.payload, b"heartbeat");
    }

    #[tokio::test]
    async fn ws_stream_close_handshake() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::new_client(client_stream);
        let mut server = WebSocketStream::new_server(server_stream);

        // Client initiates close
        client.send_close(Some(1000), "goodbye").await.unwrap();
        assert!(client.is_close_sent());

        // Server receives close and auto-responds
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Close(Some(1000), Some("goodbye".to_string())));
        assert!(server.is_close_received());
        assert!(server.is_close_sent()); // auto-responded
        assert!(server.is_closed());

        // Client reads the close response
        let close_frame = read_frame(&mut client.stream).await.unwrap();
        assert_eq!(close_frame.opcode, Opcode::Close);
        assert_eq!(close_frame.close_code(), Some(1000));
    }

    #[tokio::test]
    async fn ws_stream_fragmented_text() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut server = WebSocketStream::new_server(server_stream);

        // Manually write fragmented frames from client side
        let frag1 =
            Frame { fin: false, rsv1: false, opcode: Opcode::Text, payload: b"hel".to_vec() };
        let frag2 = Frame {
            fin: false,
            rsv1: false,
            opcode: Opcode::Continuation,
            payload: b"lo ".to_vec(),
        };
        let frag3 = Frame {
            fin: true,
            rsv1: false,
            opcode: Opcode::Continuation,
            payload: b"world".to_vec(),
        };

        let mut client_raw = client_stream;
        write_frame_masked(&mut client_raw, &frag1, true).await.unwrap();
        write_frame_masked(&mut client_raw, &frag2, true).await.unwrap();
        write_frame_masked(&mut client_raw, &frag3, true).await.unwrap();

        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Text("hello world".to_string()));
    }

    #[tokio::test]
    async fn ws_stream_fragmented_binary() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut server = WebSocketStream::new_server(server_stream);

        let frag1 = Frame { fin: false, rsv1: false, opcode: Opcode::Binary, payload: vec![1, 2] };
        let frag2 =
            Frame { fin: true, rsv1: false, opcode: Opcode::Continuation, payload: vec![3, 4] };

        let mut client_raw = client_stream;
        write_frame_masked(&mut client_raw, &frag1, true).await.unwrap();
        write_frame_masked(&mut client_raw, &frag2, true).await.unwrap();

        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Binary(vec![1, 2, 3, 4]));
    }

    #[tokio::test]
    async fn ws_stream_close_no_code() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::new_client(client_stream);
        let mut server = WebSocketStream::new_server(server_stream);

        client.send_close(None, "").await.unwrap();
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg, Message::Close(None, None));
    }

    // ─── permessage-deflate tests ───

    #[cfg(feature = "decompression")]
    mod deflate_tests {
        use super::*;

        #[test]
        fn deflate_config_default() {
            let config = DeflateConfig::default();
            assert!(!config.enabled);
            assert!(!config.client_no_context_takeover);
            assert!(!config.server_no_context_takeover);
            assert_eq!(config.server_max_window_bits, 15);
            assert_eq!(config.client_max_window_bits, 15);
        }

        #[test]
        fn deflate_config_from_header_basic() {
            let config = DeflateConfig::from_header("permessage-deflate").unwrap();
            assert!(config.enabled);
            assert!(!config.client_no_context_takeover);
        }

        #[test]
        fn deflate_config_from_header_with_params() {
            let config = DeflateConfig::from_header(
                "permessage-deflate; client_no_context_takeover; server_max_window_bits=12",
            )
            .unwrap();
            assert!(config.enabled);
            assert!(config.client_no_context_takeover);
            assert!(!config.server_no_context_takeover);
            assert_eq!(config.server_max_window_bits, 12);
        }

        #[test]
        fn deflate_config_from_header_wrong_extension() {
            assert!(DeflateConfig::from_header("x-webkit-deflate-frame").is_none());
        }

        #[test]
        fn deflate_config_to_header_default() {
            let config = DeflateConfig { enabled: true, ..DeflateConfig::default() };
            assert_eq!(config.to_header(), "permessage-deflate");
        }

        #[test]
        fn deflate_config_to_header_with_params() {
            let config = DeflateConfig {
                enabled: true,
                client_no_context_takeover: true,
                server_no_context_takeover: false,
                server_max_window_bits: 10,
                client_max_window_bits: 15,
            };
            let header = config.to_header();
            assert!(header.contains("client_no_context_takeover"));
            assert!(header.contains("server_max_window_bits=10"));
            assert!(!header.contains("server_no_context_takeover"));
        }

        #[test]
        fn deflate_codec_roundtrip() {
            let original = b"Hello, World! This is a test of WebSocket compression.";
            let compressed = DeflateCodec::compress(original).unwrap();
            let decompressed = DeflateCodec::decompress(&compressed).unwrap();
            assert_eq!(decompressed, original);
        }

        #[test]
        fn deflate_codec_compresses_data() {
            // Repetitive data should compress well
            let original = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes();
            let compressed = DeflateCodec::compress(original).unwrap();
            assert!(compressed.len() < original.len());
        }

        #[test]
        fn deflate_codec_empty_input() {
            let compressed = DeflateCodec::compress(b"").unwrap();
            let decompressed = DeflateCodec::decompress(&compressed).unwrap();
            assert!(decompressed.is_empty());
        }

        #[tokio::test]
        async fn ws_stream_deflate_text_roundtrip() {
            let config = DeflateConfig { enabled: true, ..DeflateConfig::default() };
            let (client_stream, server_stream) = tokio::io::duplex(4096);
            let mut client = WebSocketStream::new_client_deflate(client_stream, &config);
            let mut server = WebSocketStream::new_server_deflate(server_stream, &config);

            client.send_text("Hello, compressed world!").await.unwrap();
            let msg = server.read_message().await.unwrap();
            assert_eq!(msg, Message::Text("Hello, compressed world!".to_string()));
        }

        #[tokio::test]
        async fn ws_stream_deflate_binary_roundtrip() {
            let config = DeflateConfig { enabled: true, ..DeflateConfig::default() };
            let (client_stream, server_stream) = tokio::io::duplex(4096);
            let mut client = WebSocketStream::new_client_deflate(client_stream, &config);
            let mut server = WebSocketStream::new_server_deflate(server_stream, &config);

            let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
            client.send_binary(&data).await.unwrap();
            let msg = server.read_message().await.unwrap();
            assert_eq!(msg, Message::Binary(data));
        }

        #[tokio::test]
        async fn ws_stream_deflate_rsv1_set() {
            let config = DeflateConfig { enabled: true, ..DeflateConfig::default() };
            let (client_stream, server_stream) = tokio::io::duplex(4096);
            let mut client = WebSocketStream::new_client_deflate(client_stream, &config);

            client.send_text("test").await.unwrap();

            // Read the raw frame from the server side to verify RSV1 is set
            let mut server_raw = server_stream;
            let frame = read_frame(&mut server_raw).await.unwrap();
            assert!(frame.rsv1, "RSV1 bit should be set for compressed frames");
        }

        #[tokio::test]
        async fn ws_stream_deflate_multiple_messages() {
            let config = DeflateConfig { enabled: true, ..DeflateConfig::default() };
            let (client_stream, server_stream) = tokio::io::duplex(8192);
            let mut client = WebSocketStream::new_client_deflate(client_stream, &config);
            let mut server = WebSocketStream::new_server_deflate(server_stream, &config);

            for i in 0..5 {
                let msg = format!("message number {i}");
                client.send_text(&msg).await.unwrap();
                let received = server.read_message().await.unwrap();
                assert_eq!(received, Message::Text(msg));
            }
        }
    }

    #[tokio::test]
    async fn parse_upgrade_response_101() {
        let ws_key = generate_ws_key();
        let accept = compute_accept_key(&ws_key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        );
        let mut cursor = std::io::Cursor::new(response.into_bytes());
        let resp = parse_upgrade_response(&mut cursor, &accept, "ws://example.com").await.unwrap();
        assert_eq!(resp.status(), 101);
        assert_eq!(resp.header("upgrade"), Some("websocket"));
    }

    #[tokio::test]
    async fn parse_upgrade_response_403() {
        let response = b"HTTP/1.1 403 Forbidden\r\n\
             Content-Length: 0\r\n\
             \r\n";
        let mut cursor = std::io::Cursor::new(response.to_vec());
        let resp =
            parse_upgrade_response(&mut cursor, "ignored", "ws://example.com").await.unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn parse_upgrade_response_invalid_accept() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: wrong_value\r\n\
             \r\n";
        let mut cursor = std::io::Cursor::new(response.to_vec());
        let result = parse_upgrade_response(&mut cursor, "correct_value", "ws://example.com").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid Sec-WebSocket-Accept"));
    }

    #[tokio::test]
    async fn ws_connect_mock_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a mock WebSocket server
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);

            // Extract the Sec-WebSocket-Key from the request
            let key = request
                .lines()
                .find(|l| l.starts_with("Sec-WebSocket-Key:"))
                .unwrap()
                .split(':')
                .nth(1)
                .unwrap()
                .trim();

            let accept = compute_accept_key(key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 \r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let url = crate::url::Url::parse(&format!("ws://127.0.0.1:{}/chat", addr.port())).unwrap();
        let tls_config = crate::tls::TlsConfig::default();
        let resp = connect(&url, &[], &tls_config).await.unwrap();
        assert_eq!(resp.status(), 101);
        assert_eq!(resp.header("upgrade"), Some("websocket"));

        server.await.unwrap();
    }
}
