//! FTP protocol handler.
//!
//! Implements the File Transfer Protocol (RFC 959) for downloading and
//! uploading files, directory listing, and file management.
//! Supports explicit FTPS (AUTH TLS, RFC 4217) and implicit FTPS (port 990).
//! Supports active mode (PORT/EPRT) and passive mode (PASV).

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::protocol::http::response::Response;

/// FTPS mode for FTP connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpSslMode {
    /// No TLS — plain FTP.
    None,
    /// Explicit FTPS: connect plain, then upgrade with AUTH TLS (RFC 4217).
    Explicit,
    /// Implicit FTPS: connect directly over TLS (port 990).
    Implicit,
}

/// A stream that can be either plain TCP or TLS-wrapped.
///
/// Used for both FTP control and data connections.
#[allow(clippy::large_enum_variant)]
pub(crate) enum FtpStream {
    /// Plain TCP connection.
    Plain(TcpStream),
    /// TLS-wrapped connection.
    #[cfg(feature = "rustls")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for FtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for FtpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "rustls")]
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// An FTP response from the server.
#[derive(Debug, Clone)]
pub struct FtpResponse {
    /// The 3-digit status code.
    pub code: u16,
    /// The response text (may be multi-line).
    pub message: String,
}

impl FtpResponse {
    /// Check if this is a positive preliminary response (1xx).
    #[must_use]
    pub const fn is_preliminary(&self) -> bool {
        self.code >= 100 && self.code < 200
    }

    /// Check if this is a positive completion response (2xx).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// Check if this is a positive intermediate response (3xx).
    #[must_use]
    pub const fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

/// FTP method for traversing directories.
///
/// Controls how curl traverses the FTP path to reach the target file.
/// Equivalent to `CURLOPT_FTP_FILEMETHOD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtpMethod {
    /// Default multi-CWD: change directory one level at a time.
    #[default]
    MultiCwd,
    /// Single CWD: use one CWD with the full path.
    SingleCwd,
    /// No CWD: use SIZE/RETR on the full path without changing directory.
    NoCwd,
}

/// Transfer mode for FTP data connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// ASCII text mode (TYPE A).
    Ascii,
    /// Binary/image mode (TYPE I).
    Binary,
}

/// Server capabilities discovered via FEAT.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct FtpFeatures {
    /// Whether the server supports EPSV (Extended Passive Mode).
    pub epsv: bool,
    /// Whether the server supports MLST/MLSD (RFC 3659).
    pub mlst: bool,
    /// Whether the server supports REST STREAM (resume).
    pub rest_stream: bool,
    /// Whether the server supports SIZE.
    pub size: bool,
    /// Whether the server supports UTF8.
    pub utf8: bool,
    /// Whether the server supports AUTH TLS.
    pub auth_tls: bool,
    /// Raw feature list.
    pub raw: Vec<String>,
}

/// An active FTP session with an established control connection.
///
/// Handles login, passive/active mode, data transfer operations,
/// and optional TLS encryption (FTPS).
pub struct FtpSession {
    reader: BufReader<ReadHalf<FtpStream>>,
    writer: WriteHalf<FtpStream>,
    features: Option<FtpFeatures>,
    /// Server hostname for TLS SNI.
    hostname: String,
    /// Local address of the control connection (for active mode PORT commands).
    local_addr: SocketAddr,
    /// Whether data connections should use TLS (set after PROT P).
    use_tls_data: bool,
    /// Address for active mode data connections (`None` = use passive mode).
    active_port: Option<String>,
    /// TLS connector for wrapping data connections.
    #[cfg(feature = "rustls")]
    tls_connector: Option<crate::tls::TlsConnector>,
}

impl FtpSession {
    /// Connect to an FTP server and log in (plain FTP, no TLS).
    ///
    /// # Errors
    ///
    /// Returns an error if connection, login, or greeting fails.
    pub async fn connect(host: &str, port: u16, user: &str, pass: &str) -> Result<Self, Error> {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await.map_err(Error::Connect)?;
        let local_addr = tcp.local_addr().map_err(Error::Connect)?;
        let stream = FtpStream::Plain(tcp);
        let (reader, writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Read server greeting
        let greeting = read_response(&mut reader).await?;
        if !greeting.is_complete() {
            return Err(Error::Http(format!(
                "FTP server rejected connection: {} {}",
                greeting.code, greeting.message
            )));
        }

        let mut session = Self {
            reader,
            writer,
            features: None,
            hostname: host.to_string(),
            local_addr,
            use_tls_data: false,
            active_port: None,
            #[cfg(feature = "rustls")]
            tls_connector: None,
        };

        // Login
        session.login(user, pass).await?;

        Ok(session)
    }

    /// Connect to an FTP server with TLS support.
    ///
    /// For `FtpSslMode::Explicit`, connects plain, then upgrades with AUTH TLS.
    /// For `FtpSslMode::Implicit`, connects directly over TLS (port 990).
    /// For `FtpSslMode::None`, behaves like `connect()`.
    ///
    /// # Errors
    ///
    /// Returns an error if connection, TLS negotiation, or login fails.
    #[cfg(feature = "rustls")]
    pub async fn connect_with_tls(
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        ssl_mode: FtpSslMode,
        tls_config: &crate::tls::TlsConfig,
    ) -> Result<Self, Error> {
        if ssl_mode == FtpSslMode::None {
            return Self::connect(host, port, user, pass).await;
        }

        let tls_connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;

        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await.map_err(Error::Connect)?;
        let local_addr = tcp.local_addr().map_err(Error::Connect)?;

        let stream = match ssl_mode {
            FtpSslMode::Implicit => {
                // Implicit FTPS: wrap immediately with TLS
                let (tls_stream, _) = tls_connector.connect(tcp, host).await?;
                FtpStream::Tls(tls_stream)
            }
            FtpSslMode::Explicit | FtpSslMode::None => {
                // Explicit: start plain, upgrade after greeting
                FtpStream::Plain(tcp)
            }
        };

        let (reader, writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Read server greeting
        let greeting = read_response(&mut reader).await?;
        if !greeting.is_complete() {
            return Err(Error::Http(format!(
                "FTP server rejected connection: {} {}",
                greeting.code, greeting.message
            )));
        }

        let mut session = Self {
            reader,
            writer,
            features: None,
            hostname: host.to_string(),
            local_addr,
            use_tls_data: false,
            active_port: None,
            tls_connector: Some(tls_connector),
        };

        // For explicit FTPS, upgrade the control connection to TLS
        if ssl_mode == FtpSslMode::Explicit {
            session = session.auth_tls().await?;
        }

        // Set up data channel protection (PBSZ 0 + PROT P)
        session.setup_data_protection().await?;

        // Login
        session.login(user, pass).await?;

        Ok(session)
    }

    /// Upgrade the control connection to TLS using AUTH TLS (RFC 4217).
    ///
    /// Consumes the session and returns a new one with TLS-encrypted
    /// control connection.
    #[cfg(feature = "rustls")]
    async fn auth_tls(mut self) -> Result<Self, Error> {
        // Send AUTH TLS command on the plain connection
        send_command(&mut self.writer, "AUTH TLS").await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP AUTH TLS failed: {} {}",
                resp.code, resp.message
            )));
        }

        // Reassemble the FtpStream from the split reader/writer halves
        let reader_inner = self.reader.into_inner();
        let stream = reader_inner.unsplit(self.writer);

        // Extract TcpStream from the plain stream
        let tcp = match stream {
            FtpStream::Plain(tcp) => tcp,
            FtpStream::Tls(_) => {
                return Err(Error::Http("AUTH TLS on already-encrypted connection".to_string()));
            }
        };

        // Wrap with TLS
        let connector = self
            .tls_connector
            .as_ref()
            .ok_or_else(|| Error::Http("No TLS connector available for AUTH TLS".to_string()))?;
        let (tls_stream, _) = connector.connect(tcp, &self.hostname).await?;

        // Re-split the TLS-wrapped stream
        let ftp_stream = FtpStream::Tls(tls_stream);
        let (reader, writer) = tokio::io::split(ftp_stream);

        Ok(Self {
            reader: BufReader::new(reader),
            writer,
            features: self.features,
            hostname: self.hostname,
            local_addr: self.local_addr,
            use_tls_data: false,
            active_port: self.active_port,
            tls_connector: self.tls_connector,
        })
    }

    /// Set up data channel protection with PBSZ 0 and PROT P.
    ///
    /// Called after TLS is established on the control connection to
    /// enable TLS on data connections.
    #[cfg(feature = "rustls")]
    async fn setup_data_protection(&mut self) -> Result<(), Error> {
        // PBSZ 0 (Protection Buffer Size — always 0 for TLS)
        send_command(&mut self.writer, "PBSZ 0").await?;
        let pbsz_resp = read_response(&mut self.reader).await?;
        if !pbsz_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP PBSZ failed: {} {}",
                pbsz_resp.code, pbsz_resp.message
            )));
        }

        // PROT P (Protection level Private — encrypt data connections)
        send_command(&mut self.writer, "PROT P").await?;
        let prot_resp = read_response(&mut self.reader).await?;
        if !prot_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP PROT P failed: {} {}",
                prot_resp.code, prot_resp.message
            )));
        }

        self.use_tls_data = true;
        Ok(())
    }

    /// Set the address for active mode data connections.
    ///
    /// When set, PORT/EPRT commands are used instead of PASV.
    /// The address can be an IP address or `"-"` to use the control
    /// connection's local address.
    pub fn set_active_port(&mut self, addr: &str) {
        self.active_port = Some(addr.to_string());
    }

    /// Login with USER/PASS sequence.
    async fn login(&mut self, user: &str, pass: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("USER {user}")).await?;
        let user_resp = read_response(&mut self.reader).await?;

        if user_resp.is_intermediate() {
            send_command(&mut self.writer, &format!("PASS {pass}")).await?;
            let pass_resp = read_response(&mut self.reader).await?;
            if !pass_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP login failed: {} {}",
                    pass_resp.code, pass_resp.message
                )));
            }
        } else if !user_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP USER rejected: {} {}",
                user_resp.code, user_resp.message
            )));
        }

        Ok(())
    }

    /// Send FEAT command and parse server capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error on communication failure. If the server doesn't
    /// support FEAT, returns default (empty) features without error.
    pub async fn feat(&mut self) -> Result<&FtpFeatures, Error> {
        send_command(&mut self.writer, "FEAT").await?;
        let resp = read_response(&mut self.reader).await?;

        let features = if resp.is_complete() {
            parse_feat_response(&resp.message)
        } else {
            // If FEAT returns 5xx (not supported), use empty defaults
            FtpFeatures::default()
        };

        self.features = Some(features);
        // features was just inserted, so get_or_insert_with won't allocate
        Ok(self.features.get_or_insert_with(FtpFeatures::default))
    }

    /// Set the transfer type (ASCII or Binary).
    ///
    /// # Errors
    ///
    /// Returns an error if the TYPE command fails.
    pub async fn set_type(&mut self, transfer_type: TransferType) -> Result<(), Error> {
        let type_cmd = match transfer_type {
            TransferType::Ascii => "TYPE A",
            TransferType::Binary => "TYPE I",
        };
        send_command(&mut self.writer, type_cmd).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP TYPE failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Open a data connection, choosing passive or active mode.
    ///
    /// If `active_port` is set, uses PORT/EPRT (active mode).
    /// Otherwise, uses PASV (passive mode).
    async fn open_data_connection(&mut self) -> Result<FtpStream, Error> {
        if let Some(ref addr) = self.active_port {
            let addr = addr.clone();
            self.open_active_data_connection(&addr).await
        } else {
            self.open_passive_data_connection().await
        }
    }

    /// Enter passive mode and open a data connection (PASV).
    async fn open_passive_data_connection(&mut self) -> Result<FtpStream, Error> {
        send_command(&mut self.writer, "PASV").await?;
        let pasv_resp = read_response(&mut self.reader).await?;
        if pasv_resp.code != 227 {
            return Err(Error::Http(format!(
                "FTP PASV failed: {} {}",
                pasv_resp.code, pasv_resp.message
            )));
        }
        let (data_host, data_port) = parse_pasv_response(&pasv_resp.message)?;
        let data_addr = format!("{data_host}:{data_port}");
        let tcp = TcpStream::connect(&data_addr)
            .await
            .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;

        self.maybe_wrap_data_tls(tcp).await
    }

    /// Open a data connection in active mode (PORT/EPRT).
    ///
    /// Binds a listener on a local port, sends PORT/EPRT to the server,
    /// and waits for the server to connect.
    async fn open_active_data_connection(&mut self, bind_addr: &str) -> Result<FtpStream, Error> {
        // Determine the local IP to advertise
        let local_ip = if bind_addr == "-" {
            self.local_addr.ip()
        } else {
            bind_addr.parse().map_err(|e| {
                Error::Http(format!("Invalid FTP active address '{bind_addr}': {e}"))
            })?
        };

        // Bind a listener on the local IP with port 0 (OS-assigned)
        let bind = SocketAddr::new(local_ip, 0);
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| Error::Http(format!("FTP active mode bind failed: {e}")))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| Error::Http(format!("FTP active mode local_addr failed: {e}")))?;

        // Send PORT or EPRT depending on address family
        let port_cmd = if local_ip.is_ipv4() {
            format_port_command(&listen_addr)
        } else {
            format_eprt_command(&listen_addr)
        };
        send_command(&mut self.writer, &port_cmd).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP {} failed: {} {}",
                if local_ip.is_ipv4() { "PORT" } else { "EPRT" },
                resp.code,
                resp.message
            )));
        }

        // Accept the incoming data connection from the server
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| Error::Http(format!("FTP active mode accept failed: {e}")))?;

        self.maybe_wrap_data_tls(tcp).await
    }

    /// Optionally wrap a data connection TCP stream with TLS.
    ///
    /// If `use_tls_data` is true and a TLS connector is available,
    /// wraps the stream. Otherwise, returns it as plain.
    async fn maybe_wrap_data_tls(&self, tcp: TcpStream) -> Result<FtpStream, Error> {
        #[cfg(feature = "rustls")]
        if self.use_tls_data {
            if let Some(ref connector) = self.tls_connector {
                let (tls_stream, _) = connector.connect(tcp, &self.hostname).await?;
                return Ok(FtpStream::Tls(tls_stream));
            }
        }

        Ok(FtpStream::Plain(tcp))
    }

    /// Download a file from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn download(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("RETR {path}")).await?;
        let retr_resp = read_response(&mut self.reader).await?;
        if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RETR failed: {} {}",
                retr_resp.code, retr_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Download a file with resume from a byte offset (REST + RETR).
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support REST or the transfer fails.
    pub async fn download_resume(&mut self, path: &str, offset: u64) -> Result<Vec<u8>, Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        // Send REST to set the starting offset
        send_command(&mut self.writer, &format!("REST {offset}")).await?;
        let rest_resp = read_response(&mut self.reader).await?;
        if !rest_resp.is_intermediate() {
            return Err(Error::Http(format!(
                "FTP REST failed: {} {}",
                rest_resp.code, rest_resp.message
            )));
        }

        send_command(&mut self.writer, &format!("RETR {path}")).await?;
        let retr_resp = read_response(&mut self.reader).await?;
        if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RETR failed: {} {}",
                retr_resp.code, retr_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Upload a file to the server (STOR).
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn upload(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("STOR {path}")).await?;
        let stor_resp = read_response(&mut self.reader).await?;
        if !stor_resp.is_preliminary() && !stor_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP STOR failed: {} {}",
                stor_resp.code, stor_resp.message
            )));
        }

        data_stream
            .write_all(data)
            .await
            .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        data_stream
            .shutdown()
            .await
            .map_err(|e| Error::Http(format!("FTP data shutdown error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP upload failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(())
    }

    /// Append data to a file on the server (APPE).
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    pub async fn append(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.set_type(TransferType::Binary).await?;
        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, &format!("APPE {path}")).await?;
        let appe_resp = read_response(&mut self.reader).await?;
        if !appe_resp.is_preliminary() && !appe_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP APPE failed: {} {}",
                appe_resp.code, appe_resp.message
            )));
        }

        data_stream
            .write_all(data)
            .await
            .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        data_stream
            .shutdown()
            .await
            .map_err(|e| Error::Http(format!("FTP data shutdown error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP append failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(())
    }

    /// List directory contents (LIST).
    ///
    /// # Errors
    ///
    /// Returns an error if the listing fails.
    pub async fn list(&mut self, path: Option<&str>) -> Result<Vec<u8>, Error> {
        if let Some(dir) = path {
            if !dir.is_empty() && dir != "/" {
                send_command(&mut self.writer, &format!("CWD {dir}")).await?;
                let cwd_resp = read_response(&mut self.reader).await?;
                if !cwd_resp.is_complete() {
                    return Err(Error::Http(format!(
                        "FTP CWD failed: {} {}",
                        cwd_resp.code, cwd_resp.message
                    )));
                }
            }
        }

        let mut data_stream = self.open_data_connection().await?;

        send_command(&mut self.writer, "LIST").await?;
        let list_resp = read_response(&mut self.reader).await?;
        if !list_resp.is_preliminary() && !list_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP LIST failed: {} {}",
                list_resp.code, list_resp.message
            )));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Machine-readable listing (MLSD, RFC 3659).
    ///
    /// # Errors
    ///
    /// Returns an error if MLSD is not supported or fails.
    pub async fn mlsd(&mut self, path: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut data_stream = self.open_data_connection().await?;

        let cmd = path.map_or_else(|| "MLSD".to_string(), |p| format!("MLSD {p}"));
        send_command(&mut self.writer, &cmd).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_preliminary() && !resp.is_complete() {
            return Err(Error::Http(format!("FTP MLSD failed: {} {}", resp.code, resp.message)));
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut self.reader).await?;
        if !complete_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP MLSD transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }

        Ok(data)
    }

    /// Get file size (SIZE command).
    ///
    /// # Errors
    ///
    /// Returns an error if SIZE is not supported or fails.
    pub async fn size(&mut self, path: &str) -> Result<u64, Error> {
        send_command(&mut self.writer, &format!("SIZE {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP SIZE failed: {} {}", resp.code, resp.message)));
        }
        resp.message
            .trim()
            .parse::<u64>()
            .map_err(|e| Error::Http(format!("FTP SIZE parse error: {e}")))
    }

    /// Create a directory (MKD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub async fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("MKD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP MKD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Remove a directory (RMD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be removed.
    pub async fn rmdir(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("RMD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP RMD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Delete a file (DELE).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be deleted.
    pub async fn delete(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("DELE {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP DELE failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Rename a file or directory (RNFR + RNTO).
    ///
    /// # Errors
    ///
    /// Returns an error if the rename fails.
    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("RNFR {from}")).await?;
        let rnfr_resp = read_response(&mut self.reader).await?;
        if !rnfr_resp.is_intermediate() {
            return Err(Error::Http(format!(
                "FTP RNFR failed: {} {}",
                rnfr_resp.code, rnfr_resp.message
            )));
        }

        send_command(&mut self.writer, &format!("RNTO {to}")).await?;
        let rnto_resp = read_response(&mut self.reader).await?;
        if !rnto_resp.is_complete() {
            return Err(Error::Http(format!(
                "FTP RNTO failed: {} {}",
                rnto_resp.code, rnto_resp.message
            )));
        }
        Ok(())
    }

    /// Send a SITE command.
    ///
    /// # Errors
    ///
    /// Returns an error if the SITE command fails.
    pub async fn site(&mut self, command: &str) -> Result<FtpResponse, Error> {
        send_command(&mut self.writer, &format!("SITE {command}")).await?;
        read_response(&mut self.reader).await
    }

    /// Print the current working directory (PWD).
    ///
    /// # Errors
    ///
    /// Returns an error if the PWD command fails.
    pub async fn pwd(&mut self) -> Result<String, Error> {
        send_command(&mut self.writer, "PWD").await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP PWD failed: {} {}", resp.code, resp.message)));
        }
        // PWD returns: 257 "/current/dir"
        // Extract the path from between quotes
        if let Some(start) = resp.message.find('"') {
            if let Some(end) = resp.message[start + 1..].find('"') {
                return Ok(resp.message[start + 1..start + 1 + end].to_string());
            }
        }
        Ok(resp.message)
    }

    /// Change working directory (CWD).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory change fails.
    pub async fn cwd(&mut self, path: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("CWD {path}")).await?;
        let resp = read_response(&mut self.reader).await?;
        if !resp.is_complete() {
            return Err(Error::Http(format!("FTP CWD failed: {} {}", resp.code, resp.message)));
        }
        Ok(())
    }

    /// Close the FTP session (QUIT).
    ///
    /// # Errors
    ///
    /// Returns an error if sending the QUIT command fails.
    pub async fn quit(mut self) -> Result<(), Error> {
        send_command(&mut self.writer, "QUIT").await?;
        // Don't wait for QUIT response — some servers are slow
        Ok(())
    }
}

/// Read an FTP response (potentially multi-line) from the control connection.
///
/// Multi-line responses start with `code-` and end with `code ` (space).
///
/// # Errors
///
/// Returns an error if the response is malformed or the connection drops.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<FtpResponse, Error> {
    let mut full_message = String::new();
    let mut final_code: Option<u16> = None;

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("FTP read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("FTP connection closed unexpectedly".to_string()));
        }

        let line = line.trim_end_matches('\n').trim_end_matches('\r');

        if line.len() < 4 {
            // Lines shorter than "NNN " aren't valid FTP responses
            full_message.push_str(line);
            full_message.push('\n');
            continue;
        }

        let code_str = &line[..3];
        let separator = line.as_bytes().get(3).copied();

        if let Ok(code) = code_str.parse::<u16>() {
            match separator {
                Some(b' ') => {
                    // Final line of response
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    final_code = Some(code);
                    break;
                }
                Some(b'-') => {
                    // Multi-line response continues
                    let msg = &line[4..];
                    full_message.push_str(msg);
                    full_message.push('\n');
                    if final_code.is_none() {
                        final_code = Some(code);
                    }
                }
                _ => {
                    // Not a code line, just accumulate
                    full_message.push_str(line);
                    full_message.push('\n');
                }
            }
        } else {
            // Not a code line, just accumulate
            full_message.push_str(line);
            full_message.push('\n');
        }
    }

    let code =
        final_code.ok_or_else(|| Error::Http("FTP response has no status code".to_string()))?;

    Ok(FtpResponse { code, message: full_message })
}

/// Send an FTP command on the control connection.
///
/// # Errors
///
/// Returns an error if the write fails.
pub async fn send_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    command: &str,
) -> Result<(), Error> {
    let cmd = format!("{command}\r\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("FTP write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("FTP flush error: {e}")))?;
    Ok(())
}

/// Parse PASV response to extract IP and port.
///
/// PASV response format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
///
/// # Errors
///
/// Returns an error if the response cannot be parsed.
pub fn parse_pasv_response(message: &str) -> Result<(String, u16), Error> {
    // Find the parenthesized address
    let start = message
        .find('(')
        .ok_or_else(|| Error::Http("PASV response missing address".to_string()))?;
    let end = message
        .find(')')
        .ok_or_else(|| Error::Http("PASV response missing closing paren".to_string()))?;

    let nums: Vec<u16> =
        message[start + 1..end].split(',').filter_map(|s| s.trim().parse().ok()).collect();

    if nums.len() != 6 {
        return Err(Error::Http(format!("PASV response has {} numbers, expected 6", nums.len())));
    }

    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = nums[4] * 256 + nums[5];

    Ok((host, port))
}

/// Parse EPSV response to extract port.
///
/// EPSV response format: `229 Entering Extended Passive Mode (|||port|)`
///
/// # Errors
///
/// Returns an error if the response cannot be parsed.
pub fn parse_epsv_response(message: &str) -> Result<u16, Error> {
    // Find the port between ||| and |
    let start = message
        .find("|||")
        .ok_or_else(|| Error::Http("EPSV response missing port delimiter".to_string()))?;
    let rest = &message[start + 3..];
    let end = rest
        .find('|')
        .ok_or_else(|| Error::Http("EPSV response missing closing delimiter".to_string()))?;

    rest[..end].parse::<u16>().map_err(|e| Error::Http(format!("EPSV port parse error: {e}")))
}

/// Parse FEAT response into feature list.
///
/// # Errors
///
/// Returns an error if parsing fails.
#[must_use]
pub fn parse_feat_response(message: &str) -> FtpFeatures {
    let mut features = FtpFeatures::default();
    for line in message.lines() {
        let feature = line.trim().to_uppercase();
        if feature.starts_with("EPSV") {
            features.epsv = true;
        } else if feature.starts_with("MLST") {
            features.mlst = true;
        } else if feature.starts_with("REST") && feature.contains("STREAM") {
            features.rest_stream = true;
        } else if feature.starts_with("SIZE") {
            features.size = true;
        } else if feature.starts_with("UTF8") {
            features.utf8 = true;
        } else if feature.starts_with("AUTH") && feature.contains("TLS") {
            features.auth_tls = true;
        }
        if !feature.is_empty() {
            features.raw.push(line.trim().to_string());
        }
    }
    features
}

/// Format a PORT command for active mode FTP (IPv4).
///
/// PORT h1,h2,h3,h4,p1,p2 where h1-h4 are IP octets and
/// p1=port/256, p2=port%256.
#[must_use]
pub fn format_port_command(addr: &SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            let port = addr.port();
            format!(
                "PORT {},{},{},{},{},{}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                port / 256,
                port % 256
            )
        }
        std::net::IpAddr::V6(_) => {
            // PORT doesn't support IPv6; use EPRT instead
            format_eprt_command(addr)
        }
    }
}

/// Format an EPRT command for active mode FTP (IPv4 and IPv6).
///
/// EPRT |net-prt|net-addr|tcp-port| where net-prt is 1 (IPv4) or 2 (IPv6).
#[must_use]
pub fn format_eprt_command(addr: &SocketAddr) -> String {
    let (proto, ip_str) = match addr.ip() {
        std::net::IpAddr::V4(ip) => (1, ip.to_string()),
        std::net::IpAddr::V6(ip) => (2, ip.to_string()),
    };
    format!("EPRT |{proto}|{ip_str}|{}|", addr.port())
}

/// Connect an FTP session with the appropriate TLS mode.
///
/// Helper that dispatches to `FtpSession::connect` or `connect_with_tls`
/// based on the SSL mode.
async fn connect_session(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    ssl_mode: FtpSslMode,
    tls_config: &crate::tls::TlsConfig,
) -> Result<FtpSession, Error> {
    match ssl_mode {
        FtpSslMode::None => FtpSession::connect(host, port, user, pass).await,
        #[cfg(feature = "rustls")]
        _ => FtpSession::connect_with_tls(host, port, user, pass, ssl_mode, tls_config).await,
        #[cfg(not(feature = "rustls"))]
        _ => {
            let _ = tls_config;
            Err(Error::Http("FTPS requires the 'rustls' feature".to_string()))
        }
    }
}

/// Perform an FTP download and return the file contents as a Response.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or the file cannot be retrieved.
#[allow(clippy::too_many_lines)]
pub async fn download(
    url: &crate::url::Url,
    ssl_mode: FtpSslMode,
    tls_config: &crate::tls::TlsConfig,
    resume_from: Option<u64>,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = connect_session(&host, port, user, pass, ssl_mode, tls_config).await?;
    let data = if let Some(offset) = resume_from {
        session.download_resume(path, offset).await?
    } else {
        session.download(path).await?
    };
    let _ = session.quit().await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Perform an FTP directory listing and return it as a Response.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or listing fails.
#[allow(clippy::too_many_lines)]
pub async fn list(
    url: &crate::url::Url,
    ssl_mode: FtpSslMode,
    tls_config: &crate::tls::TlsConfig,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = connect_session(&host, port, user, pass, ssl_mode, tls_config).await?;
    let path_opt = if path.is_empty() || path == "/" { None } else { Some(path) };
    let data = session.list(path_opt).await?;
    let _ = session.quit().await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Perform an FTP upload.
///
/// # Errors
///
/// Returns an error if login fails, passive mode fails, or the upload fails.
pub async fn upload(
    url: &crate::url::Url,
    data: &[u8],
    ssl_mode: FtpSslMode,
    tls_config: &crate::tls::TlsConfig,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path();
    let (user, pass) = url.credentials().unwrap_or(("anonymous", "urlx@"));

    let mut session = connect_session(&host, port, user, pass, ssl_mode, tls_config).await?;
    session.upload(path, data).await?;
    let _ = session.quit().await;

    let headers = std::collections::HashMap::new();
    Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_simple_response() {
        let data = b"220 Welcome to FTP\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.message, "Welcome to FTP");
    }

    #[tokio::test]
    async fn read_multiline_response() {
        let data = b"220-Welcome\r\n220-to the\r\n220 FTP server\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 220);
        assert!(resp.message.contains("Welcome"));
        assert!(resp.message.contains("FTP server"));
    }

    #[tokio::test]
    async fn read_response_connection_closed() {
        let data = b"";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let result = read_response(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn parse_pasv_simple() {
        let msg = "Entering Passive Mode (192,168,1,1,4,1)";
        let (host, port) = parse_pasv_response(msg).unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 1025); // 4*256 + 1
    }

    #[test]
    fn parse_pasv_high_port() {
        let msg = "Entering Passive Mode (127,0,0,1,200,100)";
        let (host, port) = parse_pasv_response(msg).unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 51300); // 200*256 + 100
    }

    #[test]
    fn parse_epsv_simple() {
        let msg = "Entering Extended Passive Mode (|||12345|)";
        let port = parse_epsv_response(msg).unwrap();
        assert_eq!(port, 12345);
    }

    #[test]
    fn ftp_response_status_categories() {
        let preliminary = FtpResponse { code: 150, message: String::new() };
        assert!(preliminary.is_preliminary());
        assert!(!preliminary.is_complete());

        let complete = FtpResponse { code: 226, message: String::new() };
        assert!(complete.is_complete());
        assert!(!complete.is_intermediate());

        let intermediate = FtpResponse { code: 331, message: String::new() };
        assert!(intermediate.is_intermediate());
        assert!(!intermediate.is_complete());
    }

    #[test]
    fn parse_feat_response_full() {
        let message = "Extensions supported:\n EPSV\n MLST size*;modify*;type*\n REST STREAM\n SIZE\n UTF8\n AUTH TLS";
        let features = parse_feat_response(message);
        assert!(features.epsv);
        assert!(features.mlst);
        assert!(features.rest_stream);
        assert!(features.size);
        assert!(features.utf8);
        assert!(features.auth_tls);
    }

    #[test]
    fn parse_feat_response_minimal() {
        let message = "SIZE\nREST STREAM";
        let features = parse_feat_response(message);
        assert!(features.size);
        assert!(features.rest_stream);
        assert!(!features.epsv);
        assert!(!features.mlst);
    }

    #[test]
    fn parse_feat_response_empty() {
        let features = parse_feat_response("");
        assert!(!features.epsv);
        assert!(!features.mlst);
        assert!(!features.rest_stream);
        assert!(!features.size);
        assert!(!features.utf8);
        assert!(!features.auth_tls);
        assert!(features.raw.is_empty());
    }

    #[test]
    fn parse_feat_response_auth_tls() {
        let message = "AUTH TLS\nAUTH SSL";
        let features = parse_feat_response(message);
        assert!(features.auth_tls);
    }

    #[test]
    fn transfer_type_equality() {
        assert_eq!(TransferType::Ascii, TransferType::Ascii);
        assert_eq!(TransferType::Binary, TransferType::Binary);
        assert_ne!(TransferType::Ascii, TransferType::Binary);
    }

    #[test]
    fn ftp_features_default() {
        let features = FtpFeatures::default();
        assert!(!features.epsv);
        assert!(!features.mlst);
        assert!(!features.rest_stream);
        assert!(!features.size);
        assert!(!features.utf8);
        assert!(!features.auth_tls);
        assert!(features.raw.is_empty());
    }

    #[test]
    fn ftp_ssl_mode_equality() {
        assert_eq!(FtpSslMode::None, FtpSslMode::None);
        assert_eq!(FtpSslMode::Explicit, FtpSslMode::Explicit);
        assert_eq!(FtpSslMode::Implicit, FtpSslMode::Implicit);
        assert_ne!(FtpSslMode::None, FtpSslMode::Explicit);
        assert_ne!(FtpSslMode::Explicit, FtpSslMode::Implicit);
    }

    #[test]
    fn ftp_method_default() {
        assert_eq!(FtpMethod::default(), FtpMethod::MultiCwd);
    }

    #[test]
    fn ftp_method_equality() {
        assert_eq!(FtpMethod::MultiCwd, FtpMethod::MultiCwd);
        assert_eq!(FtpMethod::SingleCwd, FtpMethod::SingleCwd);
        assert_eq!(FtpMethod::NoCwd, FtpMethod::NoCwd);
        assert_ne!(FtpMethod::MultiCwd, FtpMethod::SingleCwd);
        assert_ne!(FtpMethod::SingleCwd, FtpMethod::NoCwd);
    }

    #[test]
    fn format_port_ipv4() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cmd = format_port_command(&addr);
        // 12345 = 48*256 + 57
        assert_eq!(cmd, "PORT 192,168,1,100,48,57");
    }

    #[test]
    fn format_port_low_port() {
        let addr: SocketAddr = "10.0.0.1:21".parse().unwrap();
        let cmd = format_port_command(&addr);
        // 21 = 0*256 + 21
        assert_eq!(cmd, "PORT 10,0,0,1,0,21");
    }

    #[test]
    fn format_port_high_port() {
        let addr: SocketAddr = "127.0.0.1:65535".parse().unwrap();
        let cmd = format_port_command(&addr);
        // 65535 = 255*256 + 255
        assert_eq!(cmd, "PORT 127,0,0,1,255,255");
    }

    #[test]
    fn format_eprt_ipv4() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cmd = format_eprt_command(&addr);
        assert_eq!(cmd, "EPRT |1|192.168.1.100|12345|");
    }

    #[test]
    fn format_eprt_ipv6() {
        let addr: SocketAddr = "[::1]:54321".parse().unwrap();
        let cmd = format_eprt_command(&addr);
        assert_eq!(cmd, "EPRT |2|::1|54321|");
    }

    #[test]
    fn format_port_roundtrip() {
        // Generate a PORT command and verify it can be parsed back
        let addr: SocketAddr = "10.20.30.40:5000".parse().unwrap();
        let cmd = format_port_command(&addr);
        // PORT 10,20,30,40,19,136  (5000 = 19*256 + 136)
        assert!(cmd.starts_with("PORT "));
        let nums: Vec<&str> = cmd[5..].split(',').collect();
        assert_eq!(nums.len(), 6);
        let h1: u16 = nums[0].parse().unwrap();
        let h2: u16 = nums[1].parse().unwrap();
        let h3: u16 = nums[2].parse().unwrap();
        let h4: u16 = nums[3].parse().unwrap();
        let p1: u16 = nums[4].parse().unwrap();
        let p2: u16 = nums[5].parse().unwrap();
        assert_eq!(format!("{h1}.{h2}.{h3}.{h4}"), "10.20.30.40");
        assert_eq!(p1 * 256 + p2, 5000);
    }

    #[tokio::test]
    async fn send_command_format() {
        let mut buf = Vec::new();
        send_command(&mut buf, "USER test").await.unwrap();
        assert_eq!(buf, b"USER test\r\n");
    }

    #[tokio::test]
    async fn send_command_feat() {
        let mut buf = Vec::new();
        send_command(&mut buf, "FEAT").await.unwrap();
        assert_eq!(buf, b"FEAT\r\n");
    }

    #[tokio::test]
    async fn read_auth_tls_response() {
        let data = b"234 AUTH TLS OK\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 234);
        assert!(resp.is_complete());
    }

    #[tokio::test]
    async fn read_pbsz_response() {
        let data = b"200 PBSZ=0\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 200);
        assert!(resp.is_complete());
    }

    #[tokio::test]
    async fn read_prot_p_response() {
        let data = b"200 Protection set to Private\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let resp = read_response(&mut reader).await.unwrap();
        assert_eq!(resp.code, 200);
        assert!(resp.is_complete());
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn tls_connector_no_alpn_creates_ok() {
        let tls_config = crate::tls::TlsConfig::default();
        let connector = crate::tls::TlsConnector::new_no_alpn(&tls_config);
        assert!(connector.is_ok());
    }
}
