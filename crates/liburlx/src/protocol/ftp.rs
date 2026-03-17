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

/// Configuration options for FTP transfers.
///
/// Controls passive/active mode selection, directory creation,
/// CWD strategy, and account handling.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // These are independent FTP options, not state flags
pub struct FtpConfig {
    /// Use EPSV (extended passive) instead of PASV (default: true).
    pub use_epsv: bool,
    /// Use EPRT (extended active) instead of PORT (default: true).
    pub use_eprt: bool,
    /// Skip the IP from the PASV response, use control connection IP.
    pub skip_pasv_ip: bool,
    /// FTP account string (sent via ACCT after login).
    pub account: Option<String>,
    /// Create missing directories on server during upload.
    pub create_dirs: bool,
    /// Directory traversal method.
    pub method: FtpMethod,
    /// Active mode address (None = passive mode).
    pub active_port: Option<String>,
    /// Use ASCII transfer mode (`--use-ascii` / `-B`).
    pub use_ascii: bool,
    /// Append to remote file instead of overwriting (`--append` / `-a`).
    pub append: bool,
    /// Convert LF to CRLF on upload (`--crlf`).
    pub crlf: bool,
    /// List only (NLST instead of LIST; `-l` / `--list-only`).
    pub list_only: bool,
    /// HEAD request — only get file info, no data transfer (`-I` / `--head`).
    pub nobody: bool,
    /// Pre-transfer FTP quote commands (from `-Q "CMD"`).
    pub pre_quote: Vec<String>,
    /// Post-transfer FTP quote commands (from `-Q "-CMD"`).
    pub post_quote: Vec<String>,
    /// Time condition for conditional download (-z).
    /// `Some((timestamp, negate))` where `negate=false` means download if newer,
    /// `negate=true` means download if older.
    pub time_condition: Option<(i64, bool)>,
    /// End byte for range download (e.g., `-r 4-16` → `range_end = Some(16)`).
    /// When set, ABOR is sent after reading `range_end - start + 1` bytes.
    pub range_end: Option<u64>,
    /// Skip SIZE command (`--ignore-content-length`).
    pub ignore_content_length: bool,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            use_epsv: true,
            use_eprt: true,
            skip_pasv_ip: false,
            account: None,
            create_dirs: false,
            method: FtpMethod::default(),
            active_port: None,
            use_ascii: false,
            append: false,
            crlf: false,
            list_only: false,
            nobody: false,
            pre_quote: Vec::new(),
            post_quote: Vec::new(),
            time_condition: None,
            range_end: None,
            ignore_content_length: false,
        }
    }
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
    /// FTP transfer configuration.
    config: FtpConfig,
}

impl FtpSession {
    /// Connect to an FTP server and log in (plain FTP, no TLS).
    ///
    /// # Errors
    ///
    /// Returns an error if connection, login, or greeting fails.
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        config: FtpConfig,
    ) -> Result<Self, Error> {
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

        let active_port = config.active_port.clone();
        let mut session = Self {
            reader,
            writer,
            features: None,
            hostname: host.to_string(),
            local_addr,
            use_tls_data: false,
            active_port,
            #[cfg(feature = "rustls")]
            tls_connector: None,
            config,
        };

        // Login
        session.login(user, pass).await?;

        // Send ACCT command if configured
        if let Some(ref account) = session.config.account {
            let acct_cmd = format!("ACCT {account}");
            send_command(&mut session.writer, &acct_cmd).await?;
            let acct_resp = read_response(&mut session.reader).await?;
            if !acct_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP ACCT failed: {} {}",
                    acct_resp.code, acct_resp.message
                )));
            }
        }

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
        config: FtpConfig,
    ) -> Result<Self, Error> {
        if ssl_mode == FtpSslMode::None {
            return Self::connect(host, port, user, pass, config).await;
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

        let active_port = config.active_port.clone();
        let mut session = Self {
            reader,
            writer,
            features: None,
            hostname: host.to_string(),
            local_addr,
            use_tls_data: false,
            active_port,
            tls_connector: Some(tls_connector),
            config,
        };

        // For explicit FTPS, upgrade the control connection to TLS
        if ssl_mode == FtpSslMode::Explicit {
            session = session.auth_tls().await?;
        }

        // Set up data channel protection (PBSZ 0 + PROT P)
        session.setup_data_protection().await?;

        // Login
        session.login(user, pass).await?;

        // Send ACCT command if configured
        if let Some(ref account) = session.config.account {
            let acct_cmd = format!("ACCT {account}");
            send_command(&mut session.writer, &acct_cmd).await?;
            let acct_resp = read_response(&mut session.reader).await?;
            if !acct_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP ACCT failed: {} {}",
                    acct_resp.code, acct_resp.message
                )));
            }
        }

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
            config: self.config,
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
    ///
    /// Returns `Error::Transfer { code: 67, .. }` on login failure (`CURLE_LOGIN_DENIED`).
    async fn login(&mut self, user: &str, pass: &str) -> Result<(), Error> {
        send_command(&mut self.writer, &format!("USER {user}")).await?;
        let user_resp = read_response(&mut self.reader).await?;

        if user_resp.code == 331 {
            // 331 = User name OK, need password
            send_command(&mut self.writer, &format!("PASS {pass}")).await?;
            let pass_resp = read_response(&mut self.reader).await?;
            // 332 = Need account for login (ACCT will be sent separately)
            if !pass_resp.is_complete() && pass_resp.code != 332 {
                return Err(Error::Transfer {
                    code: 67,
                    message: format!("Access denied: {} {}", pass_resp.code, pass_resp.message),
                });
            }
        } else if user_resp.is_complete() {
            // 230 = Logged in without needing password
        } else {
            return Err(Error::Transfer {
                code: 67,
                message: format!("Access denied: {} {}", user_resp.code, user_resp.message),
            });
        }

        Ok(())
    }

    /// Send PWD and ignore errors (curl always tries PWD but continues on failure).
    async fn pwd_safe(&mut self) -> Option<String> {
        if send_command(&mut self.writer, "PWD").await.is_err() {
            return None;
        }
        match read_response(&mut self.reader).await {
            Ok(resp) if resp.is_complete() => {
                // Parse path from 257 "/path"
                if let Some(start) = resp.message.find('"') {
                    if let Some(end) = resp.message[start + 1..].find('"') {
                        return Some(resp.message[start + 1..start + 1 + end].to_string());
                    }
                }
                Some(resp.message)
            }
            _ => None,
        }
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

    /// Enter passive mode and open a data connection (EPSV or PASV).
    ///
    /// If `config.use_epsv` is true, tries EPSV first and falls back to PASV.
    /// If `config.skip_pasv_ip` is true, uses the control connection host
    /// instead of the IP from the PASV response.
    ///
    /// Returns `Error::Transfer { code: 13, .. }` if both EPSV and PASV fail.
    async fn open_passive_data_connection(&mut self) -> Result<FtpStream, Error> {
        // Try EPSV first if enabled
        if self.config.use_epsv {
            send_command(&mut self.writer, "EPSV").await?;
            let epsv_resp = read_response(&mut self.reader).await?;
            if epsv_resp.code == 229 {
                let data_port = parse_epsv_response(&epsv_resp.message)?;
                let data_addr = format!("{}:{data_port}", self.hostname);
                let tcp = TcpStream::connect(&data_addr)
                    .await
                    .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;
                return self.maybe_wrap_data_tls(tcp).await;
            }
            // EPSV failed (e.g. 500/502), fall through to PASV
        }

        send_command(&mut self.writer, "PASV").await?;
        let pasv_resp = read_response(&mut self.reader).await?;
        if pasv_resp.code != 227 {
            return Err(Error::Transfer {
                code: 13,
                message: format!("FTP PASV failed: {} {}", pasv_resp.code, pasv_resp.message),
            });
        }
        let (data_host, data_port) = parse_pasv_response(&pasv_resp.message)?;

        // If skip_pasv_ip is set, use the control connection host instead of
        // the IP address returned in the PASV response.
        let effective_host =
            if self.config.skip_pasv_ip { self.hostname.clone() } else { data_host };

        let data_addr = format!("{effective_host}:{data_port}");
        let tcp = TcpStream::connect(&data_addr)
            .await
            .map_err(|e| Error::Http(format!("FTP data connection failed: {e}")))?;

        self.maybe_wrap_data_tls(tcp).await
    }

    /// Open a data connection in active mode (PORT/EPRT).
    ///
    /// Binds a listener on a local port, sends PORT/EPRT to the server,
    /// and waits for the server to connect.
    ///
    /// When `config.use_eprt` is true and the address is IPv4, tries EPRT first
    /// and falls back to PORT on failure (curl behavior for IPv6-capable builds).
    ///
    /// Returns `Error::Transfer { code: 30, .. }` if both EPRT and PORT fail.
    async fn open_active_data_connection(&mut self, bind_addr: &str) -> Result<FtpStream, Error> {
        // Determine the IP to advertise in PORT/EPRT.
        // `-` means use the control connection's local address.
        // An explicit IP means advertise that IP (but bind locally).
        let advertise_ip: std::net::IpAddr = if bind_addr == "-" {
            self.local_addr.ip()
        } else {
            bind_addr.parse().map_err(|e| {
                Error::Http(format!("Invalid FTP active address '{bind_addr}': {e}"))
            })?
        };

        // Bind to local address (0.0.0.0:0 or the advertise IP if it's local)
        let bind_ip = if bind_addr == "-" {
            self.local_addr.ip()
        } else {
            // Try binding to the specified IP; if it's non-local, bind to 0.0.0.0
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };
        let bind = SocketAddr::new(bind_ip, 0);
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| Error::Http(format!("FTP active mode bind failed: {e}")))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| Error::Http(format!("FTP active mode local_addr failed: {e}")))?;
        // Use the advertised IP with the locally assigned port
        let advertise_addr = SocketAddr::new(advertise_ip, listen_addr.port());
        let local_ip = advertise_ip;

        // Send PORT or EPRT depending on address family and config.
        // For IPv6, EPRT is always required (PORT doesn't support IPv6).
        // For IPv4, try EPRT first if use_eprt is true, fall back to PORT.
        let mut port_ok = false;

        if local_ip.is_ipv6() || self.config.use_eprt {
            let eprt_cmd = format_eprt_command(&advertise_addr);
            send_command(&mut self.writer, &eprt_cmd).await?;
            let resp = read_response(&mut self.reader).await?;
            if resp.is_complete() {
                port_ok = true;
            } else if local_ip.is_ipv6() {
                // IPv6 has no PORT fallback
                return Err(Error::Transfer {
                    code: 30,
                    message: format!("FTP EPRT failed: {} {}", resp.code, resp.message),
                });
            }
            // IPv4 EPRT failed, fall through to PORT
        }

        if !port_ok && local_ip.is_ipv4() {
            let port_cmd = format_port_command(&advertise_addr);
            send_command(&mut self.writer, &port_cmd).await?;
            let resp = read_response(&mut self.reader).await?;
            if !resp.is_complete() {
                return Err(Error::Transfer {
                    code: 30,
                    message: format!("FTP PORT failed: {} {}", resp.code, resp.message),
                });
            }
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

    /// Navigate to the directory containing a file and return the effective
    /// filename for RETR/STOR, according to the configured `FtpMethod`.
    ///
    /// - `NoCwd`: returns the full path unchanged (no CWD commands).
    /// - `SingleCwd`: issues one CWD to the directory portion, returns the filename.
    /// - `MultiCwd`: issues CWD for each path component, returns the filename.
    ///
    /// # Errors
    ///
    /// Returns an error if any CWD command fails.
    #[allow(dead_code)]
    async fn navigate_to_path(&mut self, path: &str) -> Result<String, Error> {
        match self.config.method {
            FtpMethod::NoCwd => Ok(path.to_string()),
            FtpMethod::SingleCwd => {
                if let Some((dir, file)) = path.rsplit_once('/') {
                    if !dir.is_empty() {
                        self.cwd(dir).await?;
                    }
                    Ok(file.to_string())
                } else {
                    Ok(path.to_string())
                }
            }
            FtpMethod::MultiCwd => {
                if let Some((dir, file)) = path.rsplit_once('/') {
                    for component in dir.split('/') {
                        if !component.is_empty() {
                            self.cwd(component).await?;
                        }
                    }
                    Ok(file.to_string())
                } else {
                    Ok(path.to_string())
                }
            }
        }
    }

    /// Create missing directories on the server for the given path.
    ///
    /// Tries MKD for each component. If CWD succeeds, the directory
    /// already exists. If CWD fails, MKD is attempted before retrying CWD.
    /// After creating directories, CWDs back to `/` so subsequent
    /// commands use absolute paths.
    ///
    /// # Errors
    ///
    /// Returns an error if a directory cannot be created.
    #[allow(dead_code)]
    async fn create_dirs(&mut self, dir_path: &str) -> Result<(), Error> {
        for component in dir_path.split('/') {
            if component.is_empty() {
                continue;
            }
            // Try CWD first — the directory may already exist
            send_command(&mut self.writer, &format!("CWD {component}")).await?;
            let cwd_resp = read_response(&mut self.reader).await?;
            if cwd_resp.is_complete() {
                continue;
            }
            // CWD failed — try MKD then CWD again
            send_command(&mut self.writer, &format!("MKD {component}")).await?;
            let mkd_resp = read_response(&mut self.reader).await?;
            if !mkd_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP MKD failed for '{}': {} {}",
                    component, mkd_resp.code, mkd_resp.message
                )));
            }
            send_command(&mut self.writer, &format!("CWD {component}")).await?;
            let retry_resp = read_response(&mut self.reader).await?;
            if !retry_resp.is_complete() {
                return Err(Error::Http(format!(
                    "FTP CWD failed after MKD for '{}': {} {}",
                    component, retry_resp.code, retry_resp.message
                )));
            }
        }
        // CWD back to root so we don't affect subsequent absolute path commands
        let _ = self.cwd("/").await;
        Ok(())
    }

    /// Close the FTP session (QUIT).
    ///
    /// Sends QUIT and reads the response. Errors are ignored since
    /// we're closing the connection anyway.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the QUIT command fails.
    pub async fn quit(mut self) -> Result<(), Error> {
        let _ = send_command(&mut self.writer, "QUIT").await;
        // Read the QUIT response with a short timeout (server may close
        // connection or exit before responding). Ignore all errors.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            read_response(&mut self.reader),
        )
        .await;
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
    config: FtpConfig,
) -> Result<FtpSession, Error> {
    match ssl_mode {
        FtpSslMode::None => FtpSession::connect(host, port, user, pass, config).await,
        #[cfg(feature = "rustls")]
        _ => {
            FtpSession::connect_with_tls(host, port, user, pass, ssl_mode, tls_config, config).await
        }
        #[cfg(not(feature = "rustls"))]
        _ => {
            let _ = (tls_config, config);
            Err(Error::Http("FTPS requires the 'rustls' feature".to_string()))
        }
    }
}

/// Perform an FTP transfer (download, listing, upload, or HEAD) and return a Response.
///
/// This is the unified entry point for all FTP operations. The operation is
/// determined from the URL path (trailing `/` = listing) and config flags
/// (`nobody` = HEAD, upload data = STOR/APPE).
///
/// The command sequence matches curl's behavior:
/// 1. Connect + greeting
/// 2. USER / PASS
/// 3. PWD
/// 4. CWD (per path components, according to `FtpMethod`)
/// 5. Pre-quote commands
/// 6. EPSV / PASV (or PORT/EPRT for active mode)
/// 7. TYPE A or TYPE I
/// 8. SIZE (for downloads)
/// 9. REST (for resume)
/// 10. RETR / LIST / STOR / APPE
/// 11. Post-quote commands
/// 12. QUIT
///
/// # Errors
///
/// Returns errors with specific `Transfer` codes matching curl's exit codes:
/// - 9: `CURLE_REMOTE_ACCESS_DENIED` (CWD failed)
/// - 13: `CURLE_FTP_WEIRD_PASV_REPLY` (PASV/EPSV failed)
/// - 17: `CURLE_FTP_COULDNT_SET_TYPE` (TYPE failed)
/// - 19: `CURLE_FTP_COULDNT_RETR_FILE` (RETR/SIZE failed)
/// - 25: `CURLE_UPLOAD_FAILED` (STOR/APPE failed)
/// - 30: `CURLE_FTP_PORT_FAILED` (PORT/EPRT failed)
/// - 36: `CURLE_BAD_DOWNLOAD_RESUME` (resume offset beyond file size)
/// - 67: `CURLE_LOGIN_DENIED` (USER/PASS rejected)
#[allow(clippy::too_many_lines)]
pub async fn perform(
    url: &crate::url::Url,
    upload_data: Option<&[u8]>,
    ssl_mode: FtpSslMode,
    tls_config: &crate::tls::TlsConfig,
    resume_from: Option<u64>,
    config: &FtpConfig,
    credentials: Option<(&str, &str)>,
) -> Result<Response, Error> {
    let range_end = config.range_end;
    let (host, port) = url.host_and_port()?;
    let raw_path = url.path();

    // Percent-decode the path for FTP
    let decoded_path = percent_decode(raw_path);
    let path = decoded_path.as_str();

    // Use provided credentials, URL credentials, or anonymous with curl-compatible password.
    // URL credentials are percent-decoded (test 191: ftp://use%3fr:pass%3fword@host/).
    let url_creds = url.credentials();
    let decoded_user;
    let decoded_pass;
    #[allow(clippy::option_if_let_else)]
    let (user, pass) = if let Some(creds) = credentials {
        creds
    } else if let Some((raw_user, raw_pass)) = url_creds {
        decoded_user = percent_decode(raw_user);
        decoded_pass = percent_decode(raw_pass);
        (decoded_user.as_str(), decoded_pass.as_str())
    } else {
        ("anonymous", "ftp@example.com")
    };

    // Determine if this is a directory listing (path ends with '/')
    let is_dir_list = path.ends_with('/') && upload_data.is_none();

    // Parse ;type=A or ;type=I from path (RFC 1738 FTP URL type)
    let (effective_path, type_override) = parse_ftp_type(path);

    let mut session =
        connect_session(&host, port, user, pass, ssl_mode, tls_config, config.clone()).await?;

    // PWD after login (curl always sends this)
    let _pwd = session.pwd_safe().await;

    // Navigate to directory via CWD commands
    let (dir_components, filename) = if is_dir_list {
        // For listings, the entire path is the directory
        let trimmed = effective_path.trim_start_matches('/');
        let trimmed = trimmed.trim_end_matches('/');
        if trimmed.is_empty() {
            // Root directory listing.
            // ftp://host/ (single slash) = relative root, no CWD needed (test 101)
            // ftp://host// (double slash) = absolute path to /, CWD / needed (tests 350, 352)
            if config.method == FtpMethod::NoCwd || !effective_path.starts_with("//") {
                (Vec::new(), String::new())
            } else {
                (vec!["/"], String::new())
            }
        } else {
            let components: Vec<&str> = trimmed.split('/').collect();
            (components, String::new())
        }
    } else {
        // For file operations, split directory from filename
        split_path_for_method(effective_path, config.method)
    };

    // Perform CWD navigation
    for component in &dir_components {
        if component.is_empty() {
            continue;
        }
        send_command(&mut session.writer, &format!("CWD {component}")).await?;
        let cwd_resp = read_response(&mut session.reader).await?;
        if !cwd_resp.is_complete() {
            if config.create_dirs {
                // --ftp-create-dirs: try MKD then retry CWD
                send_command(&mut session.writer, &format!("MKD {component}")).await?;
                let _mkd_resp = read_response(&mut session.reader).await?;
                // Always retry CWD after MKD, even if MKD failed (curl compat)
                send_command(&mut session.writer, &format!("CWD {component}")).await?;
                let retry_resp = read_response(&mut session.reader).await?;
                if !retry_resp.is_complete() {
                    let _ = session.quit().await;
                    return Err(Error::Transfer {
                        code: 9,
                        message: format!(
                            "FTP CWD failed after MKD: {} {}",
                            retry_resp.code, retry_resp.message
                        ),
                    });
                }
            } else if cwd_resp.code == 421 {
                // 421 = Service not available / timeout. Don't send QUIT —
                // the server is closing the connection (curl compat: test 1120).
                return Err(Error::Transfer {
                    code: 28,
                    message: format!("FTP server timeout: {} {}", cwd_resp.code, cwd_resp.message),
                });
            } else {
                // CWD failed - send QUIT and return error code 9
                let _ = session.quit().await;
                return Err(Error::Transfer {
                    code: 9,
                    message: format!("FTP CWD failed: {} {}", cwd_resp.code, cwd_resp.message),
                });
            }
        }
    }

    // Pre-quote commands (sent after CWD, before data transfer)
    for cmd in &config.pre_quote {
        send_command(&mut session.writer, cmd).await?;
        let resp = read_response(&mut session.reader).await?;
        if !resp.is_complete() && !resp.is_preliminary() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 21,
                message: format!(
                    "FTP quote command '{cmd}' failed: {} {}",
                    resp.code, resp.message
                ),
            });
        }
    }

    // HEAD/nobody mode: only get file metadata, no data transfer.
    // For directory listings (-I on a directory), just QUIT after CWD (curl compat: test 1000).
    if config.nobody {
        if is_dir_list {
            let _ = session.quit().await;
            let headers = std::collections::HashMap::new();
            return Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()));
        }
        let mut last_modified: Option<String> = None;
        let mut content_length: Option<String> = None;

        // MDTM (modification time)
        if !filename.is_empty() {
            send_command(&mut session.writer, &format!("MDTM {filename}")).await?;
            let mdtm_resp = read_response(&mut session.reader).await?;
            if mdtm_resp.is_complete() {
                let mdtm_str = mdtm_resp.message.trim();
                if let Some(date) = format_mdtm_as_http_date(mdtm_str) {
                    last_modified = Some(date);
                }
            }
        }

        // TYPE I for SIZE
        send_command(&mut session.writer, "TYPE I").await?;
        let type_resp = read_response(&mut session.reader).await?;
        if !type_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 17,
                message: format!("FTP TYPE failed: {} {}", type_resp.code, type_resp.message),
            });
        }

        // SIZE
        if !filename.is_empty() {
            send_command(&mut session.writer, &format!("SIZE {filename}")).await?;
            let size_resp = read_response(&mut session.reader).await?;
            if size_resp.is_complete() {
                content_length = Some(size_resp.message.trim().to_string());
            }
        }

        // REST 0 (curl sends this in HEAD mode)
        send_command(&mut session.writer, "REST 0").await?;
        let _rest_resp = read_response(&mut session.reader).await?;

        let _ = session.quit().await;

        // Build FTP HEAD output as pseudo-HTTP headers (curl compat)
        let mut body_text = String::new();
        if let Some(ref lm) = last_modified {
            body_text.push_str("Last-Modified: ");
            body_text.push_str(lm);
            body_text.push_str("\r\n");
        }
        if let Some(ref cl) = content_length {
            body_text.push_str("Content-Length: ");
            body_text.push_str(cl);
            body_text.push_str("\r\n");
        }
        body_text.push_str("Accept-ranges: bytes\r\n");

        let mut headers = std::collections::HashMap::new();
        if let Some(ref cl) = content_length {
            let _old = headers.insert("content-length".to_string(), cl.clone());
        }
        if let Some(ref lm) = last_modified {
            let _old = headers.insert("last-modified".to_string(), lm.clone());
        }
        return Ok(Response::new(200, headers, body_text.into_bytes(), url.as_str().to_string()));
    }

    // For uploads
    if let Some(upload_bytes) = upload_data {
        // Handle upload resume: skip bytes and use APPE
        let (effective_upload_data, use_appe) = if let Some(offset) = resume_from {
            #[allow(clippy::cast_possible_truncation)]
            let offset_usize = offset as usize;
            if offset_usize >= upload_bytes.len() {
                // Upload resume beyond file size: send EPSV + TYPE I then QUIT
                // (curl sends these commands even when nothing to upload)
                let _ = session.open_data_connection().await;
                send_command(&mut session.writer, "TYPE I").await?;
                let _ = read_response(&mut session.reader).await;
                let _ = session.quit().await;
                let headers = std::collections::HashMap::new();
                return Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()));
            }
            (&upload_bytes[offset_usize..], true)
        } else {
            (upload_bytes, config.append)
        };

        // Open data connection
        let data_stream_result = session.open_data_connection().await;
        let mut data_stream = match data_stream_result {
            Ok(s) => s,
            Err(e) => {
                let _ = session.quit().await;
                return Err(e);
            }
        };

        // TYPE I for binary upload
        send_command(&mut session.writer, "TYPE I").await?;
        let type_resp = read_response(&mut session.reader).await?;
        if !type_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 17,
                message: format!("FTP TYPE failed: {} {}", type_resp.code, type_resp.message),
            });
        }

        // SIZE before upload for resume offset detection (curl compat: test 362)
        // Only send SIZE for resume, not for plain --append (curl compat: test 109)
        let mut use_appe_effective = use_appe;
        if resume_from.is_some() {
            send_command(&mut session.writer, &format!("SIZE {filename}")).await?;
            let size_resp = read_response(&mut session.reader).await?;
            if !size_resp.is_complete() {
                // File doesn't exist — use STOR instead of APPE
                use_appe_effective = false;
            }
        }

        // STOR or APPE
        let stor_cmd = if use_appe_effective {
            format!("APPE {filename}")
        } else {
            format!("STOR {filename}")
        };
        send_command(&mut session.writer, &stor_cmd).await?;
        let stor_resp = read_response(&mut session.reader).await?;
        if !stor_resp.is_preliminary() && !stor_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 25,
                message: format!("FTP STOR/APPE failed: {} {}", stor_resp.code, stor_resp.message),
            });
        }

        // Write data, optionally converting LF to CRLF
        if config.crlf {
            let converted = lf_to_crlf(effective_upload_data);
            data_stream
                .write_all(&converted)
                .await
                .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        } else {
            data_stream
                .write_all(effective_upload_data)
                .await
                .map_err(|e| Error::Http(format!("FTP data write error: {e}")))?;
        }
        data_stream
            .shutdown()
            .await
            .map_err(|e| Error::Http(format!("FTP data shutdown error: {e}")))?;
        drop(data_stream);

        let complete_resp = read_response(&mut session.reader).await?;
        if !complete_resp.is_complete() {
            let _ = session.quit().await;
            // 452/552 = disk full (curl returns CURLE_REMOTE_DISK_FULL = 70)
            let code = if complete_resp.code == 452 || complete_resp.code == 552 { 70 } else { 25 };
            return Err(Error::Transfer {
                code,
                message: format!(
                    "FTP upload failed: {} {}",
                    complete_resp.code, complete_resp.message
                ),
            });
        }

        // Post-quote commands
        for cmd in &config.post_quote {
            send_command(&mut session.writer, cmd).await?;
            let resp = read_response(&mut session.reader).await?;
            if !resp.is_complete() && !resp.is_preliminary() {
                let _ = session.quit().await;
                return Err(Error::Transfer {
                    code: 21,
                    message: format!(
                        "FTP quote command '{cmd}' failed: {} {}",
                        resp.code, resp.message
                    ),
                });
            }
        }

        let _ = session.quit().await;
        let headers = std::collections::HashMap::new();
        return Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()));
    }

    // Directory listing
    if is_dir_list {
        // Open data connection
        let data_stream_result = session.open_data_connection().await;
        let mut data_stream = match data_stream_result {
            Ok(s) => s,
            Err(e) => {
                let _ = session.quit().await;
                return Err(e);
            }
        };

        // TYPE A for directory listings
        send_command(&mut session.writer, "TYPE A").await?;
        let type_resp = read_response(&mut session.reader).await?;
        if !type_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 17,
                message: format!("FTP TYPE failed: {} {}", type_resp.code, type_resp.message),
            });
        }

        // LIST or NLST — for NoCwd, include path in the command (test 351)
        let list_base = if config.list_only { "NLST" } else { "LIST" };
        let list_cmd = if config.method == FtpMethod::NoCwd {
            let path = effective_path.trim_end_matches('/');
            if path.is_empty() {
                format!("{list_base} /")
            } else {
                format!("{list_base} {path}")
            }
        } else {
            list_base.to_string()
        };
        send_command(&mut session.writer, &list_cmd).await?;
        let list_resp = read_response(&mut session.reader).await?;
        if !list_resp.is_preliminary() && !list_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 19,
                message: format!("FTP LIST failed: {} {}", list_resp.code, list_resp.message),
            });
        }

        let mut data = Vec::new();
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);

        // Read 226 Transfer Complete
        if list_resp.is_preliminary() {
            let complete_resp = read_response(&mut session.reader).await?;
            if !complete_resp.is_complete() {
                let _ = session.quit().await;
                return Err(Error::Http(format!(
                    "FTP transfer failed: {} {}",
                    complete_resp.code, complete_resp.message
                )));
            }
        }

        // Post-quote commands
        for cmd in &config.post_quote {
            send_command(&mut session.writer, cmd).await?;
            let resp = read_response(&mut session.reader).await?;
            if !resp.is_complete() && !resp.is_preliminary() {
                let _ = session.quit().await;
                return Err(Error::Transfer {
                    code: 21,
                    message: format!(
                        "FTP quote command '{cmd}' failed: {} {}",
                        resp.code, resp.message
                    ),
                });
            }
        }

        let _ = session.quit().await;
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-length".to_string(), data.len().to_string());
        return Ok(Response::new(200, headers, data, url.as_str().to_string()));
    }

    // File download (RETR)
    // Determine transfer type
    let use_ascii = type_override.unwrap_or(if config.use_ascii {
        TransferType::Ascii
    } else {
        TransferType::Binary
    }) == TransferType::Ascii;

    // FTP -z: send MDTM before download to check file modification time
    if let Some((cond_ts, negate)) = config.time_condition {
        send_command(&mut session.writer, &format!("MDTM {filename}")).await?;
        let mdtm_resp = read_response(&mut session.reader).await?;
        if mdtm_resp.is_complete() {
            // Parse MDTM response: "YYYYMMDDHHMMSS"
            let mdtm_str = mdtm_resp.message.trim();
            if let Some(file_ts) = parse_mdtm_timestamp(mdtm_str) {
                let should_skip = if negate {
                    // -z -date: download if file is older than date
                    file_ts >= cond_ts
                } else {
                    // -z date: download if file is newer than date
                    file_ts <= cond_ts
                };
                if should_skip {
                    let _ = session.quit().await;
                    let headers = std::collections::HashMap::new();
                    return Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()));
                }
            }
        }
    }

    // Open data connection BEFORE TYPE/SIZE (curl sends EPSV/PASV before TYPE)
    let data_stream_result = session.open_data_connection().await;
    let mut data_stream = match data_stream_result {
        Ok(s) => s,
        Err(e) => {
            let _ = session.quit().await;
            return Err(e);
        }
    };

    // TYPE
    let type_cmd = if use_ascii { "TYPE A" } else { "TYPE I" };
    send_command(&mut session.writer, type_cmd).await?;
    let type_resp = read_response(&mut session.reader).await?;
    if !type_resp.is_complete() {
        drop(data_stream);
        let _ = session.quit().await;
        return Err(Error::Transfer {
            code: 17,
            message: format!("FTP TYPE failed: {} {}", type_resp.code, type_resp.message),
        });
    }

    // SIZE (curl always tries SIZE before RETR for non-ASCII transfers)
    // Skip SIZE when --ignore-content-length is set (curl compat: test 1137)
    let mut remote_size: Option<u64> = None;
    if !use_ascii && !config.ignore_content_length {
        send_command(&mut session.writer, &format!("SIZE {filename}")).await?;
        let size_resp = read_response(&mut session.reader).await?;
        if size_resp.is_complete() {
            if let Ok(sz) = size_resp.message.trim().parse::<u64>() {
                remote_size = Some(sz);
            }
        }
        // SIZE failure is not fatal for download (may fail with 500)
    }

    // Resume check: if resume offset >= file size, it's an error
    if let Some(offset) = resume_from {
        if let Some(sz) = remote_size {
            if offset > sz {
                drop(data_stream);
                let _ = session.quit().await;
                return Err(Error::Transfer {
                    code: 36,
                    message: format!("Offset ({offset}) was beyond the end of the file ({sz})"),
                });
            }
            if offset == sz {
                // File already fully downloaded
                drop(data_stream);
                let _ = session.quit().await;
                let headers = std::collections::HashMap::new();
                return Ok(Response::new(200, headers, Vec::new(), url.as_str().to_string()));
            }
        }

        // REST
        send_command(&mut session.writer, &format!("REST {offset}")).await?;
        let rest_resp = read_response(&mut session.reader).await?;
        if !rest_resp.is_intermediate() {
            drop(data_stream);
            let _ = session.quit().await;
            return Err(Error::Transfer {
                code: 36,
                message: format!("FTP REST failed: {} {}", rest_resp.code, rest_resp.message),
            });
        }
    }

    // RETR
    send_command(&mut session.writer, &format!("RETR {filename}")).await?;
    let retr_resp = read_response(&mut session.reader).await?;
    if !retr_resp.is_preliminary() && !retr_resp.is_complete() {
        drop(data_stream);
        let _ = session.quit().await;
        return Err(Error::Transfer {
            code: 19,
            message: format!("FTP RETR failed: {} {}", retr_resp.code, retr_resp.message),
        });
    }

    let mut data = Vec::new();

    // If range_end is set, read only (end - start + 1) bytes, then ABOR
    let start_offset = resume_from.unwrap_or(0);
    if let Some(end) = range_end {
        #[allow(clippy::cast_possible_truncation)]
        let max_bytes = (end - start_offset + 1) as usize;
        let mut limited = data_stream.take(max_bytes as u64);
        let _ = limited
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(limited);
        // Send ABOR to terminate the transfer early
        send_command(&mut session.writer, "ABOR").await?;
        // Ignore response (may be 426 or 226)
        let _ = read_response(&mut session.reader).await;
    } else {
        let _ = data_stream
            .read_to_end(&mut data)
            .await
            .map_err(|e| Error::Http(format!("FTP data read error: {e}")))?;
        drop(data_stream);
    }

    // Check for partial file: if we know the expected size and got less data,
    // return CURLE_PARTIAL_FILE (18) without sending QUIT (curl compat: test 161).
    // Return the partial data so the CLI can still output it.
    if range_end.is_none() {
        if let Some(expected) = remote_size {
            let actual = data.len() as u64 + resume_from.unwrap_or(0);
            if actual < expected {
                // Don't send QUIT — just drop the session (curl compat)
                let mut headers = std::collections::HashMap::new();
                let _old = headers.insert("content-length".to_string(), data.len().to_string());
                let mut resp = Response::new(200, headers, data, url.as_str().to_string());
                resp.set_body_error(Some("partial".to_string()));
                return Ok(resp);
            }
        }
    }

    // Read 226 Transfer Complete
    if retr_resp.is_preliminary() && range_end.is_none() {
        let complete_resp = read_response(&mut session.reader).await?;
        if !complete_resp.is_complete() {
            let _ = session.quit().await;
            return Err(Error::Http(format!(
                "FTP transfer failed: {} {}",
                complete_resp.code, complete_resp.message
            )));
        }
    }

    // Post-quote commands
    for cmd in &config.post_quote {
        send_command(&mut session.writer, cmd).await?;
        let resp = read_response(&mut session.reader).await?;
        if !resp.is_complete() && !resp.is_preliminary() {
            // Post-quote failure is not fatal — continue with QUIT (curl compat)
        }
    }

    let _ = session.quit().await;

    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), data.len().to_string());

    Ok(Response::new(200, headers, data, url.as_str().to_string()))
}

/// Percent-decode a URL path component.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        result.push(val as char);
                        continue;
                    }
                }
                // Not valid hex, keep literal
                result.push('%');
                result.push(h as char);
                result.push(l as char);
            } else {
                result.push('%');
            }
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Parse an MDTM timestamp "YYYYMMDDHHMMSS" into a Unix timestamp (seconds since epoch).
fn parse_mdtm_timestamp(s: &str) -> Option<i64> {
    if s.len() < 14 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[4..6].parse().ok()?;
    let day: i64 = s[6..8].parse().ok()?;
    let hour: i64 = s[8..10].parse().ok()?;
    let min: i64 = s[10..12].parse().ok()?;
    let sec: i64 = s[12..14].parse().ok()?;

    // Simplified conversion to Unix timestamp (good enough for date comparison)
    // This doesn't account for leap seconds but is sufficient for -z comparisons.
    let days = days_from_date(year, month, day)?;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Calculate days since Unix epoch from a date.
fn days_from_date(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Months to days (non-leap year)
    let month_days: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let m = (month - 1) as usize;

    let y = year - 1970;
    let leap_years = if year > 1970 {
        ((year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400)
            - (1969 / 4 - 1969 / 100 + 1969 / 400)
    } else {
        0
    };
    let mut days = y * 365 + leap_years + month_days[m] + day - 1;

    // Add leap day for current year if applicable
    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;
    }

    Some(days)
}

/// Format an MDTM timestamp as an HTTP-style "Last-Modified" date string.
fn format_mdtm_as_http_date(s: &str) -> Option<String> {
    if s.len() < 14 {
        return None;
    }
    let year: u32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let hour: u32 = s[8..10].parse().ok()?;
    let min: u32 = s[10..12].parse().ok()?;
    let sec: u32 = s[12..14].parse().ok()?;

    let month_names =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    #[allow(clippy::cast_sign_loss)]
    let month_name = month_names.get((month - 1) as usize)?;

    // Calculate day of week using Zeller-like formula
    let ts = parse_mdtm_timestamp(s)?;
    #[allow(clippy::cast_sign_loss)]
    let day_of_week = ((ts / 86400 + 4) % 7) as usize; // Jan 1, 1970 was Thursday (4)
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let dow = day_names.get(day_of_week)?;

    Some(format!("{dow}, {day:02} {month_name} {year} {hour:02}:{min:02}:{sec:02} GMT"))
}

/// Parse `;type=A` or `;type=I` suffix from FTP URL path (RFC 1738).
///
/// Returns the path without the type suffix and the parsed transfer type.
fn parse_ftp_type(path: &str) -> (&str, Option<TransferType>) {
    if let Some(pos) = path.rfind(";type=") {
        let type_str = &path[pos + 6..];
        let transfer_type = match type_str {
            "A" | "a" => Some(TransferType::Ascii),
            "I" | "i" => Some(TransferType::Binary),
            _ => None,
        };
        if transfer_type.is_some() {
            return (&path[..pos], transfer_type);
        }
    }
    (path, None)
}

/// Split a path into directory components and filename based on `FtpMethod`.
///
/// Returns `(dir_components, filename)`.
fn split_path_for_method(path: &str, method: FtpMethod) -> (Vec<&str>, String) {
    let trimmed = path.trim_start_matches('/');

    match method {
        FtpMethod::NoCwd => (Vec::new(), trimmed.to_string()),
        FtpMethod::SingleCwd => {
            if let Some((dir, file)) = trimmed.rsplit_once('/') {
                if dir.is_empty() {
                    // Path like "/filename" — CWD /
                    (vec!["/"], file.to_string())
                } else {
                    (vec![dir], file.to_string())
                }
            } else {
                (Vec::new(), trimmed.to_string())
            }
        }
        FtpMethod::MultiCwd => {
            if let Some((dir, file)) = trimmed.rsplit_once('/') {
                // Split the leading slash: if path starts with "/", first CWD should be "/"
                let mut components = Vec::new();
                if path.starts_with("//") {
                    // Absolute path like //path/to/file — first CWD is "/"
                    components.push("/");
                }
                for component in dir.split('/') {
                    if !component.is_empty() {
                        components.push(component);
                    }
                }
                (components, file.to_string())
            } else {
                (Vec::new(), trimmed.to_string())
            }
        }
    }
}

/// Convert LF line endings to CRLF.
fn lf_to_crlf(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() + data.len() / 10);
    for &byte in data {
        if byte == b'\n' {
            result.push(b'\r');
        }
        result.push(byte);
    }
    result
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
    config: &FtpConfig,
) -> Result<Response, Error> {
    perform(url, None, ssl_mode, tls_config, resume_from, config, None).await
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
    config: &FtpConfig,
) -> Result<Response, Error> {
    perform(url, None, ssl_mode, tls_config, None, config, None).await
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
    config: &FtpConfig,
) -> Result<Response, Error> {
    perform(url, Some(data), ssl_mode, tls_config, None, config, None).await
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

    #[test]
    fn ftp_config_default() {
        let config = FtpConfig::default();
        assert!(config.use_epsv);
        assert!(config.use_eprt);
        assert!(!config.skip_pasv_ip);
        assert!(config.account.is_none());
        assert!(!config.create_dirs);
        assert_eq!(config.method, FtpMethod::MultiCwd);
        assert!(config.active_port.is_none());
    }

    #[test]
    fn ftp_config_clone() {
        let config = FtpConfig {
            use_epsv: false,
            use_eprt: false,
            skip_pasv_ip: true,
            account: Some("myacct".to_string()),
            create_dirs: true,
            method: FtpMethod::NoCwd,
            active_port: Some("-".to_string()),
            ..Default::default()
        };
        #[allow(clippy::redundant_clone)] // Testing Clone impl
        let cloned = config.clone();
        assert!(!cloned.use_epsv);
        assert!(!cloned.use_eprt);
        assert!(cloned.skip_pasv_ip);
        assert_eq!(cloned.account.as_deref(), Some("myacct"));
        assert!(cloned.create_dirs);
        assert_eq!(cloned.method, FtpMethod::NoCwd);
        assert_eq!(cloned.active_port.as_deref(), Some("-"));
    }
}
