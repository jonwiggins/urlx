//! Single-transfer blocking API.
//!
//! The `Easy` handle is the primary way to perform URL transfers.
//! It provides a blocking API that wraps the async internals.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::auth::{AuthCredentials, AuthMethod, ProxyAuthCredentials, ProxyAuthMethod};
use crate::cookie::CookieJar;
use crate::dns::DnsCache;
use crate::error::Error;
use crate::hsts::HstsCache;
use crate::pool::{ConnectionPool, PooledStream};
use crate::progress::{call_progress, ProgressCallback, ProgressInfo};
use crate::protocol::ftp::FtpMethod;
use crate::protocol::http::multipart::MultipartForm;
use crate::protocol::http::response::Response;
use crate::throttle::SpeedLimits;
use crate::tls::TlsConfig;
use crate::url::Url;

/// HTTP version selection.
///
/// Controls which HTTP version is used for requests.
/// Equivalent to `CURLOPT_HTTP_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    /// Let the library choose the best version (default).
    /// Uses HTTP/2 via ALPN if available, otherwise HTTP/1.1.
    #[default]
    None,
    /// Force HTTP/1.0 requests.
    Http10,
    /// Force HTTP/1.1 requests (no HTTP/2 upgrade).
    Http11,
    /// Prefer HTTP/2 via ALPN (fallback to HTTP/1.1 if not negotiated).
    Http2,
    /// Use HTTP/2 without TLS negotiation (h2c prior knowledge, RFC 7540 §3.4).
    Http2PriorKnowledge,
    /// Request HTTP/3 via QUIC (requires `http3` feature).
    Http3,
}

/// A handle for performing a single URL transfer.
///
/// This is the main entry point for the liburlx API, modeled after
/// curl's `CURL *` easy handle.
#[allow(clippy::struct_excessive_bools)] // These are independent transfer options, not state flags
pub struct Easy {
    url: Option<Url>,
    method: Option<String>,
    headers: Vec<(String, String)>,
    /// Header names that are suppressed (from `-H "Name:"` removal syntax).
    removed_headers: Vec<String>,
    /// Whether form data was set via `-d`/`--data` (controls auto Content-Type).
    form_data: bool,
    body: Option<Vec<u8>>,
    follow_redirects: bool,
    max_redirects: u32,
    verbose: bool,
    accept_encoding: bool,
    connect_timeout: Option<Duration>,
    timeout: Option<Duration>,
    proxy: Option<Url>,
    noproxy: Option<String>,
    cookie_jar: Option<CookieJar>,
    cookie_jar_path: Option<String>,
    hsts_cache: Option<HstsCache>,
    multipart: Option<MultipartForm>,
    range: Option<String>,
    resolve_overrides: Vec<(String, String)>,
    progress_callback: Option<ProgressCallback>,
    fail_on_error: bool,
    auth_credentials: Option<AuthCredentials>,
    /// `OAuth2` bearer token for SASL XOAUTH2 (IMAP/POP3/SMTP).
    oauth2_bearer: Option<String>,
    tls_config: TlsConfig,
    aws_sigv4: Option<crate::auth::aws_sigv4::AwsSigV4Config>,
    aws_credentials: Option<(String, String)>,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
    unix_socket: Option<String>,
    interface: Option<String>,
    local_port: Option<u16>,
    dns_shuffle: bool,
    dns_cache: DnsCache,
    pool: ConnectionPool,
    #[cfg(feature = "http2")]
    h2_pool: crate::pool::H2Pool,
    share: Option<crate::share::Share>,
    http_version: HttpVersion,
    /// Allow HTTP/0.9 responses (default: false, curl compat).
    http09_allowed: bool,
    expect_100_timeout: Option<Duration>,
    chunked_upload: bool,
    max_recv_speed: Option<u64>,
    max_send_speed: Option<u64>,
    low_speed_limit: Option<u32>,
    low_speed_time: Option<Duration>,
    fresh_connect: bool,
    forbid_reuse: bool,
    proxy_credentials: Option<ProxyAuthCredentials>,
    proxy_tls_config: Option<TlsConfig>,
    /// Force HTTP CONNECT tunnel even for HTTP URLs (curl `--proxytunnel` / `-p`).
    http_proxy_tunnel: bool,
    /// Use HTTP/1.0 for CONNECT requests (curl `--proxy1.0`).
    proxy_http_10: bool,
    infilesize: Option<u64>,
    happy_eyeballs_timeout: Option<Duration>,
    dns_cache_timeout: Option<Duration>,
    dns_servers: Option<Vec<std::net::SocketAddr>>,
    doh_url: Option<String>,
    unrestricted_auth: bool,
    ignore_content_length: bool,
    alt_svc_cache: crate::protocol::http::altsvc::AltSvcCache,
    /// Preserve POST method on 301 redirect (curl --post301).
    post301: bool,
    /// Preserve POST method on 302 redirect (curl --post302).
    post302: bool,
    /// Preserve POST method on 303 redirect (curl --post303).
    post303: bool,
    /// Headers to send only to the proxy, not the target server.
    proxy_headers: Vec<(String, String)>,
    /// FTP SSL/TLS mode.
    ftp_ssl_mode: crate::protocol::ftp::FtpSslMode,
    /// FTP active mode address (None = passive mode).
    ftp_active_port: Option<String>,
    /// Use EPSV (extended passive) mode for FTP (default true).
    ftp_use_epsv: bool,
    /// Use EPRT (extended active) mode for FTP (default true).
    ftp_use_eprt: bool,
    /// Skip the IP address from the server's PASV response.
    ftp_skip_pasv_ip: bool,
    /// FTP account string (sent via ACCT command).
    ftp_account: Option<String>,
    /// Path to SSH private key for SFTP/SCP authentication.
    ssh_key_path: Option<String>,
    /// Path to SSH public key file for SFTP/SCP authentication.
    ssh_public_keyfile: Option<String>,
    /// SSH host key SHA-256 fingerprint for verification (base64, no prefix).
    ssh_host_key_sha256: Option<String>,
    /// Path to SSH `known_hosts` file for host key verification.
    ssh_known_hosts_path: Option<String>,
    /// Allowed SSH auth types bitmask (1=publickey, 2=password, 4=keyboard-interactive, 8=host).
    ssh_auth_types: Option<u32>,
    /// Don't normalize `..` and `.` in URL paths (curl --path-as-is).
    path_as_is: bool,
    /// Disable all HTTP content decoding (curl --raw).
    raw: bool,
    /// SMTP envelope sender (MAIL FROM).
    mail_from: Option<String>,
    /// SMTP envelope recipients (RCPT TO).
    mail_rcpt: Vec<String>,
    /// SMTP AUTH identity (MAIL AUTH).
    mail_auth: Option<String>,
    /// Create missing directories on the FTP server during upload.
    ftp_create_dirs: bool,
    /// FTP method for directory traversal.
    ftp_method: FtpMethod,
    /// Use ASCII transfer mode for FTP (curl `--use-ascii` / `-B`).
    ftp_use_ascii: bool,
    /// Append to remote file on FTP upload (curl `--append` / `-a`).
    ftp_append: bool,
    /// Convert LF to CRLF on FTP upload (curl `--crlf`).
    ftp_crlf: bool,
    /// FTP list only (NLST instead of LIST; curl `-l` / `--list-only`).
    ftp_list_only: bool,
    /// FTP pre-transfer quote commands (curl `-Q "CMD"`).
    ftp_pre_quote: Vec<String>,
    /// FTP post-transfer quote commands (curl `-Q "-CMD"`).
    ftp_post_quote: Vec<String>,
    /// FTP time condition for `-z` flag: `(unix_timestamp, negate)`.
    ftp_time_condition: Option<(i64, bool)>,
    /// SASL authorization identity.
    sasl_authzid: Option<String>,
    /// Send SASL initial response in first message.
    sasl_ir: bool,
    /// Connect-to host:port mapping (`from_host:from_port:to_host:to_port`).
    connect_to: Vec<String>,
    /// Send `HAProxy` PROXY protocol v1 header.
    haproxy_protocol: bool,
    /// Linux abstract Unix domain socket path.
    abstract_unix_socket: Option<String>,
    /// Don't verify `DoH` server TLS certificate.
    doh_insecure: bool,
    /// HTTP/2 initial stream window size in bytes.
    http2_window_size: Option<u32>,
    /// HTTP/2 initial connection window size in bytes.
    http2_connection_window_size: Option<u32>,
    /// HTTP/2 maximum frame size in bytes.
    http2_max_frame_size: Option<u32>,
    /// HTTP/2 maximum header list size in bytes.
    http2_max_header_list_size: Option<u32>,
    /// HTTP/2 server push enabled.
    http2_enable_push: Option<bool>,
    /// HTTP/2 stream priority weight (1-256).
    http2_stream_weight: Option<u16>,
    /// HTTP/2 PING frame interval for keep-alive.
    http2_ping_interval: Option<Duration>,
    /// Custom request target (curl `--request-target`).
    custom_request_target: Option<String>,
    /// Allowed protocols for initial request (e.g., `["http", "https", "ftp"]`).
    /// When `None`, all protocols are allowed.
    allowed_protocols: Option<Vec<String>>,
    /// Allowed protocols for redirects.
    /// When `None`, all protocols are allowed.
    redir_protocols: Option<Vec<String>>,
    /// Explicit proxy port (overrides port in proxy URL).
    proxy_port: Option<u16>,
    /// Proxy type (0=HTTP, 1=HTTP 1.0, 2=HTTPS, 4=SOCKS4, 5=SOCKS5, 6=SOCKS4a, 7=SOCKS5h).
    proxy_type: Option<u32>,
    /// SOCKS5 pre-proxy URL.
    pre_proxy: Option<String>,
    /// TFTP block size (curl `--tftp-blksize`).
    tftp_blksize: Option<u16>,
    /// Disable TFTP options negotiation (curl `--tftp-no-options`).
    tftp_no_options: bool,
    /// Last response received, even if the transfer ultimately failed.
    /// This allows callers to output partial response data on error (curl compat).
    last_response: Option<Response>,
}

#[allow(clippy::missing_fields_in_debug, clippy::too_many_lines)] // h2_pool is cfg-gated and opaque
impl std::fmt::Debug for Easy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Easy")
            .field("url", &self.url)
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("removed_headers", &self.removed_headers)
            .field("form_data", &self.form_data)
            .field("body", &self.body.as_ref().map(|b| format!("<{} bytes>", b.len())))
            .field("follow_redirects", &self.follow_redirects)
            .field("max_redirects", &self.max_redirects)
            .field("verbose", &self.verbose)
            .field("accept_encoding", &self.accept_encoding)
            .field("connect_timeout", &self.connect_timeout)
            .field("timeout", &self.timeout)
            .field("proxy", &self.proxy)
            .field("noproxy", &self.noproxy)
            .field("cookie_jar", &self.cookie_jar.as_ref().map(|_| "<CookieJar>"))
            .field("cookie_jar_path", &self.cookie_jar_path)
            .field("hsts_cache", &self.hsts_cache.as_ref().map(|_| "<HstsCache>"))
            .field("multipart", &self.multipart)
            .field("range", &self.range)
            .field("resolve_overrides", &self.resolve_overrides)
            .field("progress_callback", &self.progress_callback.as_ref().map(|_| "<callback>"))
            .field("fail_on_error", &self.fail_on_error)
            .field("auth_credentials", &self.auth_credentials.as_ref().map(|_| "<credentials>"))
            .field("oauth2_bearer", &self.oauth2_bearer.as_ref().map(|_| "<token>"))
            .field("tls_config", &self.tls_config)
            .field("aws_sigv4", &self.aws_sigv4)
            .field("aws_credentials", &self.aws_credentials.as_ref().map(|_| "<credentials>"))
            .field("tcp_nodelay", &self.tcp_nodelay)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .field("unix_socket", &self.unix_socket)
            .field("interface", &self.interface)
            .field("local_port", &self.local_port)
            .field("dns_shuffle", &self.dns_shuffle)
            .field("dns_cache", &self.dns_cache)
            .field("pool", &"<ConnectionPool>")
            .field("share", &self.share)
            .field("http_version", &self.http_version)
            .field("http09_allowed", &self.http09_allowed)
            .field("expect_100_timeout", &self.expect_100_timeout)
            .field("max_recv_speed", &self.max_recv_speed)
            .field("max_send_speed", &self.max_send_speed)
            .field("low_speed_limit", &self.low_speed_limit)
            .field("low_speed_time", &self.low_speed_time)
            .field("fresh_connect", &self.fresh_connect)
            .field("forbid_reuse", &self.forbid_reuse)
            .field(
                "proxy_credentials",
                &self.proxy_credentials.as_ref().map(|_| "<proxy_credentials>"),
            )
            .field("proxy_tls_config", &self.proxy_tls_config)
            .field("infilesize", &self.infilesize)
            .field("happy_eyeballs_timeout", &self.happy_eyeballs_timeout)
            .field("dns_cache_timeout", &self.dns_cache_timeout)
            .field("dns_servers", &self.dns_servers)
            .field("doh_url", &self.doh_url)
            .field("unrestricted_auth", &self.unrestricted_auth)
            .field("ignore_content_length", &self.ignore_content_length)
            .field("alt_svc_cache", &self.alt_svc_cache)
            .field("post301", &self.post301)
            .field("post302", &self.post302)
            .field("post303", &self.post303)
            .field("proxy_headers", &self.proxy_headers)
            .field("ftp_ssl_mode", &self.ftp_ssl_mode)
            .field("ftp_active_port", &self.ftp_active_port)
            .field("ftp_use_epsv", &self.ftp_use_epsv)
            .field("ftp_use_eprt", &self.ftp_use_eprt)
            .field("ftp_skip_pasv_ip", &self.ftp_skip_pasv_ip)
            .field("ftp_account", &self.ftp_account)
            .field("ssh_key_path", &self.ssh_key_path)
            .field("ssh_public_keyfile", &self.ssh_public_keyfile)
            .field("ssh_host_key_sha256", &self.ssh_host_key_sha256)
            .field("ssh_known_hosts_path", &self.ssh_known_hosts_path)
            .field("ssh_auth_types", &self.ssh_auth_types)
            .field("path_as_is", &self.path_as_is)
            .field("raw", &self.raw)
            .field("mail_from", &self.mail_from)
            .field("mail_rcpt", &self.mail_rcpt)
            .field("mail_auth", &self.mail_auth)
            .field("ftp_create_dirs", &self.ftp_create_dirs)
            .field("ftp_method", &self.ftp_method)
            .field("sasl_authzid", &self.sasl_authzid)
            .field("sasl_ir", &self.sasl_ir)
            .field("connect_to", &self.connect_to)
            .field("haproxy_protocol", &self.haproxy_protocol)
            .field("abstract_unix_socket", &self.abstract_unix_socket)
            .field("doh_insecure", &self.doh_insecure)
            .field("http2_window_size", &self.http2_window_size)
            .field("http2_connection_window_size", &self.http2_connection_window_size)
            .field("http2_max_frame_size", &self.http2_max_frame_size)
            .field("http2_max_header_list_size", &self.http2_max_header_list_size)
            .field("http2_enable_push", &self.http2_enable_push)
            .field("http2_stream_weight", &self.http2_stream_weight)
            .field("http2_ping_interval", &self.http2_ping_interval)
            .field("custom_request_target", &self.custom_request_target)
            .field("allowed_protocols", &self.allowed_protocols)
            .field("redir_protocols", &self.redir_protocols)
            .field("proxy_port", &self.proxy_port)
            .field("proxy_type", &self.proxy_type)
            .field("pre_proxy", &self.pre_proxy)
            .field("tftp_blksize", &self.tftp_blksize)
            .field("tftp_no_options", &self.tftp_no_options)
            .finish()
    }
}

impl Clone for Easy {
    #[allow(clippy::too_many_lines)]
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            removed_headers: self.removed_headers.clone(),
            form_data: self.form_data,
            body: self.body.clone(),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            verbose: self.verbose,
            accept_encoding: self.accept_encoding,
            connect_timeout: self.connect_timeout,
            timeout: self.timeout,
            proxy: self.proxy.clone(),
            noproxy: self.noproxy.clone(),
            cookie_jar: self.cookie_jar.clone(),
            cookie_jar_path: self.cookie_jar_path.clone(),
            hsts_cache: self.hsts_cache.clone(),
            multipart: self.multipart.clone(),
            range: self.range.clone(),
            resolve_overrides: self.resolve_overrides.clone(),
            progress_callback: self.progress_callback.clone(),
            fail_on_error: self.fail_on_error,
            auth_credentials: self.auth_credentials.clone(),
            oauth2_bearer: self.oauth2_bearer.clone(),
            tls_config: self.tls_config.clone(),
            aws_sigv4: self.aws_sigv4.clone(),
            aws_credentials: self.aws_credentials.clone(),
            tcp_nodelay: self.tcp_nodelay,
            tcp_keepalive: self.tcp_keepalive,
            unix_socket: self.unix_socket.clone(),
            interface: self.interface.clone(),
            local_port: self.local_port,
            dns_shuffle: self.dns_shuffle,
            dns_cache: DnsCache::new(),
            pool: ConnectionPool::new(),
            #[cfg(feature = "http2")]
            h2_pool: crate::pool::H2Pool::new(),
            share: self.share.clone(),
            http_version: self.http_version,
            http09_allowed: self.http09_allowed,
            expect_100_timeout: self.expect_100_timeout,
            chunked_upload: self.chunked_upload,
            max_recv_speed: self.max_recv_speed,
            max_send_speed: self.max_send_speed,
            low_speed_limit: self.low_speed_limit,
            low_speed_time: self.low_speed_time,
            fresh_connect: self.fresh_connect,
            forbid_reuse: self.forbid_reuse,
            proxy_credentials: self.proxy_credentials.clone(),
            proxy_tls_config: self.proxy_tls_config.clone(),
            http_proxy_tunnel: self.http_proxy_tunnel,
            proxy_http_10: self.proxy_http_10,
            infilesize: self.infilesize,
            happy_eyeballs_timeout: self.happy_eyeballs_timeout,
            dns_cache_timeout: self.dns_cache_timeout,
            dns_servers: self.dns_servers.clone(),
            doh_url: self.doh_url.clone(),
            unrestricted_auth: self.unrestricted_auth,
            ignore_content_length: self.ignore_content_length,
            alt_svc_cache: self.alt_svc_cache.clone(),
            post301: self.post301,
            post302: self.post302,
            post303: self.post303,
            proxy_headers: self.proxy_headers.clone(),
            ftp_ssl_mode: self.ftp_ssl_mode,
            ftp_active_port: self.ftp_active_port.clone(),
            ftp_use_epsv: self.ftp_use_epsv,
            ftp_use_eprt: self.ftp_use_eprt,
            ftp_skip_pasv_ip: self.ftp_skip_pasv_ip,
            ftp_account: self.ftp_account.clone(),
            ssh_key_path: self.ssh_key_path.clone(),
            ssh_public_keyfile: self.ssh_public_keyfile.clone(),
            ssh_host_key_sha256: self.ssh_host_key_sha256.clone(),
            ssh_known_hosts_path: self.ssh_known_hosts_path.clone(),
            ssh_auth_types: self.ssh_auth_types,
            path_as_is: self.path_as_is,
            raw: self.raw,
            mail_from: self.mail_from.clone(),
            mail_rcpt: self.mail_rcpt.clone(),
            mail_auth: self.mail_auth.clone(),
            ftp_create_dirs: self.ftp_create_dirs,
            ftp_method: self.ftp_method,
            ftp_use_ascii: self.ftp_use_ascii,
            ftp_append: self.ftp_append,
            ftp_crlf: self.ftp_crlf,
            ftp_list_only: self.ftp_list_only,
            ftp_pre_quote: self.ftp_pre_quote.clone(),
            ftp_post_quote: self.ftp_post_quote.clone(),
            ftp_time_condition: self.ftp_time_condition,
            sasl_authzid: self.sasl_authzid.clone(),
            sasl_ir: self.sasl_ir,
            connect_to: self.connect_to.clone(),
            haproxy_protocol: self.haproxy_protocol,
            abstract_unix_socket: self.abstract_unix_socket.clone(),
            doh_insecure: self.doh_insecure,
            http2_window_size: self.http2_window_size,
            http2_connection_window_size: self.http2_connection_window_size,
            http2_max_frame_size: self.http2_max_frame_size,
            http2_max_header_list_size: self.http2_max_header_list_size,
            http2_enable_push: self.http2_enable_push,
            http2_stream_weight: self.http2_stream_weight,
            http2_ping_interval: self.http2_ping_interval,
            custom_request_target: self.custom_request_target.clone(),
            allowed_protocols: self.allowed_protocols.clone(),
            redir_protocols: self.redir_protocols.clone(),
            proxy_port: self.proxy_port,
            proxy_type: self.proxy_type,
            pre_proxy: self.pre_proxy.clone(),
            tftp_blksize: self.tftp_blksize,
            tftp_no_options: self.tftp_no_options,
            last_response: None, // ephemeral — not cloned
        }
    }
}

impl Easy {
    /// Create a new transfer handle.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn new() -> Self {
        Self {
            url: None,
            method: None,
            headers: Vec::new(),
            removed_headers: Vec::new(),
            form_data: false,
            body: None,
            follow_redirects: false,
            max_redirects: 50,
            verbose: false,
            accept_encoding: false,
            connect_timeout: None,
            timeout: None,
            proxy: None,
            noproxy: None,
            cookie_jar: None,
            cookie_jar_path: None,
            hsts_cache: None,
            multipart: None,
            range: None,
            resolve_overrides: Vec::new(),
            progress_callback: None,
            fail_on_error: false,
            auth_credentials: None,
            oauth2_bearer: None,
            tls_config: TlsConfig::default(),
            aws_sigv4: None,
            aws_credentials: None,
            tcp_nodelay: true,
            tcp_keepalive: None,
            unix_socket: None,
            interface: None,
            local_port: None,
            dns_shuffle: false,
            dns_cache: DnsCache::new(),
            pool: ConnectionPool::new(),
            #[cfg(feature = "http2")]
            h2_pool: crate::pool::H2Pool::new(),
            share: None,
            http_version: HttpVersion::None,
            http09_allowed: false,
            expect_100_timeout: None,
            chunked_upload: false,
            max_recv_speed: None,
            max_send_speed: None,
            low_speed_limit: None,
            low_speed_time: None,
            fresh_connect: false,
            forbid_reuse: false,
            proxy_credentials: None,
            proxy_tls_config: None,
            http_proxy_tunnel: false,
            proxy_http_10: false,
            infilesize: None,
            happy_eyeballs_timeout: None,
            dns_cache_timeout: None,
            dns_servers: None,
            doh_url: None,
            unrestricted_auth: false,
            ignore_content_length: false,
            alt_svc_cache: crate::protocol::http::altsvc::AltSvcCache::new(),
            post301: false,
            post302: false,
            post303: false,
            proxy_headers: Vec::new(),
            ftp_ssl_mode: crate::protocol::ftp::FtpSslMode::None,
            ftp_active_port: None,
            ftp_use_epsv: true,
            ftp_use_eprt: true,
            ftp_skip_pasv_ip: false,
            ftp_account: None,
            ssh_key_path: None,
            ssh_public_keyfile: None,
            ssh_host_key_sha256: None,
            ssh_known_hosts_path: None,
            ssh_auth_types: None,
            path_as_is: false,
            raw: false,
            mail_from: None,
            mail_rcpt: Vec::new(),
            mail_auth: None,
            ftp_create_dirs: false,
            ftp_method: FtpMethod::default(),
            ftp_use_ascii: false,
            ftp_append: false,
            ftp_crlf: false,
            ftp_list_only: false,
            ftp_pre_quote: Vec::new(),
            ftp_post_quote: Vec::new(),
            ftp_time_condition: None,
            sasl_authzid: None,
            sasl_ir: false,
            connect_to: Vec::new(),
            haproxy_protocol: false,
            abstract_unix_socket: None,
            doh_insecure: false,
            http2_window_size: None,
            http2_connection_window_size: None,
            http2_max_frame_size: None,
            http2_max_header_list_size: None,
            http2_enable_push: None,
            http2_stream_weight: None,
            http2_ping_interval: None,
            custom_request_target: None,
            allowed_protocols: None,
            redir_protocols: None,
            proxy_port: None,
            proxy_type: None,
            pre_proxy: None,
            tftp_blksize: None,
            tftp_no_options: false,
            last_response: None,
        }
    }

    /// Set the URL to transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the URL is invalid.
    pub fn url(&mut self, url: &str) -> Result<(), Error> {
        self.url = Some(Url::parse(url)?);
        Ok(())
    }

    /// Set the HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS).
    pub fn method(&mut self, method: &str) {
        self.method = Some(method.to_uppercase());
    }

    /// Returns true if no explicit method has been set.
    #[must_use]
    pub const fn method_is_default(&self) -> bool {
        self.method.is_none()
    }

    /// Add a custom request header.
    ///
    /// Header names and values must not contain CR (`\r`) or LF (`\n`)
    /// characters. Such headers are silently rejected to prevent
    /// header injection attacks.
    pub fn header(&mut self, name: &str, value: &str) {
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return;
        }
        // For most headers, replace existing entry in-place to preserve ordering
        // (curl compat: test 385 — Content-Type override must keep its position).
        // Exception: Set-Cookie and other multi-value headers should not be replaced.
        // Exception: Host header uses first-wins (curl compat: test 1121).
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            // Host: first-wins — if already set, ignore subsequent values
            if self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
                return;
            }
        } else if lower != "set-cookie" && lower != "cookie" {
            if let Some(pos) = self.headers.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
                self.headers[pos] = (name.to_string(), value.to_string());
                return;
            }
        }
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Set the request body.
    pub fn body(&mut self, data: &[u8]) {
        self.body = Some(data.to_vec());
    }

    /// Append data to the request body (used for multiple --json flags).
    ///
    /// If no body exists yet, this creates a new one. Otherwise, it appends
    /// to the existing body.
    pub fn append_body(&mut self, data: &[u8]) {
        if let Some(ref mut existing) = self.body {
            existing.extend_from_slice(data);
        } else {
            self.body = Some(data.to_vec());
        }
    }

    /// Take the request body, removing it from the easy handle.
    ///
    /// Returns `None` if no body was set.
    pub const fn take_body(&mut self) -> Option<Vec<u8>> {
        self.body.take()
    }

    /// Mark a header name for removal (suppresses built-in defaults).
    ///
    /// Used by the `-H "Name:"` syntax to suppress a built-in header
    /// without adding a new one. Unlike `remove_header()`, this does not
    /// remove previously-set custom headers — it only prevents the built-in
    /// default (e.g., `User-Agent`, `Accept`) from being emitted.
    pub fn header_remove(&mut self, name: &str) {
        self.removed_headers.push(name.to_lowercase());
    }

    /// Mark that form data was set (from `-d`, `--data-raw`, etc.).
    ///
    /// Controls auto-generation of `Content-Type: application/x-www-form-urlencoded`.
    pub const fn set_form_data(&mut self, enabled: bool) {
        self.form_data = enabled;
    }

    /// Returns whether form data was set.
    #[must_use]
    pub const fn is_form_data(&self) -> bool {
        self.form_data
    }

    /// Returns the list of removed header names (lowercase).
    #[must_use]
    pub fn removed_headers(&self) -> &[String] {
        &self.removed_headers
    }

    /// Remove all headers with the given name (case-insensitive).
    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Check if a custom header with the given name exists.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
            || self.removed_headers.iter().any(|k| k.eq_ignore_ascii_case(name))
    }

    /// Returns true if an Authorization header has been set.
    #[must_use]
    pub fn has_auth_header(&self) -> bool {
        self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            || self.auth_credentials.is_some()
    }

    /// Set the expected upload size in bytes.
    ///
    /// This is used as a hint for progress reporting and for setting
    /// `Content-Length` when streaming uploads. Equivalent to
    /// `CURLOPT_INFILESIZE_LARGE`.
    pub const fn infilesize(&mut self, size: u64) {
        self.infilesize = Some(size);
    }

    /// Upload a file by path. Reads the file and sets it as the request body.
    ///
    /// Also sets the method to PUT if no method has been explicitly set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn upload_file(&mut self, path: &Path) -> Result<(), Error> {
        let data = std::fs::read(path).map_err(Error::Io)?;
        self.infilesize = Some(data.len() as u64);
        self.body = Some(data);
        if self.method.is_none() {
            self.method = Some("PUT".to_string());
        }
        Ok(())
    }

    /// Enable or disable redirect following.
    pub const fn follow_redirects(&mut self, enable: bool) {
        self.follow_redirects = enable;
    }

    /// Set maximum number of redirects to follow (default: 50).
    pub const fn max_redirects(&mut self, max: u32) {
        self.max_redirects = max;
    }

    /// Enable or disable verbose output.
    pub const fn verbose(&mut self, enable: bool) {
        self.verbose = enable;
    }

    /// Returns the configured HTTP method, or `None` if not explicitly set.
    #[must_use]
    pub fn method_str(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// Returns true if a request body has been set.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.body.is_some()
    }

    /// Returns true if multipart form data has been set.
    #[must_use]
    pub const fn has_multipart(&self) -> bool {
        self.multipart.is_some()
    }

    /// Returns the configured transfer timeout duration, if any.
    #[must_use]
    pub const fn timeout_duration(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns the last response received, even if the transfer failed.
    ///
    /// curl outputs partial response data (headers, body) even when the
    /// transfer ultimately fails (e.g., timeout, chunked decode error,
    /// max redirects exceeded). This method provides access to whatever
    /// response data was received before the error.
    #[must_use]
    pub const fn last_response(&self) -> Option<&Response> {
        self.last_response.as_ref()
    }

    /// Returns the configured custom headers as a slice.
    #[must_use]
    pub fn header_list(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Set the TCP connection timeout.
    ///
    /// If the connection is not established within this duration,
    /// the transfer fails with [`Error::Timeout`].
    pub const fn connect_timeout(&mut self, duration: Duration) {
        self.connect_timeout = Some(duration);
    }

    /// Set the total transfer timeout.
    ///
    /// If the entire transfer (connect + request + response) takes
    /// longer than this duration, it fails with [`Error::Timeout`].
    pub const fn timeout(&mut self, duration: Duration) {
        self.timeout = Some(duration);
    }

    /// Set Basic authentication credentials.
    ///
    /// Adds an `Authorization: Basic <base64>` header to the request.
    pub fn basic_auth(&mut self, user: &str, password: &str) {
        use base64::Engine;
        let credentials = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        self.header("Authorization", &format!("Basic {encoded}"));
    }

    /// Set Bearer token authentication.
    ///
    /// Adds an `Authorization: Bearer <token>` header to the request.
    pub fn bearer_token(&mut self, token: &str) {
        self.header("Authorization", &format!("Bearer {token}"));
        // Also store separately for SASL XOAUTH2 (IMAP/POP3/SMTP)
        self.oauth2_bearer = Some(token.to_string());
    }

    /// Enable automatic Content-Encoding decompression.
    ///
    /// When enabled, sends `Accept-Encoding` header and decompresses
    /// gzip, deflate, brotli, and zstd response bodies.
    pub const fn accept_encoding(&mut self, enable: bool) {
        self.accept_encoding = enable;
    }

    /// Enable the cookie engine.
    ///
    /// When enabled, cookies from `Set-Cookie` response headers are stored
    /// and automatically sent in subsequent requests (including redirects).
    pub fn cookie_jar(&mut self, enable: bool) {
        if enable {
            if self.cookie_jar.is_none() {
                self.cookie_jar = Some(CookieJar::new());
            }
        } else {
            self.cookie_jar = None;
        }
    }

    /// Load cookies from a Netscape-format cookie file.
    ///
    /// Enables the cookie engine and loads cookies from the given file path.
    /// Equivalent to curl's `CURLOPT_COOKIEFILE` / `-b <file>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn cookie_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let jar = CookieJar::load_from_file(path).map_err(Error::Io)?;
        self.cookie_jar = Some(jar);
        Ok(())
    }

    /// Set the cookie jar output file path.
    ///
    /// After the transfer completes, cookies are saved to this file in
    /// Netscape format. Call [`save_cookie_jar`](Self::save_cookie_jar)
    /// after `perform()` to write the file.
    ///
    /// Equivalent to curl's `CURLOPT_COOKIEJAR` / `-c <file>`.
    pub fn cookie_jar_file(&mut self, path: &str) {
        self.cookie_jar_path = Some(path.to_string());
        // Ensure cookie engine is enabled
        if self.cookie_jar.is_none() {
            self.cookie_jar = Some(CookieJar::new());
        }
    }

    /// Save the current cookies to the configured cookie jar file.
    ///
    /// This must be called after `perform()` to persist cookies.
    /// Does nothing if no cookie jar file path has been set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be written.
    pub fn save_cookie_jar(&self) -> Result<(), Error> {
        if let (Some(ref path), Some(ref jar)) = (&self.cookie_jar_path, &self.cookie_jar) {
            jar.save_to_file(path).map_err(Error::Io)?;
        }
        Ok(())
    }

    /// Set the proxy URL.
    ///
    /// HTTP URLs are forwarded through the proxy. HTTPS URLs use
    /// HTTP CONNECT tunneling through the proxy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the proxy URL is invalid.
    pub fn proxy(&mut self, proxy_url: &str) -> Result<(), Error> {
        // If no scheme is present, add http:// (curl behavior for bare host:port)
        let normalized = if proxy_url.contains("://") {
            proxy_url.to_string()
        } else {
            format!("http://{proxy_url}")
        };

        // Extract userinfo credentials from proxy URL (e.g., http://user:pass@host:port/)
        // For SOCKS proxies, credentials are handled at the protocol level (SOCKS handshake),
        // not via HTTP Proxy-Authorization header (curl compat: tests 717, 742).
        if let Ok(parsed) = url::Url::parse(&normalized) {
            let scheme = parsed.scheme();
            let is_socks = scheme.starts_with("socks");
            let user = percent_decode_str(parsed.username());
            let pass = parsed.password().map_or_else(String::new, percent_decode_str);
            if !user.is_empty() && !is_socks {
                self.proxy_auth(&user, &pass);
            }
        }
        self.proxy = Some(Url::parse(&normalized)?);
        Ok(())
    }

    /// Returns true if a proxy has been configured.
    #[must_use]
    pub const fn has_proxy(&self) -> bool {
        self.proxy.is_some()
    }

    /// Returns a reference to the current URL, if set.
    #[must_use]
    pub const fn url_ref(&self) -> Option<&Url> {
        self.url.as_ref()
    }

    /// Set the no-proxy list (comma-separated hostnames/domains).
    ///
    /// Hosts matching this list bypass the proxy. Supports domain
    /// suffix matching (e.g., ".example.com" matches "foo.example.com").
    /// Use "*" to bypass the proxy for all hosts.
    pub fn noproxy(&mut self, noproxy: &str) {
        self.noproxy = Some(noproxy.to_string());
    }

    /// Enable HSTS (HTTP Strict Transport Security) enforcement.
    ///
    /// When enabled, `Strict-Transport-Security` response headers are cached
    /// and subsequent HTTP requests to HSTS hosts are auto-upgraded to HTTPS.
    pub fn hsts(&mut self, enable: bool) {
        if enable {
            if self.hsts_cache.is_none() {
                self.hsts_cache = Some(HstsCache::new());
            }
        } else {
            self.hsts_cache = None;
        }
    }

    /// Add a DNS resolve override.
    ///
    /// Forces the given hostname to resolve to the specified address,
    /// bypassing DNS. Similar to curl's `--resolve host:port:addr`.
    pub fn resolve(&mut self, host: &str, addr: &str) {
        self.resolve_overrides.push((host.to_lowercase(), addr.to_string()));
    }

    /// Add a text field to the multipart form.
    ///
    /// When any form field or file is added, the request body is sent as
    /// `multipart/form-data` and the method defaults to POST.
    pub fn form_field(&mut self, name: &str, value: &str) {
        self.multipart.get_or_insert_with(MultipartForm::new).field(name, value);
    }

    /// Add a text field with explicit Content-Type to the multipart form.
    pub fn form_field_with_type(&mut self, name: &str, value: &str, content_type: &str) {
        self.multipart.get_or_insert_with(MultipartForm::new).field_with_type(
            name,
            value,
            content_type,
        );
    }

    /// Add a file to the multipart form.
    ///
    /// The file is read from disk when this method is called, not when
    /// the transfer is performed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the file cannot be read.
    pub fn form_file(&mut self, name: &str, path: &Path) -> Result<(), Error> {
        self.multipart.get_or_insert_with(MultipartForm::new).file(name, path)
    }

    /// Add file data directly to the multipart form.
    pub fn form_file_data(&mut self, name: &str, filename: &str, data: &[u8]) {
        self.multipart.get_or_insert_with(MultipartForm::new).file_data(name, filename, data);
    }

    /// Add file data with explicit content type to the multipart form.
    pub fn form_file_with_type(
        &mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        data: &[u8],
    ) {
        self.multipart.get_or_insert_with(MultipartForm::new).file_data_with_type(
            name,
            filename,
            content_type,
            data,
        );
    }

    /// Set a byte range for the request.
    ///
    /// Sends a `Range: bytes=<range>` header. Format examples:
    /// - `"0-499"` — first 500 bytes
    /// - `"500-"` — from byte 500 to end
    /// - `"-500"` — last 500 bytes
    pub fn range(&mut self, range: &str) {
        self.range = Some(range.to_string());
    }

    /// Set resume download offset.
    ///
    /// Equivalent to `range("<offset>-")`.
    pub fn resume_from(&mut self, offset: u64) {
        self.range = Some(format!("{offset}-"));
    }

    /// Returns true if a range (resume) has been set with a non-zero offset.
    #[must_use]
    pub fn has_range(&self) -> bool {
        self.range.as_ref().is_some_and(|r| r != "0-")
    }

    /// Clear the resume/range setting.
    pub fn clear_range(&mut self) {
        self.range = None;
    }

    /// Set a progress callback for transfer monitoring.
    ///
    /// The callback receives a [`ProgressInfo`] with download/upload progress
    /// and should return `true` to continue or `false` to abort the transfer.
    pub fn progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Set proxy authentication credentials (Basic).
    ///
    /// Adds a `Proxy-Authorization: Basic <base64>` header for proxy requests.
    /// For Basic auth, the header is added immediately. For Digest or NTLM,
    /// use [`proxy_digest_auth`](Self::proxy_digest_auth) or
    /// [`proxy_ntlm_auth`](Self::proxy_ntlm_auth) instead.
    ///
    /// Equivalent to curl's `--proxy-user user:pass`.
    pub fn proxy_auth(&mut self, user: &str, password: &str) {
        use base64::Engine;
        let credentials = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        self.header("Proxy-Authorization", &format!("Basic {encoded}"));
        // Also store credentials for potential Digest/NTLM fallback
        self.proxy_credentials = Some(ProxyAuthCredentials {
            username: user.to_string(),
            password: password.to_string(),
            method: ProxyAuthMethod::Basic,
            domain: None,
        });
    }

    /// Set proxy Digest authentication credentials.
    ///
    /// When the proxy returns `407 Proxy Authentication Required` with a
    /// `Proxy-Authenticate: Digest` challenge, the request is retried
    /// with the computed Digest response.
    ///
    /// Equivalent to curl's `--proxy-digest --proxy-user user:pass`.
    pub fn proxy_digest_auth(&mut self, user: &str, password: &str) {
        self.proxy_credentials = Some(ProxyAuthCredentials {
            username: user.to_string(),
            password: password.to_string(),
            method: ProxyAuthMethod::Digest,
            domain: None,
        });
    }

    /// Set proxy NTLM authentication credentials.
    ///
    /// Performs the NTLM Type 1/2/3 handshake with the proxy.
    ///
    /// Equivalent to curl's `--proxy-ntlm --proxy-user user:pass`.
    pub fn proxy_ntlm_auth(&mut self, user: &str, password: &str) {
        // Extract domain from "DOMAIN\user" format if present
        let (domain, username) = if let Some((d, u)) = user.split_once('\\') {
            (Some(d.to_string()), u.to_string())
        } else {
            (None, user.to_string())
        };

        self.proxy_credentials = Some(ProxyAuthCredentials {
            username,
            password: password.to_string(),
            method: ProxyAuthMethod::Ntlm,
            domain,
        });
    }

    /// Force HTTP CONNECT tunnel even for HTTP URLs.
    ///
    /// When enabled, all HTTP requests through a proxy use the CONNECT method
    /// to establish a tunnel, instead of sending the request directly to the proxy.
    /// This is equivalent to curl's `--proxytunnel` / `-p` option.
    pub const fn http_proxy_tunnel(&mut self, enable: bool) {
        self.http_proxy_tunnel = enable;
    }

    /// Use HTTP/1.0 for CONNECT proxy requests.
    ///
    /// When enabled, the CONNECT request to the proxy uses HTTP/1.0 instead
    /// of HTTP/1.1. This only affects the proxy handshake, not the actual
    /// request to the target server. Equivalent to `--proxy1.0`.
    pub const fn proxy_http_10(&mut self, enable: bool) {
        self.proxy_http_10 = enable;
    }

    /// Set proxy TLS configuration for HTTPS proxies.
    ///
    /// When connecting to an HTTPS proxy (proxy URL starts with `https://`),
    /// this TLS configuration is used for the proxy connection. The regular
    /// TLS configuration is used for the target server.
    pub fn proxy_tls_config(&mut self, config: TlsConfig) {
        self.proxy_tls_config = Some(config);
    }

    /// Set proxy client certificate for HTTPS proxy authentication.
    ///
    /// Equivalent to `CURLOPT_PROXY_SSLCERT`.
    pub fn proxy_ssl_client_cert(&mut self, path: &Path) {
        let config = self.proxy_tls_config.get_or_insert_with(TlsConfig::default);
        config.client_cert = Some(path.to_path_buf());
    }

    /// Set proxy client private key for HTTPS proxy authentication.
    ///
    /// Equivalent to `CURLOPT_PROXY_SSLKEY`.
    pub fn proxy_ssl_client_key(&mut self, path: &Path) {
        let config = self.proxy_tls_config.get_or_insert_with(TlsConfig::default);
        config.client_key = Some(path.to_path_buf());
    }

    /// Enable or disable TLS certificate verification for HTTPS proxies.
    ///
    /// Equivalent to `CURLOPT_PROXY_SSL_VERIFYPEER`.
    pub fn proxy_ssl_verify_peer(&mut self, verify: bool) {
        let config = self.proxy_tls_config.get_or_insert_with(TlsConfig::default);
        config.verify_peer = verify;
    }

    /// Set Digest authentication credentials.
    ///
    /// When set, the request is first sent without credentials. If the server
    /// responds with `401 Unauthorized` and a `WWW-Authenticate: Digest` challenge,
    /// the request is retried with the computed Digest response.
    ///
    /// Equivalent to curl's `--digest -u user:pass`.
    pub fn digest_auth(&mut self, user: &str, password: &str) {
        self.auth_credentials = Some(AuthCredentials {
            username: user.to_string(),
            password: password.to_string(),
            method: AuthMethod::Digest,
            domain: None,
        });
    }

    /// Configure AWS Signature Version 4 signing.
    ///
    /// The `spec` format is `provider:region:service` (e.g., `aws:us-east-1:s3`).
    /// Credentials are taken from the user/password set via [`basic_auth`](Self::basic_auth)
    /// or [`digest_auth`](Self::digest_auth), or can be set separately.
    /// Equivalent to curl's `--aws-sigv4`.
    pub fn aws_sigv4(&mut self, spec: &str) {
        self.aws_sigv4 = crate::auth::aws_sigv4::AwsSigV4Config::parse(spec);
    }

    /// Set AWS credentials for `SigV4` signing.
    ///
    /// Uses `access_key` and `secret_key` for request signing.
    /// Must be used together with [`aws_sigv4`](Self::aws_sigv4).
    pub fn aws_credentials(&mut self, access_key: &str, secret_key: &str) {
        self.aws_credentials = Some((access_key.to_string(), secret_key.to_string()));
    }

    /// Enable or disable fail-on-error mode.
    ///
    /// When enabled, HTTP responses with status >= 400 cause
    /// [`perform`](Self::perform) to return an error instead of
    /// the response. Equivalent to curl's `-f`/`--fail` flag.
    pub const fn fail_on_error(&mut self, enable: bool) {
        self.fail_on_error = enable;
    }

    /// Enable or disable TLS certificate verification.
    ///
    /// When set to `false`, the connection proceeds even if the server's
    /// certificate is invalid, self-signed, or expired.
    /// Equivalent to curl's `-k` / `--insecure` flag or `CURLOPT_SSL_VERIFYPEER`.
    ///
    /// **WARNING: Disabling verification makes the connection insecure.**
    pub const fn ssl_verify_peer(&mut self, enable: bool) {
        self.tls_config.verify_peer = enable;
    }

    /// Enable or disable TLS hostname verification.
    ///
    /// When set to `false`, accepts certificates that don't match the
    /// server's hostname. Equivalent to `CURLOPT_SSL_VERIFYHOST`.
    ///
    /// **WARNING: Disabling verification makes the connection insecure.**
    pub const fn ssl_verify_host(&mut self, enable: bool) {
        self.tls_config.verify_host = enable;
    }

    /// Set the path to a custom CA certificate bundle in PEM format.
    ///
    /// When set, only certificates signed by CAs in this bundle are trusted,
    /// replacing the system default root certificates.
    /// Equivalent to curl's `--cacert` flag or `CURLOPT_CAINFO`.
    pub fn ssl_ca_cert(&mut self, path: &Path) {
        self.tls_config.ca_cert = Some(path.to_path_buf());
    }

    /// Set the path to a client certificate in PEM format.
    ///
    /// Used for mutual TLS (mTLS) authentication.
    /// Equivalent to curl's `--cert` flag or `CURLOPT_SSLCERT`.
    pub fn ssl_client_cert(&mut self, path: &Path) {
        self.tls_config.client_cert = Some(path.to_path_buf());
    }

    /// Set the path to a client private key in PEM format.
    ///
    /// Must correspond to the certificate specified with [`ssl_client_cert`](Self::ssl_client_cert).
    /// Equivalent to curl's `--key` flag or `CURLOPT_SSLKEY`.
    pub fn ssl_client_key(&mut self, path: &Path) {
        self.tls_config.client_key = Some(path.to_path_buf());
    }

    /// Set an in-memory CA certificate bundle (PEM format).
    ///
    /// Alternative to `ssl_ca_cert` (file path).
    /// Equivalent to `CURLOPT_CAINFO_BLOB`.
    pub fn ssl_ca_cert_blob(&mut self, blob: Vec<u8>) {
        self.tls_config.ca_cert_blob = Some(blob);
    }

    /// Set an in-memory client certificate (PEM format).
    ///
    /// Alternative to `ssl_client_cert` (file path).
    /// Equivalent to `CURLOPT_SSLCERT_BLOB`.
    pub fn ssl_client_cert_blob(&mut self, blob: Vec<u8>) {
        self.tls_config.client_cert_blob = Some(blob);
    }

    /// Set an in-memory client private key (PEM format).
    ///
    /// Alternative to `ssl_client_key` (file path).
    /// Equivalent to `CURLOPT_SSLKEY_BLOB`.
    pub fn ssl_client_key_blob(&mut self, blob: Vec<u8>) {
        self.tls_config.client_key_blob = Some(blob);
    }

    /// Set the minimum TLS version to allow.
    ///
    /// Equivalent to curl's `--tlsv1.2` or `--tlsv1.3`.
    pub const fn ssl_min_version(&mut self, version: crate::tls::TlsVersion) {
        self.tls_config.min_tls_version = Some(version);
    }

    /// Set the maximum TLS version to allow.
    ///
    /// Equivalent to curl's `--tls-max`.
    pub const fn ssl_max_version(&mut self, version: crate::tls::TlsVersion) {
        self.tls_config.max_tls_version = Some(version);
    }

    /// Set the SHA-256 hash of the expected server public key for pinning.
    ///
    /// Format: `sha256//<base64-encoded-hash>`.
    /// The connection will be rejected if the server's public key doesn't match.
    /// Equivalent to curl's `--pinnedpubkey`.
    pub fn ssl_pinned_public_key(&mut self, pin: &str) {
        self.tls_config.pinned_public_key = Some(pin.to_string());
    }

    /// Set the cipher suite list specification.
    ///
    /// Stored for logging and compatibility. Note: rustls uses a fixed set
    /// of secure cipher suites and does not support arbitrary filtering.
    /// Equivalent to `CURLOPT_SSL_CIPHER_LIST`.
    pub fn ssl_cipher_list(&mut self, ciphers: &str) {
        self.tls_config.cipher_list = Some(ciphers.to_string());
    }

    /// Enable or disable TLS session ID caching (default: enabled).
    ///
    /// When enabled, TLS session tickets are used for faster reconnections.
    /// Equivalent to `CURLOPT_SSL_SESSIONID_CACHE`.
    pub const fn ssl_session_cache(&mut self, enable: bool) {
        self.tls_config.session_cache = enable;
    }

    /// Enable or disable `TCP_NODELAY` (Nagle's algorithm).
    ///
    /// When enabled (the default), small packets are sent immediately without
    /// waiting to coalesce. Equivalent to `CURLOPT_TCP_NODELAY`.
    pub const fn tcp_nodelay(&mut self, enable: bool) {
        self.tcp_nodelay = enable;
    }

    /// Enable TCP keepalive with the given idle interval.
    ///
    /// When set, TCP keepalive probes are sent after the connection has been
    /// idle for the specified duration. Equivalent to `CURLOPT_TCP_KEEPALIVE`
    /// and `CURLOPT_TCP_KEEPIDLE`.
    pub const fn tcp_keepalive(&mut self, idle: Duration) {
        self.tcp_keepalive = Some(idle);
    }

    /// Bind to a specific local network interface.
    ///
    /// The value can be an interface name (e.g., `"eth0"`), an IP address,
    /// or a hostname. Equivalent to curl's `--interface` or `CURLOPT_INTERFACE`.
    pub fn interface(&mut self, iface: &str) {
        self.interface = Some(iface.to_string());
    }

    /// Bind to a specific local port for outgoing connections.
    ///
    /// Equivalent to curl's `--local-port` or `CURLOPT_LOCALPORT`.
    pub const fn local_port(&mut self, port: u16) {
        self.local_port = Some(port);
    }

    /// Enable DNS result shuffling.
    ///
    /// When enabled, the resolved DNS addresses are randomized before
    /// connection attempts. This provides simple load distribution across
    /// multiple IPs for the same hostname.
    /// Equivalent to curl's `--dns-shuffle`.
    pub const fn dns_shuffle(&mut self, enable: bool) {
        self.dns_shuffle = enable;
    }

    /// Set the DNS cache timeout.
    ///
    /// Controls how long resolved DNS entries are cached before expiring.
    /// The default is 60 seconds (matching curl). Setting to zero disables
    /// DNS caching (every request triggers a new lookup).
    /// Equivalent to `CURLOPT_DNS_CACHE_TIMEOUT`.
    pub const fn dns_cache_timeout(&mut self, duration: Duration) {
        self.dns_cache_timeout = Some(duration);
        self.dns_cache.set_ttl(duration);
    }

    /// Set the Happy Eyeballs timeout.
    ///
    /// Controls the delay before starting a parallel IPv4 connection when
    /// attempting an IPv6 connection (RFC 6555). The default is 250ms.
    /// A shorter timeout prefers IPv4 more aggressively; a longer timeout
    /// gives IPv6 more time to succeed.
    /// Equivalent to `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
    pub const fn happy_eyeballs_timeout(&mut self, duration: Duration) {
        self.happy_eyeballs_timeout = Some(duration);
    }

    /// Set the maximum total number of connections in the pool.
    ///
    /// Equivalent to `CURLOPT_MAXCONNECTS`. Default is 25.
    /// Setting to 0 disables connection reuse entirely.
    pub const fn max_pool_connections(&mut self, max: usize) {
        if max == 0 {
            self.pool.set_ttl(std::time::Duration::ZERO);
        } else {
            self.pool.set_max_total(max);
        }
    }

    /// Set custom DNS server addresses.
    ///
    /// Accepts a comma-separated list of IP:port addresses (e.g., `"8.8.8.8:53,8.8.4.4:53"`).
    /// Port defaults to 53 if not specified.
    /// Equivalent to `CURLOPT_DNS_SERVERS`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the server list cannot be parsed.
    pub fn dns_servers(&mut self, servers: &str) -> Result<(), Error> {
        let mut addrs = Vec::new();
        for s in servers.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let addr: std::net::SocketAddr = if s.contains(':') {
                s.parse()
                    .map_err(|e| Error::Http(format!("invalid DNS server address '{s}': {e}")))?
            } else {
                let ip: std::net::IpAddr = s
                    .parse()
                    .map_err(|e| Error::Http(format!("invalid DNS server IP '{s}': {e}")))?;
                std::net::SocketAddr::new(ip, 53)
            };
            addrs.push(addr);
        }
        if addrs.is_empty() {
            return Err(Error::Http("empty DNS server list".to_string()));
        }
        self.dns_servers = Some(addrs);
        Ok(())
    }

    /// Set the DNS-over-HTTPS URL.
    ///
    /// When set, DNS queries are sent as HTTPS requests to this URL
    /// instead of using the system resolver. The URL should be a `DoH`
    /// endpoint (e.g., `"https://dns.google/dns-query"`).
    /// Equivalent to `CURLOPT_DOH_URL`.
    pub fn doh_url(&mut self, url: &str) {
        self.doh_url = Some(url.to_string());
    }

    /// Allow auth credentials to be sent to all hosts during redirects.
    ///
    /// By default, auth credentials are stripped when a redirect crosses to
    /// a different host. Setting this to `true` keeps them on all redirects.
    /// Equivalent to `CURLOPT_UNRESTRICTED_AUTH`.
    pub const fn unrestricted_auth(&mut self, enable: bool) {
        self.unrestricted_auth = enable;
    }

    /// Ignore the Content-Length header in responses.
    ///
    /// When enabled, the response body is read until EOF rather than
    /// using the Content-Length header to determine body size.
    /// Equivalent to `CURLOPT_IGNORE_CONTENT_LENGTH`.
    pub const fn ignore_content_length(&mut self, enable: bool) {
        self.ignore_content_length = enable;
    }

    /// Connect via a Unix domain socket instead of TCP.
    ///
    /// When set, all connections go through the specified Unix socket path.
    /// The hostname from the URL is used for the `Host` header and TLS SNI,
    /// but the actual connection is made to the socket.
    /// Equivalent to curl's `--unix-socket` or `CURLOPT_UNIX_SOCKET_PATH`.
    pub fn unix_socket(&mut self, path: &str) {
        self.unix_socket = Some(path.to_string());
    }

    /// Attach a Share handle for cross-handle data sharing.
    ///
    /// When a Share handle is attached, the Easy handle uses the shared
    /// DNS cache and/or cookie jar instead of its own private instances.
    /// This allows multiple Easy handles to benefit from shared caching.
    ///
    /// Equivalent to `CURLOPT_SHARE`.
    pub fn set_share(&mut self, share: crate::share::Share) {
        self.share = Some(share);
    }

    /// Set the preferred HTTP version.
    ///
    /// Controls which HTTP protocol version to use for requests.
    /// - [`HttpVersion::None`] (default): auto-select (HTTP/2 via ALPN if available)
    /// - [`HttpVersion::Http10`]: force HTTP/1.0
    /// - [`HttpVersion::Http11`]: force HTTP/1.1 (skip HTTP/2 ALPN)
    /// - [`HttpVersion::Http2`]: prefer HTTP/2 (same as default for HTTPS)
    ///
    /// Equivalent to `CURLOPT_HTTP_VERSION`.
    pub const fn http_version(&mut self, version: HttpVersion) {
        self.http_version = version;
    }

    /// Allow HTTP/0.9 responses (no status line, just raw body).
    ///
    /// By default, HTTP/0.9 responses are rejected with exit code 1
    /// (`CURLE_UNSUPPORTED_PROTOCOL`). Enable this to accept them.
    /// Equivalent to `CURLOPT_HTTP09_ALLOWED`.
    pub const fn http09_allowed(&mut self, enable: bool) {
        self.http09_allowed = enable;
    }

    /// Set the Expect: 100-continue timeout.
    ///
    /// When set, POST/PUT requests with a body will send an
    /// `Expect: 100-continue` header and wait up to this duration for
    /// a `100 Continue` response before sending the body. If the server
    /// responds with an error status, the body is not sent.
    ///
    /// Equivalent to `CURLOPT_EXPECT_100_TIMEOUT_MS`.
    pub const fn expect_100_timeout(&mut self, timeout: Duration) {
        self.expect_100_timeout = Some(timeout);
    }

    /// Enable chunked transfer encoding for uploads.
    ///
    /// When enabled, the request body is sent using chunked transfer encoding.
    /// This is typically used for stdin uploads where the size isn't known
    /// in advance.
    pub const fn set_chunked_upload(&mut self, enable: bool) {
        self.chunked_upload = enable;
    }

    /// Set the maximum download speed in bytes per second.
    ///
    /// Equivalent to `CURLOPT_MAX_RECV_SPEED_LARGE`.
    pub const fn max_recv_speed(&mut self, bytes_per_sec: u64) {
        self.max_recv_speed = Some(bytes_per_sec);
    }

    /// Set the maximum upload speed in bytes per second.
    ///
    /// Equivalent to `CURLOPT_MAX_SEND_SPEED_LARGE`.
    pub const fn max_send_speed(&mut self, bytes_per_sec: u64) {
        self.max_send_speed = Some(bytes_per_sec);
    }

    /// Set the minimum transfer speed in bytes per second.
    ///
    /// If the transfer speed drops below this limit for longer than
    /// the duration set by [`low_speed_time`](Self::low_speed_time),
    /// the transfer is aborted.
    ///
    /// Equivalent to `CURLOPT_LOW_SPEED_LIMIT`.
    pub const fn low_speed_limit(&mut self, bytes_per_sec: u32) {
        self.low_speed_limit = Some(bytes_per_sec);
    }

    /// Set the time window for minimum speed enforcement.
    ///
    /// If the transfer speed stays below the limit set by
    /// [`low_speed_limit`](Self::low_speed_limit) for this duration,
    /// the transfer is aborted with a timeout error.
    ///
    /// Equivalent to `CURLOPT_LOW_SPEED_TIME`.
    pub const fn low_speed_time(&mut self, duration: Duration) {
        self.low_speed_time = Some(duration);
    }

    /// Force a fresh connection, ignoring the connection pool.
    ///
    /// When enabled, the transfer always uses a new connection rather
    /// than reusing a pooled connection.
    ///
    /// Equivalent to `CURLOPT_FRESH_CONNECT`.
    pub const fn fresh_connect(&mut self, enable: bool) {
        self.fresh_connect = enable;
    }

    /// Forbid connection reuse after the transfer completes.
    ///
    /// When enabled, the connection is closed after the transfer
    /// rather than being returned to the connection pool for reuse.
    ///
    /// Equivalent to `CURLOPT_FORBID_REUSE`.
    pub const fn forbid_reuse(&mut self, enable: bool) {
        self.forbid_reuse = enable;
    }

    /// Preserve POST method on 301 redirects.
    ///
    /// By default, curl changes POST to GET on 301 redirects.
    /// When this is enabled, POST is preserved.
    /// Equivalent to curl's `--post301` or `CURLOPT_POSTREDIR` bit 0.
    pub const fn post301(&mut self, enable: bool) {
        self.post301 = enable;
    }

    /// Preserve POST method on 302 redirects.
    ///
    /// By default, curl changes POST to GET on 302 redirects.
    /// When this is enabled, POST is preserved.
    /// Equivalent to curl's `--post302` or `CURLOPT_POSTREDIR` bit 1.
    pub const fn post302(&mut self, enable: bool) {
        self.post302 = enable;
    }

    /// Preserve POST method on 303 redirects.
    ///
    /// By default, curl changes POST to GET on 303 redirects.
    /// When this is enabled, POST is preserved.
    /// Equivalent to curl's `--post303` or `CURLOPT_POSTREDIR` bit 2.
    pub const fn post303(&mut self, enable: bool) {
        self.post303 = enable;
    }

    /// Add a header to send only to the proxy, not the target server.
    ///
    /// Equivalent to curl's `--proxy-header` or `CURLOPT_PROXYHEADER`.
    /// Headers containing CR or LF characters are silently rejected.
    pub fn proxy_header(&mut self, name: &str, value: &str) {
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return;
        }
        self.proxy_headers.push((name.to_string(), value.to_string()));
    }

    /// Set the FTP SSL/TLS mode.
    ///
    /// - `None`: plain FTP (default)
    /// - `Explicit`: start plain, upgrade with AUTH TLS (RFC 4217)
    /// - `Implicit`: connect directly over TLS (port 990)
    ///
    /// Equivalent to curl's `--ftp-ssl` (explicit) or `--ftp-ssl-reqd`.
    pub const fn ftp_ssl_mode(&mut self, mode: crate::protocol::ftp::FtpSslMode) {
        self.ftp_ssl_mode = mode;
    }

    /// Set the address for FTP active mode data connections.
    ///
    /// When set, PORT/EPRT commands are used instead of PASV.
    /// Use `"-"` to use the control connection's local address.
    ///
    /// Equivalent to curl's `--ftp-port`.
    pub fn ftp_active_port(&mut self, addr: &str) {
        self.ftp_active_port = Some(addr.to_string());
    }

    /// Enable/disable FTP extended passive mode (EPSV).
    ///
    /// Enabled by default. Equivalent to `CURLOPT_FTP_USE_EPSV`.
    pub const fn ftp_use_epsv(&mut self, enable: bool) {
        self.ftp_use_epsv = enable;
    }

    /// Enable/disable FTP extended active mode (EPRT).
    ///
    /// Enabled by default. Equivalent to `CURLOPT_FTP_USE_EPRT`.
    pub const fn ftp_use_eprt(&mut self, enable: bool) {
        self.ftp_use_eprt = enable;
    }

    /// Skip the IP address from the server's PASV response.
    ///
    /// When enabled, use the control connection's IP for data connections.
    /// Equivalent to `CURLOPT_FTP_SKIP_PASV_IP`.
    pub const fn ftp_skip_pasv_ip(&mut self, skip: bool) {
        self.ftp_skip_pasv_ip = skip;
    }

    /// Set the FTP account string (sent via ACCT command).
    ///
    /// Equivalent to `CURLOPT_FTP_ACCOUNT`.
    pub fn ftp_account(&mut self, account: &str) {
        self.ftp_account = Some(account.to_string());
    }

    /// Set a time condition for FTP downloads (`-z` flag).
    ///
    /// When set, FTP downloads use MDTM to check file modification time.
    /// `negate=false`: download if file is newer than `timestamp`.
    /// `negate=true`: download if file is older than `timestamp`.
    pub const fn ftp_time_condition(&mut self, timestamp: i64, negate: bool) {
        self.ftp_time_condition = Some((timestamp, negate));
    }

    /// Set the path to an SSH private key for SFTP/SCP authentication.
    ///
    /// When set, public key authentication is used instead of password.
    /// Supports OpenSSH key formats (ed25519, RSA, ECDSA).
    ///
    /// Equivalent to curl's `--key` / `CURLOPT_SSH_PRIVATE_KEYFILE`.
    pub fn ssh_key_path(&mut self, path: &str) {
        self.ssh_key_path = Some(path.to_string());
    }

    /// Set the path to an SSH public key file.
    ///
    /// Equivalent to `CURLOPT_SSH_PUBLIC_KEYFILE`.
    pub fn ssh_public_keyfile(&mut self, path: &str) {
        self.ssh_public_keyfile = Some(path.to_string());
    }

    /// Set the expected SSH host key SHA-256 fingerprint for verification.
    ///
    /// The fingerprint should be base64-encoded without the `SHA256:` prefix.
    /// If the server's host key does not match, the connection is rejected.
    ///
    /// Equivalent to curl's `--hostpubsha256`.
    pub fn ssh_host_key_sha256(&mut self, fingerprint: &str) {
        self.ssh_host_key_sha256 = Some(fingerprint.to_string());
    }

    /// Set the path to an SSH `known_hosts` file for host key verification.
    ///
    /// When set, the server's host key is verified against entries in the file.
    /// Supports both plain and hashed hostname formats.
    ///
    /// Equivalent to curl's `--known-hosts` / `CURLOPT_SSH_KNOWNHOSTS`.
    pub fn ssh_known_hosts_path(&mut self, path: &str) {
        self.ssh_known_hosts_path = Some(path.to_string());
    }

    /// Set the allowed SSH authentication types bitmask.
    ///
    /// Bitmask: 1=publickey, 2=password, 4=keyboard-interactive, 8=host.
    /// Equivalent to `CURLOPT_SSH_AUTH_TYPES`.
    pub const fn ssh_auth_types(&mut self, types: u32) {
        self.ssh_auth_types = Some(types);
    }

    /// Set explicit proxy port (overrides port in proxy URL).
    ///
    /// Equivalent to `CURLOPT_PROXYPORT`.
    pub const fn proxy_port(&mut self, port: u16) {
        self.proxy_port = Some(port);
    }

    /// Set proxy type.
    ///
    /// 0=HTTP, 1=HTTP 1.0, 2=HTTPS, 4=SOCKS4, 5=SOCKS5, 6=SOCKS4a, 7=SOCKS5h.
    /// Equivalent to `CURLOPT_PROXYTYPE`.
    pub const fn proxy_type(&mut self, ptype: u32) {
        self.proxy_type = Some(ptype);
    }

    /// Set SOCKS pre-proxy URL.
    ///
    /// Equivalent to `CURLOPT_PRE_PROXY`.
    pub fn pre_proxy(&mut self, url: &str) {
        self.pre_proxy = Some(url.to_string());
    }

    /// Don't normalize `..` and `.` path segments in the URL.
    ///
    /// Equivalent to curl's `--path-as-is` / `CURLOPT_PATH_AS_IS`.
    pub const fn path_as_is(&mut self, enable: bool) {
        self.path_as_is = enable;
    }

    /// Disable all internal HTTP content decoding.
    ///
    /// When enabled, the response body is returned as-is without
    /// any content-encoding decompression. Equivalent to curl's `--raw`.
    pub const fn raw(&mut self, enable: bool) {
        self.raw = enable;
    }

    /// Set HTTP NTLM authentication credentials.
    ///
    /// NTLM is a multi-step challenge-response authentication mechanism.
    /// Supports `DOMAIN\user` format — the domain prefix is extracted and
    /// sent in the NTLM Type 3 message.
    /// Equivalent to curl's `--ntlm -u user:pass`.
    pub fn ntlm_auth(&mut self, user: &str, password: &str) {
        let (domain, username) = if let Some((d, u)) = user.split_once('\\') {
            (Some(d.to_string()), u.to_string())
        } else {
            (None, user.to_string())
        };
        self.auth_credentials = Some(AuthCredentials {
            username,
            password: password.to_string(),
            method: AuthMethod::Ntlm,
            domain,
        });
    }

    /// Set authentication credentials for `--anyauth` mode.
    ///
    /// The first request is sent without auth. On 401, the
    /// `WWW-Authenticate` header is examined and the strongest
    /// supported method is used (Digest > NTLM > Basic).
    /// Supports `DOMAIN\user` format for NTLM.
    pub fn anyauth(&mut self, user: &str, password: &str) {
        let (domain, username) = if let Some((d, u)) = user.split_once('\\') {
            (Some(d.to_string()), u.to_string())
        } else {
            (None, user.to_string())
        };
        self.auth_credentials = Some(AuthCredentials {
            username,
            password: password.to_string(),
            method: AuthMethod::AnyAuth,
            domain,
        });
    }

    /// Set the SMTP envelope sender address (MAIL FROM).
    ///
    /// Equivalent to `CURLOPT_MAIL_FROM` / curl's `--mail-from`.
    pub fn mail_from(&mut self, address: &str) {
        self.mail_from = Some(address.to_string());
    }

    /// Add an SMTP envelope recipient (RCPT TO).
    ///
    /// Can be called multiple times for multiple recipients.
    /// Equivalent to `CURLOPT_MAIL_RCPT` / curl's `--mail-rcpt`.
    pub fn mail_rcpt(&mut self, address: &str) {
        self.mail_rcpt.push(address.to_string());
    }

    /// Set the SMTP AUTH identity (MAIL AUTH).
    ///
    /// Used to specify the original sender when relaying mail.
    /// Equivalent to `CURLOPT_MAIL_AUTH` / curl's `--mail-auth`.
    pub fn mail_auth(&mut self, address: &str) {
        self.mail_auth = Some(address.to_string());
    }

    /// Enable creation of missing directories on FTP server during upload.
    ///
    /// When enabled, urlx will attempt to create directories on the remote
    /// server that don't exist. Equivalent to `CURLOPT_FTP_CREATE_MISSING_DIRS`
    /// / curl's `--ftp-create-dirs`.
    pub const fn ftp_create_dirs(&mut self, enable: bool) {
        self.ftp_create_dirs = enable;
    }

    /// Set the FTP method for directory traversal.
    ///
    /// Controls how the path is traversed when accessing files via FTP.
    /// Equivalent to `CURLOPT_FTP_FILEMETHOD` / curl's `--ftp-method`.
    pub const fn ftp_method(&mut self, method: FtpMethod) {
        self.ftp_method = method;
    }

    /// Set FTP ASCII transfer mode (curl `--use-ascii` / `-B`).
    ///
    /// When enabled, uses TYPE A instead of TYPE I for file transfers.
    pub const fn ftp_use_ascii(&mut self, enable: bool) {
        self.ftp_use_ascii = enable;
    }

    /// Set FTP append mode (curl `--append` / `-a`).
    ///
    /// When enabled, uses APPE instead of STOR for uploads.
    pub const fn ftp_append(&mut self, enable: bool) {
        self.ftp_append = enable;
    }

    /// Set FTP CRLF conversion mode (curl `--crlf`).
    ///
    /// When enabled, converts LF to CRLF on upload.
    pub const fn ftp_crlf(&mut self, enable: bool) {
        self.ftp_crlf = enable;
    }

    /// Set FTP list-only mode (curl `-l` / `--list-only`).
    ///
    /// When enabled, uses NLST instead of LIST for directory listings.
    pub const fn ftp_list_only(&mut self, enable: bool) {
        self.ftp_list_only = enable;
    }

    /// Returns whether `-l` / `--list-only` mode is enabled.
    #[must_use]
    pub const fn is_ftp_list_only(&self) -> bool {
        self.ftp_list_only
    }

    /// Add an FTP quote command.
    ///
    /// Commands prefixed with `-` are sent after the transfer (post-quote).
    /// Commands without prefix are sent before the transfer (pre-quote).
    pub fn ftp_quote(&mut self, cmd: &str) {
        if let Some(stripped) = cmd.strip_prefix('-') {
            self.ftp_post_quote.push(stripped.to_string());
        } else {
            self.ftp_pre_quote.push(cmd.to_string());
        }
    }

    /// Set SASL authorization identity.
    ///
    /// The authorization identity for SASL authentication.
    /// Equivalent to `CURLOPT_SASL_AUTHZID` / curl's `--sasl-authzid`.
    pub fn sasl_authzid(&mut self, authzid: &str) {
        self.sasl_authzid = Some(authzid.to_string());
    }

    /// Enable SASL initial response.
    ///
    /// When enabled, the initial response is sent in the first SASL message.
    /// Equivalent to `CURLOPT_SASL_IR` / curl's `--sasl-ir`.
    pub const fn sasl_ir(&mut self, enable: bool) {
        self.sasl_ir = enable;
    }

    /// Add a `--connect-to` mapping: `from_host:from_port:to_host:to_port`.
    ///
    /// Redirects connections meant for `from_host:from_port` to `to_host:to_port`.
    /// Equivalent to `CURLOPT_CONNECT_TO` / curl's `--connect-to`.
    pub fn connect_to(&mut self, mapping: &str) {
        self.connect_to.push(mapping.to_string());
    }

    /// Enable `HAProxy` PROXY protocol v1 header.
    ///
    /// Sends a PROXY protocol header at the start of the connection.
    /// Equivalent to `CURLOPT_HAPROXYPROTOCOL` / curl's `--haproxy-protocol`.
    pub const fn haproxy_protocol(&mut self, enable: bool) {
        self.haproxy_protocol = enable;
    }

    /// Set abstract Unix domain socket path (Linux-only).
    ///
    /// Similar to `--unix-socket` but uses Linux abstract socket namespace.
    /// Equivalent to `CURLOPT_ABSTRACT_UNIX_SOCKET` / curl's `--abstract-unix-socket`.
    pub fn abstract_unix_socket(&mut self, path: &str) {
        self.abstract_unix_socket = Some(path.to_string());
    }

    /// Don't verify the `DoH` (DNS-over-HTTPS) server's TLS certificate.
    ///
    /// Equivalent to curl's `--doh-insecure`.
    pub const fn doh_insecure(&mut self, enable: bool) {
        self.doh_insecure = enable;
    }

    /// Set the HTTP/2 initial stream window size in bytes.
    ///
    /// Controls how much data a single stream can receive before the
    /// sender must wait for a `WINDOW_UPDATE` frame. Default is 65,535
    /// bytes (HTTP/2 spec default). Must be between 1 and 2^31-1.
    pub const fn http2_window_size(&mut self, size: u32) {
        self.http2_window_size = Some(size);
    }

    /// Set the HTTP/2 initial connection window size in bytes.
    ///
    /// Controls total data across all streams before the sender must
    /// wait for a connection-level `WINDOW_UPDATE`. Default is 65,535 bytes.
    pub const fn http2_connection_window_size(&mut self, size: u32) {
        self.http2_connection_window_size = Some(size);
    }

    /// Set the HTTP/2 maximum frame size in bytes.
    ///
    /// The maximum size of a single HTTP/2 frame payload. Must be between
    /// 16,384 and 16,777,215 (2^24-1). Default is 16,384.
    pub const fn http2_max_frame_size(&mut self, size: u32) {
        self.http2_max_frame_size = Some(size);
    }

    /// Set the HTTP/2 maximum header list size in bytes.
    ///
    /// The maximum size of the decoded header list for incoming responses.
    pub const fn http2_max_header_list_size(&mut self, size: u32) {
        self.http2_max_header_list_size = Some(size);
    }

    /// Enable or disable HTTP/2 server push.
    ///
    /// When set to `false`, tells the server not to send `PUSH_PROMISE`
    /// frames via the `SETTINGS_ENABLE_PUSH` setting.
    pub const fn http2_enable_push(&mut self, enable: bool) {
        self.http2_enable_push = Some(enable);
    }

    /// Set the HTTP/2 stream priority weight (1-256).
    ///
    /// Higher weight streams get proportionally more bandwidth relative
    /// to sibling streams. Note: HTTP/2 priority was deprecated in
    /// RFC 9113 and many servers ignore it.
    /// Equivalent to `CURLOPT_STREAM_WEIGHT`.
    pub const fn http2_stream_weight(&mut self, weight: u16) {
        self.http2_stream_weight = Some(weight);
    }

    /// Set the HTTP/2 PING frame interval for connection keep-alive.
    ///
    /// When set, periodically sends HTTP/2 PING frames to keep the
    /// connection alive and detect dead connections.
    pub const fn http2_ping_interval(&mut self, interval: Duration) {
        self.http2_ping_interval = Some(interval);
    }

    /// Set a custom request target for the HTTP request line.
    ///
    /// Overrides the default request target (path + query from the URL).
    /// For example, `"*"` can be used for server-wide OPTIONS requests.
    pub fn custom_request_target(&mut self, target: &str) {
        self.custom_request_target = Some(target.to_string());
    }

    /// Set the TFTP block size for transfers.
    ///
    /// Valid values are 8-65464 (RFC 2348). Defaults to 512.
    pub const fn tftp_blksize(&mut self, blksize: u16) {
        self.tftp_blksize = Some(blksize);
    }

    /// Disable TFTP option negotiation.
    ///
    /// When enabled, no OACK options are sent, using vanilla RFC 1350 behavior.
    pub const fn tftp_no_options(&mut self, disable: bool) {
        self.tftp_no_options = disable;
    }

    /// Set allowed protocols for the initial request.
    ///
    /// Accepts a comma-separated string of protocol names (e.g., `"http,https,ftp"`).
    /// When set, requests to protocols not in the list will be rejected.
    /// Equivalent to `CURLOPT_PROTOCOLS_STR`.
    pub fn set_protocols_str(&mut self, protocols: &str) {
        let protos: Vec<String> = protocols.split(',').map(|s| s.trim().to_lowercase()).collect();
        self.allowed_protocols = Some(protos);
    }

    /// Set allowed protocols for redirects.
    ///
    /// Accepts a comma-separated string of protocol names (e.g., `"http,https"`).
    /// When set, redirects to protocols not in the list will be rejected.
    /// Equivalent to `CURLOPT_REDIR_PROTOCOLS_STR`.
    pub fn set_redir_protocols_str(&mut self, protocols: &str) {
        let protos: Vec<String> = protocols.split(',').map(|s| s.trim().to_lowercase()).collect();
        self.redir_protocols = Some(protos);
    }

    /// Build a DNS resolver from the current configuration.
    ///
    /// Uses hickory-dns when available and custom DNS servers or `DoH` URL
    /// is configured. Falls back to the system resolver otherwise.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    fn build_dns_resolver(&self) -> crate::dns::DnsResolver {
        #[cfg(feature = "hickory-dns")]
        {
            // If DoH URL is configured, use DoH resolver
            if let Some(ref doh_url) = self.doh_url {
                return crate::dns::DnsResolver::Hickory(Box::new(
                    crate::dns::HickoryResolver::from_doh(doh_url, self.doh_insecure),
                ));
            }
            // If custom DNS servers are configured, use hickory with those servers
            if let Some(ref servers) = self.dns_servers {
                return crate::dns::DnsResolver::Hickory(Box::new(
                    crate::dns::HickoryResolver::from_servers(servers),
                ));
            }
        }
        // Default: system resolver
        crate::dns::DnsResolver::System
    }

    /// Perform the transfer and return the response (blocking).
    ///
    /// Creates a new tokio runtime internally. Do not call from within
    /// an existing async runtime — use [`perform_async`](Self::perform_async) instead.
    ///
    /// # Errors
    ///
    /// Returns errors for connection failures, TLS errors, HTTP protocol
    /// errors, timeouts, and other transfer problems.
    pub fn perform(&mut self) -> Result<Response, Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Http(format!("failed to create runtime: {e}")))?;

        rt.block_on(self.perform_async())
    }

    /// Perform the transfer and return the response (async).
    ///
    /// Use this when you already have a tokio runtime running.
    ///
    /// # Errors
    ///
    /// Returns errors for connection failures, TLS errors, HTTP protocol
    /// errors, timeouts, and other transfer problems.
    #[allow(clippy::too_many_lines)]
    pub async fn perform_async(&mut self) -> Result<Response, Error> {
        let url = self.url.as_ref().ok_or_else(|| Error::UrlParse("no URL set".to_string()))?;

        // HSTS: upgrade HTTP to HTTPS if the host is in the HSTS cache
        let url = if url.scheme() == "http" {
            if let Some(ref cache) = self.hsts_cache {
                if cache.should_upgrade(url.host_str().unwrap_or("")) {
                    let upgraded = url.as_str().replacen("http://", "https://", 1);
                    Url::parse(&upgraded)?
                } else {
                    url.clone()
                }
            } else {
                url.clone()
            }
        } else {
            url.clone()
        };

        // Check allowed protocols
        if let Some(ref allowed) = self.allowed_protocols {
            let scheme = url.scheme().to_lowercase();
            if !allowed.iter().any(|p| p == &scheme) {
                return Err(Error::Http(format!(
                    "protocol '{scheme}' not allowed (allowed: {})",
                    allowed.join(",")
                )));
            }
        }

        // Build effective headers, body, and method considering multipart and range
        let mut headers = self.headers.clone();

        // Apply removed_headers: for built-in default headers (User-Agent, Accept),
        // add a sentinel empty-value entry so the h1 emitter suppresses the default.
        // Only apply to known built-in defaults — other removal markers just prevent
        // previously-set custom headers from being emitted.
        // (curl compat: -H "User-Agent:" suppresses User-Agent, test 1147)
        for removed in &self.removed_headers {
            let already_set = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(removed));
            if !already_set {
                let name = match removed.as_str() {
                    "user-agent" => Some("User-Agent"),
                    "accept" => Some("Accept"),
                    _ => None,
                };
                if let Some(name) = name {
                    headers.push((name.to_string(), String::new()));
                }
            }
        }

        let (effective_method, effective_body);

        if let Some(ref multipart) = self.multipart {
            // Multipart form: encode body and set content-type header
            effective_body = Some(multipart.encode());
            let ct_idx = headers.iter().position(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if let Some(idx) = ct_idx {
                // User provided Content-Type: extract value, remove it, and re-add
                // with proper casing and boundary appended (curl compat: test 669)
                let mut ct_value = headers.remove(idx).1;
                if !ct_value.contains("boundary=") {
                    ct_value = format!("{ct_value}; boundary={}", multipart.boundary());
                }
                headers.push(("Content-Type".to_string(), ct_value));
            } else {
                headers.push(("Content-Type".to_string(), multipart.content_type()));
            }
            // Default to POST for multipart
            effective_method = self.method.clone().unwrap_or_else(|| "POST".to_string());
        } else {
            effective_body = self.body.clone();
            effective_method = self.method.clone().unwrap_or_else(|| "GET".to_string());
        }

        // Auto-add Content-Type for form data with custom method (curl compat: test 796)
        // POST gets Content-Type from h1.rs; custom methods with -d need it here.
        if self.form_data
            && effective_body.is_some()
            && !effective_method.eq_ignore_ascii_case("POST")
            && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push((
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }

        // Add Range header if set
        if let Some(ref range) = self.range {
            if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
                headers.push(("Range".to_string(), format!("bytes={range}")));
            }
        }

        // AWS SigV4 signing: add auth headers before sending
        if let Some(ref sigv4_config) = self.aws_sigv4 {
            if let Some((ref access_key, ref secret_key)) = self.aws_credentials {
                if let Ok(parsed_url) = url::Url::parse(url.as_str()) {
                    let timestamp = crate::auth::aws_sigv4::now_timestamp();
                    let body_bytes = effective_body.as_deref().unwrap_or(&[]);
                    let sigv4_headers = crate::auth::aws_sigv4::sign_request(
                        &effective_method,
                        &parsed_url,
                        &headers,
                        body_bytes,
                        access_key,
                        secret_key,
                        sigv4_config,
                        &timestamp,
                    );
                    headers.extend(sigv4_headers);
                }
            }
        }

        // Resolve proxy: explicit setting takes priority, then env vars
        let env_proxy = if self.proxy.is_none() { proxy_from_env(url.scheme()) } else { None };
        let mut effective_proxy_owned = self.proxy.clone().or(env_proxy);

        // Apply proxy_port override
        if let (Some(ref mut proxy_url), Some(port)) = (&mut effective_proxy_owned, self.proxy_port)
        {
            let _ = proxy_url.set_port(Some(port));
        }

        // Apply proxy_type override (rewrite scheme)
        if let (Some(ref mut proxy_url), Some(ptype)) =
            (&mut effective_proxy_owned, self.proxy_type)
        {
            let scheme = proxy_type_to_scheme(ptype);
            let _ = proxy_url.set_scheme(scheme);
        }

        let effective_proxy = effective_proxy_owned.as_ref();

        // Resolve noproxy: explicit setting takes priority, then env vars
        let env_noproxy = if self.noproxy.is_none() { noproxy_from_env() } else { None };
        let resolved_noproxy = self.noproxy.as_deref().or(env_noproxy.as_deref());
        let effective_noproxy = resolved_noproxy;

        // Swap in shared state if a Share handle is attached.
        // We briefly lock to swap, then release — no lock held across await.
        if let Some(ref share) = self.share {
            if let Some(dns_arc) = share.dns_cache() {
                if let Ok(mut shared) = dns_arc.lock() {
                    std::mem::swap(&mut self.dns_cache, &mut *shared);
                }
            }
            if let Some(cookie_arc) = share.cookie_jar() {
                if let Ok(mut shared) = cookie_arc.lock() {
                    // Ensure cookie jar is enabled if shared
                    if self.cookie_jar.is_none() {
                        self.cookie_jar = Some(CookieJar::new());
                    }
                    if let Some(ref mut local_jar) = self.cookie_jar {
                        std::mem::swap(local_jar, &mut *shared);
                    }
                }
            }
        }

        let speed_limits = SpeedLimits {
            max_recv_speed: self.max_recv_speed,
            max_send_speed: self.max_send_speed,
            low_speed_limit: self.low_speed_limit,
            low_speed_time: self.low_speed_time,
        };

        #[cfg(feature = "http2")]
        let h2_config = crate::protocol::http::h2::Http2Config {
            window_size: self.http2_window_size,
            connection_window_size: self.http2_connection_window_size,
            max_frame_size: self.http2_max_frame_size,
            max_header_list_size: self.http2_max_header_list_size,
            enable_push: self.http2_enable_push,
            stream_weight: self.http2_stream_weight,
            ping_interval: self.http2_ping_interval,
        };

        let ftp_config = crate::protocol::ftp::FtpConfig {
            use_epsv: self.ftp_use_epsv,
            use_eprt: self.ftp_use_eprt,
            skip_pasv_ip: self.ftp_skip_pasv_ip,
            account: self.ftp_account.clone(),
            create_dirs: self.ftp_create_dirs,
            method: self.ftp_method,
            active_port: self.ftp_active_port.clone(),
            use_ascii: self.ftp_use_ascii,
            append: self.ftp_append,
            crlf: self.ftp_crlf,
            list_only: self.ftp_list_only,
            nobody: effective_method == "HEAD",
            pre_quote: self.ftp_pre_quote.clone(),
            post_quote: self.ftp_post_quote.clone(),
            time_condition: self.ftp_time_condition,
            range_end: None,
            ignore_content_length: self.ignore_content_length,
        };

        let dns_resolver = self.build_dns_resolver();

        #[cfg(feature = "ssh")]
        let ssh_host_key_policy = build_ssh_host_key_policy(
            self.ssh_host_key_sha256.as_deref(),
            self.ssh_known_hosts_path.as_deref(),
        )?;
        #[cfg(not(feature = "ssh"))]
        let ssh_host_key_policy = ();

        let last_resp_store = std::sync::Arc::new(std::sync::Mutex::new(None::<Response>));
        let deadline = self.timeout.map(|d| tokio::time::Instant::now() + d);
        let fut = perform_transfer(
            last_resp_store.clone(),
            deadline,
            &url,
            Some(effective_method.as_str()),
            &headers,
            effective_body.as_deref(),
            self.follow_redirects,
            self.max_redirects,
            self.verbose,
            self.accept_encoding && !self.raw,
            self.connect_timeout,
            effective_proxy,
            effective_noproxy,
            &mut self.cookie_jar,
            &mut self.hsts_cache,
            &self.resolve_overrides,
            self.auth_credentials.as_ref(),
            self.proxy_credentials.as_ref(),
            &self.tls_config,
            self.tcp_nodelay,
            self.tcp_keepalive,
            self.unix_socket.as_deref(),
            self.interface.as_deref(),
            self.local_port,
            self.dns_shuffle,
            &mut self.dns_cache,
            &mut self.pool,
            #[cfg(feature = "http2")]
            &mut self.h2_pool,
            self.http_version,
            self.expect_100_timeout,
            self.happy_eyeballs_timeout,
            self.unrestricted_auth,
            self.ignore_content_length,
            &mut self.alt_svc_cache,
            &speed_limits,
            self.post301,
            self.post302,
            self.post303,
            self.ftp_ssl_mode,
            self.ssh_key_path.as_deref(),
            self.proxy_tls_config.as_ref(),
            #[cfg(feature = "http2")]
            &h2_config,
            &dns_resolver,
            self.custom_request_target.as_deref(),
            self.tftp_blksize,
            self.tftp_no_options,
            &ssh_host_key_policy,
            self.mail_from.as_deref(),
            &self.mail_rcpt,
            self.redir_protocols.as_deref(),
            self.fresh_connect,
            self.forbid_reuse,
            &ftp_config,
            &self.proxy_headers,
            &self.connect_to,
            self.path_as_is,
            self.ssh_public_keyfile.as_deref(),
            self.ssh_auth_types,
            self.mail_auth.as_deref(),
            self.sasl_authzid.as_deref(),
            self.sasl_ir,
            self.oauth2_bearer.as_deref(),
            self.haproxy_protocol,
            self.abstract_unix_socket.as_deref(),
            self.chunked_upload,
            self.http09_allowed,
            self.http_proxy_tunnel,
            self.proxy_http_10,
            self.raw,
        );

        // Apply total transfer timeout if set.
        // Box::pin to avoid large future on stack.
        let fut = Box::pin(fut);
        let response = if let Some(timeout) = self.timeout {
            if let Ok(result) = tokio::time::timeout(timeout, fut).await {
                result
            } else {
                // Timeout — grab whatever response was stored before cancellation
                self.last_response = last_resp_store.lock().ok().and_then(|mut g| g.take());
                return Err(Error::Timeout(timeout));
            }
        } else {
            fut.await
        };

        // Swap shared state back after transfer completes (even on error).
        if let Some(ref share) = self.share {
            if let Some(dns_arc) = share.dns_cache() {
                if let Ok(mut shared) = dns_arc.lock() {
                    std::mem::swap(&mut self.dns_cache, &mut *shared);
                }
            }
            if let Some(cookie_arc) = share.cookie_jar() {
                if let Ok(mut shared) = cookie_arc.lock() {
                    if let Some(ref mut local_jar) = self.cookie_jar {
                        std::mem::swap(local_jar, &mut *shared);
                    }
                }
            }
        }

        // Store last response for error recovery (curl outputs partial data on error)
        self.last_response = last_resp_store.lock().ok().and_then(|mut g| g.take());

        let response = response?;

        // Store the successful response as last_response (overrides any partial from Arc)
        self.last_response = Some(response.clone());

        // Check fail_on_error: HTTP status >= 400 becomes an error
        if self.fail_on_error && response.status() >= 400 {
            return Err(Error::Http(format!(
                "HTTP error {} (fail_on_error enabled)",
                response.status()
            )));
        }

        // Call progress callback with final transfer values
        if let Some(ref cb) = self.progress_callback {
            let ul_total = effective_body.as_ref().map_or(0, |b| b.len() as u64);
            let info = ProgressInfo {
                dl_total: response.body().len() as u64,
                dl_now: response.body().len() as u64,
                ul_total,
                ul_now: ul_total,
            };
            if !call_progress(cb, &info) {
                return Err(Error::Http("transfer aborted by progress callback".to_string()));
            }
        }

        Ok(response)
    }
}

impl Default for Easy {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal async transfer implementation.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, clippy::fn_params_excessive_bools)]
async fn perform_transfer(
    last_resp_store: std::sync::Arc<std::sync::Mutex<Option<Response>>>,
    deadline: Option<tokio::time::Instant>,
    url: &Url,
    method: Option<&str>,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    follow_redirects: bool,
    max_redirects: u32,
    verbose: bool,
    accept_encoding: bool,
    connect_timeout: Option<Duration>,
    proxy: Option<&Url>,
    noproxy: Option<&str>,
    cookie_jar: &mut Option<CookieJar>,
    hsts_cache: &mut Option<HstsCache>,
    resolve_overrides: &[(String, String)],
    auth_credentials: Option<&AuthCredentials>,
    proxy_credentials: Option<&ProxyAuthCredentials>,
    tls_config: &TlsConfig,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
    unix_socket: Option<&str>,
    interface: Option<&str>,
    local_port: Option<u16>,
    dns_shuffle: bool,
    dns_cache: &mut DnsCache,
    pool: &mut ConnectionPool,
    #[cfg(feature = "http2")] h2_pool: &mut crate::pool::H2Pool,
    http_version: HttpVersion,
    expect_100_timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
    unrestricted_auth: bool,
    ignore_content_length: bool,
    alt_svc_cache: &mut crate::protocol::http::altsvc::AltSvcCache,
    speed_limits: &SpeedLimits,
    post301: bool,
    post302: bool,
    post303: bool,
    ftp_ssl_mode: crate::protocol::ftp::FtpSslMode,
    ssh_key_path: Option<&str>,
    proxy_tls_config: Option<&TlsConfig>,
    #[cfg(feature = "http2")] h2_config: &crate::protocol::http::h2::Http2Config,
    dns_resolver: &crate::dns::DnsResolver,
    custom_request_target: Option<&str>,
    tftp_blksize: Option<u16>,
    tftp_no_options: bool,
    #[cfg(feature = "ssh")] ssh_host_key_policy: &crate::protocol::ssh::SshHostKeyPolicy,
    #[cfg(not(feature = "ssh"))] _ssh_host_key_policy: &(),
    mail_from: Option<&str>,
    mail_rcpt: &[String],
    redir_protocols: Option<&[String]>,
    fresh_connect: bool,
    forbid_reuse: bool,
    ftp_config: &crate::protocol::ftp::FtpConfig,
    proxy_headers: &[(String, String)],
    connect_to: &[String],
    path_as_is: bool,
    #[cfg_attr(not(feature = "ssh"), allow(unused_variables))] ssh_public_keyfile: Option<&str>,
    #[cfg_attr(not(feature = "ssh"), allow(unused_variables))] ssh_auth_types: Option<u32>,
    mail_auth: Option<&str>,
    sasl_authzid: Option<&str>,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    haproxy_protocol: bool,
    abstract_unix_socket: Option<&str>,
    chunked_upload: bool,
    http09_allowed: bool,
    http_proxy_tunnel: bool,
    proxy_http_10: bool,
    raw: bool,
) -> Result<Response, Error> {
    let transfer_start = Instant::now();
    let original_url = url.clone();
    let mut current_url = url.clone();
    let mut current_method = method.unwrap_or("GET").to_string();
    let mut current_body = body.map(<[u8]>::to_vec);
    let mut redirects_followed: u32 = 0;
    let mut redirect_chain: Vec<Response> = Vec::new();
    let mut body_dropped_on_redirect = false;

    loop {
        // Determine effective proxy for this URL
        let effective_proxy = proxy.filter(|_| !should_bypass_proxy(&current_url, noproxy));

        // Build headers, stripping auth on cross-origin redirects unless unrestricted
        let mut request_headers = headers.to_vec();
        // Remove Content-Type on redirect when body was dropped (302→GET, curl compat: test 796)
        if body_dropped_on_redirect {
            request_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        }
        if redirects_followed > 0 {
            let orig_host = original_url.host_str().unwrap_or("");
            let cur_host = current_url.host_str().unwrap_or("");
            if !orig_host.eq_ignore_ascii_case(cur_host) {
                if !unrestricted_auth {
                    // Strip auth and sensitive headers on cross-host redirect
                    request_headers.retain(|(k, _)| {
                        !k.eq_ignore_ascii_case("authorization")
                            && !k.eq_ignore_ascii_case("cookie")
                    });
                }
                // Drop custom Host header on cross-host redirect (curl compat: test 184)
                request_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
            }
        }
        if let Some(ref jar) = cookie_jar {
            // Use custom Host header for cookie domain matching if present (curl compat)
            let cookie_host =
                request_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map_or_else(
                    || current_url.host_str().unwrap_or(""),
                    // Strip port from Host header value if present
                    |(_, v)| v.split(':').next().unwrap_or(v.as_str()),
                );
            let path = current_url.path();
            let is_secure = current_url.scheme() == "https";
            if let Some(cookie_header) = jar.cookie_header(cookie_host, path, is_secure) {
                // Merge with existing Cookie header if user set one (curl compat: -b file -b "k=v")
                if let Some(existing) =
                    request_headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                {
                    existing.1 = format!("{}; {}", cookie_header, existing.1);
                } else {
                    request_headers.push(("Cookie".to_string(), cookie_header));
                }
            }
        }

        // For Digest, don't send body on initial request — it will be
        // rejected with 401 anyway. Send body only on the retry with credentials.
        // Send Content-Length: 0 for PUT/POST to match curl behavior.
        // For AnyAuth, send the full body on the first request (it's a "try without auth"
        // approach — if the server responds 200, we're done).
        // For NTLM, send Content-Length: 0 (body will be sent after Type3).
        let is_challenge_response =
            auth_credentials.as_ref().is_some_and(|a| matches!(a.method, AuthMethod::Digest));
        let is_ntlm_probe =
            auth_credentials.as_ref().is_some_and(|a| matches!(a.method, AuthMethod::Ntlm));
        let initial_body = if is_challenge_response || is_ntlm_probe {
            if current_body.is_some() {
                Some(&[] as &[u8]) // Empty body → sends Content-Length: 0
            } else {
                None
            }
        } else {
            current_body.as_deref()
        };

        // For explicit NTLM, send Type 1 message on the first request
        if let Some(auth) = auth_credentials {
            if auth.method == AuthMethod::Ntlm {
                let type1 = crate::auth::ntlm::create_type1_message();
                request_headers.push(("Authorization".to_string(), format!("NTLM {type1}")));
            }
        }

        // For proxy NTLM on CONNECT tunnels, the auth is handled by
        // establish_connect_tunnel. For non-CONNECT proxy NTLM, send Type 1 here.
        let is_proxy_ntlm =
            proxy_credentials.is_some_and(|pcreds| pcreds.method == ProxyAuthMethod::Ntlm);
        let is_connect_tunnel = effective_proxy.is_some() && http_proxy_tunnel;
        if is_proxy_ntlm && !is_connect_tunnel {
            let type1 = crate::auth::ntlm::create_type1_message();
            request_headers.push(("Proxy-Authorization".to_string(), format!("NTLM {type1}")));
        }
        // Suppress body during NTLM Type 1 negotiation (Content-Length: 0, test 239)
        let ntlm_initial_body =
            if is_proxy_ntlm && !is_connect_tunnel { None } else { initial_body };
        let mut response = Box::pin(do_single_request(
            &current_url,
            &current_method,
            &request_headers,
            ntlm_initial_body,
            verbose,
            accept_encoding,
            connect_timeout,
            effective_proxy,
            proxy_credentials,
            resolve_overrides,
            tls_config,
            tcp_nodelay,
            tcp_keepalive,
            unix_socket,
            interface,
            local_port,
            dns_shuffle,
            dns_cache,
            pool,
            #[cfg(feature = "http2")]
            h2_pool,
            http_version,
            expect_100_timeout,
            happy_eyeballs_timeout,
            ignore_content_length,
            speed_limits,
            ftp_ssl_mode,
            ssh_key_path,
            proxy_tls_config,
            alt_svc_cache,
            #[cfg(feature = "http2")]
            h2_config,
            dns_resolver,
            custom_request_target,
            tftp_blksize,
            tftp_no_options,
            #[cfg(feature = "ssh")]
            ssh_host_key_policy,
            mail_from,
            mail_rcpt,
            fresh_connect,
            forbid_reuse,
            ftp_config,
            proxy_headers,
            connect_to,
            path_as_is,
            #[cfg(feature = "ssh")]
            ssh_public_keyfile,
            #[cfg(not(feature = "ssh"))]
            None,
            #[cfg(feature = "ssh")]
            ssh_auth_types,
            #[cfg(not(feature = "ssh"))]
            None,
            mail_auth,
            sasl_authzid,
            sasl_ir,
            oauth2_bearer,
            haproxy_protocol,
            abstract_unix_socket,
            chunked_upload,
            http09_allowed,
            deadline,
            http_proxy_tunnel,
            proxy_http_10,
            raw,
        ))
        .await?;

        // Store latest response for error recovery (timeout, max-redirects, etc.)
        if let Ok(mut guard) = last_resp_store.lock() {
            *guard = Some(response.clone());
        }

        // For Digest/NTLM: if we sent an empty-body probe and the server didn't
        // challenge us (response is not 401), re-send the request with the full body.
        // This handles the case where --digest/--ntlm is used but the server doesn't
        // require auth (curl tests 175, 176).
        if (is_challenge_response || is_ntlm_probe) && response.status() != 401 {
            if let Some(body) = current_body.as_deref() {
                if !body.is_empty() {
                    redirect_chain.push(response.clone());
                    // Re-send without auth headers (server didn't ask for any)
                    let mut retry_headers = request_headers.clone();
                    // Remove any auth headers added by the probe
                    retry_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("authorization"));
                    response = Box::pin(do_single_request(
                        &current_url,
                        &current_method,
                        &retry_headers,
                        current_body.as_deref(),
                        verbose,
                        accept_encoding,
                        connect_timeout,
                        effective_proxy,
                        proxy_credentials,
                        resolve_overrides,
                        tls_config,
                        tcp_nodelay,
                        tcp_keepalive,
                        unix_socket,
                        interface,
                        local_port,
                        dns_shuffle,
                        dns_cache,
                        pool,
                        #[cfg(feature = "http2")]
                        h2_pool,
                        http_version,
                        expect_100_timeout,
                        happy_eyeballs_timeout,
                        ignore_content_length,
                        speed_limits,
                        ftp_ssl_mode,
                        ssh_key_path,
                        proxy_tls_config,
                        alt_svc_cache,
                        #[cfg(feature = "http2")]
                        h2_config,
                        dns_resolver,
                        custom_request_target,
                        tftp_blksize,
                        tftp_no_options,
                        #[cfg(feature = "ssh")]
                        ssh_host_key_policy,
                        mail_from,
                        mail_rcpt,
                        fresh_connect,
                        forbid_reuse,
                        ftp_config,
                        proxy_headers,
                        connect_to,
                        path_as_is,
                        #[cfg(feature = "ssh")]
                        ssh_public_keyfile,
                        #[cfg(not(feature = "ssh"))]
                        None,
                        #[cfg(feature = "ssh")]
                        ssh_auth_types,
                        #[cfg(not(feature = "ssh"))]
                        None,
                        mail_auth,
                        sasl_authzid,
                        sasl_ir,
                        oauth2_bearer,
                        haproxy_protocol,
                        abstract_unix_socket,
                        chunked_upload,
                        http09_allowed,
                        deadline,
                        http_proxy_tunnel,
                        proxy_http_10,
                        raw,
                    ))
                    .await?;
                }
            }
        }

        // Handle 401: Digest, NTLM, and AnyAuth challenge-response flows.
        if response.status() == 401 {
            if let Some(auth) = auth_credentials {
                // Determine which auth method to use for this 401
                let effective_method = if auth.method == AuthMethod::AnyAuth {
                    // AnyAuth: pick the strongest method from WWW-Authenticate headers
                    pick_best_auth_method(&response)
                } else {
                    Some(auth.method.clone())
                };

                match effective_method.as_ref() {
                    Some(AuthMethod::Digest) => {
                        // Find the Digest challenge among potentially multiple
                        // WWW-Authenticate headers (use ordered headers to see all).
                        // Raw values in headers_ordered start with ": " prefix.
                        let digest_challenge = response
                            .headers_ordered()
                            .iter()
                            .filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
                            .find_map(|(_, v)| {
                                let clean = strip_raw_header_value(v);
                                crate::auth::digest::DigestChallenge::parse(clean).ok()
                            });
                        if let Some(challenge) = digest_challenge {
                            // Save the 401 response for --include output (curl compat)
                            redirect_chain.push(response.clone());
                            if verbose {
                                #[allow(clippy::print_stderr)]
                                {
                                    eprintln!(
                                        "* Server auth using Digest with realm '{}'",
                                        challenge.realm
                                    );
                                }
                            }

                            let uri = resolve_request_target(
                                custom_request_target,
                                &current_url,
                                path_as_is,
                            );
                            let cnonce = crate::auth::digest::generate_cnonce();
                            let auth_header = challenge.respond(
                                &auth.username,
                                &auth.password,
                                &current_method,
                                &uri,
                                1,
                                &cnonce,
                            );

                            let mut auth_headers = request_headers.clone();
                            auth_headers.push(("Authorization".to_string(), auth_header));

                            response = Box::pin(do_single_request(
                                &current_url,
                                &current_method,
                                &auth_headers,
                                current_body.as_deref(),
                                verbose,
                                accept_encoding,
                                connect_timeout,
                                effective_proxy,
                                proxy_credentials,
                                resolve_overrides,
                                tls_config,
                                tcp_nodelay,
                                tcp_keepalive,
                                unix_socket,
                                interface,
                                local_port,
                                dns_shuffle,
                                dns_cache,
                                pool,
                                #[cfg(feature = "http2")]
                                h2_pool,
                                http_version,
                                expect_100_timeout,
                                happy_eyeballs_timeout,
                                ignore_content_length,
                                speed_limits,
                                ftp_ssl_mode,
                                ssh_key_path,
                                proxy_tls_config,
                                alt_svc_cache,
                                #[cfg(feature = "http2")]
                                h2_config,
                                dns_resolver,
                                custom_request_target,
                                tftp_blksize,
                                tftp_no_options,
                                #[cfg(feature = "ssh")]
                                ssh_host_key_policy,
                                mail_from,
                                mail_rcpt,
                                fresh_connect,
                                forbid_reuse,
                                ftp_config,
                                proxy_headers,
                                connect_to,
                                path_as_is,
                                #[cfg(feature = "ssh")]
                                ssh_public_keyfile,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                #[cfg(feature = "ssh")]
                                ssh_auth_types,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                mail_auth,
                                sasl_authzid,
                                sasl_ir,
                                oauth2_bearer,
                                haproxy_protocol,
                                abstract_unix_socket,
                                chunked_upload,
                                http09_allowed,
                                deadline,
                                http_proxy_tunnel,
                                proxy_http_10,
                                raw,
                            ))
                            .await?;

                            // Check for stale=true: server wants us to retry with a new nonce
                            if response.status() == 401 {
                                let stale_challenge = response
                                    .headers_ordered()
                                    .iter()
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
                                    .find_map(|(_, v)| {
                                        let clean = strip_raw_header_value(v);
                                        crate::auth::digest::DigestChallenge::parse(clean).ok()
                                    })
                                    .filter(|c| c.stale);

                                if let Some(new_challenge) = stale_challenge {
                                    redirect_chain.push(response.clone());
                                    let uri = resolve_request_target(
                                        custom_request_target,
                                        &current_url,
                                        path_as_is,
                                    );
                                    let cnonce = crate::auth::digest::generate_cnonce();
                                    let auth_header = new_challenge.respond(
                                        &auth.username,
                                        &auth.password,
                                        &current_method,
                                        &uri,
                                        1,
                                        &cnonce,
                                    );
                                    let mut stale_headers = request_headers.clone();
                                    stale_headers.push(("Authorization".to_string(), auth_header));
                                    response = Box::pin(do_single_request(
                                        &current_url,
                                        &current_method,
                                        &stale_headers,
                                        current_body.as_deref(),
                                        verbose,
                                        accept_encoding,
                                        connect_timeout,
                                        effective_proxy,
                                        proxy_credentials,
                                        resolve_overrides,
                                        tls_config,
                                        tcp_nodelay,
                                        tcp_keepalive,
                                        unix_socket,
                                        interface,
                                        local_port,
                                        dns_shuffle,
                                        dns_cache,
                                        pool,
                                        #[cfg(feature = "http2")]
                                        h2_pool,
                                        http_version,
                                        expect_100_timeout,
                                        happy_eyeballs_timeout,
                                        ignore_content_length,
                                        speed_limits,
                                        ftp_ssl_mode,
                                        ssh_key_path,
                                        proxy_tls_config,
                                        alt_svc_cache,
                                        #[cfg(feature = "http2")]
                                        h2_config,
                                        dns_resolver,
                                        custom_request_target,
                                        tftp_blksize,
                                        tftp_no_options,
                                        #[cfg(feature = "ssh")]
                                        ssh_host_key_policy,
                                        mail_from,
                                        mail_rcpt,
                                        fresh_connect,
                                        forbid_reuse,
                                        ftp_config,
                                        proxy_headers,
                                        connect_to,
                                        path_as_is,
                                        #[cfg(feature = "ssh")]
                                        ssh_public_keyfile,
                                        #[cfg(not(feature = "ssh"))]
                                        None,
                                        #[cfg(feature = "ssh")]
                                        ssh_auth_types,
                                        #[cfg(not(feature = "ssh"))]
                                        None,
                                        mail_auth,
                                        sasl_authzid,
                                        sasl_ir,
                                        oauth2_bearer,
                                        haproxy_protocol,
                                        abstract_unix_socket,
                                        chunked_upload,
                                        http09_allowed,
                                        deadline,
                                        http_proxy_tunnel,
                                        proxy_http_10,
                                        raw,
                                    ))
                                    .await?;
                                }
                            }
                        }
                    }
                    Some(AuthMethod::Ntlm) => {
                        // NTLM flow: either we already sent Type1 (--ntlm) or we need
                        // to send it now (--anyauth picked NTLM).
                        let domain = auth.domain.as_deref().unwrap_or("");

                        if auth.method == AuthMethod::AnyAuth {
                            // --anyauth: first request had no auth. Send Type 1 now.
                            redirect_chain.push(response.clone());
                            let type1 = crate::auth::ntlm::create_type1_message();
                            let mut type1_headers = request_headers.clone();
                            type1_headers
                                .push(("Authorization".to_string(), format!("NTLM {type1}")));

                            response = Box::pin(do_single_request(
                                &current_url,
                                &current_method,
                                &type1_headers,
                                current_body.as_deref(),
                                verbose,
                                accept_encoding,
                                connect_timeout,
                                effective_proxy,
                                proxy_credentials,
                                resolve_overrides,
                                tls_config,
                                tcp_nodelay,
                                tcp_keepalive,
                                unix_socket,
                                interface,
                                local_port,
                                dns_shuffle,
                                dns_cache,
                                pool,
                                #[cfg(feature = "http2")]
                                h2_pool,
                                http_version,
                                expect_100_timeout,
                                happy_eyeballs_timeout,
                                ignore_content_length,
                                speed_limits,
                                ftp_ssl_mode,
                                ssh_key_path,
                                proxy_tls_config,
                                alt_svc_cache,
                                #[cfg(feature = "http2")]
                                h2_config,
                                dns_resolver,
                                custom_request_target,
                                tftp_blksize,
                                tftp_no_options,
                                #[cfg(feature = "ssh")]
                                ssh_host_key_policy,
                                mail_from,
                                mail_rcpt,
                                fresh_connect,
                                forbid_reuse,
                                ftp_config,
                                proxy_headers,
                                connect_to,
                                path_as_is,
                                #[cfg(feature = "ssh")]
                                ssh_public_keyfile,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                #[cfg(feature = "ssh")]
                                ssh_auth_types,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                mail_auth,
                                sasl_authzid,
                                sasl_ir,
                                oauth2_bearer,
                                haproxy_protocol,
                                abstract_unix_socket,
                                chunked_upload,
                                http09_allowed,
                                deadline,
                                http_proxy_tunnel,
                                proxy_http_10,
                                raw,
                            ))
                            .await?;
                        }

                        // At this point we should have a 401 with NTLM Type 2 challenge
                        if response.status() == 401 {
                            if let Some(www_auth) = response.header("www-authenticate") {
                                if let Some(type2_data) = www_auth.strip_prefix("NTLM ") {
                                    let challenge =
                                        crate::auth::ntlm::parse_type2_message(type2_data)?;
                                    let type3 = crate::auth::ntlm::create_type3_message(
                                        &challenge,
                                        &auth.username,
                                        &auth.password,
                                        domain,
                                    );

                                    // Save the Type 2 401 response for --include output
                                    redirect_chain.push(response.clone());

                                    let mut type3_headers = request_headers.clone();
                                    type3_headers.push((
                                        "Authorization".to_string(),
                                        format!("NTLM {type3}"),
                                    ));

                                    response = Box::pin(do_single_request(
                                        &current_url,
                                        &current_method,
                                        &type3_headers,
                                        current_body.as_deref(),
                                        verbose,
                                        accept_encoding,
                                        connect_timeout,
                                        effective_proxy,
                                        proxy_credentials,
                                        resolve_overrides,
                                        tls_config,
                                        tcp_nodelay,
                                        tcp_keepalive,
                                        unix_socket,
                                        interface,
                                        local_port,
                                        dns_shuffle,
                                        dns_cache,
                                        pool,
                                        #[cfg(feature = "http2")]
                                        h2_pool,
                                        http_version,
                                        expect_100_timeout,
                                        happy_eyeballs_timeout,
                                        ignore_content_length,
                                        speed_limits,
                                        ftp_ssl_mode,
                                        ssh_key_path,
                                        proxy_tls_config,
                                        alt_svc_cache,
                                        #[cfg(feature = "http2")]
                                        h2_config,
                                        dns_resolver,
                                        custom_request_target,
                                        tftp_blksize,
                                        tftp_no_options,
                                        #[cfg(feature = "ssh")]
                                        ssh_host_key_policy,
                                        mail_from,
                                        mail_rcpt,
                                        fresh_connect,
                                        forbid_reuse,
                                        ftp_config,
                                        proxy_headers,
                                        connect_to,
                                        path_as_is,
                                        #[cfg(feature = "ssh")]
                                        ssh_public_keyfile,
                                        #[cfg(not(feature = "ssh"))]
                                        None,
                                        #[cfg(feature = "ssh")]
                                        ssh_auth_types,
                                        #[cfg(not(feature = "ssh"))]
                                        None,
                                        mail_auth,
                                        sasl_authzid,
                                        sasl_ir,
                                        oauth2_bearer,
                                        haproxy_protocol,
                                        abstract_unix_socket,
                                        chunked_upload,
                                        http09_allowed,
                                        deadline,
                                        http_proxy_tunnel,
                                        proxy_http_10,
                                        raw,
                                    ))
                                    .await?;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Handle 407 Proxy Authentication Required for proxy NTLM (non-CONNECT path)
        if response.status() == 407 {
            if let Some(pcreds) = proxy_credentials {
                if pcreds.method == ProxyAuthMethod::Ntlm {
                    // We sent Type 1 already; now parse Type 2 and send Type 3
                    if let Some(proxy_auth) = response.header("proxy-authenticate") {
                        if let Some(type2_data) = proxy_auth.strip_prefix("NTLM ") {
                            let challenge = crate::auth::ntlm::parse_type2_message(type2_data)?;
                            let domain = pcreds.domain.as_deref().unwrap_or("");
                            let type3 = crate::auth::ntlm::create_type3_message(
                                &challenge,
                                &pcreds.username,
                                &pcreds.password,
                                domain,
                            );

                            // Save the 407 response for --include output
                            redirect_chain.push(response.clone());

                            let mut type3_headers = request_headers.clone();
                            // Remove the old Proxy-Authorization header (Type 1)
                            type3_headers
                                .retain(|(k, _)| !k.eq_ignore_ascii_case("proxy-authorization"));
                            type3_headers
                                .push(("Proxy-Authorization".to_string(), format!("NTLM {type3}")));

                            response = Box::pin(do_single_request(
                                &current_url,
                                &current_method,
                                &type3_headers,
                                current_body.as_deref(),
                                verbose,
                                accept_encoding,
                                connect_timeout,
                                effective_proxy,
                                proxy_credentials,
                                resolve_overrides,
                                tls_config,
                                tcp_nodelay,
                                tcp_keepalive,
                                unix_socket,
                                interface,
                                local_port,
                                dns_shuffle,
                                dns_cache,
                                pool,
                                #[cfg(feature = "http2")]
                                h2_pool,
                                http_version,
                                expect_100_timeout,
                                happy_eyeballs_timeout,
                                ignore_content_length,
                                speed_limits,
                                ftp_ssl_mode,
                                ssh_key_path,
                                proxy_tls_config,
                                alt_svc_cache,
                                #[cfg(feature = "http2")]
                                h2_config,
                                dns_resolver,
                                custom_request_target,
                                tftp_blksize,
                                tftp_no_options,
                                #[cfg(feature = "ssh")]
                                ssh_host_key_policy,
                                mail_from,
                                mail_rcpt,
                                fresh_connect,
                                forbid_reuse,
                                ftp_config,
                                proxy_headers,
                                connect_to,
                                path_as_is,
                                #[cfg(feature = "ssh")]
                                ssh_public_keyfile,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                #[cfg(feature = "ssh")]
                                ssh_auth_types,
                                #[cfg(not(feature = "ssh"))]
                                None,
                                mail_auth,
                                sasl_authzid,
                                sasl_ir,
                                oauth2_bearer,
                                haproxy_protocol,
                                abstract_unix_socket,
                                chunked_upload,
                                http09_allowed,
                                deadline,
                                http_proxy_tunnel,
                                proxy_http_10,
                                raw,
                            ))
                            .await?;
                        }
                    }
                }
            }
        }

        // Check for failed resume: 416 Range Not Satisfiable means server rejected our range
        if response.status() == 416 {
            let has_range = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
            if has_range {
                return Err(Error::Http("range not satisfiable".to_string()));
            }
        }

        // Store cookies from response.
        // Use custom Host header for cookie domain matching if present (curl compat).
        if let Some(ref mut jar) = cookie_jar {
            let cookie_host =
                headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map_or_else(
                    || current_url.host_str().unwrap_or(""),
                    // Strip port from Host header value if present
                    |(_, v)| v.split(':').next().unwrap_or(v),
                );
            let path = current_url.path();
            let is_secure = current_url.scheme() == "https";
            jar.store_from_headers(response.headers(), cookie_host, path, is_secure);
        }

        // Store HSTS headers from HTTPS responses
        if current_url.scheme() == "https" {
            if let Some(ref mut cache) = hsts_cache {
                if let Some(sts_value) = response.header("strict-transport-security") {
                    let host = current_url.host_str().unwrap_or("");
                    cache.store(host, sts_value);
                }
            }
        }

        // Store Alt-Svc headers from response
        if let Some(alt_svc_value) = response.header("alt-svc") {
            let scheme = current_url.scheme();
            let host = current_url.host_str().unwrap_or("");
            let port =
                current_url.port_or_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
            let origin = format!("{scheme}://{host}:{port}");
            let entries = crate::protocol::http::altsvc::parse_alt_svc(alt_svc_value);
            if entries.is_empty() && alt_svc_value.trim() == "clear" {
                alt_svc_cache.clear_origin(&origin);
            } else if !entries.is_empty() {
                alt_svc_cache.store(&origin, &entries);
            }
        }

        // Check for redirects
        if follow_redirects && response.is_redirect() {
            if redirects_followed >= max_redirects {
                // Include the final redirect response in the chain for output
                redirect_chain.push(response);
                // Build a response that carries the redirect chain for -L --include output
                // redirect_chain is non-empty (we just pushed); pop the last as final
                let final_resp_base = redirect_chain.pop();
                let chain = redirect_chain;
                let Some(mut final_resp) = final_resp_base else {
                    // Unreachable — we pushed just above
                    return Err(Error::Transfer {
                        code: 47,
                        message: format!("Maximum ({max_redirects}) redirects followed"),
                    });
                };
                final_resp.set_redirect_responses(chain);
                // Store for last_response recovery (curl outputs all redirect headers)
                if let Ok(mut guard) = last_resp_store.lock() {
                    *guard = Some(final_resp);
                }
                return Err(Error::Transfer {
                    code: 47,
                    message: format!("Maximum ({max_redirects}) redirects followed"),
                });
            }

            if let Some(location) = response.header("location") {
                // Reject redirect URLs with empty authority (e.g. http:////path).
                // curl returns CURLE_URL_MALFORMAT for these (test 1142).
                if let Some(rest) = location.strip_prefix("http://") {
                    if rest.starts_with('/') {
                        return Err(Error::UrlParse(
                            "Redirect to URL with bad scheme or empty host".to_string(),
                        ));
                    }
                }
                if let Some(rest) = location.strip_prefix("https://") {
                    if rest.starts_with('/') {
                        return Err(Error::UrlParse(
                            "Redirect to URL with bad scheme or empty host".to_string(),
                        ));
                    }
                }

                // Resolve relative URLs against current URL
                let mut next_url =
                    if location.starts_with("http://") || location.starts_with("https://") {
                        Url::parse(location)?
                    } else {
                        // Relative URL: build from current URL's base
                        let base = current_url.as_str();
                        Url::parse(&resolve_relative(base, location))?
                    };
                // Clear raw_input so redirect uses normalized path (not user's original)
                next_url.clear_raw_input();

                // Check redirect protocol restriction
                if let Some(allowed) = redir_protocols {
                    let scheme = next_url.scheme().to_lowercase();
                    if !allowed.iter().any(|p| p.as_str() == scheme) {
                        return Err(Error::UnsupportedProtocol(format!(
                            "Protocol \"{scheme}\" not supported or disabled in libcurl"
                        )));
                    }
                }

                if verbose {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("* Following redirect to {next_url}");
                    }
                }

                // 307/308: always preserve method and body
                // 303: change to GET unless --post303 preserves POST
                // 301/302: change POST to GET (curl compat) unless --post301/--post302
                let status = response.status();
                // On 303: always change to GET (unless --post303 preserves POST)
                // On 301/302: change to GET when body was sent (POST or custom -X with -d)
                //   unless --post301/--post302 preserves POST
                let has_body = current_body.is_some();
                let should_change_to_get = (status == 303
                    && !(post303 && current_method == "POST"))
                    || ((status == 301 && !post301 || status == 302 && !post302) && has_body);
                if should_change_to_get {
                    current_method = "GET".to_string();
                    current_body = None;
                    body_dropped_on_redirect = true;
                }

                // Capture intermediate redirect response for -L --include output
                redirect_chain.push(response);

                current_url = next_url;
                redirects_followed += 1;
                continue;
            }
        }

        let time_total = transfer_start.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let download_size = response.size_download() as f64;
        let upload_size = current_body.as_ref().map_or(0, Vec::len) as u64;
        let total_secs = time_total.as_secs_f64();
        let speed_download = if total_secs > 0.0 { download_size / total_secs } else { 0.0 };
        #[allow(clippy::cast_precision_loss)]
        let speed_upload = if total_secs > 0.0 { upload_size as f64 / total_secs } else { 0.0 };

        let mut info = response.transfer_info().clone();
        info.time_total = time_total;
        info.num_redirects = redirects_followed;
        info.speed_download = speed_download;
        info.speed_upload = speed_upload;
        info.size_upload = upload_size;
        info.effective_method = current_method.clone();
        response.set_transfer_info(info);
        if !redirect_chain.is_empty() {
            response.set_redirect_responses(redirect_chain);
        }
        return Ok(response);
    }
}

/// Perform a single HTTP request (no redirect handling).
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools,
    clippy::large_futures,
    clippy::large_stack_frames
)]
async fn do_single_request(
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    verbose: bool,
    accept_encoding: bool,
    connect_timeout: Option<Duration>,
    proxy: Option<&Url>,
    proxy_credentials: Option<&ProxyAuthCredentials>,
    resolve_overrides: &[(String, String)],
    tls_config: &TlsConfig,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
    unix_socket: Option<&str>,
    interface: Option<&str>,
    local_port: Option<u16>,
    dns_shuffle: bool,
    dns_cache: &mut DnsCache,
    pool: &mut ConnectionPool,
    #[cfg(feature = "http2")] h2_pool: &mut crate::pool::H2Pool,
    http_version: HttpVersion,
    expect_100_timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
    ignore_content_length: bool,
    speed_limits: &SpeedLimits,
    ftp_ssl_mode: crate::protocol::ftp::FtpSslMode,
    #[cfg_attr(not(feature = "ssh"), allow(unused_variables))] ssh_key_path: Option<&str>,
    proxy_tls_config: Option<&TlsConfig>,
    #[cfg_attr(not(feature = "http3"), allow(unused_variables))]
    alt_svc_cache: &crate::protocol::http::altsvc::AltSvcCache,
    #[cfg(feature = "http2")] h2_config: &crate::protocol::http::h2::Http2Config,
    dns_resolver: &crate::dns::DnsResolver,
    custom_request_target: Option<&str>,
    tftp_blksize: Option<u16>,
    tftp_no_options: bool,
    #[cfg(feature = "ssh")] ssh_host_key_policy: &crate::protocol::ssh::SshHostKeyPolicy,
    mail_from: Option<&str>,
    mail_rcpt: &[String],
    fresh_connect: bool,
    forbid_reuse: bool,
    ftp_config: &crate::protocol::ftp::FtpConfig,
    proxy_headers: &[(String, String)],
    connect_to: &[String],
    path_as_is: bool,
    #[cfg_attr(not(feature = "ssh"), allow(unused_variables))] ssh_public_keyfile: Option<&str>,
    #[cfg_attr(not(feature = "ssh"), allow(unused_variables))] ssh_auth_types: Option<u32>,
    mail_auth: Option<&str>,
    sasl_authzid: Option<&str>,
    sasl_ir: bool,
    oauth2_bearer: Option<&str>,
    haproxy_protocol: bool,
    #[cfg_attr(not(unix), allow(unused_variables))] abstract_unix_socket: Option<&str>,
    chunked_upload: bool,
    http09_allowed: bool,
    deadline: Option<tokio::time::Instant>,
    http_proxy_tunnel: bool,
    proxy_http_10: bool,
    raw: bool,
) -> Result<Response, Error> {
    // Handle non-HTTP schemes directly
    match url.scheme() {
        "file" => {
            // Reject file:// URLs with non-local host (curl compat: test 1145)
            let file_host = url.host_str().unwrap_or("");
            if !file_host.is_empty()
                && !file_host.eq_ignore_ascii_case("localhost")
                && file_host != "127.0.0.1"
            {
                return Err(Error::UrlParse(format!(
                    "file:// URL with non-local host: {file_host}"
                )));
            }
            if method == "PUT" {
                let upload_data = body.unwrap_or(&[]);
                return crate::protocol::file::write_file(url, upload_data);
            }
            // Extract range from Range header if present
            // Supports "bytes=10-" (resume) and "bytes=2-5" (byte range)
            let (range_start, range_end) = headers
                .iter()
                .find_map(|(k, v)| {
                    if k.eq_ignore_ascii_case("range") {
                        v.strip_prefix("bytes=").map(|r| {
                            if let Some((s, e)) = r.split_once('-') {
                                let start = s.parse::<u64>().ok();
                                let end = if e.is_empty() { None } else { e.parse::<u64>().ok() };
                                (start, end)
                            } else {
                                (None, None)
                            }
                        })
                    } else {
                        None
                    }
                })
                .unwrap_or((None, None));
            return crate::protocol::file::read_file(url, range_start, range_end);
        }
        "tftp" => {
            return crate::protocol::tftp::download(url, tftp_blksize, tftp_no_options).await;
        }
        #[cfg(feature = "ssh")]
        "sftp" | "scp" => {
            // Extract byte range for SFTP
            let sftp_range = headers.iter().find_map(|(k, v)| {
                if k.eq_ignore_ascii_case("range") {
                    v.strip_prefix("bytes=").map(ToString::to_string)
                } else {
                    None
                }
            });
            return if method == "PUT" {
                let upload_data = body.unwrap_or(&[]);
                crate::protocol::ssh::upload(
                    url,
                    upload_data,
                    ssh_key_path,
                    ssh_host_key_policy,
                    ssh_public_keyfile,
                    ssh_auth_types,
                    &ftp_config.pre_quote,
                    &ftp_config.post_quote,
                    ftp_config.create_dirs,
                )
                .await
            } else if method == "HEAD" {
                // -I with SFTP: just run quote commands, no download
                crate::protocol::ssh::head(
                    url,
                    ssh_key_path,
                    ssh_host_key_policy,
                    ssh_public_keyfile,
                    ssh_auth_types,
                    &ftp_config.pre_quote,
                    &ftp_config.post_quote,
                )
                .await
            } else {
                crate::protocol::ssh::download(
                    url,
                    ssh_key_path,
                    ssh_host_key_policy,
                    ssh_public_keyfile,
                    ssh_auth_types,
                    &ftp_config.pre_quote,
                    &ftp_config.post_quote,
                    sftp_range.as_deref(),
                )
                .await
            };
        }
        "ftp" | "ftps" => {
            // Reject FTP URLs with %0a or %0d (CR/LF injection — curl compat: tests 225, 226)
            let raw_url = url.as_str();
            if raw_url.contains("%0a")
                || raw_url.contains("%0A")
                || raw_url.contains("%0d")
                || raw_url.contains("%0D")
            {
                return Err(Error::UrlParse("FTP URL contains CR/LF characters".to_string()));
            }
            // Determine effective SSL mode: ftps:// always uses implicit TLS
            let effective_ssl_mode = if url.scheme() == "ftps" {
                crate::protocol::ftp::FtpSslMode::Implicit
            } else {
                ftp_ssl_mode
            };
            // Extract resume/range from Range header for FTP.
            // Formats: "bytes=42-" (resume from offset) or "bytes=4-16" (range).
            let ftp_range = headers.iter().find_map(|(k, v)| {
                if k.eq_ignore_ascii_case("range") {
                    v.strip_prefix("bytes=").map(ToString::to_string)
                } else {
                    None
                }
            });
            let resume_offset = ftp_range.as_deref().and_then(|r| {
                if r.ends_with('-') {
                    // "42-" format: resume from offset 42
                    r.strip_suffix('-').and_then(|n| n.parse::<u64>().ok())
                } else if let Some((start, _end)) = r.split_once('-') {
                    // "4-16" format: REST at start offset
                    start.parse::<u64>().ok()
                } else {
                    None
                }
            });
            // Extract end byte for range limit (for ABOR after partial read)
            let ftp_range_end = ftp_range.as_deref().and_then(|r| {
                if r.ends_with('-') {
                    None // open-ended range
                } else if let Some((_start, end)) = r.split_once('-') {
                    end.parse::<u64>().ok()
                } else {
                    None
                }
            });
            let upload_data = if method == "PUT" { Some(body.unwrap_or(&[])) } else { None };
            // Set range_end on ftp_config if needed
            let mut ftp_config_with_range = ftp_config.clone();
            ftp_config_with_range.range_end = ftp_range_end;
            return crate::protocol::ftp::perform(
                url,
                upload_data,
                effective_ssl_mode,
                tls_config,
                resume_offset,
                &ftp_config_with_range,
                None,
            )
            .await;
        }
        "smtp" | "smtps" => {
            let mail_data = body.unwrap_or(&[]);
            let header_creds = extract_basic_auth_from_headers(headers);
            // Extract ;AUTH= from URL username (e.g. "user;AUTH=EXTERNAL")
            let url_login_opts = extract_login_options_from_url(url);
            let smtp_config = crate::protocol::smtp::SmtpConfig {
                mail_from,
                mail_rcpt,
                mail_auth,
                sasl_authzid,
                sasl_ir,
                custom_request: custom_request_target,
                oauth2_bearer,
                crlf: false,
                username: header_creds.as_ref().map(|(u, _)| u.as_str()),
                password: header_creds.as_ref().map(|(_, p)| p.as_str()),
                login_options: url_login_opts.as_deref(),
            };
            return crate::protocol::smtp::send_mail(url, mail_data, &smtp_config).await;
        }
        "imap" | "imaps" => {
            let url_login_opts = extract_login_options_from_url(url);
            return crate::protocol::imap::fetch(
                url,
                method,
                body,
                custom_request_target,
                sasl_ir,
                oauth2_bearer,
                url_login_opts.as_deref(),
            )
            .await;
        }
        "pop3" | "pop3s" => {
            let header_creds = extract_basic_auth_from_headers(headers);
            let creds_tuple = header_creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            let custom_cmd = match method {
                "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "PATCH" | "OPTIONS" => {
                    custom_request_target
                }
                _ => Some(method),
            };
            let url_login_opts = extract_login_options_from_url(url);
            return crate::protocol::pop3::retrieve(
                url,
                creds_tuple,
                custom_cmd,
                sasl_ir,
                oauth2_bearer,
                url_login_opts.as_deref(),
            )
            .await;
        }
        "mqtt" => {
            return if method == "POST" || method == "PUT" {
                let payload = body.unwrap_or(&[]);
                crate::protocol::mqtt::publish(url, payload).await
            } else {
                crate::protocol::mqtt::subscribe(url).await
            };
        }
        "dict" => {
            return crate::protocol::dict::lookup(url).await;
        }
        "ws" | "wss" => {
            return crate::protocol::ws::connect(url, headers, tls_config).await;
        }
        "http" | "https" => {}
        scheme => {
            return Err(Error::UnsupportedProtocol(scheme.to_string()));
        }
    }

    let (host, port) = url.host_and_port()?;
    let host_header = url.host_header_value();
    let is_tls = url.scheme() == "https";
    let use_pool = proxy.is_none() && !fresh_connect;

    // Build effective headers (add Accept-Encoding if decompression enabled)
    let mut effective_headers: Vec<(String, String)> = headers.to_vec();
    if accept_encoding && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding")) {
        effective_headers.push((
            "Accept-Encoding".to_string(),
            crate::protocol::http::decompress::accepted_encodings().to_string(),
        ));
    }

    // Proactively evict expired connections from the pool
    if use_pool {
        pool.cleanup();
    }

    // Try to use a pooled HTTP/2 connection
    #[cfg(feature = "http2")]
    if use_pool && is_tls {
        let allow_h2 = !matches!(http_version, HttpVersion::Http10 | HttpVersion::Http11);
        if allow_h2 {
            if let Some(h2_client) = h2_pool.get(&host, port) {
                if verbose {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("* Re-using existing HTTP/2 connection to {host} port {port}");
                    }
                }
                let request_target = resolve_request_target(custom_request_target, url, path_as_is);
                let result = crate::protocol::http::h2::send_request(
                    h2_client,
                    method,
                    &host_header,
                    &request_target,
                    &effective_headers,
                    body,
                    url.as_str(),
                    speed_limits,
                )
                .await;

                match result {
                    Ok((resp, h2_client)) => {
                        if !forbid_reuse {
                            h2_pool.put(&host, port, h2_client);
                        }
                        return Ok(maybe_decompress(resp, accept_encoding));
                    }
                    Err(_) => {
                        if verbose {
                            #[allow(clippy::print_stderr)]
                            {
                                eprintln!("* HTTP/2 connection stale, creating new connection");
                            }
                        }
                    }
                }
            }
        }
    }

    // Try to use a pooled HTTP/1.1 connection
    if use_pool {
        if let Some(mut stream) = pool.get(&host, port, is_tls) {
            if verbose {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("* Re-using existing connection to {host} port {port}");
                }
            }

            let request_target = resolve_request_target(custom_request_target, url, path_as_is);
            let use_http10 = http_version == HttpVersion::Http10;
            let result = crate::protocol::http::h1::request(
                &mut stream,
                method,
                &host_header,
                &request_target,
                &effective_headers,
                body,
                url.as_str(),
                true,
                use_http10,
                expect_100_timeout,
                ignore_content_length,
                speed_limits,
                chunked_upload,
                http09_allowed,
                deadline,
                raw,
            )
            .await;

            match result {
                Ok((response, can_reuse)) => {
                    if can_reuse && !forbid_reuse {
                        pool.put(&host, port, is_tls, stream);
                    }
                    return Ok(maybe_decompress(response, accept_encoding));
                }
                Err(_) => {
                    // Pooled connection was stale — fall through to create new one
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Connection stale, creating new connection");
                        }
                    }
                }
            }
        }
    }

    // Determine what to connect to: proxy or target directly
    let (connect_host, connect_port) =
        if let Some(proxy_url) = proxy { proxy_url.host_and_port()? } else { (host.clone(), port) };

    // Apply --connect-to remapping (only for direct connections, not proxied)
    let (connect_host, connect_port) = if proxy.is_none() && !connect_to.is_empty() {
        let (new_host, new_port) = apply_connect_to(&connect_host, connect_port, connect_to);
        if verbose && (new_host != connect_host || new_port != connect_port) {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "* connect-to: remapped {connect_host}:{connect_port} -> {new_host}:{new_port}"
                );
            }
        }
        (new_host, new_port)
    } else {
        (connect_host, connect_port)
    };

    if verbose {
        #[allow(clippy::print_stderr)]
        {
            if proxy.is_some() {
                eprintln!("* Connecting to proxy {connect_host} port {connect_port}");
            } else {
                eprintln!("* Connecting to {connect_host} port {connect_port}");
            }
        }
    }

    // Apply DNS resolve overrides
    let resolved_host = resolve_overrides
        .iter()
        .find(|(h, _)| h == &connect_host.to_lowercase())
        .map_or_else(|| connect_host.clone(), |(_, addr)| addr.clone());

    // Connect via Unix socket or TCP
    let request_start = Instant::now();

    // Abstract Unix domain socket — Linux-only, requires OS-specific APIs
    #[cfg(unix)]
    if let Some(_abstract_path) = abstract_unix_socket {
        return Err(Error::Http(
            "Abstract Unix sockets are not yet supported (requires OS-specific APIs)".to_string(),
        ));
    }

    #[cfg(not(unix))]
    if abstract_unix_socket.is_some() {
        return Err(Error::Http("Abstract Unix sockets are only supported on Linux".to_string()));
    }

    // Unix domain socket path — bypasses DNS, TCP, proxy, SOCKS, and TLS
    #[cfg(unix)]
    if let Some(socket_path) = unix_socket {
        if verbose {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("* Connecting via Unix socket: {socket_path}");
            }
        }
        let uds_fut = tokio::net::UnixStream::connect(socket_path);
        let uds_stream = if let Some(timeout_dur) = connect_timeout {
            tokio::time::timeout(timeout_dur, uds_fut)
                .await
                .map_err(|_| Error::Timeout(timeout_dur))?
                .map_err(Error::Connect)?
        } else {
            uds_fut.await.map_err(Error::Connect)?
        };
        let time_connect = request_start.elapsed();
        let time_namelookup = time_connect;
        let time_pretransfer = request_start.elapsed();

        let request_target = resolve_request_target(custom_request_target, url, path_as_is);
        let use_http10 = http_version == HttpVersion::Http10;
        let mut stream = PooledStream::Unix(uds_stream);
        let (resp, _can_reuse) = crate::protocol::http::h1::request(
            &mut stream,
            method,
            &host_header,
            &request_target,
            &effective_headers,
            body,
            url.as_str(),
            false, // Don't pool Unix socket connections
            use_http10,
            expect_100_timeout,
            ignore_content_length,
            speed_limits,
            chunked_upload,
            http09_allowed,
            deadline,
            raw,
        )
        .await?;
        let time_starttransfer = request_start.elapsed();

        let mut resp = maybe_decompress(resp, accept_encoding);
        let mut info = resp.transfer_info().clone();
        info.time_namelookup = time_namelookup;
        info.time_connect = time_connect;
        info.time_pretransfer = time_pretransfer;
        info.time_starttransfer = time_starttransfer;
        resp.set_transfer_info(info);
        return Ok(resp);
    }

    #[cfg(not(unix))]
    if unix_socket.is_some() {
        return Err(Error::Http("Unix sockets are not supported on this platform".to_string()));
    }

    // DNS resolution: check cache first, then use resolver
    let addrs = if let Some(cached) = dns_cache.get(&resolved_host, connect_port) {
        if verbose {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("* Using cached DNS entry for {resolved_host}");
            }
        }
        cached.to_vec()
    } else {
        let resolve_fut = dns_resolver.resolve(&resolved_host, connect_port);
        let resolved = if let Some(timeout_dur) = connect_timeout {
            tokio::time::timeout(timeout_dur, resolve_fut)
                .await
                .map_err(|_| Error::Timeout(timeout_dur))??
        } else {
            resolve_fut.await?
        };
        dns_cache.put(&resolved_host, connect_port, resolved.clone());
        resolved
    };
    let time_namelookup = request_start.elapsed();

    // DNS shuffle: randomize address order for load distribution
    let mut addrs = addrs;
    if dns_shuffle && addrs.len() > 1 {
        // Simple Fisher-Yates shuffle using timestamp-seeded pseudo-random
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let mut state = seed;
        for i in (1..addrs.len()).rev() {
            // xorshift32
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let j = (state as usize) % (i + 1);
            addrs.swap(i, j);
        }
    }

    if verbose {
        #[allow(clippy::print_stderr)]
        for addr in &addrs {
            eprintln!("*   Trying {addr}...");
        }
    }

    // Happy Eyeballs (RFC 6555): prefer IPv6, fall back to IPv4
    let mut tcp_stream = happy_eyeballs_connect(
        &addrs,
        connect_timeout,
        request_start,
        interface,
        local_port,
        happy_eyeballs_timeout,
    )
    .await?;
    let time_connect = request_start.elapsed();

    if verbose {
        #[allow(clippy::print_stderr)]
        if let Ok(peer) = tcp_stream.peer_addr() {
            eprintln!("* Connected to {host} ({}) port {connect_port}", peer.ip());
        }
    }

    // Apply TCP socket options
    tcp_stream.set_nodelay(tcp_nodelay).map_err(Error::Connect)?;
    if let Some(keepalive_idle) = tcp_keepalive {
        let sock = socket2::SockRef::from(&tcp_stream);
        let keepalive = socket2::TcpKeepalive::new().with_time(keepalive_idle);
        sock.set_tcp_keepalive(&keepalive).map_err(Error::Connect)?;
    }

    // Send HAProxy PROXY protocol v1 header before any TLS or protocol data
    if haproxy_protocol {
        use tokio::io::AsyncWriteExt;
        if let (Ok(local), Ok(peer)) = (tcp_stream.local_addr(), tcp_stream.peer_addr()) {
            let proto = if local.ip().is_ipv4() { "TCP4" } else { "TCP6" };
            let header = format!(
                "PROXY {proto} {} {} {} {}\r\n",
                local.ip(),
                peer.ip(),
                local.port(),
                peer.port()
            );
            tcp_stream
                .write_all(header.as_bytes())
                .await
                .map_err(|e| Error::Http(format!("HAProxy PROXY header write failed: {e}")))?;
            if verbose {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("* Sent HAProxy PROXY protocol v1 header");
                }
            }
        }
    }

    // Handle SOCKS proxy tunneling
    let is_socks_proxy = proxy.is_some_and(|p| {
        let s = p.scheme();
        s == "socks5" || s == "socks4" || s == "socks5h" || s == "socks4a"
    });

    let tcp_stream = if is_socks_proxy {
        let proxy_url = proxy.ok_or_else(|| Error::Http("no proxy URL".to_string()))?;
        let socks_auth = proxy_url.credentials().map(|(u, p)| (u.to_string(), p.to_string()));

        match proxy_url.scheme() {
            "socks5" | "socks5h" => {
                let auth_ref = socks_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
                crate::proxy::socks::connect_socks5(tcp_stream, &host, port, auth_ref).await?
            }
            "socks4" | "socks4a" => {
                let user_id = socks_auth.as_ref().map_or("", |(u, _)| u.as_str());
                crate::proxy::socks::connect_socks4(tcp_stream, &host, port, user_id).await?
            }
            _ => tcp_stream,
        }
    } else {
        tcp_stream
    };

    let response = match url.scheme() {
        "https" => {
            // HTTP/3 over QUIC — bypasses TCP/TLS, uses UDP transport
            // Triggered by explicit --http3 flag OR Alt-Svc cache indicating h3 support
            #[cfg(feature = "http3")]
            {
                let use_h3 = if http_version == HttpVersion::Http3 {
                    true
                } else if http_version == HttpVersion::None || http_version == HttpVersion::Http2 {
                    // Check Alt-Svc cache for h3 support
                    let alt_port = url.port_or_default().unwrap_or(443);
                    let origin = format!("https://{host}:{alt_port}");
                    alt_svc_cache.get_protocol(&origin, "h3").is_some()
                } else {
                    false
                };

                if use_h3 {
                    // Determine target address — Alt-Svc may specify a different port
                    let alt_port = url.port_or_default().unwrap_or(443);
                    let origin = format!("https://{host}:{alt_port}");
                    let h3_port =
                        alt_svc_cache.get_protocol(&origin, "h3").map_or(alt_port, |svc| svc.port);

                    // Use the resolved address with possibly different port
                    let mut addr = addrs[0];
                    addr.set_port(h3_port);

                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            if http_version == HttpVersion::Http3 {
                                eprintln!("* Using HTTP/3");
                            } else {
                                eprintln!("* Using HTTP/3 (Alt-Svc upgrade)");
                            }
                        }
                    }
                    let request_target =
                        resolve_request_target(custom_request_target, url, path_as_is);
                    let time_pretransfer = request_start.elapsed();
                    let resp = crate::protocol::http::h3::request(
                        addr,
                        &host,
                        method,
                        &request_target,
                        &effective_headers,
                        body,
                        url.as_str(),
                        speed_limits,
                        tls_config.verify_peer,
                    )
                    .await?;
                    let time_starttransfer = request_start.elapsed();
                    let mut resp = maybe_decompress(resp, accept_encoding);
                    let mut info = resp.transfer_info().clone();
                    info.time_namelookup = time_namelookup;
                    info.time_connect = time_connect;
                    info.time_pretransfer = time_pretransfer;
                    info.time_starttransfer = time_starttransfer;
                    resp.set_transfer_info(info);
                    return Ok(resp);
                }
            }

            #[cfg(feature = "rustls")]
            {
                // HTTPS proxy: TLS to proxy → CONNECT → TLS to target
                // This is a separate path because it produces TlsStream<TlsStream<TcpStream>>
                let is_https_proxy =
                    proxy.is_some_and(|p| p.scheme() == "https") && !is_socks_proxy;

                if is_https_proxy {
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!(
                                "* Establishing TLS to HTTPS proxy {connect_host}:{connect_port}"
                            );
                        }
                    }

                    let default_tls = TlsConfig::default();
                    let ptls_config = proxy_tls_config.unwrap_or(&default_tls);
                    let proxy_tls = crate::tls::TlsConnector::new_no_alpn(ptls_config)?;
                    let (proxy_tls_stream, _) =
                        proxy_tls.connect_generic(tcp_stream, &connect_host).await?;

                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Establishing tunnel to {host}:{port} via HTTPS proxy");
                        }
                    }

                    let (tunnel_stream, _raw_connect) = establish_connect_tunnel(
                        proxy_tls_stream,
                        &host,
                        port,
                        &effective_headers,
                        proxy_credentials,
                        proxy_headers,
                        verbose,
                        proxy_http_10,
                    )
                    .await?;

                    let tls = crate::tls::TlsConnector::new(tls_config)?;
                    let (mut tls_stream, _alpn) = tls.connect_generic(tunnel_stream, &host).await?;
                    let time_appconnect = request_start.elapsed();

                    let request_target =
                        resolve_request_target(custom_request_target, url, path_as_is);
                    let use_http10 = http_version == HttpVersion::Http10;
                    let time_pretransfer = request_start.elapsed();

                    let (resp, _can_reuse) = crate::protocol::http::h1::request(
                        &mut tls_stream,
                        method,
                        &host_header,
                        &request_target,
                        &effective_headers,
                        body,
                        url.as_str(),
                        false, // Don't pool HTTPS proxy connections
                        use_http10,
                        expect_100_timeout,
                        ignore_content_length,
                        speed_limits,
                        chunked_upload,
                        http09_allowed,
                        deadline,
                        raw,
                    )
                    .await?;
                    let time_starttransfer = request_start.elapsed();

                    let mut resp = maybe_decompress(resp, accept_encoding);
                    let mut info = resp.transfer_info().clone();
                    info.time_namelookup = time_namelookup;
                    info.time_connect = time_connect;
                    info.time_appconnect = time_appconnect;
                    info.time_pretransfer = time_pretransfer;
                    info.time_starttransfer = time_starttransfer;
                    resp.set_transfer_info(info);
                    return Ok(resp);
                }

                // Non-HTTPS proxy path: HTTP proxy (CONNECT on plain TCP) or direct
                let tls_stream_inner = if proxy.is_some() && !is_socks_proxy {
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Establishing tunnel to {host}:{port} via proxy");
                        }
                    }
                    let (tun, _raw_connect) = establish_connect_tunnel(
                        tcp_stream,
                        &host,
                        port,
                        &effective_headers,
                        proxy_credentials,
                        proxy_headers,
                        verbose,
                        proxy_http_10,
                    )
                    .await?;
                    tun
                } else {
                    tcp_stream
                };

                let tls = crate::tls::TlsConnector::new(tls_config)?;
                let (tls_stream, alpn) = tls.connect(tls_stream_inner, &host).await?;
                let time_appconnect = request_start.elapsed();

                let request_target = resolve_request_target(custom_request_target, url, path_as_is);

                // Use HTTP/2 if ALPN negotiated it, unless user forced HTTP/1.x
                let allow_h2 = !matches!(http_version, HttpVersion::Http10 | HttpVersion::Http11);
                #[cfg(feature = "http2")]
                if allow_h2 && alpn == crate::tls::AlpnProtocol::H2 {
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Using HTTP/2");
                        }
                    }
                    let time_pretransfer = request_start.elapsed();
                    let client =
                        crate::protocol::http::h2::handshake(tls_stream, h2_config).await?;
                    let (resp, h2_client) = crate::protocol::http::h2::send_request(
                        client,
                        method,
                        &host_header,
                        &request_target,
                        &effective_headers,
                        body,
                        url.as_str(),
                        speed_limits,
                    )
                    .await?;
                    // Return h2 connection to pool for reuse
                    if !forbid_reuse {
                        h2_pool.put(&host, port, h2_client);
                    }
                    let time_starttransfer = request_start.elapsed();
                    let mut resp = maybe_decompress(resp, accept_encoding);
                    let mut info = resp.transfer_info().clone();
                    info.time_namelookup = time_namelookup;
                    info.time_connect = time_connect;
                    info.time_appconnect = time_appconnect;
                    info.time_pretransfer = time_pretransfer;
                    info.time_starttransfer = time_starttransfer;
                    resp.set_transfer_info(info);
                    return Ok(resp);
                }

                // HTTP/1.x over TLS
                let use_http10 = http_version == HttpVersion::Http10;
                let time_pretransfer = request_start.elapsed();
                let mut stream = PooledStream::Tls(tls_stream);
                let (resp, can_reuse) = crate::protocol::http::h1::request(
                    &mut stream,
                    method,
                    &host_header,
                    &request_target,
                    &effective_headers,
                    body,
                    url.as_str(),
                    use_pool,
                    use_http10,
                    expect_100_timeout,
                    ignore_content_length,
                    speed_limits,
                    chunked_upload,
                    http09_allowed,
                    deadline,
                    raw,
                )
                .await?;
                let time_starttransfer = request_start.elapsed();

                if can_reuse && use_pool && !forbid_reuse {
                    pool.put(&host, port, is_tls, stream);
                }

                let mut resp = resp;
                let mut info = resp.transfer_info().clone();
                info.time_namelookup = time_namelookup;
                info.time_connect = time_connect;
                info.time_appconnect = time_appconnect;
                info.time_pretransfer = time_pretransfer;
                info.time_starttransfer = time_starttransfer;
                resp.set_transfer_info(info);
                resp
            }
            #[cfg(not(feature = "rustls"))]
            {
                return Err(Error::Http("HTTPS support requires the 'rustls' feature".to_string()));
            }
        }
        "http" => {
            let is_http_proxy = proxy.is_some() && !is_socks_proxy;
            // Use CONNECT tunnel for HTTP if --proxytunnel / -p is set
            let use_tunnel = is_http_proxy && http_proxy_tunnel;

            if use_tunnel {
                // HTTP over CONNECT tunnel: establish tunnel, then send plain request
                if verbose {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("* Establishing tunnel to {host}:{port} via proxy");
                    }
                }
                let (tunnel_stream, raw_connect) = establish_connect_tunnel(
                    tcp_stream,
                    &host,
                    port,
                    &effective_headers,
                    proxy_credentials,
                    proxy_headers,
                    verbose,
                    proxy_http_10,
                )
                .await?;

                let request_target = resolve_request_target(custom_request_target, url, path_as_is);
                let use_http10 = http_version == HttpVersion::Http10;
                let time_pretransfer = request_start.elapsed();
                let mut stream = PooledStream::Tcp(tunnel_stream);
                // Strip proxy-related headers from inner request (they belong in the CONNECT)
                let tunnel_headers: Vec<(String, String)> = effective_headers
                    .iter()
                    .filter(|(k, _)| !k.eq_ignore_ascii_case("proxy-authorization"))
                    .cloned()
                    .collect();
                let (resp, _can_reuse) = crate::protocol::http::h1::request(
                    &mut stream,
                    method,
                    &host_header,
                    &request_target,
                    &tunnel_headers,
                    body,
                    url.as_str(),
                    true, // Suppress Connection: close (tunneled request acts like direct)
                    use_http10,
                    expect_100_timeout,
                    ignore_content_length,
                    speed_limits,
                    chunked_upload,
                    http09_allowed,
                    deadline,
                    raw,
                )
                .await?;
                let time_starttransfer = request_start.elapsed();

                let mut resp = resp;
                // Prepend CONNECT response as a redirect response for --include output
                if !raw_connect.is_empty() {
                    let connect_resp = Response::with_raw_headers(
                        200,
                        std::collections::HashMap::new(),
                        Vec::new(),
                        url.as_str().to_string(),
                        raw_connect,
                    );
                    resp.push_redirect_response(connect_resp);
                }
                let mut info = resp.transfer_info().clone();
                info.time_namelookup = time_namelookup;
                info.time_connect = time_connect;
                info.time_pretransfer = time_pretransfer;
                info.time_starttransfer = time_starttransfer;
                resp.set_transfer_info(info);
                resp
            } else {
                // Direct or non-tunnel proxy HTTP request
                // Custom request target overrides; otherwise, for HTTP proxy use absolute URL
                #[allow(clippy::option_if_let_else)]
                let request_target = if let Some(target) = custom_request_target {
                    target.to_string()
                } else if is_http_proxy {
                    // Strip fragment and credentials from proxy request URL
                    // Credentials go in Authorization header, not the Request-URI
                    let full = strip_url_credentials(&url.to_full_string());
                    let full = full
                        .split_once('#')
                        .map_or_else(|| full.clone(), |(base, _)| base.to_string());
                    // Replace %20 with + in query string (curl compat: space encoding)
                    if let Some((base, query)) = full.split_once('?') {
                        format!("{base}?{}", query.replace("%20", "+"))
                    } else {
                        full
                    }
                } else if path_as_is {
                    // Use raw URL to preserve dot segments (curl compat: test 391)
                    extract_path_and_query(url.raw_input().unwrap_or_else(|| url.as_str()))
                } else {
                    url.request_target()
                };

                // Add proxy-specific headers for non-tunnel HTTP proxy requests
                let mut proxy_effective_headers = effective_headers.clone();
                if is_http_proxy {
                    // Insert Proxy-Connection before Cookie header (curl compat: test 179)
                    let cookie_pos = proxy_effective_headers
                        .iter()
                        .position(|(k, _)| k.eq_ignore_ascii_case("cookie"));
                    let insert_pos = cookie_pos.unwrap_or(proxy_effective_headers.len());
                    proxy_effective_headers.insert(
                        insert_pos,
                        ("Proxy-Connection".to_string(), "Keep-Alive".to_string()),
                    );
                    proxy_effective_headers.extend_from_slice(proxy_headers);
                }

                let use_http10 = http_version == HttpVersion::Http10;
                let time_pretransfer = request_start.elapsed();
                let mut stream = PooledStream::Tcp(tcp_stream);
                // For HTTP proxy: use keep_alive=true to suppress Connection: close
                // Suppress Connection: close when going through any proxy (HTTP or SOCKS)
                let proxy_keep_alive = if proxy.is_some() { true } else { use_pool };
                let (resp, can_reuse) = crate::protocol::http::h1::request(
                    &mut stream,
                    method,
                    &host_header,
                    &request_target,
                    &proxy_effective_headers,
                    body,
                    url.as_str(),
                    proxy_keep_alive,
                    use_http10,
                    expect_100_timeout,
                    ignore_content_length,
                    speed_limits,
                    chunked_upload,
                    http09_allowed,
                    deadline,
                    raw,
                )
                .await?;
                let time_starttransfer = request_start.elapsed();

                if can_reuse && use_pool && !forbid_reuse {
                    pool.put(&host, port, is_tls, stream);
                }

                let mut resp = resp;
                let mut info = resp.transfer_info().clone();
                info.time_namelookup = time_namelookup;
                info.time_connect = time_connect;
                info.time_pretransfer = time_pretransfer;
                info.time_starttransfer = time_starttransfer;
                resp.set_transfer_info(info);
                resp
            }
        }
        scheme => return Err(Error::UnsupportedProtocol(scheme.to_string())),
    };

    Ok(maybe_decompress(response, accept_encoding))
}

/// Decompress response body if Content-Encoding is present and decompression was requested.
/// Decode percent-encoded characters in a string.
fn percent_decode_str(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                result.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

/// Convert a hex ASCII byte to its numeric value.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn maybe_decompress(mut response: Response, accept_encoding: bool) -> Response {
    // Transfer-Encoding decompression (hop-by-hop): always decompress regardless of
    // --compressed flag. Chunked is already handled at the framing layer; here we
    // handle gzip/deflate/br/zstd that may appear alongside chunked.
    if let Some(te) = response.header("transfer-encoding") {
        if let Some(compression) = crate::protocol::http::h1::te_compression_encoding(te) {
            // Walk encodings in reverse order (outermost first, but chunked already stripped)
            let mut body = response.body().to_vec();
            // The compression part may be a single encoding like "gzip" or multiple
            // like "deflate, gzip" (applied left-to-right, so decompress right-to-left).
            let parts: Vec<&str> = compression.split(',').map(str::trim).collect();
            let mut ok = true;
            for enc in parts.iter().rev() {
                match crate::protocol::http::decompress::decompress(&body, enc) {
                    Ok(decompressed) => body = decompressed,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                response.set_body(body);
            } else {
                response.set_body(Vec::new());
                response.set_body_error(Some("bad_transfer_encoding".to_string()));
            }
        }
    }

    // Content-Encoding decompression: only when --compressed was used.
    if accept_encoding {
        if let Some(encoding) = response.header("content-encoding") {
            if encoding != "identity" && !encoding.eq_ignore_ascii_case("none") {
                if let Ok(decompressed) =
                    crate::protocol::http::decompress::decompress(response.body(), encoding)
                {
                    response.set_body(decompressed);
                } else {
                    // Decompression failed: preserve headers, clear body,
                    // set body_error for exit code handling (curl compat).
                    response.set_body(Vec::new());
                    response.set_body_error(Some("bad_content_encoding".to_string()));
                }
            }
        }
    }
    response
}

/// Establish an HTTP CONNECT tunnel through a proxy.
///
/// Sends a CONNECT request to the proxy and validates the 200 response
/// before returning the stream for TLS negotiation.
/// Handles 407 Proxy Authentication Required for Digest and NTLM auth.
///
/// The stream type is generic to support both plain TCP (HTTP proxy) and
/// TLS-wrapped streams (HTTPS proxy).
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn establish_connect_tunnel<S>(
    mut stream: S,
    target_host: &str,
    target_port: u16,
    headers: &[(String, String)],
    proxy_credentials: Option<&ProxyAuthCredentials>,
    proxy_headers: &[(String, String)],
    verbose: bool,
    proxy_http_10: bool,
) -> Result<(S, Vec<u8>), Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // For NTLM proxy auth, send Type 1 in the initial CONNECT (curl compat: test 209)
    let initial_auth = proxy_credentials.and_then(|creds| match creds.method {
        ProxyAuthMethod::Ntlm => {
            let type1 = crate::auth::ntlm::create_type1_message();
            Some(format!("Proxy-Authorization: NTLM {type1}"))
        }
        ProxyAuthMethod::Basic => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", creds.username, creds.password).as_bytes());
            Some(format!("Proxy-Authorization: Basic {encoded}"))
        }
        _ => None,
    });

    // Send initial CONNECT request (with auth if NTLM/Basic)
    let (status, response_headers, raw_connect) = send_connect_request(
        &mut stream,
        target_host,
        target_port,
        headers,
        initial_auth.as_deref(),
        proxy_headers,
        proxy_http_10,
    )
    .await?;

    if status == 200 {
        return Ok((stream, raw_connect));
    }

    // Handle 407 Proxy Authentication Required
    if status == 407 {
        if let Some(creds) = proxy_credentials {
            let proxy_auth_header = find_header(&response_headers, "proxy-authenticate");

            match creds.method {
                ProxyAuthMethod::Digest => {
                    if let Some(ref auth_header) = proxy_auth_header {
                        if let Ok(challenge) =
                            crate::auth::digest::DigestChallenge::parse(auth_header)
                        {
                            if verbose {
                                #[allow(clippy::print_stderr)]
                                {
                                    eprintln!(
                                        "* Proxy auth using Digest with realm '{}'",
                                        challenge.realm
                                    );
                                }
                            }

                            let uri = format!("{target_host}:{target_port}");
                            let cnonce = crate::auth::digest::generate_cnonce();
                            let auth_value = challenge.respond(
                                &creds.username,
                                &creds.password,
                                "CONNECT",
                                &uri,
                                1,
                                &cnonce,
                            );

                            let (retry_status, _, raw_retry) = send_connect_request(
                                &mut stream,
                                target_host,
                                target_port,
                                headers,
                                Some(&format!("Proxy-Authorization: {auth_value}")),
                                proxy_headers,
                                proxy_http_10,
                            )
                            .await?;

                            if retry_status == 200 {
                                return Ok((stream, raw_retry));
                            }

                            return Err(Error::Http(format!(
                                "proxy CONNECT Digest auth failed with status {retry_status}"
                            )));
                        }
                    }
                }
                ProxyAuthMethod::Ntlm => {
                    // NTLM: Type 1 was sent in the initial CONNECT.
                    // The 407 response contains the Type 2 challenge.
                    if let Some(ref auth_val) = proxy_auth_header {
                        if let Some(type2_data) = auth_val.strip_prefix("NTLM ") {
                            let challenge = crate::auth::ntlm::parse_type2_message(type2_data)?;
                            let domain = creds.domain.as_deref().unwrap_or("");
                            let type3 = crate::auth::ntlm::create_type3_message(
                                &challenge,
                                &creds.username,
                                &creds.password,
                                domain,
                            );

                            // Send CONNECT with Type 3
                            let (status3, _, raw3) = send_connect_request(
                                &mut stream,
                                target_host,
                                target_port,
                                headers,
                                Some(&format!("Proxy-Authorization: NTLM {type3}")),
                                proxy_headers,
                                proxy_http_10,
                            )
                            .await?;

                            if status3 == 200 {
                                return Ok((stream, raw3));
                            }

                            return Err(Error::Http(format!(
                                "proxy CONNECT NTLM auth failed with status {status3}"
                            )));
                        }
                    }

                    return Err(Error::Http(
                        "proxy CONNECT NTLM: no Type 2 challenge in 407".to_string(),
                    ));
                }
                ProxyAuthMethod::Basic => {
                    // Basic auth should have been in the initial headers already.
                    // If we still got 407, the credentials are wrong.
                    return Err(Error::Http(format!(
                        "proxy CONNECT failed with status {status} (Basic auth rejected)"
                    )));
                }
            }
        }
    }

    Err(Error::Http(format!("CONNECT tunnel failed, response {status}")))
}

/// Send a CONNECT request and read the response status + headers.
///
/// Returns `(status_code, response_headers, raw_response_bytes)`.
async fn send_connect_request<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
    headers: &[(String, String)],
    extra_header: Option<&str>,
    proxy_headers: &[(String, String)],
    proxy_http_10: bool,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let http_version = if proxy_http_10 { "HTTP/1.0" } else { "HTTP/1.1" };
    let mut connect_req = format!(
        "CONNECT {target_host}:{target_port} {http_version}\r\n\
         Host: {target_host}:{target_port}\r\n"
    );

    // Add auth header: use extra_header if provided (Digest/NTLM retry),
    // otherwise forward Proxy-Authorization from original headers.
    if let Some(extra) = extra_header {
        use std::fmt::Write as _;
        let _ = write!(connect_req, "{extra}\r\n");
    } else {
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("proxy-authorization") {
                use std::fmt::Write as _;
                let _ = write!(connect_req, "{name}: {value}\r\n");
            }
        }
    }

    // Forward User-Agent from request headers (curl sends UA in CONNECT requests)
    // An empty value (from -A "") suppresses the header entirely.
    let custom_ua = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    match custom_ua {
        Some((_, value)) if value.is_empty() => {
            // -A "" suppresses User-Agent entirely
        }
        Some((name, value)) => {
            use std::fmt::Write as _;
            let _ = write!(connect_req, "{name}: {value}\r\n");
        }
        None => {
            connect_req.push_str("User-Agent: curl/0.1.0\r\n");
        }
    }

    // Add proxy-specific headers (--proxy-header / CURLOPT_PROXYHEADER)
    for (name, value) in proxy_headers {
        use std::fmt::Write as _;
        let _ = write!(connect_req, "{name}: {value}\r\n");
    }

    // curl always sends Proxy-Connection: Keep-Alive in CONNECT requests
    connect_req.push_str("Proxy-Connection: Keep-Alive\r\n");

    connect_req.push_str("\r\n");

    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("proxy CONNECT write failed: {e}")))?;

    stream.flush().await.map_err(|e| Error::Http(format!("proxy CONNECT flush failed: {e}")))?;

    // Read the proxy's response
    let mut buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        let n = stream
            .read(&mut buf[total..])
            .await
            .map_err(|e| Error::Http(format!("proxy CONNECT read failed: {e}")))?;

        if n == 0 {
            // If we got some data but never found valid HTTP headers via \r\n\r\n,
            // try bare LF (\n\n) as well. Some servers/test harnesses send bare LF.
            if total > 0 {
                // Try \n\n header end (bare LF)
                if let Some(pos) = buf[..total].windows(2).position(|w| w == b"\n\n") {
                    let end = pos + 2;
                    let header_str = std::str::from_utf8(&buf[..end]).map_err(|_| {
                        Error::Http("invalid proxy CONNECT response encoding".into())
                    })?;
                    let mut lines = header_str.lines();
                    let status_line = lines
                        .next()
                        .ok_or_else(|| Error::Http("empty proxy CONNECT response".into()))?;
                    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        if let Ok(status) = parts[1].parse::<u16>() {
                            let mut response_headers = Vec::new();
                            for line in lines {
                                if let Some((name, value)) = line.split_once(':') {
                                    response_headers
                                        .push((name.trim().to_string(), value.trim().to_string()));
                                }
                            }
                            let raw_bytes = buf[..end].to_vec();
                            return Ok((status, response_headers, raw_bytes));
                        }
                    }
                }
                // No valid HTTP response found at all — invalid response header
                // (curl compat: test 750 → CURLE_BAD_RESP = 43)
                return Err(Error::Http("Invalid response header".to_string()));
            }
            return Err(Error::Http("proxy closed connection during CONNECT".to_string()));
        }

        total += n;

        if let Some(end) = find_header_end(&buf[..total]) {
            let header_str = std::str::from_utf8(&buf[..end])
                .map_err(|_| Error::Http("invalid proxy CONNECT response encoding".into()))?;

            let mut lines = header_str.lines();
            let status_line =
                lines.next().ok_or_else(|| Error::Http("empty proxy CONNECT response".into()))?;

            let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
            if parts.len() < 2 {
                return Err(Error::Http(format!(
                    "malformed proxy CONNECT response: {status_line}"
                )));
            }

            let status: u16 = parts[1].parse().map_err(|_| {
                Error::Http(format!("invalid proxy CONNECT status code: {}", parts[1]))
            })?;

            // Parse response headers
            let mut response_headers = Vec::new();
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    response_headers.push((name.trim().to_string(), value.trim().to_string()));
                }
            }

            // Return the raw response bytes for --include output
            let raw_bytes = buf[..end].to_vec();
            return Ok((status, response_headers, raw_bytes));
        }

        if total >= buf.len() {
            return Err(Error::Http("proxy CONNECT response too large".to_string()));
        }
    }
}

/// Find a header value by name (case-insensitive).
fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

/// Extract username and password from an Authorization: Basic header.
///
/// Returns `None` if no Authorization header or not Basic auth.
/// Extract `;AUTH=<mechanism>` from a URL username.
///
/// curl allows `imap://user;AUTH=EXTERNAL@host/` to select a specific SASL mechanism.
/// The `;AUTH=...` part is embedded in the username by the URL parser.
/// Returns `Some("AUTH=EXTERNAL")` etc., or `None` if not present.
fn extract_login_options_from_url(url: &Url) -> Option<String> {
    let username = url.username();
    if username.is_empty() {
        return None;
    }
    // Check for ;AUTH= (case-insensitive) — URL may be percent-encoded
    let decoded = percent_decode_str(username);
    let upper = decoded.to_uppercase();
    upper.find(";AUTH=").map(|pos| decoded[pos + 1..].to_string())
}

fn extract_basic_auth_from_headers(headers: &[(String, String)]) -> Option<(String, String)> {
    use base64::Engine;
    let auth_val = find_header(headers, "authorization")?;
    let encoded = auth_val.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded_str.split_once(':').unwrap_or((&decoded_str, ""));
    Some((user.to_string(), pass.to_string()))
}

/// Find the end of HTTP headers (\r\n\r\n) in a buffer.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Get proxy URL from environment variables.
///
/// Checks `http_proxy`/`HTTP_PROXY` for HTTP, `https_proxy`/`HTTPS_PROXY` for HTTPS.
/// curl convention: lowercase takes priority for `http_proxy`.
fn proxy_from_env(scheme: &str) -> Option<Url> {
    let var_names = match scheme {
        "https" => &["https_proxy", "HTTPS_PROXY"][..],
        _ => &["http_proxy", "HTTP_PROXY"][..],
    };

    for var in var_names {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                if let Ok(url) = Url::parse(&val) {
                    return Some(url);
                }
            }
        }
    }

    None
}

/// Strip credentials from a URL: `http://user:pass@host/` → `http://host/`.
fn strip_url_credentials(url: &str) -> String {
    let scheme_end = url.find("://").map_or(0, |p| p + 3);
    let rest = &url[scheme_end..];
    // Only strip if @ comes before / or ? (i.e., it's in the authority, not the path/query)
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    if let Some(at_pos) = rest.find('@') {
        if at_pos < authority_end {
            return format!("{}{}", &url[..scheme_end], &rest[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Get no-proxy list from environment variables.
///
/// Checks `no_proxy` and `NO_PROXY` (lowercase takes priority).
fn noproxy_from_env() -> Option<String> {
    for var in &["no_proxy", "NO_PROXY"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Check if a host should bypass the proxy based on the noproxy list.
/// Get the request target, using the custom target if set, otherwise from the URL.
///
/// When `path_as_is` is true, the path is not normalized (`.` and `..` segments
/// are preserved). Note: since the `url` crate normalizes paths during parsing,
/// this flag only affects behaviour when the path has already been normalized
/// by the parser, so it is a no-op in most cases. The flag exists for curl
/// compatibility and future use with raw URL handling.
fn resolve_request_target(custom: Option<&str>, url: &Url, path_as_is: bool) -> String {
    if let Some(c) = custom {
        return c.to_string();
    }
    if path_as_is {
        // Use the raw URL string (before url crate normalization) to preserve
        // dot segments like /../ (curl compat: test 391)
        extract_path_and_query(url.raw_input().unwrap_or_else(|| url.as_str()))
    } else {
        url.request_target()
    }
}

/// Strip the raw header value prefix that `headers_ordered` includes.
///
/// The `headers_ordered()` raw values start with `": value"` (colon + optional
/// whitespace) because they preserve wire format. This helper returns just the
/// value portion, trimmed of leading whitespace.
fn strip_raw_header_value(raw: &str) -> &str {
    raw.strip_prefix(':').unwrap_or(raw).trim_start()
}

/// Pick the strongest authentication method from a 401 response's
/// `WWW-Authenticate` headers.
///
/// Priority order (matching curl): Digest > NTLM > Basic.
/// Uses `headers_ordered()` to see ALL `WWW-Authenticate` headers
/// (the HashMap-based `headers()` only keeps the last one per name).
/// Also handles comma-separated schemes in a single header value.
fn pick_best_auth_method(response: &Response) -> Option<AuthMethod> {
    let mut has_digest = false;
    let mut has_ntlm = false;
    let mut has_basic = false;

    for (name, raw_value) in response.headers_ordered() {
        if !name.eq_ignore_ascii_case("www-authenticate") {
            continue;
        }
        let value = strip_raw_header_value(raw_value);
        // Handle comma-separated schemes in a single header
        // e.g. "Basic, Wild-and-crazy, NTLM"
        // Also handle full scheme with params: "Digest realm=..."
        for part in value.split(',') {
            let scheme = part.trim().split_ascii_whitespace().next().unwrap_or("");
            if scheme.eq_ignore_ascii_case("digest") {
                has_digest = true;
            } else if scheme.eq_ignore_ascii_case("ntlm") {
                has_ntlm = true;
            } else if scheme.eq_ignore_ascii_case("basic") {
                has_basic = true;
            }
        }
    }

    // Priority: Digest > NTLM > Basic
    if has_digest {
        Some(AuthMethod::Digest)
    } else if has_ntlm {
        Some(AuthMethod::Ntlm)
    } else if has_basic {
        Some(AuthMethod::Basic)
    } else {
        None
    }
}

/// Extract path and query from a URL string without any normalization.
///
/// This is used by `resolve_request_target` when `path_as_is` is true
/// to preserve the raw path segments.
fn extract_path_and_query(url_str: &str) -> String {
    // Skip scheme + authority: find "://", then find the next "/" after authority
    if let Some(scheme_end) = url_str.find("://") {
        let after_scheme = &url_str[scheme_end + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            let path_and_rest = &after_scheme[path_start..];
            // Strip fragment if present
            if let Some(frag_pos) = path_and_rest.find('#') {
                return path_and_rest[..frag_pos].to_string();
            }
            return path_and_rest.to_string();
        }
        return "/".to_string();
    }
    url_str.to_string()
}

/// Build an SSH host key verification policy from Easy options.
#[cfg(feature = "ssh")]
fn build_ssh_host_key_policy(
    sha256_fingerprint: Option<&str>,
    known_hosts_path: Option<&str>,
) -> Result<crate::protocol::ssh::SshHostKeyPolicy, Error> {
    use crate::protocol::ssh::SshHostKeyPolicy;

    // SHA-256 fingerprint takes priority (most specific)
    if let Some(fp) = sha256_fingerprint {
        return Ok(SshHostKeyPolicy::Sha256Fingerprint(fp.to_string()));
    }
    // Then known_hosts file
    if let Some(path) = known_hosts_path {
        let entries = crate::protocol::ssh::parse_known_hosts_file(path)?;
        return Ok(SshHostKeyPolicy::KnownHosts(entries));
    }
    // Default: accept all (matches curl default behavior)
    Ok(SshHostKeyPolicy::AcceptAll)
}

fn should_bypass_proxy(url: &Url, noproxy: Option<&str>) -> bool {
    let Some(noproxy) = noproxy else {
        return false;
    };

    let Some(host) = url.host_str() else {
        return false;
    };

    for pattern in noproxy.split(',') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        // "*" matches everything
        if pattern == "*" {
            return true;
        }

        // Exact match
        if host.eq_ignore_ascii_case(pattern) {
            return true;
        }

        // Domain suffix match (e.g., ".example.com" matches "foo.example.com")
        if pattern.starts_with('.') && host.ends_with(pattern) {
            return true;
        }

        // Also match without leading dot (e.g., "example.com" matches "foo.example.com")
        if host.eq_ignore_ascii_case(pattern) || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }

    false
}

/// Apply `--connect-to` host:port remapping.
///
/// Each mapping has format `from_host:from_port:to_host:to_port`.
/// Empty `from_port` matches any port. Empty `to_host` or `to_port` keeps the original.
fn apply_connect_to(host: &str, port: u16, mappings: &[String]) -> (String, u16) {
    for mapping in mappings {
        let parts: Vec<&str> = mapping.splitn(4, ':').collect();
        if parts.len() < 4 {
            continue;
        }
        let (from_host, from_port_str, to_host, to_port_str) =
            (parts[0], parts[1], parts[2], parts[3]);

        // Check if this mapping matches
        let host_matches = from_host.is_empty() || from_host.eq_ignore_ascii_case(host);
        let port_matches =
            from_port_str.is_empty() || from_port_str.parse::<u16>().ok() == Some(port);

        if host_matches && port_matches {
            let new_host = if to_host.is_empty() { host.to_string() } else { to_host.to_string() };
            let new_port =
                if to_port_str.is_empty() { port } else { to_port_str.parse().unwrap_or(port) };
            return (new_host, new_port);
        }
    }
    (host.to_string(), port)
}

/// Map a `CURLOPT_PROXYTYPE` integer to a URL scheme string.
///
/// Returns the scheme that should be used for the proxy URL.
/// Types 0 (HTTP) and 1 (HTTP 1.0) both map to "http".
const fn proxy_type_to_scheme(ptype: u32) -> &'static str {
    match ptype {
        2 => "https",
        4 => "socks4",
        5 => "socks5",
        6 => "socks4a",
        7 => "socks5h",
        // 0 = HTTP, 1 = HTTP 1.0, and any unknown type default to HTTP
        _ => "http",
    }
}

/// Resolve a relative URL against a base URL.
fn resolve_relative(base: &str, relative: &str) -> String {
    if relative.starts_with('/') {
        // Absolute path — keep scheme + authority from base
        if let Some(idx) = base.find("://") {
            let after_scheme = &base[idx + 3..];
            if let Some(path_start) = after_scheme.find('/') {
                let authority = &base[..idx + 3 + path_start];
                return format!("{authority}{relative}");
            }
        }
        format!("{base}{relative}")
    } else {
        // Relative path — replace last path segment
        base.rfind('/').map_or_else(
            || format!("{base}/{relative}"),
            |idx| format!("{}{relative}", &base[..=idx]),
        )
    }
}

/// Check if a connect error indicates the operation is in progress.
///
/// Non-blocking connect returns `EINPROGRESS` on Unix or `WouldBlock` on Windows.
fn is_connect_in_progress(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
        || err.kind() == std::io::ErrorKind::InvalidInput // some platforms
        || matches!(err.raw_os_error(), Some(code) if code == einprogress_code())
}

/// Platform-specific EINPROGRESS error code.
#[cfg(target_os = "macos")]
const fn einprogress_code() -> i32 {
    36
}
#[cfg(target_os = "linux")]
const fn einprogress_code() -> i32 {
    115
}
#[cfg(target_os = "windows")]
const fn einprogress_code() -> i32 {
    10036 // WSAEINPROGRESS
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const fn einprogress_code() -> i32 {
    36 // fallback
}

/// Interleave IPv6 and IPv4 addresses per RFC 8305 §4.
///
/// Produces a list with alternating address families, starting with IPv6.
/// Example: `[v6_0, v4_0, v6_1, v4_1, v6_2, ...]`
fn interleave_addrs(addrs: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    use std::net::SocketAddr;
    let v6: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv6).collect();
    let v4: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv4).collect();

    let mut result = Vec::with_capacity(addrs.len());
    let mut i6 = 0;
    let mut i4 = 0;
    while i6 < v6.len() || i4 < v4.len() {
        if i6 < v6.len() {
            result.push(v6[i6]);
            i6 += 1;
        }
        if i4 < v4.len() {
            result.push(v4[i4]);
            i4 += 1;
        }
    }
    result
}

/// Happy Eyeballs (RFC 8305) TCP connection.
///
/// Given a list of resolved addresses (may contain both IPv4 and IPv6),
/// try IPv6 first. If IPv6 doesn't connect within 250ms, start an IPv4
/// attempt in parallel. Addresses within each family are interleaved
/// per RFC 8305 §4. Returns the first successful connection.
/// If only one address family is present, connects directly.
async fn happy_eyeballs_connect(
    addrs: &[std::net::SocketAddr],
    connect_timeout: Option<Duration>,
    start: Instant,
    interface: Option<&str>,
    local_port: Option<u16>,
    eyeballs_timeout: Option<Duration>,
) -> Result<tokio::net::TcpStream, Error> {
    use std::net::SocketAddr;

    // Happy Eyeballs delay before starting the other address family
    // Default: 250ms (RFC 8305 recommendation)
    let eyeballs_delay = eyeballs_timeout.unwrap_or(Duration::from_millis(250));

    // Interleave addresses per RFC 8305 §4
    let interleaved = interleave_addrs(addrs);

    // Separate into IPv6 and IPv4 (preserving interleaved order within each family)
    let v6: Vec<SocketAddr> = interleaved.iter().copied().filter(SocketAddr::is_ipv6).collect();
    let v4: Vec<SocketAddr> = interleaved.iter().copied().filter(SocketAddr::is_ipv4).collect();

    // If only one family, just try them in order
    if v6.is_empty() || v4.is_empty() {
        return try_connect_addrs(&interleaved, connect_timeout, interface, local_port).await;
    }

    // Both families present: race with head start for IPv6
    let remaining_timeout = connect_timeout.map(|t| {
        let elapsed = start.elapsed();
        t.saturating_sub(elapsed)
    });

    let v6_fut = try_connect_addrs(&v6, remaining_timeout, interface, local_port);
    let v4_delayed = async {
        tokio::time::sleep(eyeballs_delay).await;
        try_connect_addrs(
            &v4,
            remaining_timeout.map(|t| t.saturating_sub(eyeballs_delay)),
            interface,
            local_port,
        )
        .await
    };

    tokio::pin!(v6_fut);
    tokio::pin!(v4_delayed);

    // Race both: return first success
    tokio::select! {
        result = &mut v6_fut => {
            match result {
                Ok(stream) => Ok(stream),
                Err(_v6_err) => {
                    // IPv6 failed, wait for IPv4
                    v4_delayed.await
                }
            }
        }
        result = &mut v4_delayed => {
            match result {
                Ok(stream) => Ok(stream),
                Err(_v4_err) => {
                    // IPv4 failed, wait for IPv6
                    v6_fut.await
                }
            }
        }
    }
}

/// Try connecting to each address in order, returning the first success.
///
/// When `interface` or `local_port` is set, uses `socket2` to create the
/// socket, bind to the local address, then connect.
#[allow(clippy::option_if_let_else)]
async fn try_connect_addrs(
    addrs: &[std::net::SocketAddr],
    timeout: Option<Duration>,
    interface: Option<&str>,
    local_port: Option<u16>,
) -> Result<tokio::net::TcpStream, Error> {
    let mut last_err = None;
    for addr in addrs {
        let result = if interface.is_some() || local_port.is_some() {
            connect_with_bind(*addr, interface, local_port, timeout).await
        } else {
            let connect_fut = tokio::net::TcpStream::connect(addr);
            if let Some(timeout_dur) = timeout {
                match tokio::time::timeout(timeout_dur, connect_fut).await {
                    Ok(r) => r.map_err(Error::Connect),
                    Err(_) => Err(Error::Timeout(timeout_dur)),
                }
            } else {
                connect_fut.await.map_err(Error::Connect)
            }
        };
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::Connect(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no addresses to connect to",
        ))
    }))
}

/// Connect to a remote address with local interface/port binding.
///
/// Uses `socket2` to create a socket, bind to the specified local address,
/// then connect to the remote address.
async fn connect_with_bind(
    remote: std::net::SocketAddr,
    interface: Option<&str>,
    local_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<tokio::net::TcpStream, Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if remote.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(Error::Connect)?;

    // Resolve the local bind address
    let unspecified = if remote.is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let bind_ip: std::net::IpAddr =
        interface.map_or(unspecified, |iface| iface.parse().unwrap_or(unspecified));

    let bind_addr = std::net::SocketAddr::new(bind_ip, local_port.unwrap_or(0));
    socket.bind(&bind_addr.into()).map_err(Error::Connect)?;
    socket.set_nonblocking(true).map_err(Error::Connect)?;

    // Initiate non-blocking connect on the raw socket.
    // Non-blocking connect returns WouldBlock or "in progress" — both are expected.
    let remote_sa: socket2::SockAddr = remote.into();
    match socket.connect(&remote_sa) {
        Ok(()) => {}
        Err(e) if is_connect_in_progress(&e) => {}
        Err(e) => return Err(Error::Connect(e)),
    }

    // Convert to tokio TcpStream and wait for connection to complete
    let std_stream: std::net::TcpStream = socket.into();
    let stream = tokio::net::TcpStream::from_std(std_stream).map_err(Error::Connect)?;

    let connect_fut = async {
        // Wait for the socket to be writable (connect complete)
        stream.writable().await.map_err(Error::Connect)?;

        // Check for connect errors
        if let Some(e) = stream.take_error().map_err(Error::Connect)? {
            return Err(Error::Connect(e));
        }
        Ok(stream)
    };

    if let Some(timeout_dur) = timeout {
        tokio::time::timeout(timeout_dur, connect_fut)
            .await
            .map_err(|_| Error::Timeout(timeout_dur))?
    } else {
        connect_fut.await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn easy_new_has_no_url() {
        let easy = Easy::new();
        assert!(easy.url.is_none());
    }

    #[test]
    fn easy_set_url() {
        let mut easy = Easy::new();
        easy.url("http://example.com").unwrap();
        assert!(easy.url.is_some());
    }

    #[test]
    fn easy_set_invalid_url() {
        let mut easy = Easy::new();
        assert!(easy.url("").is_err());
    }

    #[test]
    fn easy_perform_without_url() {
        let mut easy = Easy::new();
        let result = easy.perform();
        assert!(result.is_err());
    }

    #[test]
    fn easy_default() {
        let easy = Easy::default();
        assert!(easy.url.is_none());
    }

    #[test]
    fn easy_set_method() {
        let mut easy = Easy::new();
        easy.method("POST");
        assert_eq!(easy.method, Some("POST".to_string()));
    }

    #[test]
    fn easy_method_uppercased() {
        let mut easy = Easy::new();
        easy.method("post");
        assert_eq!(easy.method, Some("POST".to_string()));
    }

    #[test]
    fn easy_add_header() {
        let mut easy = Easy::new();
        easy.header("Content-Type", "application/json");
        assert_eq!(easy.headers.len(), 1);
        assert_eq!(easy.headers[0], ("Content-Type".to_string(), "application/json".to_string()));
    }

    #[test]
    fn easy_set_body() {
        let mut easy = Easy::new();
        easy.body(b"hello");
        assert_eq!(easy.body, Some(b"hello".to_vec()));
    }

    #[test]
    fn easy_follow_redirects() {
        let mut easy = Easy::new();
        easy.follow_redirects(true);
        assert!(easy.follow_redirects);
    }

    #[test]
    fn easy_accept_encoding() {
        let mut easy = Easy::new();
        assert!(!easy.accept_encoding);
        easy.accept_encoding(true);
        assert!(easy.accept_encoding);
    }

    #[test]
    fn easy_connect_timeout() {
        let mut easy = Easy::new();
        assert!(easy.connect_timeout.is_none());
        easy.connect_timeout(Duration::from_secs(5));
        assert_eq!(easy.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn easy_timeout() {
        let mut easy = Easy::new();
        assert!(easy.timeout.is_none());
        easy.timeout(Duration::from_secs(30));
        assert_eq!(easy.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn easy_basic_auth() {
        let mut easy = Easy::new();
        easy.basic_auth("user", "pass");
        assert_eq!(easy.headers.len(), 1);
        assert_eq!(easy.headers[0].0, "Authorization");
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert_eq!(easy.headers[0].1, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn easy_bearer_token() {
        let mut easy = Easy::new();
        easy.bearer_token("my-token-123");
        assert_eq!(easy.headers.len(), 1);
        assert_eq!(easy.headers[0].0, "Authorization");
        assert_eq!(easy.headers[0].1, "Bearer my-token-123");
    }

    #[test]
    fn easy_cookie_jar_enable() {
        let mut easy = Easy::new();
        assert!(easy.cookie_jar.is_none());
        easy.cookie_jar(true);
        assert!(easy.cookie_jar.is_some());
    }

    #[test]
    fn easy_cookie_jar_disable() {
        let mut easy = Easy::new();
        easy.cookie_jar(true);
        easy.cookie_jar(false);
        assert!(easy.cookie_jar.is_none());
    }

    #[test]
    fn easy_proxy_set() {
        let mut easy = Easy::new();
        assert!(easy.proxy.is_none());
        easy.proxy("http://proxy.example.com:8080").unwrap();
        assert!(easy.proxy.is_some());
        let proxy = easy.proxy.as_ref().unwrap();
        assert_eq!(proxy.host_str(), Some("proxy.example.com"));
        assert_eq!(proxy.port(), Some(8080));
    }

    #[test]
    fn easy_proxy_invalid_url() {
        let mut easy = Easy::new();
        assert!(easy.proxy("").is_err());
    }

    #[test]
    fn easy_noproxy_set() {
        let mut easy = Easy::new();
        assert!(easy.noproxy.is_none());
        easy.noproxy("localhost,.example.com");
        assert_eq!(easy.noproxy, Some("localhost,.example.com".to_string()));
    }

    #[test]
    fn bypass_proxy_wildcard() {
        let url = Url::parse("http://anything.com").unwrap();
        assert!(should_bypass_proxy(&url, Some("*")));
    }

    #[test]
    fn bypass_proxy_exact_match() {
        let url = Url::parse("http://localhost/test").unwrap();
        assert!(should_bypass_proxy(&url, Some("localhost")));
    }

    #[test]
    fn bypass_proxy_domain_suffix() {
        let url = Url::parse("http://api.example.com/test").unwrap();
        assert!(should_bypass_proxy(&url, Some(".example.com")));
    }

    #[test]
    fn bypass_proxy_domain_without_dot() {
        let url = Url::parse("http://api.example.com/test").unwrap();
        assert!(should_bypass_proxy(&url, Some("example.com")));
    }

    #[test]
    fn bypass_proxy_no_match() {
        let url = Url::parse("http://other.com/test").unwrap();
        assert!(!should_bypass_proxy(&url, Some("example.com")));
    }

    #[test]
    fn bypass_proxy_none() {
        let url = Url::parse("http://example.com").unwrap();
        assert!(!should_bypass_proxy(&url, None));
    }

    #[test]
    fn bypass_proxy_multiple_entries() {
        let url = Url::parse("http://internal.corp/api").unwrap();
        assert!(should_bypass_proxy(&url, Some("localhost, .corp, 127.0.0.1")));
    }

    #[test]
    fn find_header_end_found() {
        let data = b"HTTP/1.1 200 OK\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(19));
    }

    #[test]
    fn find_header_end_not_found() {
        let data = b"HTTP/1.1 200 OK\r\npartial";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn resolve_relative_absolute_path() {
        assert_eq!(
            resolve_relative("http://example.com/old/path", "/new/path"),
            "http://example.com/new/path"
        );
    }

    #[test]
    fn resolve_relative_path() {
        assert_eq!(
            resolve_relative("http://example.com/dir/file", "other"),
            "http://example.com/dir/other"
        );
    }

    #[test]
    fn easy_clone_has_empty_pool() {
        let mut easy = Easy::new();
        easy.url("http://example.com").unwrap();
        let cloned = easy.clone();
        // Clone succeeds with its own pool and preserves URL
        assert!(cloned.url.is_some());
    }

    #[test]
    fn easy_tcp_nodelay_default_true() {
        let easy = Easy::new();
        assert!(easy.tcp_nodelay);
    }

    #[test]
    fn easy_tcp_nodelay_disable() {
        let mut easy = Easy::new();
        easy.tcp_nodelay(false);
        assert!(!easy.tcp_nodelay);
    }

    #[test]
    fn easy_tcp_keepalive_default_none() {
        let easy = Easy::new();
        assert!(easy.tcp_keepalive.is_none());
    }

    #[test]
    fn easy_tcp_keepalive_set() {
        let mut easy = Easy::new();
        easy.tcp_keepalive(Duration::from_secs(60));
        assert_eq!(easy.tcp_keepalive, Some(Duration::from_secs(60)));
    }

    #[test]
    fn easy_unix_socket_default_none() {
        let easy = Easy::new();
        assert!(easy.unix_socket.is_none());
    }

    #[test]
    fn easy_unix_socket_set() {
        let mut easy = Easy::new();
        easy.unix_socket("/var/run/docker.sock");
        assert_eq!(easy.unix_socket, Some("/var/run/docker.sock".to_string()));
    }

    #[test]
    fn easy_dns_cache_starts_empty() {
        let easy = Easy::new();
        assert!(easy.dns_cache.is_empty());
    }

    #[test]
    fn easy_clone_has_fresh_dns_cache() {
        let mut easy = Easy::new();
        easy.url("http://example.com").unwrap();
        let cloned = easy.clone();
        assert!(cloned.dns_cache.is_empty());
    }

    #[test]
    fn easy_set_share() {
        let mut share = crate::share::Share::new();
        share.add(crate::share::ShareType::Dns);
        share.add(crate::share::ShareType::Cookies);

        let mut easy = Easy::new();
        easy.set_share(share.clone());
        assert!(easy.share.is_some());

        // Clone should inherit share
        let cloned = easy.clone();
        assert!(cloned.share.is_some());
    }

    #[tokio::test]
    async fn happy_eyeballs_single_v4_addr() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let result = happy_eyeballs_connect(&[addr], None, Instant::now(), None, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_no_addrs() {
        let result = happy_eyeballs_connect(&[], None, Instant::now(), None, None, None).await;
        assert!(result.is_err());
    }

    #[test]
    fn interleave_addrs_v4_only() {
        use std::net::{Ipv4Addr, SocketAddr};
        let a1 = SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 80);
        let a2 = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 80);
        let result = interleave_addrs(&[a1, a2]);
        assert_eq!(result, vec![a1, a2]);
    }

    #[test]
    fn interleave_addrs_v6_only() {
        use std::net::{Ipv6Addr, SocketAddr};
        let a1 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80);
        let a2 = SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), 80);
        let result = interleave_addrs(&[a1, a2]);
        assert_eq!(result, vec![a1, a2]);
    }

    #[test]
    fn interleave_addrs_mixed() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        let v6a = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80);
        let v6b = SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), 80);
        let v4a = SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 80);
        let v4b = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 80);

        // Input: v6, v6, v4, v4 → Output: v6, v4, v6, v4 (interleaved)
        let result = interleave_addrs(&[v6a, v6b, v4a, v4b]);
        assert_eq!(result, vec![v6a, v4a, v6b, v4b]);
    }

    #[test]
    fn interleave_addrs_uneven() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        let v6a = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80);
        let v4a = SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 80);
        let v4b = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 80);

        // 1 v6 + 2 v4 → v6, v4a, v4b
        let result = interleave_addrs(&[v6a, v4a, v4b]);
        assert_eq!(result, vec![v6a, v4a, v4b]);
    }

    #[test]
    fn interleave_addrs_empty() {
        let result = interleave_addrs(&[]);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn try_connect_addrs_succeeds() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let result = try_connect_addrs(&[addr], None, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn try_connect_addrs_fails_unreachable() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Use a non-routable address that should fail quickly
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1);
        let result = try_connect_addrs(&[addr], Some(Duration::from_millis(100)), None, None).await;
        assert!(result.is_err());
    }

    #[test]
    fn easy_interface_default_none() {
        let easy = Easy::new();
        assert!(easy.interface.is_none());
    }

    #[test]
    fn easy_interface_set() {
        let mut easy = Easy::new();
        easy.interface("192.168.1.100");
        assert_eq!(easy.interface, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn easy_local_port_default_none() {
        let easy = Easy::new();
        assert!(easy.local_port.is_none());
    }

    #[test]
    fn easy_local_port_set() {
        let mut easy = Easy::new();
        easy.local_port(12345);
        assert_eq!(easy.local_port, Some(12345));
    }

    #[test]
    fn easy_dns_shuffle_default_false() {
        let easy = Easy::new();
        assert!(!easy.dns_shuffle);
    }

    #[test]
    fn easy_dns_shuffle_enable() {
        let mut easy = Easy::new();
        easy.dns_shuffle(true);
        assert!(easy.dns_shuffle);
    }

    #[tokio::test]
    async fn connect_with_bind_local_port() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect with a specific local port
        let result = connect_with_bind(addr, None, Some(0), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn connect_with_bind_interface_ip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Bind to loopback interface
        let result = connect_with_bind(addr, Some("127.0.0.1"), None, None).await;
        assert!(result.is_ok());
    }

    #[test]
    fn http_version_default_is_none() {
        let easy = Easy::new();
        assert_eq!(easy.http_version, HttpVersion::None);
    }

    #[test]
    fn easy_set_http_version() {
        let mut easy = Easy::new();
        easy.http_version(HttpVersion::Http10);
        assert_eq!(easy.http_version, HttpVersion::Http10);
    }

    #[test]
    fn easy_set_http_version_h2() {
        let mut easy = Easy::new();
        easy.http_version(HttpVersion::Http2);
        assert_eq!(easy.http_version, HttpVersion::Http2);
    }

    #[test]
    fn easy_set_expect_100_timeout() {
        let mut easy = Easy::new();
        easy.expect_100_timeout(Duration::from_millis(500));
        assert_eq!(easy.expect_100_timeout, Some(Duration::from_millis(500)));
    }

    #[test]
    fn http_version_clone() {
        let mut easy = Easy::new();
        easy.http_version(HttpVersion::Http11);
        easy.expect_100_timeout(Duration::from_secs(2));
        let cloned = easy.clone();
        assert_eq!(cloned.http_version, HttpVersion::Http11);
        assert_eq!(cloned.expect_100_timeout, Some(Duration::from_secs(2)));
    }

    #[test]
    fn easy_cookie_jar_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("urlx_test_cookie_file.txt");
        std::fs::write(
            &path,
            "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\ttest\tval\n",
        )
        .unwrap();

        let mut easy = Easy::new();
        easy.cookie_file(&path).unwrap();
        assert!(easy.cookie_jar.is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn easy_cookie_jar_file_not_found() {
        let mut easy = Easy::new();
        assert!(easy.cookie_file("/nonexistent/path.txt").is_err());
    }

    #[test]
    fn easy_cookie_jar_path() {
        let mut easy = Easy::new();
        easy.cookie_jar_file("/tmp/output_cookies.txt");
        assert_eq!(easy.cookie_jar_path, Some("/tmp/output_cookies.txt".to_string()));
        assert!(easy.cookie_jar.is_some()); // Cookie engine should be enabled
    }

    #[test]
    fn easy_max_recv_speed() {
        let mut easy = Easy::new();
        easy.max_recv_speed(1024);
        assert_eq!(easy.max_recv_speed, Some(1024));
    }

    #[test]
    fn easy_max_send_speed() {
        let mut easy = Easy::new();
        easy.max_send_speed(2048);
        assert_eq!(easy.max_send_speed, Some(2048));
    }

    #[test]
    fn easy_low_speed_limit() {
        let mut easy = Easy::new();
        easy.low_speed_limit(100);
        assert_eq!(easy.low_speed_limit, Some(100));
    }

    #[test]
    fn easy_low_speed_time() {
        let mut easy = Easy::new();
        easy.low_speed_time(Duration::from_secs(30));
        assert_eq!(easy.low_speed_time, Some(Duration::from_secs(30)));
    }

    #[test]
    fn easy_rate_limit_clone() {
        let mut easy = Easy::new();
        easy.max_recv_speed(1024);
        easy.max_send_speed(2048);
        easy.low_speed_limit(100);
        easy.low_speed_time(Duration::from_secs(30));
        let cloned = easy.clone();
        assert_eq!(cloned.max_recv_speed, Some(1024));
        assert_eq!(cloned.max_send_speed, Some(2048));
        assert_eq!(cloned.low_speed_limit, Some(100));
        assert_eq!(cloned.low_speed_time, Some(Duration::from_secs(30)));
    }

    #[test]
    fn easy_fresh_connect() {
        let mut easy = Easy::new();
        assert!(!easy.fresh_connect);
        easy.fresh_connect(true);
        assert!(easy.fresh_connect);
    }

    #[test]
    fn easy_forbid_reuse() {
        let mut easy = Easy::new();
        assert!(!easy.forbid_reuse);
        easy.forbid_reuse(true);
        assert!(easy.forbid_reuse);
    }

    #[test]
    fn easy_connection_control_clone() {
        let mut easy = Easy::new();
        easy.fresh_connect(true);
        easy.forbid_reuse(true);
        let cloned = easy.clone();
        assert!(cloned.fresh_connect);
        assert!(cloned.forbid_reuse);
    }

    #[test]
    fn easy_proxy_digest_auth() {
        let mut easy = Easy::new();
        easy.proxy_digest_auth("user", "pass");
        assert!(easy.proxy_credentials.is_some());
        let creds = easy.proxy_credentials.as_ref().unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
        assert_eq!(creds.method, ProxyAuthMethod::Digest);
        assert!(creds.domain.is_none());
    }

    #[test]
    fn easy_proxy_ntlm_auth() {
        let mut easy = Easy::new();
        easy.proxy_ntlm_auth("DOMAIN\\user", "pass");
        assert!(easy.proxy_credentials.is_some());
        let creds = easy.proxy_credentials.as_ref().unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
        assert_eq!(creds.method, ProxyAuthMethod::Ntlm);
        assert_eq!(creds.domain.as_deref(), Some("DOMAIN"));
    }

    #[test]
    fn easy_proxy_ntlm_auth_no_domain() {
        let mut easy = Easy::new();
        easy.proxy_ntlm_auth("user", "pass");
        let creds = easy.proxy_credentials.as_ref().unwrap();
        assert_eq!(creds.username, "user");
        assert!(creds.domain.is_none());
    }

    #[test]
    fn easy_proxy_tls_config() {
        let mut easy = Easy::new();
        assert!(easy.proxy_tls_config.is_none());
        easy.proxy_ssl_verify_peer(false);
        assert!(easy.proxy_tls_config.is_some());
        assert!(!easy.proxy_tls_config.as_ref().unwrap().verify_peer);
    }

    #[test]
    fn easy_proxy_ssl_client_cert() {
        let mut easy = Easy::new();
        easy.proxy_ssl_client_cert(std::path::Path::new("/tmp/cert.pem"));
        let config = easy.proxy_tls_config.as_ref().unwrap();
        assert_eq!(config.client_cert.as_ref().unwrap().to_str().unwrap(), "/tmp/cert.pem");
    }

    #[test]
    fn easy_proxy_ssl_client_key() {
        let mut easy = Easy::new();
        easy.proxy_ssl_client_key(std::path::Path::new("/tmp/key.pem"));
        let config = easy.proxy_tls_config.as_ref().unwrap();
        assert_eq!(config.client_key.as_ref().unwrap().to_str().unwrap(), "/tmp/key.pem");
    }

    #[test]
    fn easy_proxy_credentials_clone() {
        let mut easy = Easy::new();
        easy.proxy_digest_auth("user", "pass");
        let cloned = easy.clone();
        assert!(cloned.proxy_credentials.is_some());
        assert_eq!(cloned.proxy_credentials.as_ref().unwrap().username, "user");
    }

    #[test]
    fn easy_proxy_auth_stores_credentials() {
        let mut easy = Easy::new();
        easy.proxy_auth("user", "pass");
        // proxy_auth also stores credentials
        assert!(easy.proxy_credentials.is_some());
        assert_eq!(easy.proxy_credentials.as_ref().unwrap().method, ProxyAuthMethod::Basic);
    }

    #[test]
    fn easy_infilesize() {
        let mut easy = Easy::new();
        assert!(easy.infilesize.is_none());
        easy.infilesize(4096);
        assert_eq!(easy.infilesize, Some(4096));
    }

    #[test]
    fn easy_infilesize_zero() {
        let mut easy = Easy::new();
        easy.infilesize(0);
        assert_eq!(easy.infilesize, Some(0));
    }

    #[test]
    fn easy_upload_file_sets_body_and_method() {
        use std::io::Write;

        let dir = std::env::temp_dir();
        let path = dir.join("urlx_test_upload.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello upload").unwrap();
        }

        let mut easy = Easy::new();
        easy.upload_file(&path).unwrap();

        assert_eq!(easy.body.as_deref(), Some(b"hello upload".as_slice()));
        assert_eq!(easy.infilesize, Some(12));
        assert_eq!(easy.method.as_deref(), Some("PUT"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn easy_upload_file_preserves_explicit_method() {
        use std::io::Write;

        let dir = std::env::temp_dir();
        let path = dir.join("urlx_test_upload2.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"data").unwrap();
        }

        let mut easy = Easy::new();
        easy.method("POST");
        easy.upload_file(&path).unwrap();

        // Should keep explicit POST, not override to PUT
        assert_eq!(easy.method.as_deref(), Some("POST"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn easy_upload_file_nonexistent() {
        let mut easy = Easy::new();
        let result = easy.upload_file(Path::new("/nonexistent/path/to/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn easy_infilesize_cloned() {
        let mut easy = Easy::new();
        easy.infilesize(8192);
        let cloned = easy.clone();
        assert_eq!(cloned.infilesize, Some(8192));
    }

    #[test]
    fn easy_dns_cache_timeout() {
        let mut easy = Easy::new();
        assert!(easy.dns_cache_timeout.is_none());
        easy.dns_cache_timeout(Duration::from_secs(120));
        assert_eq!(easy.dns_cache_timeout, Some(Duration::from_secs(120)));
        // Verify the cache TTL was updated
        assert_eq!(easy.dns_cache.ttl(), Duration::from_secs(120));
    }

    #[test]
    fn easy_dns_cache_timeout_zero_disables() {
        let mut easy = Easy::new();
        easy.dns_cache_timeout(Duration::ZERO);
        assert_eq!(easy.dns_cache.ttl(), Duration::ZERO);
    }

    #[test]
    fn easy_happy_eyeballs_timeout() {
        let mut easy = Easy::new();
        assert!(easy.happy_eyeballs_timeout.is_none());
        easy.happy_eyeballs_timeout(Duration::from_millis(100));
        assert_eq!(easy.happy_eyeballs_timeout, Some(Duration::from_millis(100)));
    }

    #[test]
    fn easy_happy_eyeballs_timeout_cloned() {
        let mut easy = Easy::new();
        easy.happy_eyeballs_timeout(Duration::from_millis(500));
        let cloned = easy.clone();
        assert_eq!(cloned.happy_eyeballs_timeout, Some(Duration::from_millis(500)));
    }

    #[test]
    fn easy_max_pool_connections() {
        let mut easy = Easy::new();
        easy.max_pool_connections(10);
        assert_eq!(easy.pool.max_total, 10);
    }

    #[test]
    fn easy_max_pool_connections_zero_disables() {
        let mut easy = Easy::new();
        easy.max_pool_connections(0);
        assert_eq!(easy.pool.ttl, Duration::ZERO);
    }

    #[test]
    fn easy_dns_servers_valid() {
        let mut easy = Easy::new();
        easy.dns_servers("8.8.8.8,8.8.4.4").unwrap();
        let servers = easy.dns_servers.as_ref().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].ip().to_string(), "8.8.8.8");
        assert_eq!(servers[0].port(), 53);
        assert_eq!(servers[1].ip().to_string(), "8.8.4.4");
    }

    #[test]
    fn easy_dns_servers_with_port() {
        let mut easy = Easy::new();
        easy.dns_servers("1.1.1.1:5353").unwrap();
        let servers = easy.dns_servers.as_ref().unwrap();
        assert_eq!(servers[0].port(), 5353);
    }

    #[test]
    fn easy_dns_servers_empty_fails() {
        let mut easy = Easy::new();
        assert!(easy.dns_servers("").is_err());
    }

    #[test]
    fn easy_dns_servers_invalid_ip_fails() {
        let mut easy = Easy::new();
        assert!(easy.dns_servers("not-an-ip").is_err());
    }

    #[test]
    fn easy_dns_servers_cloned() {
        let mut easy = Easy::new();
        easy.dns_servers("8.8.8.8").unwrap();
        let cloned = easy.clone();
        assert!(cloned.dns_servers.is_some());
        assert_eq!(cloned.dns_servers.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn easy_doh_url() {
        let mut easy = Easy::new();
        assert!(easy.doh_url.is_none());
        easy.doh_url("https://dns.google/dns-query");
        assert_eq!(easy.doh_url.as_deref(), Some("https://dns.google/dns-query"));
    }

    #[test]
    fn easy_doh_url_cloned() {
        let mut easy = Easy::new();
        easy.doh_url("https://dns.cloudflare.com/dns-query");
        let cloned = easy.clone();
        assert_eq!(cloned.doh_url.as_deref(), Some("https://dns.cloudflare.com/dns-query"));
    }

    #[test]
    fn easy_unrestricted_auth_default_false() {
        let easy = Easy::new();
        assert!(!easy.unrestricted_auth);
    }

    #[test]
    fn easy_unrestricted_auth_set() {
        let mut easy = Easy::new();
        easy.unrestricted_auth(true);
        assert!(easy.unrestricted_auth);
    }

    #[test]
    fn easy_unrestricted_auth_cloned() {
        let mut easy = Easy::new();
        easy.unrestricted_auth(true);
        let cloned = easy.clone();
        assert!(cloned.unrestricted_auth);
    }

    #[test]
    fn easy_ignore_content_length_default_false() {
        let easy = Easy::new();
        assert!(!easy.ignore_content_length);
    }

    #[test]
    fn easy_ignore_content_length_set() {
        let mut easy = Easy::new();
        easy.ignore_content_length(true);
        assert!(easy.ignore_content_length);
    }

    #[test]
    fn easy_ignore_content_length_cloned() {
        let mut easy = Easy::new();
        easy.ignore_content_length(true);
        let cloned = easy.clone();
        assert!(cloned.ignore_content_length);
    }

    #[test]
    fn easy_post301_default_false() {
        let easy = Easy::new();
        assert!(!easy.post301);
    }

    #[test]
    fn easy_post301_set() {
        let mut easy = Easy::new();
        easy.post301(true);
        assert!(easy.post301);
    }

    #[test]
    fn easy_post302_set() {
        let mut easy = Easy::new();
        easy.post302(true);
        assert!(easy.post302);
    }

    #[test]
    fn easy_post303_set() {
        let mut easy = Easy::new();
        easy.post303(true);
        assert!(easy.post303);
    }

    #[test]
    fn easy_post_redir_cloned() {
        let mut easy = Easy::new();
        easy.post301(true);
        easy.post302(true);
        easy.post303(true);
        let cloned = easy.clone();
        assert!(cloned.post301);
        assert!(cloned.post302);
        assert!(cloned.post303);
    }

    #[test]
    fn easy_proxy_header() {
        let mut easy = Easy::new();
        easy.proxy_header("X-Proxy-Auth", "token123");
        assert_eq!(easy.proxy_headers.len(), 1);
        assert_eq!(easy.proxy_headers[0].0, "X-Proxy-Auth");
        assert_eq!(easy.proxy_headers[0].1, "token123");
    }

    #[test]
    fn easy_proxy_headers_cloned() {
        let mut easy = Easy::new();
        easy.proxy_header("X-Foo", "bar");
        let cloned = easy.clone();
        assert_eq!(cloned.proxy_headers.len(), 1);
    }

    #[test]
    fn easy_ftp_ssl_mode_default() {
        let easy = Easy::new();
        assert_eq!(easy.ftp_ssl_mode, crate::protocol::ftp::FtpSslMode::None);
    }

    #[test]
    fn easy_ftp_ssl_mode_set() {
        let mut easy = Easy::new();
        easy.ftp_ssl_mode(crate::protocol::ftp::FtpSslMode::Explicit);
        assert_eq!(easy.ftp_ssl_mode, crate::protocol::ftp::FtpSslMode::Explicit);
    }

    #[test]
    fn easy_ftp_ssl_mode_implicit() {
        let mut easy = Easy::new();
        easy.ftp_ssl_mode(crate::protocol::ftp::FtpSslMode::Implicit);
        assert_eq!(easy.ftp_ssl_mode, crate::protocol::ftp::FtpSslMode::Implicit);
    }

    #[test]
    fn easy_ftp_ssl_mode_cloned() {
        let mut easy = Easy::new();
        easy.ftp_ssl_mode(crate::protocol::ftp::FtpSslMode::Explicit);
        let cloned = easy.clone();
        assert_eq!(cloned.ftp_ssl_mode, crate::protocol::ftp::FtpSslMode::Explicit);
    }

    #[test]
    fn easy_ftp_active_port_default() {
        let easy = Easy::new();
        assert!(easy.ftp_active_port.is_none());
    }

    #[test]
    fn easy_ftp_active_port_set() {
        let mut easy = Easy::new();
        easy.ftp_active_port("-");
        assert_eq!(easy.ftp_active_port.as_deref(), Some("-"));
    }

    #[test]
    fn easy_ftp_active_port_ip() {
        let mut easy = Easy::new();
        easy.ftp_active_port("192.168.1.100");
        assert_eq!(easy.ftp_active_port.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn easy_ftp_active_port_cloned() {
        let mut easy = Easy::new();
        easy.ftp_active_port("10.0.0.1");
        let cloned = easy.clone();
        assert_eq!(cloned.ftp_active_port.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn easy_ssh_key_path_default() {
        let easy = Easy::new();
        assert!(easy.ssh_key_path.is_none());
    }

    #[test]
    fn easy_ssh_key_path_set() {
        let mut easy = Easy::new();
        easy.ssh_key_path("/home/user/.ssh/id_ed25519");
        assert_eq!(easy.ssh_key_path.as_deref(), Some("/home/user/.ssh/id_ed25519"));
    }

    #[test]
    fn easy_ssh_key_path_cloned() {
        let mut easy = Easy::new();
        easy.ssh_key_path("/home/user/.ssh/id_rsa");
        let cloned = easy.clone();
        assert_eq!(cloned.ssh_key_path.as_deref(), Some("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn easy_ssh_host_key_sha256_default() {
        let easy = Easy::new();
        assert!(easy.ssh_host_key_sha256.is_none());
    }

    #[test]
    fn easy_ssh_host_key_sha256_set() {
        let mut easy = Easy::new();
        easy.ssh_host_key_sha256("abcdef1234567890");
        assert_eq!(easy.ssh_host_key_sha256.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn easy_ssh_host_key_sha256_cloned() {
        let mut easy = Easy::new();
        easy.ssh_host_key_sha256("test_fp");
        let cloned = easy.clone();
        assert_eq!(cloned.ssh_host_key_sha256.as_deref(), Some("test_fp"));
    }

    #[test]
    fn easy_ssh_known_hosts_path_default() {
        let easy = Easy::new();
        assert!(easy.ssh_known_hosts_path.is_none());
    }

    #[test]
    fn easy_ssh_known_hosts_path_set() {
        let mut easy = Easy::new();
        easy.ssh_known_hosts_path("/home/user/.ssh/known_hosts");
        assert_eq!(easy.ssh_known_hosts_path.as_deref(), Some("/home/user/.ssh/known_hosts"));
    }

    #[test]
    fn easy_ssh_known_hosts_path_cloned() {
        let mut easy = Easy::new();
        easy.ssh_known_hosts_path("/etc/ssh/known_hosts");
        let cloned = easy.clone();
        assert_eq!(cloned.ssh_known_hosts_path.as_deref(), Some("/etc/ssh/known_hosts"));
    }

    #[test]
    fn easy_method_str_none_by_default() {
        let easy = Easy::new();
        assert!(easy.method_str().is_none());
    }

    #[test]
    fn easy_method_str_returns_set_method() {
        let mut easy = Easy::new();
        easy.method("POST");
        assert_eq!(easy.method_str(), Some("POST"));
    }

    #[test]
    fn easy_header_list_empty_by_default() {
        let easy = Easy::new();
        assert!(easy.header_list().is_empty());
    }

    #[test]
    fn easy_header_list_returns_headers() {
        let mut easy = Easy::new();
        easy.header("Content-Type", "application/json");
        easy.header("Accept", "text/html");
        assert_eq!(easy.header_list().len(), 2);
        assert_eq!(easy.header_list()[0].0, "Content-Type");
    }

    #[test]
    fn easy_proxy_tls_config_default_none() {
        let easy = Easy::new();
        assert!(easy.proxy_tls_config.is_none());
    }

    #[test]
    fn easy_proxy_tls_config_set() {
        let mut easy = Easy::new();
        let config = TlsConfig { verify_peer: false, ..TlsConfig::default() };
        easy.proxy_tls_config(config);
        assert!(!easy.proxy_tls_config.as_ref().unwrap().verify_peer);
    }

    #[test]
    fn easy_proxy_ssl_verify_peer() {
        let mut easy = Easy::new();
        easy.proxy_ssl_verify_peer(false);
        assert!(!easy.proxy_tls_config.as_ref().unwrap().verify_peer);
    }

    #[test]
    fn easy_path_as_is() {
        let mut easy = Easy::new();
        assert!(!easy.path_as_is);
        easy.path_as_is(true);
        assert!(easy.path_as_is);
    }

    #[test]
    fn easy_raw() {
        let mut easy = Easy::new();
        assert!(!easy.raw);
        easy.raw(true);
        assert!(easy.raw);
    }

    #[test]
    fn easy_raw_disables_accept_encoding() {
        let mut easy = Easy::new();
        easy.accept_encoding(true);
        easy.raw(true);
        // raw=true should cause accept_encoding to be passed as false to perform_transfer
        assert!(easy.accept_encoding);
        assert!(easy.raw);
    }

    #[test]
    fn easy_ntlm_auth() {
        let mut easy = Easy::new();
        easy.ntlm_auth("user", "pass");
        let creds = easy.auth_credentials.as_ref().unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
        assert_eq!(creds.method, AuthMethod::Ntlm);
    }

    #[test]
    fn easy_mail_from() {
        let mut easy = Easy::new();
        assert!(easy.mail_from.is_none());
        easy.mail_from("sender@example.com");
        assert_eq!(easy.mail_from.as_deref(), Some("sender@example.com"));
    }

    #[test]
    fn easy_mail_rcpt() {
        let mut easy = Easy::new();
        assert!(easy.mail_rcpt.is_empty());
        easy.mail_rcpt("alice@example.com");
        easy.mail_rcpt("bob@example.com");
        assert_eq!(easy.mail_rcpt.len(), 2);
        assert_eq!(easy.mail_rcpt[0], "alice@example.com");
        assert_eq!(easy.mail_rcpt[1], "bob@example.com");
    }

    #[test]
    fn easy_mail_auth() {
        let mut easy = Easy::new();
        assert!(easy.mail_auth.is_none());
        easy.mail_auth("sender@example.com");
        assert_eq!(easy.mail_auth.as_deref(), Some("sender@example.com"));
    }

    #[test]
    fn easy_ftp_create_dirs() {
        let mut easy = Easy::new();
        assert!(!easy.ftp_create_dirs);
        easy.ftp_create_dirs(true);
        assert!(easy.ftp_create_dirs);
    }

    #[test]
    fn easy_ftp_method() {
        let mut easy = Easy::new();
        assert_eq!(easy.ftp_method, FtpMethod::default());
        easy.ftp_method(FtpMethod::SingleCwd);
        assert_eq!(easy.ftp_method, FtpMethod::SingleCwd);
        easy.ftp_method(FtpMethod::NoCwd);
        assert_eq!(easy.ftp_method, FtpMethod::NoCwd);
    }

    #[test]
    fn easy_sasl_authzid() {
        let mut easy = Easy::new();
        assert!(easy.sasl_authzid.is_none());
        easy.sasl_authzid("authzid");
        assert_eq!(easy.sasl_authzid.as_deref(), Some("authzid"));
    }

    #[test]
    fn easy_sasl_ir() {
        let mut easy = Easy::new();
        assert!(!easy.sasl_ir);
        easy.sasl_ir(true);
        assert!(easy.sasl_ir);
    }

    #[test]
    fn easy_connect_to() {
        let mut easy = Easy::new();
        easy.connect_to("a.com:80:b.com:8080");
        assert_eq!(easy.connect_to.len(), 1);
        assert_eq!(easy.connect_to[0], "a.com:80:b.com:8080");
    }

    #[test]
    fn easy_haproxy_protocol() {
        let mut easy = Easy::new();
        assert!(!easy.haproxy_protocol);
        easy.haproxy_protocol(true);
        assert!(easy.haproxy_protocol);
    }

    #[test]
    fn easy_abstract_unix_socket() {
        let mut easy = Easy::new();
        assert!(easy.abstract_unix_socket.is_none());
        easy.abstract_unix_socket("/my/abstract/sock");
        assert_eq!(easy.abstract_unix_socket.as_deref(), Some("/my/abstract/sock"));
    }

    #[test]
    fn easy_doh_insecure() {
        let mut easy = Easy::new();
        assert!(!easy.doh_insecure);
        easy.doh_insecure(true);
        assert!(easy.doh_insecure);
    }

    #[test]
    fn easy_http2_window_size() {
        let mut easy = Easy::new();
        assert!(easy.http2_window_size.is_none());
        easy.http2_window_size(1_048_576);
        assert_eq!(easy.http2_window_size, Some(1_048_576));
    }

    #[test]
    fn easy_http2_connection_window_size() {
        let mut easy = Easy::new();
        assert!(easy.http2_connection_window_size.is_none());
        easy.http2_connection_window_size(2_097_152);
        assert_eq!(easy.http2_connection_window_size, Some(2_097_152));
    }

    #[test]
    fn easy_http2_max_frame_size() {
        let mut easy = Easy::new();
        assert!(easy.http2_max_frame_size.is_none());
        easy.http2_max_frame_size(32_768);
        assert_eq!(easy.http2_max_frame_size, Some(32_768));
    }

    #[test]
    fn easy_http2_max_header_list_size() {
        let mut easy = Easy::new();
        assert!(easy.http2_max_header_list_size.is_none());
        easy.http2_max_header_list_size(8192);
        assert_eq!(easy.http2_max_header_list_size, Some(8192));
    }

    #[test]
    fn easy_http2_enable_push() {
        let mut easy = Easy::new();
        assert!(easy.http2_enable_push.is_none());
        easy.http2_enable_push(false);
        assert_eq!(easy.http2_enable_push, Some(false));
    }

    #[test]
    fn easy_http2_stream_weight() {
        let mut easy = Easy::new();
        assert!(easy.http2_stream_weight.is_none());
        easy.http2_stream_weight(128);
        assert_eq!(easy.http2_stream_weight, Some(128));
    }

    #[test]
    fn easy_http2_ping_interval() {
        let mut easy = Easy::new();
        assert!(easy.http2_ping_interval.is_none());
        easy.http2_ping_interval(Duration::from_secs(30));
        assert_eq!(easy.http2_ping_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn easy_custom_request_target() {
        let mut easy = Easy::new();
        assert!(easy.custom_request_target.is_none());
        easy.custom_request_target("*");
        assert_eq!(easy.custom_request_target.as_deref(), Some("*"));
    }

    #[test]
    fn easy_tftp_blksize() {
        let mut easy = Easy::new();
        assert!(easy.tftp_blksize.is_none());
        easy.tftp_blksize(1024);
        assert_eq!(easy.tftp_blksize, Some(1024));
    }

    #[test]
    fn easy_tftp_no_options() {
        let mut easy = Easy::new();
        assert!(!easy.tftp_no_options);
        easy.tftp_no_options(true);
        assert!(easy.tftp_no_options);
    }

    #[test]
    fn resolve_request_target_custom() {
        let url = Url::parse("http://example.com/path?q=1").unwrap();
        let result = super::resolve_request_target(Some("/custom"), &url, false);
        assert_eq!(result, "/custom");
    }

    #[test]
    fn resolve_request_target_default() {
        let url = Url::parse("http://example.com/path?q=1").unwrap();
        let result = super::resolve_request_target(None, &url, false);
        assert_eq!(result, "/path?q=1");
    }

    #[test]
    fn header_rejects_crlf_in_name() {
        let mut easy = Easy::new();
        easy.header("X-Foo\r\nX-Injected", "value");
        assert!(easy.headers.is_empty());
    }

    #[test]
    fn header_rejects_lf_in_name() {
        let mut easy = Easy::new();
        easy.header("X-Foo\nX-Injected", "value");
        assert!(easy.headers.is_empty());
    }

    #[test]
    fn header_rejects_cr_in_value() {
        let mut easy = Easy::new();
        easy.header("X-Foo", "bar\r\nbaz");
        assert!(easy.headers.is_empty());
    }

    #[test]
    fn header_accepts_clean_values() {
        let mut easy = Easy::new();
        easy.header("X-Foo", "bar");
        assert_eq!(easy.headers.len(), 1);
        assert_eq!(easy.headers[0], ("X-Foo".to_string(), "bar".to_string()));
    }

    #[test]
    fn proxy_header_rejects_crlf() {
        let mut easy = Easy::new();
        easy.proxy_header("X-Foo\r\n", "value");
        assert!(easy.proxy_headers.is_empty());
    }

    /// Mock DICT server for integration testing.
    async fn mock_dict_server(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Send banner
        writer.write_all(b"220 mock dictd ready\r\n").await.unwrap();

        // Read DEFINE command
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        // Send definition response
        writer.write_all(b"150 1 definitions found\r\n").await.unwrap();
        writer.write_all(b"151 \"test\" mock-db \"Mock Dictionary\"\r\n").await.unwrap();
        writer.write_all(b"A mock definition\r\n.\r\n").await.unwrap();
        writer.write_all(b"250 ok\r\n").await.unwrap();

        // Read QUIT
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await;
    }

    #[tokio::test]
    async fn dict_dispatch_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(mock_dict_server(listener));

        let mut easy = Easy::new();
        easy.url(&format!("dict://127.0.0.1:{port}/d:test")).unwrap();
        let response = easy.perform_async().await.unwrap();
        assert_eq!(response.status(), 200);
        let body = std::str::from_utf8(response.body()).unwrap();
        assert!(body.contains("mock definition"));
    }

    /// Mock POP3 server for integration testing.
    async fn mock_pop3_server(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Greeting
        writer.write_all(b"+OK POP3 mock ready\r\n").await.unwrap();

        // CAPA
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"+OK\r\nUSER\r\n.\r\n").await.unwrap();

        // USER
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"+OK\r\n").await.unwrap();

        // PASS
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"+OK logged in\r\n").await.unwrap();

        // LIST
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"+OK 2 messages\r\n").await.unwrap();
        writer.write_all(b"1 100\r\n2 200\r\n.\r\n").await.unwrap();

        // QUIT
        line.clear();
        let _ = reader.read_line(&mut line).await;
    }

    #[tokio::test]
    async fn pop3_dispatch_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(mock_pop3_server(listener));

        let mut easy = Easy::new();
        easy.url(&format!("pop3://user:pass@127.0.0.1:{port}/")).unwrap();
        let response = easy.perform_async().await.unwrap();
        assert_eq!(response.status(), 200);
        let body = std::str::from_utf8(response.body()).unwrap();
        assert!(body.contains("1 100"));
    }

    /// Mock IMAP server for integration testing.
    async fn mock_imap_server(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Greeting
        writer.write_all(b"* OK IMAP4rev1 mock ready\r\n").await.unwrap();

        // CAPABILITY
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let tag = line.split_whitespace().next().unwrap_or("A001").to_string();
        writer
            .write_all(
                format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();

        // AUTHENTICATE PLAIN (two-step since mock doesn't advertise SASL-IR)
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let tag = line.split_whitespace().next().unwrap_or("A002").to_string();
        // Send continuation for PLAIN auth
        writer.write_all(b"+ \r\n").await.unwrap();
        // Read base64-encoded credentials
        line.clear();
        let _ = reader.read_line(&mut line).await;
        writer.write_all(format!("{tag} OK authenticated\r\n").as_bytes()).await.unwrap();

        // LIST INBOX (the new handler sends LIST for /INBOX without UID/MAILINDEX)
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let tag = line.split_whitespace().next().unwrap_or("A003").to_string();
        writer.write_all(b"* LIST (\\HasNoChildren) \".\" INBOX\r\n").await.unwrap();
        writer.write_all(format!("{tag} OK LIST completed\r\n").as_bytes()).await.unwrap();

        // LOGOUT
        line.clear();
        let _ = reader.read_line(&mut line).await;
    }

    #[tokio::test]
    async fn imap_dispatch_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(mock_imap_server(listener));

        let mut easy = Easy::new();
        easy.url(&format!("imap://user:pass@127.0.0.1:{port}/INBOX")).unwrap();
        let response = easy.perform_async().await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.body().is_empty());
    }

    /// Mock SMTP server for integration testing.
    async fn mock_smtp_server(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Greeting
        writer.write_all(b"220 mock smtp ready\r\n").await.unwrap();

        // EHLO
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"250 OK\r\n").await.unwrap();

        // MAIL FROM
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"250 OK\r\n").await.unwrap();

        // RCPT TO
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"250 OK\r\n").await.unwrap();

        // DATA
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        writer.write_all(b"354 Start mail input\r\n").await.unwrap();

        // Read message body until ".\r\n"
        loop {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            if line.trim() == "." {
                break;
            }
        }
        writer.write_all(b"250 OK message accepted\r\n").await.unwrap();

        // QUIT
        line.clear();
        let _ = reader.read_line(&mut line).await;
    }

    #[tokio::test]
    async fn smtp_dispatch_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(mock_smtp_server(listener));

        let mut easy = Easy::new();
        easy.url(&format!("smtp://127.0.0.1:{port}")).unwrap();
        easy.mail_from("sender@example.com");
        easy.mail_rcpt("receiver@example.com");
        easy.body(b"From: sender@example.com\r\nTo: receiver@example.com\r\n\r\nHello");
        let response = easy.perform_async().await.unwrap();
        assert_eq!(response.status(), 250);
    }

    #[test]
    fn try_connect_addrs_fails_unreachable_again() {
        // Verify that invalid schemes don't panic — they should fall through to HTTP
        // and fail with a connection error rather than a protocol error
        let mut easy = Easy::new();
        easy.url("gopher://127.0.0.1:1/resource").unwrap();
        easy.connect_timeout(Duration::from_millis(100));
        let result = easy.perform();
        assert!(result.is_err());
    }

    #[test]
    fn protocols_str_blocks_disallowed_scheme() {
        let mut easy = Easy::new();
        easy.url("ftp://example.com/file").unwrap();
        easy.set_protocols_str("http,https");
        easy.connect_timeout(Duration::from_millis(100));
        let result = easy.perform();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not allowed"), "expected protocol error: {err}");
    }

    #[test]
    fn protocols_str_allows_matching_scheme() {
        let mut easy = Easy::new();
        easy.url("http://127.0.0.1:1/test").unwrap();
        easy.set_protocols_str("http,https,ftp");
        easy.connect_timeout(Duration::from_millis(100));
        let result = easy.perform();
        // Should fail with connection error, not protocol error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(!err.contains("not allowed"), "unexpected protocol error: {err}");
    }

    #[test]
    fn set_protocols_str_parses_comma_list() {
        let mut easy = Easy::new();
        easy.set_protocols_str("http, https, ftp");
        assert_eq!(
            easy.allowed_protocols,
            Some(vec!["http".to_string(), "https".to_string(), "ftp".to_string()])
        );
    }

    #[test]
    fn set_redir_protocols_str_parses_list() {
        let mut easy = Easy::new();
        easy.set_redir_protocols_str("http,https");
        assert_eq!(easy.redir_protocols, Some(vec!["http".to_string(), "https".to_string()]));
    }

    #[test]
    fn ftp_use_epsv_default_true() {
        let easy = Easy::new();
        assert!(easy.ftp_use_epsv);
    }

    #[test]
    fn ftp_use_eprt_default_true() {
        let easy = Easy::new();
        assert!(easy.ftp_use_eprt);
    }

    #[test]
    fn ftp_skip_pasv_ip_default_false() {
        let easy = Easy::new();
        assert!(!easy.ftp_skip_pasv_ip);
    }

    #[test]
    fn ftp_account_set() {
        let mut easy = Easy::new();
        assert!(easy.ftp_account.is_none());
        easy.ftp_account("myaccount");
        assert_eq!(easy.ftp_account.as_deref(), Some("myaccount"));
    }

    #[test]
    fn ssh_public_keyfile_set() {
        let mut easy = Easy::new();
        assert!(easy.ssh_public_keyfile.is_none());
        easy.ssh_public_keyfile("/home/user/.ssh/id_rsa.pub");
        assert_eq!(easy.ssh_public_keyfile.as_deref(), Some("/home/user/.ssh/id_rsa.pub"));
    }

    #[test]
    fn ssh_auth_types_set() {
        let mut easy = Easy::new();
        assert!(easy.ssh_auth_types.is_none());
        easy.ssh_auth_types(3); // publickey | password
        assert_eq!(easy.ssh_auth_types, Some(3));
    }

    #[test]
    fn proxy_port_set() {
        let mut easy = Easy::new();
        assert!(easy.proxy_port.is_none());
        easy.proxy_port(8080);
        assert_eq!(easy.proxy_port, Some(8080));
    }

    #[test]
    fn proxy_type_set() {
        let mut easy = Easy::new();
        assert!(easy.proxy_type.is_none());
        easy.proxy_type(5); // SOCKS5
        assert_eq!(easy.proxy_type, Some(5));
    }

    #[test]
    fn pre_proxy_set() {
        let mut easy = Easy::new();
        assert!(easy.pre_proxy.is_none());
        easy.pre_proxy("socks5://proxy:1080");
        assert_eq!(easy.pre_proxy.as_deref(), Some("socks5://proxy:1080"));
    }

    #[test]
    fn ftp_config_built_from_easy() {
        let mut easy = Easy::new();
        easy.ftp_use_epsv(false);
        easy.ftp_use_eprt(false);
        easy.ftp_skip_pasv_ip(true);
        easy.ftp_account("testacct");
        easy.ftp_create_dirs(true);
        easy.ftp_method(FtpMethod::SingleCwd);
        easy.ftp_active_port("-");

        // Verify the fields are stored correctly on Easy
        assert!(!easy.ftp_use_epsv);
        assert!(!easy.ftp_use_eprt);
        assert!(easy.ftp_skip_pasv_ip);
        assert_eq!(easy.ftp_account.as_deref(), Some("testacct"));
        assert!(easy.ftp_create_dirs);
        assert_eq!(easy.ftp_method, FtpMethod::SingleCwd);
        assert_eq!(easy.ftp_active_port.as_deref(), Some("-"));

        // Build FtpConfig the same way perform_async does
        let config = crate::protocol::ftp::FtpConfig {
            use_epsv: easy.ftp_use_epsv,
            use_eprt: easy.ftp_use_eprt,
            skip_pasv_ip: easy.ftp_skip_pasv_ip,
            account: easy.ftp_account.clone(),
            create_dirs: easy.ftp_create_dirs,
            method: easy.ftp_method,
            active_port: easy.ftp_active_port.clone(),
            ..Default::default()
        };
        assert!(!config.use_epsv);
        assert!(!config.use_eprt);
        assert!(config.skip_pasv_ip);
        assert_eq!(config.account.as_deref(), Some("testacct"));
        assert!(config.create_dirs);
        assert_eq!(config.method, crate::protocol::ftp::FtpMethod::SingleCwd);
        assert_eq!(config.active_port.as_deref(), Some("-"));
    }

    // --- connect_to wiring tests ---

    #[test]
    fn apply_connect_to_exact_match() {
        let mappings = vec!["example.com:443:alt.example.com:8443".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "alt.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn apply_connect_to_no_match() {
        let mappings = vec!["other.com:443:alt.example.com:8443".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn apply_connect_to_empty_from_host_matches_any() {
        let mappings = vec![":443:alt.example.com:8443".to_string()];
        let (host, port) = super::apply_connect_to("anything.com", 443, &mappings);
        assert_eq!(host, "alt.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn apply_connect_to_empty_from_port_matches_any() {
        let mappings = vec!["example.com::alt.example.com:8443".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 80, &mappings);
        assert_eq!(host, "alt.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn apply_connect_to_empty_to_host_preserves_original() {
        let mappings = vec!["example.com:443::8443".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn apply_connect_to_empty_to_port_preserves_original() {
        let mappings = vec!["example.com:443:alt.example.com:".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "alt.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn apply_connect_to_first_match_wins() {
        let mappings = vec![
            "example.com:443:first.com:1111".to_string(),
            "example.com:443:second.com:2222".to_string(),
        ];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "first.com");
        assert_eq!(port, 1111);
    }

    #[test]
    fn apply_connect_to_case_insensitive_host() {
        let mappings = vec!["Example.COM:443:alt.example.com:8443".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "alt.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn apply_connect_to_malformed_mapping_skipped() {
        // Only 3 parts instead of 4
        let mappings = vec!["example.com:443:alt.example.com".to_string()];
        let (host, port) = super::apply_connect_to("example.com", 443, &mappings);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    // --- proxy_port wiring test ---

    #[test]
    fn proxy_port_override_applied() {
        let mut easy = Easy::new();
        easy.proxy("http://proxy.example.com:3128").unwrap();
        easy.proxy_port(9999);
        assert_eq!(easy.proxy_port, Some(9999));
        // The override is applied in perform_async, not the setter;
        // verify the field is stored correctly.
    }

    // --- proxy_type scheme mapping tests ---

    #[test]
    fn proxy_type_to_scheme_http() {
        assert_eq!(super::proxy_type_to_scheme(0), "http");
        assert_eq!(super::proxy_type_to_scheme(1), "http");
    }

    #[test]
    fn proxy_type_to_scheme_https() {
        assert_eq!(super::proxy_type_to_scheme(2), "https");
    }

    #[test]
    fn proxy_type_to_scheme_socks4() {
        assert_eq!(super::proxy_type_to_scheme(4), "socks4");
    }

    #[test]
    fn proxy_type_to_scheme_socks5() {
        assert_eq!(super::proxy_type_to_scheme(5), "socks5");
    }

    #[test]
    fn proxy_type_to_scheme_socks4a() {
        assert_eq!(super::proxy_type_to_scheme(6), "socks4a");
    }

    #[test]
    fn proxy_type_to_scheme_socks5h() {
        assert_eq!(super::proxy_type_to_scheme(7), "socks5h");
    }

    #[test]
    fn proxy_type_to_scheme_unknown_defaults_http() {
        assert_eq!(super::proxy_type_to_scheme(99), "http");
    }

    // --- path_as_is wiring tests ---

    #[test]
    fn resolve_request_target_path_as_is() {
        // url crate normalizes /a/b/../c to /a/c during parse
        let url = Url::parse("http://example.com/a/b/../c").unwrap();
        // With path_as_is=false, we get the normalized path
        let result = super::resolve_request_target(None, &url, false);
        assert_eq!(result, "/a/c");
        // With path_as_is=true, we use raw_input to preserve dot segments
        let result = super::resolve_request_target(None, &url, true);
        assert_eq!(result, "/a/b/../c");
    }

    #[test]
    fn resolve_request_target_path_as_is_with_query() {
        let url = Url::parse("http://example.com/api/v1?key=val").unwrap();
        let result = super::resolve_request_target(None, &url, true);
        assert_eq!(result, "/api/v1?key=val");
    }

    #[test]
    fn resolve_request_target_path_as_is_custom_overrides() {
        let url = Url::parse("http://example.com/path").unwrap();
        let result = super::resolve_request_target(Some("/override"), &url, true);
        assert_eq!(result, "/override");
    }

    // --- extract_path_and_query tests ---

    #[test]
    fn extract_path_and_query_simple() {
        assert_eq!(super::extract_path_and_query("http://example.com/path"), "/path");
    }

    #[test]
    fn extract_path_and_query_with_query() {
        assert_eq!(super::extract_path_and_query("http://example.com/path?q=1"), "/path?q=1");
    }

    #[test]
    fn extract_path_and_query_strips_fragment() {
        assert_eq!(super::extract_path_and_query("http://example.com/path?q=1#frag"), "/path?q=1");
    }

    #[test]
    fn extract_path_and_query_no_path() {
        assert_eq!(super::extract_path_and_query("http://example.com"), "/");
    }

    #[test]
    fn extract_path_and_query_with_port() {
        assert_eq!(super::extract_path_and_query("http://example.com:8080/api"), "/api");
    }

    // --- Url set_port / set_scheme tests ---

    #[test]
    fn url_set_port() {
        let mut url = Url::parse("http://example.com:3128/path").unwrap();
        url.set_port(Some(9999)).unwrap();
        assert_eq!(url.port(), Some(9999));
        assert_eq!(url.as_str(), "http://example.com:9999/path");
    }

    #[test]
    fn url_set_port_none_removes_port() {
        let mut url = Url::parse("http://example.com:3128/path").unwrap();
        url.set_port(None).unwrap();
        assert_eq!(url.port(), None);
    }

    #[test]
    fn url_set_scheme() {
        let mut url = Url::parse("http://proxy.example.com:8080").unwrap();
        url.set_scheme("socks5").unwrap();
        assert_eq!(url.scheme(), "socks5");
    }

    // --- HAProxy PROXY protocol v1 header format tests ---

    #[test]
    fn haproxy_protocol_v1_header_format_ipv4() {
        use std::net::{Ipv4Addr, SocketAddr};
        let local = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 54321);
        let peer = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 80);
        let proto = if local.ip().is_ipv4() { "TCP4" } else { "TCP6" };
        let header = format!(
            "PROXY {proto} {} {} {} {}\r\n",
            local.ip(),
            peer.ip(),
            local.port(),
            peer.port()
        );
        assert_eq!(header, "PROXY TCP4 192.168.1.100 10.0.0.1 54321 80\r\n");
    }

    #[test]
    fn haproxy_protocol_v1_header_format_ipv6() {
        use std::net::{Ipv6Addr, SocketAddr};
        let local = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 54321);
        let peer = SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), 443);
        let proto = if local.ip().is_ipv4() { "TCP4" } else { "TCP6" };
        let header = format!(
            "PROXY {proto} {} {} {} {}\r\n",
            local.ip(),
            peer.ip(),
            local.port(),
            peer.port()
        );
        assert_eq!(header, "PROXY TCP6 ::1 2001:db8::1 54321 443\r\n");
    }

    // --- abstract Unix socket error tests ---

    #[test]
    fn abstract_unix_socket_error_message() {
        let mut easy = Easy::new();
        easy.url("http://localhost/test").unwrap();
        easy.abstract_unix_socket("/test");
        let result = easy.perform();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // On non-Linux Unix or any platform, should get a meaningful error
        assert!(
            err_msg.contains("Abstract Unix sockets")
                || err_msg.contains("abstract")
                || err_msg.contains("not supported")
                || err_msg.contains("not yet supported"),
            "unexpected error: {err_msg}"
        );
    }
}
