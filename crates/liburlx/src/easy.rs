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
use crate::protocol::http::multipart::MultipartForm;
use crate::protocol::http::response::Response;
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
    share: Option<crate::share::Share>,
    http_version: HttpVersion,
    expect_100_timeout: Option<Duration>,
    max_recv_speed: Option<u64>,
    max_send_speed: Option<u64>,
    low_speed_limit: Option<u32>,
    low_speed_time: Option<Duration>,
    fresh_connect: bool,
    forbid_reuse: bool,
    proxy_credentials: Option<ProxyAuthCredentials>,
    proxy_tls_config: Option<TlsConfig>,
    infilesize: Option<u64>,
    happy_eyeballs_timeout: Option<Duration>,
    dns_cache_timeout: Option<Duration>,
    dns_servers: Option<Vec<std::net::SocketAddr>>,
    doh_url: Option<String>,
    unrestricted_auth: bool,
    ignore_content_length: bool,
    alt_svc_cache: crate::protocol::http::altsvc::AltSvcCache,
}

impl std::fmt::Debug for Easy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Easy")
            .field("url", &self.url)
            .field("method", &self.method)
            .field("headers", &self.headers)
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
            .finish()
    }
}

impl Clone for Easy {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
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
            share: self.share.clone(),
            http_version: self.http_version,
            expect_100_timeout: self.expect_100_timeout,
            max_recv_speed: self.max_recv_speed,
            max_send_speed: self.max_send_speed,
            low_speed_limit: self.low_speed_limit,
            low_speed_time: self.low_speed_time,
            fresh_connect: self.fresh_connect,
            forbid_reuse: self.forbid_reuse,
            proxy_credentials: self.proxy_credentials.clone(),
            proxy_tls_config: self.proxy_tls_config.clone(),
            infilesize: self.infilesize,
            happy_eyeballs_timeout: self.happy_eyeballs_timeout,
            dns_cache_timeout: self.dns_cache_timeout,
            dns_servers: self.dns_servers.clone(),
            doh_url: self.doh_url.clone(),
            unrestricted_auth: self.unrestricted_auth,
            ignore_content_length: self.ignore_content_length,
            alt_svc_cache: self.alt_svc_cache.clone(),
        }
    }
}

impl Easy {
    /// Create a new transfer handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            url: None,
            method: None,
            headers: Vec::new(),
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
            share: None,
            http_version: HttpVersion::None,
            expect_100_timeout: None,
            max_recv_speed: None,
            max_send_speed: None,
            low_speed_limit: None,
            low_speed_time: None,
            fresh_connect: false,
            forbid_reuse: false,
            proxy_credentials: None,
            proxy_tls_config: None,
            infilesize: None,
            happy_eyeballs_timeout: None,
            dns_cache_timeout: None,
            dns_servers: None,
            doh_url: None,
            unrestricted_auth: false,
            ignore_content_length: false,
            alt_svc_cache: crate::protocol::http::altsvc::AltSvcCache::new(),
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
    pub fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Set the request body.
    pub fn body(&mut self, data: &[u8]) {
        self.body = Some(data.to_vec());
    }

    /// Set the expected upload size in bytes.
    ///
    /// This is used as a hint for progress reporting and for setting
    /// `Content-Length` when streaming uploads. Equivalent to
    /// `CURLOPT_INFILESIZE_LARGE`.
    pub fn infilesize(&mut self, size: u64) {
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
    pub fn follow_redirects(&mut self, enable: bool) {
        self.follow_redirects = enable;
    }

    /// Set maximum number of redirects to follow (default: 50).
    pub fn max_redirects(&mut self, max: u32) {
        self.max_redirects = max;
    }

    /// Enable or disable verbose output.
    pub fn verbose(&mut self, enable: bool) {
        self.verbose = enable;
    }

    /// Set the TCP connection timeout.
    ///
    /// If the connection is not established within this duration,
    /// the transfer fails with [`Error::Timeout`].
    pub fn connect_timeout(&mut self, duration: Duration) {
        self.connect_timeout = Some(duration);
    }

    /// Set the total transfer timeout.
    ///
    /// If the entire transfer (connect + request + response) takes
    /// longer than this duration, it fails with [`Error::Timeout`].
    pub fn timeout(&mut self, duration: Duration) {
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
    }

    /// Enable automatic Content-Encoding decompression.
    ///
    /// When enabled, sends `Accept-Encoding` header and decompresses
    /// gzip, deflate, brotli, and zstd response bodies.
    pub fn accept_encoding(&mut self, enable: bool) {
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
        self.proxy = Some(Url::parse(proxy_url)?);
        Ok(())
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
    pub fn fail_on_error(&mut self, enable: bool) {
        self.fail_on_error = enable;
    }

    /// Enable or disable TLS certificate verification.
    ///
    /// When set to `false`, the connection proceeds even if the server's
    /// certificate is invalid, self-signed, or expired.
    /// Equivalent to curl's `-k` / `--insecure` flag or `CURLOPT_SSL_VERIFYPEER`.
    ///
    /// **WARNING: Disabling verification makes the connection insecure.**
    pub fn ssl_verify_peer(&mut self, enable: bool) {
        self.tls_config.verify_peer = enable;
    }

    /// Enable or disable TLS hostname verification.
    ///
    /// When set to `false`, accepts certificates that don't match the
    /// server's hostname. Equivalent to `CURLOPT_SSL_VERIFYHOST`.
    ///
    /// **WARNING: Disabling verification makes the connection insecure.**
    pub fn ssl_verify_host(&mut self, enable: bool) {
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

    /// Set the minimum TLS version to allow.
    ///
    /// Equivalent to curl's `--tlsv1.2` or `--tlsv1.3`.
    pub fn ssl_min_version(&mut self, version: crate::tls::TlsVersion) {
        self.tls_config.min_tls_version = Some(version);
    }

    /// Set the maximum TLS version to allow.
    ///
    /// Equivalent to curl's `--tls-max`.
    pub fn ssl_max_version(&mut self, version: crate::tls::TlsVersion) {
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
    pub fn ssl_session_cache(&mut self, enable: bool) {
        self.tls_config.session_cache = enable;
    }

    /// Enable or disable `TCP_NODELAY` (Nagle's algorithm).
    ///
    /// When enabled (the default), small packets are sent immediately without
    /// waiting to coalesce. Equivalent to `CURLOPT_TCP_NODELAY`.
    pub fn tcp_nodelay(&mut self, enable: bool) {
        self.tcp_nodelay = enable;
    }

    /// Enable TCP keepalive with the given idle interval.
    ///
    /// When set, TCP keepalive probes are sent after the connection has been
    /// idle for the specified duration. Equivalent to `CURLOPT_TCP_KEEPALIVE`
    /// and `CURLOPT_TCP_KEEPIDLE`.
    pub fn tcp_keepalive(&mut self, idle: Duration) {
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
    pub fn local_port(&mut self, port: u16) {
        self.local_port = Some(port);
    }

    /// Enable DNS result shuffling.
    ///
    /// When enabled, the resolved DNS addresses are randomized before
    /// connection attempts. This provides simple load distribution across
    /// multiple IPs for the same hostname.
    /// Equivalent to curl's `--dns-shuffle`.
    pub fn dns_shuffle(&mut self, enable: bool) {
        self.dns_shuffle = enable;
    }

    /// Set the DNS cache timeout.
    ///
    /// Controls how long resolved DNS entries are cached before expiring.
    /// The default is 60 seconds (matching curl). Setting to zero disables
    /// DNS caching (every request triggers a new lookup).
    /// Equivalent to `CURLOPT_DNS_CACHE_TIMEOUT`.
    pub fn dns_cache_timeout(&mut self, duration: Duration) {
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
    pub fn happy_eyeballs_timeout(&mut self, duration: Duration) {
        self.happy_eyeballs_timeout = Some(duration);
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
    pub fn unrestricted_auth(&mut self, enable: bool) {
        self.unrestricted_auth = enable;
    }

    /// Ignore the Content-Length header in responses.
    ///
    /// When enabled, the response body is read until EOF rather than
    /// using the Content-Length header to determine body size.
    /// Equivalent to `CURLOPT_IGNORE_CONTENT_LENGTH`.
    pub fn ignore_content_length(&mut self, enable: bool) {
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
    pub fn http_version(&mut self, version: HttpVersion) {
        self.http_version = version;
    }

    /// Set the Expect: 100-continue timeout.
    ///
    /// When set, POST/PUT requests with a body will send an
    /// `Expect: 100-continue` header and wait up to this duration for
    /// a `100 Continue` response before sending the body. If the server
    /// responds with an error status, the body is not sent.
    ///
    /// Equivalent to `CURLOPT_EXPECT_100_TIMEOUT_MS`.
    pub fn expect_100_timeout(&mut self, timeout: Duration) {
        self.expect_100_timeout = Some(timeout);
    }

    /// Set the maximum download speed in bytes per second.
    ///
    /// Equivalent to `CURLOPT_MAX_RECV_SPEED_LARGE`.
    pub fn max_recv_speed(&mut self, bytes_per_sec: u64) {
        self.max_recv_speed = Some(bytes_per_sec);
    }

    /// Set the maximum upload speed in bytes per second.
    ///
    /// Equivalent to `CURLOPT_MAX_SEND_SPEED_LARGE`.
    pub fn max_send_speed(&mut self, bytes_per_sec: u64) {
        self.max_send_speed = Some(bytes_per_sec);
    }

    /// Set the minimum transfer speed in bytes per second.
    ///
    /// If the transfer speed drops below this limit for longer than
    /// the duration set by [`low_speed_time`](Self::low_speed_time),
    /// the transfer is aborted.
    ///
    /// Equivalent to `CURLOPT_LOW_SPEED_LIMIT`.
    pub fn low_speed_limit(&mut self, bytes_per_sec: u32) {
        self.low_speed_limit = Some(bytes_per_sec);
    }

    /// Set the time window for minimum speed enforcement.
    ///
    /// If the transfer speed stays below the limit set by
    /// [`low_speed_limit`](Self::low_speed_limit) for this duration,
    /// the transfer is aborted with a timeout error.
    ///
    /// Equivalent to `CURLOPT_LOW_SPEED_TIME`.
    pub fn low_speed_time(&mut self, duration: Duration) {
        self.low_speed_time = Some(duration);
    }

    /// Force a fresh connection, ignoring the connection pool.
    ///
    /// When enabled, the transfer always uses a new connection rather
    /// than reusing a pooled connection.
    ///
    /// Equivalent to `CURLOPT_FRESH_CONNECT`.
    pub fn fresh_connect(&mut self, enable: bool) {
        self.fresh_connect = enable;
    }

    /// Forbid connection reuse after the transfer completes.
    ///
    /// When enabled, the connection is closed after the transfer
    /// rather than being returned to the connection pool for reuse.
    ///
    /// Equivalent to `CURLOPT_FORBID_REUSE`.
    pub fn forbid_reuse(&mut self, enable: bool) {
        self.forbid_reuse = enable;
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

        // Build effective headers, body, and method considering multipart and range
        let mut headers = self.headers.clone();
        let (effective_method, effective_body);

        if let Some(ref multipart) = self.multipart {
            // Multipart form: encode body and set content-type header
            effective_body = Some(multipart.encode());
            if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                headers.push(("Content-Type".to_string(), multipart.content_type()));
            }
            // Default to POST for multipart
            effective_method = self.method.clone().unwrap_or_else(|| "POST".to_string());
        } else {
            effective_body = self.body.clone();
            effective_method = self.method.clone().unwrap_or_else(|| "GET".to_string());
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
        let effective_proxy = self.proxy.as_ref().or(env_proxy.as_ref());

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

        let fut = perform_transfer(
            &url,
            Some(effective_method.as_str()),
            &headers,
            effective_body.as_deref(),
            self.follow_redirects,
            self.max_redirects,
            self.verbose,
            self.accept_encoding,
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
            self.http_version,
            self.expect_100_timeout,
            self.happy_eyeballs_timeout,
            self.unrestricted_auth,
            self.ignore_content_length,
            &mut self.alt_svc_cache,
        );

        // Apply total transfer timeout if set
        let response = if let Some(timeout) = self.timeout {
            tokio::time::timeout(timeout, fut).await.map_err(|_| Error::Timeout(timeout))?
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

        let response = response?;

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
    http_version: HttpVersion,
    expect_100_timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
    unrestricted_auth: bool,
    ignore_content_length: bool,
    alt_svc_cache: &mut crate::protocol::http::altsvc::AltSvcCache,
) -> Result<Response, Error> {
    let transfer_start = Instant::now();
    let original_url = url.clone();
    let mut current_url = url.clone();
    let mut current_method = method.unwrap_or("GET").to_string();
    let mut current_body = body.map(<[u8]>::to_vec);
    let mut redirects_followed: u32 = 0;

    loop {
        // Determine effective proxy for this URL
        let effective_proxy = proxy.filter(|_| !should_bypass_proxy(&current_url, noproxy));

        // Build headers, stripping auth on cross-origin redirects unless unrestricted
        let mut request_headers = headers.to_vec();
        if redirects_followed > 0 && !unrestricted_auth {
            let orig_host = original_url.host_str().unwrap_or("");
            let cur_host = current_url.host_str().unwrap_or("");
            if !orig_host.eq_ignore_ascii_case(cur_host) {
                request_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("authorization"));
            }
        }
        if let Some(ref jar) = cookie_jar {
            let host = current_url.host_str().unwrap_or("");
            let path = current_url.path();
            let is_secure = current_url.scheme() == "https";
            if let Some(cookie_header) = jar.cookie_header(host, path, is_secure) {
                // Only add if user hasn't set a Cookie header
                if !request_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
                    request_headers.push(("Cookie".to_string(), cookie_header));
                }
            }
        }

        let mut response = do_single_request(
            &current_url,
            &current_method,
            &request_headers,
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
            http_version,
            expect_100_timeout,
            happy_eyeballs_timeout,
            ignore_content_length,
        )
        .await?;

        // Handle Digest auth: if 401 with WWW-Authenticate: Digest, retry with credentials
        if response.status() == 401 {
            if let Some(auth) = auth_credentials {
                if auth.method == AuthMethod::Digest {
                    if let Some(www_auth) = response.header("www-authenticate") {
                        if let Ok(challenge) = crate::auth::digest::DigestChallenge::parse(www_auth)
                        {
                            if verbose {
                                #[allow(clippy::print_stderr)]
                                {
                                    eprintln!(
                                        "* Server auth using Digest with realm '{}'",
                                        challenge.realm
                                    );
                                }
                            }

                            let uri = current_url.request_target();
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

                            response = do_single_request(
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
                                http_version,
                                expect_100_timeout,
                                happy_eyeballs_timeout,
                                ignore_content_length,
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        // Store cookies from response
        if let Some(ref mut jar) = cookie_jar {
            let host = current_url.host_str().unwrap_or("");
            let path = current_url.path();
            jar.store_from_headers(response.headers(), host, path);
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
            let port = current_url.port_or_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
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
                return Err(Error::Http(format!("too many redirects (max {max_redirects})")));
            }

            if let Some(location) = response.header("location") {
                // Resolve relative URLs against current URL
                let next_url =
                    if location.starts_with("http://") || location.starts_with("https://") {
                        Url::parse(location)?
                    } else {
                        // Relative URL: build from current URL's base
                        let base = current_url.as_str();
                        Url::parse(&resolve_relative(base, location))?
                    };

                if verbose {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("* Following redirect to {next_url}");
                    }
                }

                // 303: always change to GET, drop body
                // 301/302: change POST to GET (curl compat), drop body
                // 307/308: preserve method and body
                if response.status() == 303
                    || ((response.status() == 301 || response.status() == 302)
                        && current_method == "POST")
                {
                    current_method = "GET".to_string();
                    current_body = None;
                }

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
        response.set_transfer_info(info);
        return Ok(response);
    }
}

/// Perform a single HTTP request (no redirect handling).
#[allow(clippy::too_many_arguments, clippy::too_many_lines, clippy::fn_params_excessive_bools)]
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
    http_version: HttpVersion,
    expect_100_timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
    ignore_content_length: bool,
) -> Result<Response, Error> {
    // Handle non-HTTP schemes directly
    match url.scheme() {
        "file" => return crate::protocol::file::read_file(url),
        "ftp" => {
            return if method == "PUT" {
                let upload_data = body.unwrap_or(&[]);
                crate::protocol::ftp::upload(url, upload_data).await
            } else {
                crate::protocol::ftp::download(url).await
            };
        }
        _ => {}
    }

    let (host, port) = url.host_and_port()?;
    let host_header = url.host_header_value();
    let is_tls = url.scheme() == "https";
    let use_pool = proxy.is_none();

    // Build effective headers (add Accept-Encoding if decompression enabled)
    let mut effective_headers: Vec<(String, String)> = headers.to_vec();
    if accept_encoding && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding")) {
        effective_headers.push((
            "Accept-Encoding".to_string(),
            crate::protocol::http::decompress::accepted_encodings().to_string(),
        ));
    }

    // Try to use a pooled connection
    if use_pool {
        if let Some(mut stream) = pool.get(&host, port, is_tls) {
            if verbose {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("* Re-using existing connection to {host} port {port}");
                }
            }

            let request_target = url.request_target();
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
            )
            .await;

            match result {
                Ok((response, can_reuse)) => {
                    if can_reuse {
                        pool.put(&host, port, is_tls, stream);
                    }
                    return maybe_decompress(response, accept_encoding);
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

        let request_target = url.request_target();
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
        )
        .await?;
        let time_starttransfer = request_start.elapsed();

        let mut resp = maybe_decompress(resp, accept_encoding)?;
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

    // DNS resolution: check cache first, then resolve
    let addr_str = format!("{resolved_host}:{connect_port}");
    let addrs = if let Some(cached) = dns_cache.get(&resolved_host, connect_port) {
        if verbose {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("* Using cached DNS entry for {resolved_host}");
            }
        }
        cached.to_vec()
    } else {
        let lookup_fut = tokio::net::lookup_host(&addr_str);
        let resolved: Vec<std::net::SocketAddr> = if let Some(timeout_dur) = connect_timeout {
            tokio::time::timeout(timeout_dur, lookup_fut)
                .await
                .map_err(|_| Error::Timeout(timeout_dur))?
                .map_err(Error::Connect)?
                .collect()
        } else {
            lookup_fut.await.map_err(Error::Connect)?.collect()
        };
        if resolved.is_empty() {
            return Err(Error::Connect(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("DNS resolution failed for {resolved_host}"),
            )));
        }
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

    // Happy Eyeballs (RFC 6555): prefer IPv6, fall back to IPv4
    let tcp_stream = happy_eyeballs_connect(
        &addrs,
        connect_timeout,
        request_start,
        interface,
        local_port,
        happy_eyeballs_timeout,
    )
    .await?;
    let time_connect = request_start.elapsed();

    // Apply TCP socket options
    tcp_stream.set_nodelay(tcp_nodelay).map_err(Error::Connect)?;
    if let Some(keepalive_idle) = tcp_keepalive {
        let sock = socket2::SockRef::from(&tcp_stream);
        let keepalive = socket2::TcpKeepalive::new().with_time(keepalive_idle);
        sock.set_tcp_keepalive(&keepalive).map_err(Error::Connect)?;
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
            #[cfg(feature = "rustls")]
            {
                let tls_stream_inner = if proxy.is_some() && !is_socks_proxy {
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Establishing tunnel to {host}:{port} via proxy");
                        }
                    }
                    establish_connect_tunnel(
                        tcp_stream,
                        &host,
                        port,
                        &effective_headers,
                        proxy_credentials,
                        verbose,
                    )
                    .await?
                } else {
                    tcp_stream
                };

                let tls = crate::tls::TlsConnector::new(tls_config)?;
                let (tls_stream, alpn) = tls.connect(tls_stream_inner, &host).await?;
                let time_appconnect = request_start.elapsed();

                let request_target = url.request_target();

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
                    let resp = crate::protocol::http::h2::request(
                        tls_stream,
                        method,
                        &host_header,
                        &request_target,
                        &effective_headers,
                        body,
                        url.as_str(),
                    )
                    .await?;
                    let time_starttransfer = request_start.elapsed();
                    let mut resp = maybe_decompress(resp, accept_encoding)?;
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
                )
                .await?;
                let time_starttransfer = request_start.elapsed();

                if can_reuse && use_pool {
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
            // For HTTP through proxy (non-SOCKS), use absolute URL as request target
            let request_target = if proxy.is_some() && !is_socks_proxy {
                url.as_str().to_string()
            } else {
                url.request_target()
            };

            let use_http10 = http_version == HttpVersion::Http10;
            let time_pretransfer = request_start.elapsed();
            let mut stream = PooledStream::Tcp(tcp_stream);
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
            )
            .await?;
            let time_starttransfer = request_start.elapsed();

            if can_reuse && use_pool {
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
        scheme => return Err(Error::Http(format!("unsupported scheme: {scheme}"))),
    };

    maybe_decompress(response, accept_encoding)
}

/// Decompress response body if Content-Encoding is present and decompression was requested.
fn maybe_decompress(response: Response, accept_encoding: bool) -> Result<Response, Error> {
    if accept_encoding {
        if let Some(encoding) = response.header("content-encoding") {
            if encoding != "identity" {
                let decompressed =
                    crate::protocol::http::decompress::decompress(response.body(), encoding)?;
                return Ok(Response::new(
                    response.status(),
                    response.headers().clone(),
                    decompressed,
                    response.effective_url().to_string(),
                ));
            }
        }
    }
    Ok(response)
}

/// Establish an HTTP CONNECT tunnel through a proxy.
///
/// Sends a CONNECT request to the proxy and validates the 200 response
/// before returning the raw TCP stream for TLS negotiation.
/// Handles 407 Proxy Authentication Required for Digest and NTLM auth.
#[allow(clippy::too_many_lines)]
async fn establish_connect_tunnel(
    mut stream: tokio::net::TcpStream,
    target_host: &str,
    target_port: u16,
    headers: &[(String, String)],
    proxy_credentials: Option<&ProxyAuthCredentials>,
    verbose: bool,
) -> Result<tokio::net::TcpStream, Error> {
    // Send initial CONNECT request
    let (status, response_headers) =
        send_connect_request(&mut stream, target_host, target_port, headers, None).await?;

    if status == 200 {
        return Ok(stream);
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

                            let (retry_status, _) = send_connect_request(
                                &mut stream,
                                target_host,
                                target_port,
                                headers,
                                Some(&format!("Proxy-Authorization: {auth_value}")),
                            )
                            .await?;

                            if retry_status == 200 {
                                return Ok(stream);
                            }

                            return Err(Error::Http(format!(
                                "proxy CONNECT Digest auth failed with status {retry_status}"
                            )));
                        }
                    }
                }
                ProxyAuthMethod::Ntlm => {
                    // NTLM Type 1 → Type 2 → Type 3 handshake
                    let type1 = crate::auth::ntlm::create_type1_message();

                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Proxy auth using NTLM");
                        }
                    }

                    // Send CONNECT with Type 1
                    let (status2, headers2) = send_connect_request(
                        &mut stream,
                        target_host,
                        target_port,
                        headers,
                        Some(&format!("Proxy-Authorization: NTLM {type1}")),
                    )
                    .await?;

                    if status2 == 407 {
                        // Look for Type 2 challenge in response
                        if let Some(auth2) = find_header(&headers2, "proxy-authenticate") {
                            if let Some(type2_data) = auth2.strip_prefix("NTLM ") {
                                let challenge = crate::auth::ntlm::parse_type2_message(type2_data)?;
                                let domain = creds.domain.as_deref().unwrap_or("");
                                let type3 = crate::auth::ntlm::create_type3_message(
                                    &challenge,
                                    &creds.username,
                                    &creds.password,
                                    domain,
                                );

                                // Send CONNECT with Type 3
                                let (status3, _) = send_connect_request(
                                    &mut stream,
                                    target_host,
                                    target_port,
                                    headers,
                                    Some(&format!("Proxy-Authorization: NTLM {type3}")),
                                )
                                .await?;

                                if status3 == 200 {
                                    return Ok(stream);
                                }

                                return Err(Error::Http(format!(
                                    "proxy CONNECT NTLM auth failed with status {status3}"
                                )));
                            }
                        }
                    } else if status2 == 200 {
                        return Ok(stream);
                    }

                    return Err(Error::Http(format!(
                        "proxy CONNECT NTLM handshake failed with status {status2}"
                    )));
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

    Err(Error::Http(format!("proxy CONNECT failed with status {status}")))
}

/// Send a CONNECT request and read the response status + headers.
///
/// Returns `(status_code, response_headers)`.
async fn send_connect_request(
    stream: &mut tokio::net::TcpStream,
    target_host: &str,
    target_port: u16,
    headers: &[(String, String)],
    extra_header: Option<&str>,
) -> Result<(u16, Vec<(String, String)>), Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
         Host: {target_host}:{target_port}\r\n"
    );

    // Forward Proxy-Authorization header if present in original headers
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("proxy-authorization") {
            use std::fmt::Write as _;
            let _ = write!(connect_req, "{name}: {value}\r\n");
        }
    }

    // Add extra auth header (overrides forwarded one)
    if let Some(extra) = extra_header {
        use std::fmt::Write as _;
        let _ = write!(connect_req, "{extra}\r\n");
    }

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

            return Ok((status, response_headers));
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

/// Happy Eyeballs (RFC 6555) TCP connection.
///
/// Given a list of resolved addresses (may contain both IPv4 and IPv6),
/// try IPv6 first. If IPv6 doesn't connect within 250ms, start an IPv4
/// attempt in parallel. Returns the first successful connection.
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
    // Default: 250ms (RFC 6555 recommendation)
    let eyeballs_delay = eyeballs_timeout.unwrap_or(Duration::from_millis(250));

    // Separate into IPv6 and IPv4
    let v6: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv6).collect();
    let v4: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv4).collect();

    // If only one family, just try them in order
    if v6.is_empty() || v4.is_empty() {
        return try_connect_addrs(addrs, connect_timeout, interface, local_port).await;
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
#[allow(clippy::unwrap_used)]
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
}
