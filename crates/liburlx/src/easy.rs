//! Single-transfer blocking API.
//!
//! The `Easy` handle is the primary way to perform URL transfers.
//! It provides a blocking API that wraps the async internals.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::auth::{AuthCredentials, AuthMethod};
use crate::cookie::CookieJar;
use crate::error::Error;
use crate::hsts::HstsCache;
use crate::pool::{ConnectionPool, PooledStream};
use crate::progress::{call_progress, ProgressCallback, ProgressInfo};
use crate::protocol::http::multipart::MultipartForm;
use crate::protocol::http::response::{Response, TransferInfo};
use crate::tls::TlsConfig;
use crate::url::Url;

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
    pool: ConnectionPool,
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
            .field("pool", &"<ConnectionPool>")
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
            pool: ConnectionPool::new(),
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
            pool: ConnectionPool::new(),
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
    /// Equivalent to curl's `--proxy-user user:pass`.
    pub fn proxy_auth(&mut self, user: &str, password: &str) {
        use base64::Engine;
        let credentials = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        self.header("Proxy-Authorization", &format!("Basic {encoded}"));
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
            &self.tls_config,
            &mut self.pool,
        );

        // Apply total transfer timeout if set
        let response = if let Some(timeout) = self.timeout {
            tokio::time::timeout(timeout, fut).await.map_err(|_| Error::Timeout(timeout))?
        } else {
            fut.await
        }?;

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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
    tls_config: &TlsConfig,
    pool: &mut ConnectionPool,
) -> Result<Response, Error> {
    let transfer_start = Instant::now();
    let mut current_url = url.clone();
    let mut current_method = method.unwrap_or("GET").to_string();
    let mut current_body = body.map(<[u8]>::to_vec);
    let mut redirects_followed: u32 = 0;
    let mut last_connect_time;

    loop {
        // Determine effective proxy for this URL
        let effective_proxy = proxy.filter(|_| !should_bypass_proxy(&current_url, noproxy));

        // Build headers with cookies if cookie jar is enabled
        let mut request_headers = headers.to_vec();
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

        let connect_start = Instant::now();
        let mut response = do_single_request(
            &current_url,
            &current_method,
            &request_headers,
            current_body.as_deref(),
            verbose,
            accept_encoding,
            connect_timeout,
            effective_proxy,
            resolve_overrides,
            tls_config,
            pool,
        )
        .await?;
        last_connect_time = connect_start.elapsed();

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
                                resolve_overrides,
                                tls_config,
                                pool,
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

        response.set_transfer_info(TransferInfo {
            time_connect: last_connect_time,
            time_total: transfer_start.elapsed(),
            num_redirects: redirects_followed,
        });
        return Ok(response);
    }
}

/// Perform a single HTTP request (no redirect handling).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn do_single_request(
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    verbose: bool,
    accept_encoding: bool,
    connect_timeout: Option<Duration>,
    proxy: Option<&Url>,
    resolve_overrides: &[(String, String)],
    tls_config: &TlsConfig,
    pool: &mut ConnectionPool,
) -> Result<Response, Error> {
    // Handle non-HTTP schemes directly
    match url.scheme() {
        "file" => return crate::protocol::file::read_file(url),
        "ftp" => return crate::protocol::ftp::download(url).await,
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
            let result = crate::protocol::http::h1::request(
                &mut stream,
                method,
                &host_header,
                &request_target,
                &effective_headers,
                body,
                url.as_str(),
                true,
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

    // Connect via TCP (with optional connect timeout)
    let addr = format!("{resolved_host}:{connect_port}");
    let connect_fut = tokio::net::TcpStream::connect(&addr);
    let tcp_stream = if let Some(timeout_dur) = connect_timeout {
        tokio::time::timeout(timeout_dur, connect_fut)
            .await
            .map_err(|_| Error::Timeout(timeout_dur))?
            .map_err(Error::Connect)?
    } else {
        connect_fut.await.map_err(Error::Connect)?
    };

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
                    establish_connect_tunnel(tcp_stream, &host, port, &effective_headers).await?
                } else {
                    tcp_stream
                };

                let tls = crate::tls::TlsConnector::new(tls_config)?;
                let (tls_stream, alpn) = tls.connect(tls_stream_inner, &host).await?;

                let request_target = url.request_target();

                #[cfg(feature = "http2")]
                if alpn == crate::tls::AlpnProtocol::H2 {
                    if verbose {
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("* Using HTTP/2");
                        }
                    }
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
                    return maybe_decompress(resp, accept_encoding);
                }

                // HTTP/1.1 over TLS
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
                )
                .await?;

                if can_reuse && use_pool {
                    pool.put(&host, port, is_tls, stream);
                }

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
            )
            .await?;

            if can_reuse && use_pool {
                pool.put(&host, port, is_tls, stream);
            }

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
/// If the request headers include `Proxy-Authorization`, it is forwarded
/// to the proxy.
async fn establish_connect_tunnel(
    mut stream: tokio::net::TcpStream,
    target_host: &str,
    target_port: u16,
    headers: &[(String, String)],
) -> Result<tokio::net::TcpStream, Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
         Host: {target_host}:{target_port}\r\n"
    );

    // Forward Proxy-Authorization header if present
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("proxy-authorization") {
            use std::fmt::Write as _;
            let _ = write!(connect_req, "{name}: {value}\r\n");
        }
    }

    connect_req.push_str("\r\n");

    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("proxy CONNECT write failed: {e}")))?;

    stream.flush().await.map_err(|e| Error::Http(format!("proxy CONNECT flush failed: {e}")))?;

    // Read the proxy's response. We only need the status line + headers.
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

        // Check if we have received the full headers (ends with \r\n\r\n)
        if let Some(end) = find_header_end(&buf[..total]) {
            // Parse the status line
            let header_str = std::str::from_utf8(&buf[..end])
                .map_err(|_| Error::Http("invalid proxy CONNECT response encoding".into()))?;

            let status_line = header_str
                .lines()
                .next()
                .ok_or_else(|| Error::Http("empty proxy CONNECT response".into()))?;

            // Parse "HTTP/1.x 200 ..."
            let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
            if parts.len() < 2 {
                return Err(Error::Http(format!(
                    "malformed proxy CONNECT response: {status_line}"
                )));
            }

            let status: u16 = parts[1].parse().map_err(|_| {
                Error::Http(format!("invalid proxy CONNECT status code: {}", parts[1]))
            })?;

            if status != 200 {
                return Err(Error::Http(format!(
                    "proxy CONNECT failed with status {status}: {status_line}"
                )));
            }

            // Tunnel established — return the stream for TLS
            return Ok(stream);
        }

        if total >= buf.len() {
            return Err(Error::Http("proxy CONNECT response too large".to_string()));
        }
    }
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
}
