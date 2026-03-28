//! CLI argument parsing and configuration.
//!
//! Contains the [`CliOptions`] struct, [`ParseResult`] enum, and the
//! [`parse_args`] function that converts command-line arguments into a
//! structured options object.

/// Result of parsing CLI arguments.
///
/// Distinguishes between successful option parsing, early-exit actions
/// (help/version), and errors.
pub enum ParseResult {
    /// Successfully parsed options — proceed with transfer.
    Options(Box<CliOptions>),
    /// `--help` / `-h` was requested — print usage and exit 0.
    Help,
    /// `--version` / `-V` was requested — print version and exit 0.
    Version,
    /// `--engine list` was requested — print available engines and exit 0.
    EngineList,
    /// Parse error — message already printed to stderr.
    /// Contains the curl-compatible exit code (default 1).
    Error(u8),
}

/// Parsed CLI options.
#[allow(clippy::struct_excessive_bools)]
pub struct CliOptions {
    pub(crate) easy: liburlx::Easy,
    pub(crate) urls: Vec<String>,
    pub(crate) output_file: Option<String>,
    /// All output files specified (each `-o` adds to this list).
    /// Each entry pairs with a URL by position.
    pub(crate) output_files: Vec<String>,
    /// Per-URL glob match values for `#1`, `#2` output template substitution.
    /// Each inner vec contains the glob group values for the corresponding URL.
    pub(crate) glob_values: Vec<Vec<String>>,
    pub(crate) write_out: Option<String>,
    pub(crate) show_progress: bool,
    pub(crate) silent: bool,
    pub(crate) show_error: bool,
    pub(crate) fail_on_error: bool,
    pub(crate) include_headers: bool,
    pub(crate) dump_header: Option<String>,
    pub(crate) use_digest: bool,
    pub(crate) use_aws_sigv4: bool,
    pub(crate) use_bearer: bool,
    pub(crate) user_credentials: Option<(String, String)>,
    pub(crate) retry_count: u32,
    pub(crate) retry_delay_secs: u64,
    pub(crate) retry_max_time_secs: u64,
    /// Number of retry attempts actually performed (for -w %{`num_retries`}).
    pub(crate) retry_attempts: u32,
    pub(crate) parallel: bool,
    pub(crate) parallel_max: usize,
    pub(crate) cookie_jar_file: Option<String>,
    pub(crate) limit_rate: Option<String>,
    pub(crate) speed_limit: Option<u32>,
    pub(crate) speed_time: Option<u64>,
    pub(crate) remote_name: bool,
    pub(crate) create_dirs: bool,
    pub(crate) proxy_digest: bool,
    pub(crate) proxy_ntlm: bool,
    pub(crate) proxy_negotiate: bool,
    pub(crate) proxy_anyauth: bool,
    pub(crate) proxy_user: Option<(String, String)>,
    pub(crate) suppress_connect_headers: bool,
    pub(crate) trace_file: Option<String>,
    pub(crate) trace_ascii_file: Option<String>,
    pub(crate) trace_time: bool,
    pub(crate) max_filesize: Option<u64>,
    pub(crate) no_keepalive: bool,
    pub(crate) proto: Option<String>,
    pub(crate) proto_redir: Option<String>,
    pub(crate) libcurl: Option<String>,
    pub(crate) netrc_file: Option<String>,
    pub(crate) netrc_optional: bool,
    pub(crate) post301: bool,
    pub(crate) post302: bool,
    pub(crate) post303: bool,
    pub(crate) remote_time: bool,
    pub(crate) stderr_file: Option<String>,
    pub(crate) remote_header_name: bool,
    /// Whether `-o` was explicitly specified (vs derived from `-O`).
    pub(crate) explicit_output: bool,
    pub(crate) url_queries: Vec<String>,
    pub(crate) rate: Option<String>,
    pub(crate) use_ntlm: bool,
    pub(crate) use_negotiate: bool,
    pub(crate) use_anyauth: bool,
    /// User-Agent string set via -A/--user-agent (for --libcurl output).
    pub(crate) user_agent_str: Option<String>,
    pub(crate) globoff: bool,
    pub(crate) alt_svc_file: Option<String>,
    pub(crate) ssl_session_file: Option<String>,
    pub(crate) etag_save_file: Option<String>,
    pub(crate) etag_compare_file: Option<String>,
    /// IPFS gateway URL from `--ipfs-gateway`.
    pub(crate) ipfs_gateway: Option<String>,
    pub(crate) proto_default: Option<String>,
    pub(crate) output_dir: Option<String>,
    pub(crate) remove_on_error: bool,
    /// `--no-clobber`: don't overwrite existing output files, append `.1`, `.2`, etc.
    pub(crate) no_clobber: bool,
    pub(crate) fail_with_body: bool,
    pub(crate) fail_early: bool,
    pub(crate) retry_all_errors: bool,
    pub(crate) no_progress_meter: bool,
    pub(crate) location_trusted: bool,
    /// Track --location/-L was seen (for duplicate warning with --follow)
    saw_location: bool,
    /// Track --follow was seen (for duplicate warning with --location)
    saw_follow: bool,
    pub(crate) time_cond: Option<String>,
    /// Parsed time condition timestamp (seconds since epoch) for body suppression.
    pub(crate) time_cond_ts: Option<i64>,
    /// Whether the time condition is negated (`-z -date` = If-Unmodified-Since).
    pub(crate) time_cond_negate: bool,
    /// `-G` / `--get`: convert POST data to GET query string.
    pub(crate) get_mode: bool,
    /// `-C -` auto-resume: determine offset from output file size.
    pub(crate) auto_resume: bool,
    /// Whether -C was used (triggers `CURLE_RANGE_ERROR` on non-206 response).
    pub(crate) resume_check: bool,
    /// Explicit resume offset from `-C <offset>` (not `-C -`).
    pub(crate) resume_offset: Option<u64>,
    /// Whether `-d` / `--data` was used (POST data).
    pub(crate) has_post_data: bool,
    /// Whether `-T` upload was used (PUT).
    pub(crate) is_upload: bool,
    /// Whether `-T -` (stdin upload) was used.
    pub(crate) is_stdin_upload: bool,
    /// Filename from `-T` for appending to URL path.
    pub(crate) upload_filename: Option<String>,
    /// File path from `-T` for deferred reading at transfer time.
    pub(crate) upload_file_path: Option<String>,
    /// Per-URL upload file paths. If a `-T` flag precedes each URL, the corresponding
    /// entry is `Some(path)`. If a URL has no preceding `-T`, it is `None`.
    /// This allows distinguishing `-T file URL1 -T file URL2` (both PUT) from
    /// `-T file URL1 URL2` (first PUT, second GET).
    pub(crate) per_url_upload_files: Vec<Option<String>>,
    /// Accumulated inline cookie values from `-b` (joined with "; " before sending).
    pub(crate) inline_cookies: Vec<String>,
    /// Whether `--next` was seen without a following URL (parse error if true at end).
    pub(crate) next_needs_url: bool,
    /// Whether `--next` was used at least once (for per-URL output file mapping).
    pub(crate) had_next: bool,
    /// Per-URL credentials from `-u` (indexed by URL position).
    /// Each entry records the `-u` credential active when the URL was added.
    pub(crate) per_url_credentials: Vec<Option<(String, String)>>,
    /// Original -X value preserving case (for non-HTTP protocol commands).
    pub(crate) custom_request_original: Option<String>,
    /// Per-URL original -X value (indexed by URL position, for --next groups).
    pub(crate) per_url_custom_request: Vec<Option<String>>,
    /// Variables set via `--variable` for `--expand-*` expansion.
    /// Values are stored as raw bytes to support binary data (null bytes etc.).
    pub(crate) variables: Vec<(String, Vec<u8>)>,
    /// `--skip-existing`: skip download if output file already exists.
    pub(crate) skip_existing: bool,
    /// `--json` was used — defer Content-Type/Accept headers until after arg parsing.
    pub(crate) json_mode: bool,
    /// Per-URL FTP method (indexed by URL position).
    /// Supports `--next` changing `--ftp-method` between URL groups (test 1096).
    pub(crate) per_url_ftp_methods: Vec<liburlx::protocol::ftp::FtpMethod>,
    /// Per-URL Easy handles for `--next` groups (indexed by URL position).
    /// Each entry records the Easy handle state for that URL's group.
    pub(crate) per_url_easy: Vec<Option<liburlx::Easy>>,
    /// Per-URL group ID (indexed by URL position).
    /// URLs in the same --next group share the same group ID.
    /// Used to detect group transitions in `run_multi` for connection reuse.
    pub(crate) per_url_group: Vec<usize>,
    /// Current group ID counter (incremented on --next).
    group_id: usize,
    /// Tracks which option to blame when etag + multiple URLs conflict.
    /// Set to "--url" when --url adds a URL while etag is set, or to
    /// "--etag-save"/etc. when etag is set after multiple URLs exist.
    etag_conflict_blame: Option<String>,
    /// URL index where the current --next group starts (for per-URL Easy handles).
    pub(crate) group_easy_start: usize,
}

/// Print version information to stdout.
///
/// Shows urlx's own branding. The `urlx-as-curl` wrapper script translates
/// this to curl-compatible format for the curl test suite.
pub fn print_version() {
    let version = env!("CARGO_PKG_VERSION");
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    // TLS backends
    let mut tls_backends = Vec::new();
    if cfg!(feature = "rustls") {
        tls_backends.push("rustls");
    }
    if cfg!(feature = "tls-srp") {
        tls_backends.push("OpenSSL");
    }
    let tls_str = tls_backends.join(" ");

    println!("urlx {version} ({arch}-{os}) liburlx/{version} {tls_str}");
    println!("Release-Date: {}", env!("URLX_RELEASE_DATE"));

    // Protocols — built from compiled features
    let mut protocols = vec!["dict", "file"];
    protocols.extend_from_slice(&["ftp", "ftps"]);
    protocols.extend_from_slice(&["gopher", "gophers"]);
    protocols.extend_from_slice(&["http", "https"]);
    protocols.extend_from_slice(&["imap", "imaps"]);
    protocols.extend_from_slice(&["ipfs", "ipns"]);
    protocols.extend_from_slice(&["ldap", "ldaps"]);
    protocols.push("mqtt");
    protocols.extend_from_slice(&["pop3", "pop3s"]);
    protocols.push("rtsp");
    if cfg!(feature = "ssh") {
        protocols.extend_from_slice(&["scp", "sftp"]);
    }
    if cfg!(feature = "smb") {
        protocols.extend_from_slice(&["smb", "smbs"]);
    }
    protocols.extend_from_slice(&["smtp", "smtps"]);
    protocols.push("tftp");
    protocols.extend_from_slice(&["ws", "wss"]);
    println!("Protocols: {}", protocols.join(" "));

    // Features — built from compiled features
    let mut features = Vec::new();
    features.push("alt-svc");
    features.push("AsynchDNS");
    if cfg!(feature = "decompression") {
        features.push("brotli");
    }
    features.push("cookies");
    features.push("Digest");
    features.push("HSTS");
    if cfg!(feature = "http2") {
        features.push("HTTP2");
    }
    if cfg!(feature = "http3") {
        features.push("HTTP3");
    }
    features.push("HTTPS-proxy");
    features.push("IDN");
    features.push("IPv6");
    features.push("Largefile");
    if cfg!(feature = "decompression") {
        features.push("libz");
    }
    features.push("NTLM");
    features.push("PSL");
    features.push("ssl-sessions");
    if cfg!(feature = "rustls") || cfg!(feature = "tls-srp") {
        features.push("SSL");
    }
    if cfg!(feature = "tls-srp") {
        features.push("TLS-SRP");
    }
    features.push("UnixSockets");
    if cfg!(feature = "decompression") {
        features.push("zstd");
    }
    println!("Features: {}", features.join(" "));
}

/// Print usage information to stderr.
#[allow(clippy::too_many_lines)]
pub fn print_usage() {
    eprintln!("urlx {} — a memory-safe curl replacement", env!("CARGO_PKG_VERSION"));
    eprintln!("Usage: urlx [options] <url>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -X, --request <method>    HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH)");
    eprintln!("  -H, --header <header>     Custom header (e.g., 'Content-Type: application/json')");
    eprintln!("  -d, --data <data>         Request body data (use @filename to read from file)");
    eprintln!("      --data-raw <data>     Request body data (@ is not interpreted)");
    eprintln!("  -L, --location            Follow redirects");
    eprintln!("      --max-redirs <num>    Maximum number of redirects (default: 50)");
    eprintln!("  -I, --head                Send HEAD request");
    eprintln!("  -o, --output <file>       Write output to file");
    eprintln!("  -O, --remote-name         Save as remote filename from URL");
    eprintln!("  -D, --dump-header <file>  Write response headers to file");
    eprintln!("  -i, --include             Include response headers in output");
    eprintln!("  -v, --verbose             Verbose output");
    eprintln!("  -s, --silent              Silent mode (no progress or errors)");
    eprintln!("  -S, --show-error          Show errors even in silent mode");
    eprintln!("  -f, --fail                Fail silently on HTTP errors (exit code 22)");
    eprintln!("      --compressed          Request compressed response and decompress");
    eprintln!("      --connect-timeout <s> Maximum time for connection in seconds");
    eprintln!("  -m, --max-time <s>        Maximum time for transfer in seconds");
    eprintln!("  -u, --user <user:pass>    HTTP Basic authentication");
    eprintln!("  -A, --user-agent <name>   Set User-Agent header");
    eprintln!("  -w, --write-out <fmt>     Output format after transfer");
    eprintln!("  -x, --proxy <url>         Use proxy (e.g., http://proxy:8080)");
    eprintln!("      --noproxy <list>      Comma-separated list of hosts to bypass proxy");
    eprintln!("  -F, --form <name=value>   Multipart form field (use @file for file upload)");
    eprintln!("  -r, --range <range>       Byte range (e.g., 0-499, 500-, -500)");
    eprintln!("  -C, --continue-at <off>   Resume download from byte offset");
    eprintln!("  -#, --progress-bar        Display transfer progress bar");
    eprintln!("  -k, --insecure            Allow insecure TLS connections");
    eprintln!("      --cacert <file>       CA certificate bundle (PEM format)");
    eprintln!("      --cert <file>         Client certificate (PEM format)");
    eprintln!("      --key <file>          Client private key (PEM/SSH format)");
    eprintln!("      --hostpubsha256 <hash>  SSH host key SHA-256 fingerprint (base64)");
    eprintln!("      --known-hosts <file>  SSH known_hosts file for host key verification");
    eprintln!("      --hostpubmd5 <hash>   SSH host key MD5 fingerprint (32 hex chars)");
    eprintln!("      --digest              Use HTTP Digest authentication");
    eprintln!("      --ntlm                Use HTTP NTLM authentication");
    eprintln!("      --proxy-user <u:p>    Proxy authentication (user:password)");
    eprintln!("      --proxy-digest        Use Digest auth with proxy");
    eprintln!("      --proxy-ntlm          Use NTLM auth with proxy");
    eprintln!("      --ciphers <list>      TLS cipher suite list");
    eprintln!("      --unix-socket <path>  Connect via Unix domain socket");
    eprintln!("      --interface <name>    Use network interface/address for outgoing connections");
    eprintln!("      --local-port <port>   Bind to local port for outgoing connections");
    eprintln!("      --dns-shuffle         Randomize DNS resolution order");
    eprintln!("      --unrestricted-auth   Keep auth on cross-origin redirects");
    eprintln!("      --ignore-content-length  Ignore Content-Length in responses");
    eprintln!("      --dns-servers <addrs> Use custom DNS servers (comma-separated IP:port)");
    eprintln!("      --doh-url <url>       DNS-over-HTTPS URL");
    eprintln!("      --happy-eyeballs-timeout-ms <ms>  Happy Eyeballs timeout (milliseconds)");
    eprintln!("  -T, --upload-file <file>  Upload file (PUT)");
    eprintln!("  -b, --cookie <data>       Send cookies (e.g., 'name=value; name2=value2')");
    eprintln!("  -e, --referer <url>       Set Referer header");
    eprintln!("  -G, --get                 Force GET even with --data (append to URL query)");
    eprintln!("      --create-dirs         Create output directories as needed");
    eprintln!("      --data-binary <data>  POST binary data (use @filename)");
    eprintln!("      --data-urlencode <d>  POST URL-encoded data");
    eprintln!("      --resolve <h:p:a>     Resolve host:port to address");
    eprintln!("      --http1.0             Use HTTP/1.0");
    eprintln!("      --http1.1             Use HTTP/1.1");
    eprintln!("      --http2               Request HTTP/2");
    eprintln!("      --http3               Request HTTP/3 (QUIC)");
    eprintln!("      --expect100-timeout <ms>  Expect: 100-continue timeout (milliseconds)");
    eprintln!("      --retry <num>         Retry on transient errors");
    eprintln!("      --retry-delay <s>     Wait between retries (seconds)");
    eprintln!("      --retry-max-time <s>  Maximum total retry time (seconds)");
    eprintln!("  -Z, --parallel            Perform transfers in parallel");
    eprintln!("      --parallel-max <n>    Maximum parallel transfers (default: 50)");
    eprintln!("      --socks5-hostname <h> SOCKS5 proxy (resolve via proxy)");
    eprintln!("      --tcp-nodelay         Use TCP_NODELAY");
    eprintln!("      --tcp-keepalive <s>   TCP keepalive idle time (seconds)");
    eprintln!("      --hsts                Enable HSTS (HTTP Strict Transport Security)");
    eprintln!("      --bearer <token>      Bearer token authentication");
    eprintln!("  -c, --cookie-jar <file>   Write cookies to file after transfer");
    eprintln!("      --limit-rate <speed>  Limit transfer speed (e.g., 100K, 1M)");
    eprintln!("      --speed-limit <bps>   Minimum transfer speed in bytes/sec");
    eprintln!("      --speed-time <s>      Time for speed-limit check (default: 30)");
    eprintln!("      --trace <file>        Write wire debug output to file");
    eprintln!("      --trace-ascii <file>  Write wire debug output to file (ASCII)");
    eprintln!("      --trace-time          Add timestamps to trace output");
    eprintln!("  -K, --config <file>       Read arguments from config file");
    eprintln!("      --libcurl <file>       Output equivalent C code using libcurl to file");
    eprintln!("      --proto <protocols>   Enable protocols (e.g., =http,https)");
    eprintln!("      --proto-redir <p>     Enable protocols for redirects");
    eprintln!("      --max-filesize <bytes> Maximum file size to download");
    eprintln!("      --no-keepalive        Disable TCP keepalive");
    eprintln!("      --netrc               Use ~/.netrc for credentials");
    eprintln!("      --netrc-file <file>    Use specified netrc file");
    eprintln!("      --netrc-optional       Use ~/.netrc if it exists");
    eprintln!("      --proxy-header <h>    Header to send only to proxy");
    eprintln!("      --post301             Preserve POST method on 301 redirect");
    eprintln!("      --post302             Preserve POST method on 302 redirect");
    eprintln!("      --post303             Preserve POST method on 303 redirect");
    eprintln!("  -R, --remote-time         Set local file time from server");
    eprintln!("      --next                Separate URL option groups");
    eprintln!("      --ftp-pasv            Use passive mode for FTP (default)");
    eprintln!("      --ftp-ssl             Try SSL/TLS for FTP (explicit, AUTH TLS)");
    eprintln!("      --ftp-ssl-reqd        Require SSL/TLS for FTP");
    eprintln!("      --ftp-port <addr>     Use active mode, bind to address ('-' for auto)");
    eprintln!("      --globoff             Disable URL globbing");
    eprintln!("      --path-as-is          Don't normalize . and .. in URL path");
    eprintln!("      --raw                 Disable HTTP content decoding");
    eprintln!("  -J, --remote-header-name  Use Content-Disposition filename with -O");
    eprintln!("      --styled-output       Enable styled output (no-op)");
    eprintln!("      --no-styled-output    Disable styled output (no-op)");
    eprintln!("      --url-query <params>  Append query parameters to URL");
    eprintln!("      --json <data>         JSON POST (sets Content-Type and Accept)");
    eprintln!("      --rate <rate>         Request rate for parallel transfers");
    eprintln!("      --ciphers <list>      TLS cipher suite list");
    eprintln!("      --negotiate           Use HTTP Negotiate (SPNEGO) authentication");
    eprintln!("      --delegation <level>  GSS-API delegation (none, policy, always)");
    eprintln!("      --sasl-authzid <id>   SASL authorization identity");
    eprintln!("      --sasl-ir             Send SASL initial response");
    eprintln!("      --mail-from <addr>    SMTP envelope sender (MAIL FROM)");
    eprintln!("      --mail-rcpt <addr>    SMTP envelope recipient (RCPT TO)");
    eprintln!("      --mail-auth <addr>    SMTP AUTH identity (MAIL AUTH)");
    eprintln!("      --ftp-create-dirs     Create remote directories during upload");
    eprintln!("      --ftp-method <method> FTP method (multicwd, singlecwd, nocwd)");
    eprintln!("      --connect-to <h:p:h:p> Connect to host:port instead of URL");
    eprintln!("      --alt-svc <file>      Alt-Svc cache file");
    eprintln!("      --etag-save <file>    Save ETag to file");
    eprintln!("      --etag-compare <file> Compare ETag from file (If-None-Match)");
    eprintln!("      --haproxy-protocol    Send HAProxy PROXY protocol v1 header");
    eprintln!("      --abstract-unix-socket <path> Connect via abstract Unix socket");
    eprintln!("      --proxy-cacert <file> CA cert for proxy TLS verification");
    eprintln!("      --proxy-cert <file>   Client cert for proxy TLS");
    eprintln!("      --proxy-key <file>    Private key for proxy TLS");
    eprintln!("      --doh-insecure        Don't verify DoH server TLS");
    eprintln!("      --compressed-ssh      Enable SSH compression (no-op)");
    eprintln!("      --proto-default <proto> Default protocol for schemeless URLs");
    eprintln!("      --form-string <n=v>   Literal form field (@ not interpreted as file)");
    eprintln!("      --request-target <t>  Custom request target (e.g., *)");
    eprintln!("      --socks4 <host:port>  SOCKS4 proxy");
    eprintln!("      --socks4a <host:port> SOCKS4a proxy (remote DNS)");
    eprintln!("      --socks5 <host:port>  SOCKS5 proxy (local DNS)");
    eprintln!("      --proxy-1.0 <url>     HTTP/1.0 proxy");
    eprintln!("      --tftp-blksize <n>    TFTP block size (8-65464)");
    eprintln!("      --tftp-no-options     Disable TFTP option negotiation");
    eprintln!("      --url <url>           Explicit URL (alternative to positional arg)");
    eprintln!("      --output-dir <dir>    Output directory for downloaded files");
    eprintln!("      --remove-on-error     Remove output file on error");
    eprintln!("      --proxy-insecure      Don't verify proxy TLS certificate");
    eprintln!("      --tlsv1               Use TLS 1.x");
    eprintln!("      --tlsv1.0             Use TLS 1.0 or later");
    eprintln!("      --tlsv1.1             Use TLS 1.1 or later");
    eprintln!("      --sslv3               Use SSLv3 (treated as TLS 1.2)");
    eprintln!("  -N, --no-buffer           Disable output buffering (no-op)");
    eprintln!("      --no-sessionid        Disable TLS session ID reuse (no-op)");
    eprintln!("      --no-alpn             Disable ALPN negotiation (no-op)");
    eprintln!("      --no-npn              Disable NPN negotiation (no-op)");
    eprintln!("      --cert-status         Request OCSP stapling (no-op)");
    eprintln!("      --false-start          Enable TLS false start (no-op)");
    eprintln!("      --disable-eprt        Disable EPRT for FTP (no-op)");
    eprintln!("      --disable-epsv        Disable EPSV for FTP (no-op)");
}

/// Parse command-line arguments into a [`ParseResult`].
///
/// Expands combined short flags (e.g. `-sSfL` → `-s -S -f -L`), checks for
/// `--help`/`-h` and `--version`/`-V` early-exit flags, then delegates to
/// the full option parser.
pub fn parse_args(args: &[String]) -> ParseResult {
    // Step 1: Expand combined short flags
    let expanded = expand_combined_flags(args);

    // Step 2: Check for --help/-h, --version/-V, and --engine list (early exit, like curl)
    for (idx, arg) in expanded.iter().enumerate().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => return ParseResult::Help,
            "-V" | "--version" => return ParseResult::Version,
            // --engine list: print available engines and exit (curl compat: test 307)
            "--engine" => {
                if expanded.get(idx + 1).map(String::as_str) == Some("list") {
                    return ParseResult::EngineList;
                }
            }
            _ => {}
        }
    }

    // Step 2b: Check if -K/--config or -q was explicitly given.
    // If not, auto-load .curlrc from standard locations (curl compat: tests 433, 436).
    let has_explicit_config = expanded
        .iter()
        .skip(1)
        .any(|a| a == "-K" || a == "--config" || a == "-q" || a == "--disable");
    let mut final_args = expanded;
    if !has_explicit_config {
        if let Some(rc_path) = find_curlrc() {
            if let Ok(contents) = std::fs::read_to_string(&rc_path) {
                let config_args = parse_config_file(&contents);
                if !config_args.is_empty() {
                    // Emit note about reading config file (curl compat: tests 433, 436)
                    eprintln!("Note: Read config file from '{rc_path}'");
                    // Insert config args after program name, before user args
                    let mut with_rc = vec![final_args[0].clone()];
                    with_rc.extend(config_args);
                    with_rc.extend_from_slice(&final_args[1..]);
                    final_args = with_rc;
                }
            }
        }
    }

    // Step 3: Parse options
    match parse_args_options_with_depth(&final_args, 0) {
        Ok(opts) => ParseResult::Options(Box::new(opts)),
        Err(code) => ParseResult::Error(code),
    }
}

/// Find the .curlrc configuration file in standard locations.
///
/// Search order (curl compat: tests 433, 436):
/// 1. `$CURL_HOME/.curlrc`
/// 2. `$XDG_CONFIG_HOME/curlrc` (note: NOT `.curlrc`, just `curlrc`)
/// 3. `$HOME/.curlrc`
fn find_curlrc() -> Option<String> {
    // Check $CURL_HOME/.curlrc then $CURL_HOME/.config/curlrc
    if let Ok(curl_home) = std::env::var("CURL_HOME") {
        if !curl_home.is_empty() {
            let path = format!("{curl_home}/.curlrc");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
            let path = format!("{curl_home}/.config/curlrc");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    // Check $XDG_CONFIG_HOME/curlrc (NOT .curlrc)
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            let path = format!("{xdg}/curlrc");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    // Check $HOME/.curlrc
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let path = format!("{home}/.curlrc");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    None
}

/// Expand combined short flags into individual flags.
///
/// For example, `-sSfL` becomes `-s`, `-S`, `-f`, `-L`.
/// If the last character in a combined group is a flag that takes an argument,
/// the next argument is consumed as that flag's value (e.g., `-Lo output.txt`
/// becomes `-L`, `-o`, `output.txt`).
///
/// Long flags (`--foo`) and single-character flags (`-s`) pass through unchanged.
fn expand_combined_flags(args: &[String]) -> Vec<String> {
    // Set of short flags that take an argument (next arg is the value)
    const ARG_FLAGS: &[char] = &[
        'X', 'H', 'd', 'o', 'D', 'w', 'x', 'u', 'A', 'F', 'r', 'C', 'T', 'b', 'e', 'm', 'K', 'c',
        'z', 'U', 'Q', 'P', 'E', 'Y', 'y',
    ];

    let mut result = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            // This arg is the value for a preceding flag — don't expand
            result.push(arg.clone());
            skip_next = false;
            continue;
        }
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && arg.as_bytes()[1] != b'#'
        {
            // This is a combined short flag like -sSfL or -Lo
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                result.push(format!("-{ch}"));
                if ARG_FLAGS.contains(&ch) {
                    if j + 1 < chars.len() {
                        // Remaining chars are the argument value (e.g., -ofile → -o, file)
                        let rest: String = chars[j + 1..].iter().collect();
                        result.push(rest);
                    } else {
                        // Flag is the last char — next arg is the value, skip expansion
                        skip_next = true;
                    }
                    break;
                }
            }
        } else if arg.starts_with("--") && arg.contains('=') {
            // Split --long=value into --long value (curl compat)
            if let Some((flag, value)) = arg.split_once('=') {
                result.push(flag.to_string());
                result.push(value.to_string());
            } else {
                result.push(arg.clone());
            }
        } else {
            result.push(arg.clone());
            // For single-char short flags or long flags that take args,
            // mark the next arg to skip expansion.
            if arg.len() == 2 && arg.starts_with('-') && !arg.starts_with("--") {
                let ch = arg.as_bytes()[1] as char;
                if ARG_FLAGS.contains(&ch) {
                    skip_next = true;
                }
            } else if arg.starts_with("--") {
                // Long flags that take an argument — skip expansion of next arg.
                // This prevents values like "-http" from being expanded as short flags.
                if matches!(
                    arg.as_str(),
                    "--proto-redir"
                        | "--proto"
                        | "--request"
                        | "--header"
                        | "--data"
                        | "--data-raw"
                        | "--data-binary"
                        | "--data-urlencode"
                        | "--output"
                        | "--dump-header"
                        | "--write-out"
                        | "--proxy"
                        | "--user"
                        | "--user-agent"
                        | "--cookie"
                        | "--cookie-jar"
                        | "--referer"
                        | "--form"
                        | "--upload-file"
                        | "--range"
                        | "--continue-at"
                        | "--max-time"
                        | "--connect-timeout"
                        | "--max-redirs"
                        | "--resolve"
                        | "--connect-to"
                        | "--interface"
                        | "--abstract-unix-socket"
                        | "--unix-socket"
                        | "--doh-url"
                        | "--cert"
                        | "--key"
                        | "--cacert"
                        | "--capath"
                        | "--trace"
                        | "--trace-ascii"
                        | "--config"
                        | "--proxy-user"
                        | "--proxy-header"
                        | "--max-filesize"
                        | "--netrc-file"
                        | "--etag-compare"
                        | "--etag-save"
                        | "--limit-rate"
                        | "--speed-limit"
                        | "--speed-time"
                        | "--local-port"
                        | "--ciphers"
                        | "--engine"
                        | "--tls13-ciphers"
                        | "--proxy-cert"
                        | "--proxy-key"
                        | "--proxy-cacert"
                        | "--proxy-capath"
                        | "--proxy-ciphers"
                        | "--variable"
                        | "--expand-data"
                        | "--expand-url"
                        | "--expand-output"
                        | "--json"
                        | "--mail-from"
                        | "--mail-rcpt"
                        | "--mail-auth"
                        | "--sasl-authzid"
                        | "--service-name"
                        | "--oauth2-bearer"
                        | "--hostpubsha256"
                        | "--pubkey"
                        | "--noproxy"
                        | "--preproxy"
                        | "--proxy1.0"
                        | "--socks4"
                        | "--socks4a"
                        | "--socks5"
                        | "--socks5-hostname"
                        | "--delegation"
                        | "--aws-sigv4"
                        | "--time-cond"
                        | "--url"
                        | "--alt-svc"
                        | "--hsts"
                        | "--ftp-method"
                        | "--ftp-account"
                        | "--ftp-port"
                        | "--quote"
                        | "--ftp-alternative-to-user"
                        | "--ssl-sessions"
                        | "--ftp-ssl-ccc-mode"
                        | "--tftp-blksize"
                        | "--http2-ping-interval"
                        | "--libcurl"
                        | "--ipfs-gateway"
                        | "--tlsauthtype"
                        | "--tlsuser"
                        | "--tlspassword"
                ) {
                    skip_next = true;
                }
            }
        }
    }
    result
}

/// Maximum recursion depth for config files (`-K`/`--config`).
/// Matches curl's `CURL_MAX_INPUT_LENGTH` recursion limit of 16.
const MAX_CONFIG_DEPTH: u32 = 16;

/// Internal option parser with config file recursion depth tracking.
/// Returns `Err(exit_code)` if parsing fails (error already printed).
#[allow(clippy::too_many_lines)]
fn parse_args_options_with_depth(args: &[String], config_depth: u32) -> Result<CliOptions, u8> {
    let mut opts = CliOptions {
        easy: liburlx::Easy::new(),
        urls: Vec::new(),
        output_file: None,
        output_files: Vec::new(),
        glob_values: Vec::new(),
        write_out: None,
        show_progress: false,
        silent: false,
        show_error: false,
        fail_on_error: false,
        include_headers: false,
        dump_header: None,
        use_digest: false,
        use_aws_sigv4: false,
        use_bearer: false,
        user_credentials: None,
        retry_count: 0,
        retry_delay_secs: 0,
        retry_attempts: 0,
        retry_max_time_secs: 0,
        parallel: false,
        parallel_max: 50,
        cookie_jar_file: None,
        limit_rate: None,
        speed_limit: None,
        speed_time: None,
        remote_name: false,
        create_dirs: false,
        proxy_digest: false,
        proxy_ntlm: false,
        proxy_negotiate: false,
        proxy_anyauth: false,
        proxy_user: None,
        suppress_connect_headers: false,
        trace_file: None,
        trace_ascii_file: None,
        trace_time: false,
        max_filesize: None,
        no_keepalive: false,
        proto: None,
        proto_redir: None,
        libcurl: None,
        netrc_file: None,
        netrc_optional: false,
        post301: false,
        post302: false,
        post303: false,
        remote_time: false,
        stderr_file: None,
        remote_header_name: false,
        explicit_output: false,
        url_queries: Vec::new(),
        rate: None,
        use_ntlm: false,
        use_negotiate: false,
        use_anyauth: false,
        user_agent_str: None,
        globoff: false,
        alt_svc_file: None,
        ssl_session_file: None,
        etag_save_file: None,
        etag_compare_file: None,
        ipfs_gateway: None,
        proto_default: None,
        output_dir: None,
        remove_on_error: false,
        no_clobber: false,
        fail_with_body: false,
        fail_early: false,
        retry_all_errors: false,
        no_progress_meter: false,
        location_trusted: false,
        saw_location: false,
        saw_follow: false,
        time_cond: None,
        time_cond_ts: None,
        time_cond_negate: false,
        get_mode: false,
        auto_resume: false,
        resume_check: false,
        resume_offset: None,
        has_post_data: false,
        is_upload: false,
        is_stdin_upload: false,
        upload_filename: None,
        upload_file_path: None,
        per_url_upload_files: Vec::new(),
        inline_cookies: Vec::new(),
        next_needs_url: false,
        had_next: false,
        per_url_credentials: Vec::new(),
        custom_request_original: None,
        per_url_custom_request: Vec::new(),
        variables: Vec::new(),
        skip_existing: false,
        json_mode: false,
        per_url_ftp_methods: Vec::new(),
        per_url_easy: Vec::new(),
        per_url_group: Vec::new(),
        group_id: 0,
        group_easy_start: 0,
        etag_conflict_blame: None,
    };

    let mut i = 1;
    let mut group_start_idx: usize = 0;
    let mut current_ftp_method = liburlx::protocol::ftp::FtpMethod::default();
    // Track pending -T upload file: set when -T is encountered, consumed when the next URL is added
    let mut pending_upload_file: Option<String> = None;
    // Track whether any per-request option was set in the current --next group.
    // Used to distinguish "no-op --next" from "badly used --next" (curl compat: tests 422, 430).
    let mut group_has_options = false;
    // Stack for nested multipart containers (`-F "=(;type=..."` / `-F "=)"`)
    let mut mime_container_stack: Vec<usize> = Vec::new();
    while i < args.len() {
        // No per-iteration tracking needed here — group_has_options is set
        // by specific URL-consuming options (-O, -I, -d, -T, etc.) below.
        match args[i].as_str() {
            "-X" | "--request" => {
                i += 1;
                let val = require_arg(args, i, "-X")?;
                opts.easy.method(val);
                // Store original case value for non-HTTP protocols
                // (IMAP/POP3/SMTP use -X as custom protocol command).
                // Don't set custom_request_target here — that's for --request-target.
                // The transfer code applies custom_request_original to email protocols only.
                opts.custom_request_original = Some(val.to_string());
            }
            "-H" | "--header" => {
                i += 1;
                let val = require_arg(args, i, "-H")?;
                // Warn about Unicode quote characters at start of value
                // (curl compat: tests 469, 470)
                warn_unicode_quote(val);
                // -H @filename: read headers from file, one per line (curl compat: test 1147)
                if let Some(path) = val.strip_prefix('@') {
                    if let Ok(contents) = std::fs::read_to_string(path) {
                        for line in contents.lines() {
                            // Skip empty lines
                            if line.trim().is_empty() {
                                continue;
                            }
                            if let Some((name, value)) = line.split_once(':') {
                                let value_trimmed = value.trim();
                                if value_trimmed.is_empty() {
                                    // "Name:" → removal marker
                                    opts.easy.header_remove(name.trim());
                                } else {
                                    // "Name: value" → set header
                                    opts.easy.header(name, value.trim_start());
                                }
                            }
                            // Lines without colon are silently ignored (curl compat)
                        }
                    } else {
                        eprintln!("curl: Failed to open {path}");
                        return Err(2);
                    }
                } else if let Some((name, value)) = val.split_once(':') {
                    let name = name.trim();
                    let value_trimmed = value.trim();
                    if value_trimmed.is_empty() {
                        // "Name:" or "Name:  " → removal marker (suppress built-in)
                        opts.easy.header_remove(name);
                    } else {
                        // "Name: value" → set header (trim leading whitespace only)
                        opts.easy.header(name, value.trim_start());
                    }
                } else if let Some(name_part) = val.strip_suffix(';') {
                    // "Name;" → send header with empty value (Name:\r\n)
                    let name = name_part.trim();
                    opts.easy.header(name, "");
                } else {
                    // No colon, doesn't end with ';' → ignore (curl compat)
                    // Covers "Name;stuff", "Name;  ", etc.
                }
            }
            "-d" | "--data" => {
                i += 1;
                let val = require_arg(args, i, "-d")?;
                // Check for -T + -d conflict (curl compat: test 378)
                if opts.is_upload {
                    eprintln!(
                        "Warning: You can only select one HTTP request method! You asked for both PUT "
                    );
                    eprintln!("Warning: (-T, --upload-file) and POST (-d, --data).");
                    return Err(2);
                }
                // Support @filename to read from file, @- for stdin
                if let Some(path) = val.strip_prefix('@') {
                    match read_data_source(path) {
                        Ok(data) => {
                            // curl's -d @file strips \r, \n, and \0 bytes
                            // (unlike --data-binary which preserves them)
                            // (curl compat: test 463)
                            let stripped: Vec<u8> = data
                                .into_iter()
                                .filter(|&b| b != b'\r' && b != b'\n' && b != 0)
                                .collect();
                            opts.easy.body(&stripped);
                        }
                        Err(e) => {
                            eprintln!("curl: error reading data: {e}");
                            return Err(1);
                        }
                    }
                } else {
                    opts.easy.body(val.as_bytes());
                }
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
            }
            "--data-raw" => {
                i += 1;
                let val = require_arg(args, i, "--data-raw")?;
                opts.easy.body(val.as_bytes());
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
            }
            "--data-ascii" => {
                i += 1;
                let val = require_arg(args, i, "--data-ascii")?;
                opts.easy.body(val.as_bytes());
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
            }
            "-L" | "--location" => {
                if opts.saw_follow {
                    eprintln!("Warning: --follow overrides --location");
                }
                opts.saw_location = true;
                opts.easy.follow_redirects(true);
            }
            "--follow" => {
                if opts.saw_location {
                    eprintln!("Warning: --follow overrides --location");
                }
                opts.saw_follow = true;
                opts.easy.follow_redirects(true);
            }
            "--location-trusted" => {
                opts.easy.follow_redirects(true);
                opts.easy.unrestricted_auth(true);
                opts.location_trusted = true;
            }
            "--max-redirs" => {
                i += 1;
                let val = require_arg(args, i, "--max-redirs")?;
                if let Ok(max) = val.parse::<u32>() {
                    opts.easy.max_redirects(max);
                } else {
                    eprintln!("curl: invalid max-redirs value: {val}");
                    return Err(1);
                }
            }
            "-I" | "--head" => {
                opts.easy.method("HEAD");
            }
            "-o" | "--output" => {
                i += 1;
                let val = require_arg(args, i, "-o")?;
                opts.output_files.push(val.to_string());
                opts.explicit_output = true;
                group_has_options = true;
            }
            "--out-null" => {
                // Discard output for this URL (curl compat: test 756).
                // Map to platform-appropriate null device.
                #[cfg(unix)]
                opts.output_files.push("/dev/null".to_string());
                #[cfg(windows)]
                opts.output_files.push("NUL".to_string());
            }
            "-O" | "--remote-name" | "--remote-name-all" => {
                opts.remote_name = true;
                group_has_options = true;
            }
            "--no-remote-name" => {
                opts.remote_name = false;
            }
            "-e" | "--referer" => {
                i += 1;
                let val = require_arg(args, i, "-e")?;
                if let Some(referer) = val.strip_suffix(";auto") {
                    opts.easy.header("Referer", referer);
                    opts.easy.auto_referer(true);
                } else {
                    opts.easy.header("Referer", val);
                }
            }
            "-G" | "--get" => {
                opts.get_mode = true;
            }
            "--create-dirs" => {
                opts.create_dirs = true;
            }
            "-D" | "--dump-header" => {
                i += 1;
                let val = require_arg(args, i, "-D")?;
                opts.dump_header = Some(val.to_string());
            }
            "-i" | "--include" | "--show-headers" => {
                opts.include_headers = true;
            }
            "--no-include" => {
                opts.include_headers = false;
            }
            "-v" | "--verbose" => {
                opts.easy.verbose(true);
            }
            "-s" | "--silent" => {
                opts.silent = true;
            }
            "-S" | "--show-error" => {
                opts.show_error = true;
            }
            "--no-progress-meter" => {
                opts.no_progress_meter = true;
            }
            "-f" | "--fail" => {
                opts.fail_on_error = true;
            }
            "--fail-with-body" => {
                opts.fail_on_error = true;
                opts.fail_with_body = true;
            }
            "--fail-early" => {
                opts.fail_early = true;
            }
            "--compressed" => {
                opts.easy.accept_encoding(true);
            }
            "--tr-encoding" => {
                // Add TE: gzip header and mark that Connection should include TE.
                // The h1 request builder merges TE into Connection (curl compat: tests
                // 1125, 1171, 1277).
                opts.easy.header("TE", "gzip");
                opts.easy.header("_tr_encoding_connection", "TE");
            }
            "--connect-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--connect-timeout")?;
                if let Ok(secs) = val.parse::<f64>() {
                    // curl rejects values that overflow a 32-bit long
                    if secs < 0.0 || secs > f64::from(u32::MAX) {
                        eprintln!(
                            "curl: option --connect-timeout: expected a proper numerical parameter"
                        );
                        eprintln!(
                            "curl: try 'curl --help' or 'curl --manual' for more information"
                        );
                        return Err(2);
                    }
                    opts.easy.connect_timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!(
                        "curl: option --connect-timeout: expected a proper numerical parameter"
                    );
                    eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                    return Err(2);
                }
            }
            "-m" | "--max-time" => {
                i += 1;
                let val = require_arg(args, i, "-m")?;
                if let Ok(secs) = val.parse::<f64>() {
                    // curl rejects values that overflow a 32-bit long
                    if secs < 0.0 || secs > f64::from(u32::MAX) {
                        eprintln!("curl: option -m: expected a proper numerical parameter");
                        eprintln!(
                            "curl: try 'curl --help' or 'curl --manual' for more information"
                        );
                        return Err(2);
                    }
                    opts.easy.timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("curl: option -m: expected a proper numerical parameter");
                    eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                    return Err(2);
                }
            }
            "-w" | "--write-out" => {
                i += 1;
                let val = require_arg(args, i, "-w")?;
                opts.write_out = Some(val.to_string());
            }
            "-x" | "--proxy" => {
                i += 1;
                let val = require_arg(args, i, "-x")?;
                if val.is_empty() {
                    // --proxy "" means no proxy (curl compat: test 1004)
                    opts.easy.clear_proxy();
                } else if let Err(e) = opts.easy.proxy(val) {
                    eprintln!("curl: invalid proxy URL: {e}");
                    return Err(1);
                }
            }
            "--noproxy" => {
                i += 1;
                let val = require_arg(args, i, "--noproxy")?;
                opts.easy.noproxy(val);
            }
            "-u" | "--user" => {
                i += 1;
                let val = require_arg(args, i, "-u")?;
                let (user, pass) = if let Some((u, p)) = val.split_once(':') {
                    (u.to_string(), p.to_string())
                } else {
                    (val.to_string(), String::new())
                };
                opts.user_credentials = Some((user, pass));
            }
            "-A" | "--user-agent" => {
                i += 1;
                let val = require_arg(args, i, "-A")?;
                opts.user_agent_str = Some(val.to_string());
                if val.is_empty() {
                    // -A "" removes the User-Agent header entirely (curl compat).
                    // Set empty value so h1 detects it and suppresses the default.
                    opts.easy.remove_header("User-Agent");
                    opts.easy.header("User-Agent", "");
                } else {
                    opts.easy.header("User-Agent", val);
                }
            }
            "-F" | "--form" => {
                i += 1;
                let val = require_arg(args, i, "-F")?;
                if let Err(msg) =
                    parse_form_field_ext(&mut opts.easy, val, &mut mime_container_stack, false)
                {
                    eprintln!("curl: {msg}");
                    // Exit code 26 = CURLE_READ_ERROR (file not found / read error)
                    return Err(26);
                }
            }
            "-r" | "--range" => {
                i += 1;
                let val = require_arg(args, i, "-r")?;
                // curl appends '-' if range is just a number (e.g., "4" → "4-")
                if val.contains('-') {
                    opts.easy.range(val);
                } else {
                    opts.easy.range(&format!("{val}-"));
                }
            }
            "-C" | "--continue-at" => {
                i += 1;
                let val = require_arg(args, i, "-C")?;
                opts.resume_check = true;
                if val == "-" {
                    // Auto-resume: determine offset from output file size at transfer time
                    opts.auto_resume = true;
                } else if let Ok(offset) = val.parse::<u64>() {
                    opts.resume_offset = Some(offset);
                    opts.easy.resume_from(offset);
                } else {
                    eprintln!("curl: invalid offset value: {val}");
                    return Err(1);
                }
            }
            "-#" | "--progress-bar" => {
                opts.show_progress = true;
            }
            "-k" | "--insecure" => {
                opts.easy.ssl_verify_peer(false);
                opts.easy.ssl_verify_host(false);
            }
            "--cacert" => {
                i += 1;
                let val = require_arg(args, i, "--cacert")?;
                opts.easy.ssl_ca_cert(std::path::Path::new(val));
            }
            "--crlfile" => {
                i += 1;
                let val = require_arg(args, i, "--crlfile")?;
                opts.easy.ssl_crl_file(std::path::Path::new(val));
            }
            "--cert" => {
                i += 1;
                let val = require_arg(args, i, "--cert")?;
                opts.easy.ssl_client_cert(std::path::Path::new(val));
            }
            "--key" => {
                i += 1;
                let val = require_arg(args, i, "--key")?;
                opts.easy.ssl_client_key(std::path::Path::new(val));
                opts.easy.ssh_key_path(val);
            }
            "--hostpubsha256" => {
                i += 1;
                let val = require_arg(args, i, "--hostpubsha256")?;
                opts.easy.ssh_host_key_sha256(val);
            }
            "--known-hosts" => {
                i += 1;
                let val = require_arg(args, i, "--known-hosts")?;
                opts.easy.ssh_known_hosts_path(val);
            }
            "--hostpubmd5" => {
                i += 1;
                let val = require_arg(args, i, "--hostpubmd5")?;
                // Validate MD5 fingerprint: must be exactly 32 hex characters
                if val.len() != 32 || !val.chars().all(|c| c.is_ascii_hexdigit()) {
                    eprintln!(
                        "curl: (2) Argument to --hostpubmd5 must be a 32 character hex string"
                    );
                    return Err(2);
                }
                opts.easy.ssh_host_key_md5(val);
            }
            "--digest" => {
                opts.use_digest = true;
            }
            "-U" | "--proxy-user" => {
                i += 1;
                let val = require_arg(args, i, "-U")?;
                let (user, pass) =
                    if let Some((u, p)) = val.split_once(':') { (u, p) } else { (val, "") };
                opts.proxy_user = Some((user.to_string(), pass.to_string()));
            }
            "-p" | "--proxytunnel" => {
                opts.easy.http_proxy_tunnel(true);
            }
            "--proxy-digest" => {
                opts.proxy_digest = true;
            }
            "--proxy-ntlm" => {
                opts.proxy_ntlm = true;
            }
            "--proxy-anyauth" => {
                opts.proxy_anyauth = true;
            }
            "--suppress-connect-headers" => {
                opts.suppress_connect_headers = true;
            }
            "--tlsv1.2" => {
                opts.easy.ssl_min_version(liburlx::TlsVersion::Tls12);
            }
            "--tlsv1.3" => {
                opts.easy.ssl_min_version(liburlx::TlsVersion::Tls13);
            }
            "--tls-max" => {
                i += 1;
                let val = require_arg(args, i, "--tls-max")?;
                match val {
                    "1.2" => opts.easy.ssl_max_version(liburlx::TlsVersion::Tls12),
                    "1.3" => opts.easy.ssl_max_version(liburlx::TlsVersion::Tls13),
                    _ => {
                        eprintln!("curl: unsupported TLS version: {val}");
                        return Err(1);
                    }
                }
            }
            "--pinnedpubkey" => {
                i += 1;
                let val = require_arg(args, i, "--pinnedpubkey")?;
                opts.easy.ssl_pinned_public_key(val);
            }
            "--tlsuser" => {
                i += 1;
                let val = require_arg(args, i, "--tlsuser")?;
                opts.easy.ssl_srp_user(val);
            }
            "--tlspassword" => {
                i += 1;
                let val = require_arg(args, i, "--tlspassword")?;
                opts.easy.ssl_srp_password(val);
            }
            "--tlsauthtype" => {
                i += 1;
                let val = require_arg(args, i, "--tlsauthtype")?;
                if !val.eq_ignore_ascii_case("SRP") {
                    eprintln!("curl: unsupported TLS auth type: {val}");
                    return Err(1);
                }
                // SRP is the only supported type; credentials set via --tlsuser/--tlspassword
            }
            "--aws-sigv4" => {
                i += 1;
                let val = require_arg(args, i, "--aws-sigv4")?;
                opts.easy.aws_sigv4(val);
                opts.use_aws_sigv4 = true;
            }
            "--unix-socket" => {
                i += 1;
                let val = require_arg(args, i, "--unix-socket")?;
                warn_filename_like_flag(val);
                opts.easy.unix_socket(val);
            }
            "--interface" => {
                i += 1;
                let val = require_arg(args, i, "--interface")?;
                opts.easy.interface(val);
            }
            "--local-port" => {
                i += 1;
                let val = require_arg(args, i, "--local-port")?;
                let port = if let Some((start_s, _end_s)) = val.split_once('-') {
                    start_s.parse::<u16>().ok()
                } else {
                    val.parse::<u16>().ok()
                };
                if let Some(p) = port {
                    opts.easy.local_port(p);
                } else {
                    eprintln!("curl: invalid port: {val}");
                    return Err(1);
                }
            }
            "--dns-shuffle" => {
                opts.easy.dns_shuffle(true);
            }
            "--unrestricted-auth" => {
                opts.easy.unrestricted_auth(true);
            }
            "--ignore-content-length" => {
                opts.easy.ignore_content_length(true);
            }
            "--dns-servers" => {
                i += 1;
                let val = require_arg(args, i, "--dns-servers")?;
                if let Err(e) = opts.easy.dns_servers(val) {
                    eprintln!("curl: invalid DNS servers: {e}");
                    return Err(1);
                }
            }
            "--doh-url" => {
                i += 1;
                let val = require_arg(args, i, "--doh-url")?;
                opts.easy.doh_url(val);
            }
            "--happy-eyeballs-timeout-ms" => {
                i += 1;
                let val = require_arg(args, i, "--happy-eyeballs-timeout-ms")?;
                if let Ok(ms) = val.parse::<u64>() {
                    opts.easy.happy_eyeballs_timeout(std::time::Duration::from_millis(ms));
                } else {
                    eprintln!("curl: invalid happy-eyeballs-timeout-ms: {val}");
                    return Err(1);
                }
            }
            "-T" | "--upload-file" => {
                i += 1;
                let val = require_arg(args, i, "-T")?;
                // Check for -d + -T conflict before reading file (curl compat: test 378)
                if opts.has_post_data {
                    eprintln!(
                        "Warning: You can only select one HTTP request method! You asked for both PUT "
                    );
                    eprintln!("Warning: (-T, --upload-file) and POST (-d, --data).");
                    return Err(2);
                }
                if val == "-" {
                    // Read from stdin
                    use std::io::Read;
                    let mut data = Vec::new();
                    if let Err(e) = std::io::stdin().read_to_end(&mut data) {
                        eprintln!("curl: can't read from stdin: {e}");
                        return Err(1);
                    }
                    opts.easy.body(&data);
                    opts.is_upload = true;
                    opts.is_stdin_upload = true;
                    if opts.easy.method_is_default() {
                        opts.easy.method("PUT");
                    }
                } else {
                    // Mark as upload (defer file read to transfer time for -T/-d
                    // conflict detection: test 378)
                    opts.is_upload = true;
                    if opts.easy.method_is_default() {
                        opts.easy.method("PUT");
                    }
                    // Append filename to URL path if URL ends with /
                    let filename = std::path::Path::new(val)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !filename.is_empty() {
                        opts.upload_filename = Some(filename);
                    }
                    // Store file path; read at transfer time
                    opts.upload_file_path = Some(val.to_string());
                    // Track pending upload for per-URL association
                    pending_upload_file = Some(val.to_string());
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                let val = require_arg(args, i, "-b")?;
                // "-b none" or "-b ''" enables the cookie engine without sending cookies
                if val == "none" || val.is_empty() {
                    opts.easy.cookie_jar(true);
                } else if val.contains('=') || val.contains(';') {
                    // Contains '=' or ';': treat as inline cookie string
                    opts.easy.cookie_jar(true);
                    opts.inline_cookies.push(val.to_string());
                } else {
                    // No '=' or ';': treat as a cookie file path (curl compat)
                    if let Err(e) = opts.easy.cookie_file(val) {
                        eprintln!("curl: error reading cookie file '{val}': {e}");
                        return Err(1);
                    }
                }
            }
            "--data-binary" => {
                i += 1;
                let val = require_arg(args, i, "--data-binary")?;
                if let Some(path) = val.strip_prefix('@') {
                    match read_data_source(path) {
                        Ok(data) => opts.easy.body(&data),
                        Err(e) => {
                            eprintln!("curl: error reading data: {e}");
                            return Err(1);
                        }
                    }
                } else {
                    opts.easy.body(val.as_bytes());
                }
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
            }
            "--data-urlencode" => {
                i += 1;
                let val = require_arg(args, i, "--data-urlencode")?;
                let encoded = data_urlencode(val)?;
                // Concatenate multiple --data-urlencode with & separator (curl compat: test 1015)
                if opts.easy.has_body() {
                    opts.easy.append_body(b"&");
                    opts.easy.append_body(encoded.as_bytes());
                } else {
                    opts.easy.body(encoded.as_bytes());
                }
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
            }
            "--resolve" => {
                i += 1;
                let val = require_arg(args, i, "--resolve")?;
                // Format: host:port:address
                let parts: Vec<&str> = val.splitn(3, ':').collect();
                if parts.len() == 3 {
                    opts.easy.resolve(parts[0], parts[2]);
                } else {
                    eprintln!("curl: invalid --resolve format: {val}");
                    eprintln!("  Use: --resolve host:port:address");
                    return Err(1);
                }
            }
            "-0" | "--http1.0" => {
                opts.easy.http_version(liburlx::HttpVersion::Http10);
            }
            "--http1.1" => {
                opts.easy.http_version(liburlx::HttpVersion::Http11);
            }
            "--http2" => {
                opts.easy.http_version(liburlx::HttpVersion::Http2);
            }
            "--http3" | "--http3-only" => {
                opts.easy.http_version(liburlx::HttpVersion::Http3);
            }
            "--http2-prior-knowledge" => {
                opts.easy.http_version(liburlx::HttpVersion::Http2PriorKnowledge);
            }
            "--http0.9" => {
                opts.easy.http09_allowed(true);
            }
            "--no-http0.9" => {
                opts.easy.http09_allowed(false);
            }
            "--expect100-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--expect100-timeout")?;
                // curl's --expect100-timeout is in seconds (integer or decimal)
                if let Ok(secs) = val.parse::<f64>() {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let millis = (secs * 1000.0) as u64;
                    opts.easy.expect_100_timeout(std::time::Duration::from_millis(millis));
                } else {
                    eprintln!("curl: invalid expect100-timeout value: {val}");
                    return Err(1);
                }
            }
            "--retry" => {
                i += 1;
                let val = require_arg(args, i, "--retry")?;
                if let Ok(n) = val.parse::<u32>() {
                    opts.retry_count = n;
                } else {
                    eprintln!("curl: invalid retry count: {val}");
                    return Err(1);
                }
            }
            "--retry-delay" => {
                i += 1;
                let val = require_arg(args, i, "--retry-delay")?;
                if let Ok(s) = val.parse::<u64>() {
                    // Reject values that would overflow Duration (curl returns exit 2)
                    if s > 86_400 * 365 * 100 {
                        // > 100 years is unreasonable
                        eprintln!("curl: too large --retry-delay value");
                        return Err(2);
                    }
                    opts.retry_delay_secs = s;
                } else {
                    eprintln!("curl: invalid retry-delay value: {val}");
                    return Err(2);
                }
            }
            "--retry-max-time" => {
                i += 1;
                let val = require_arg(args, i, "--retry-max-time")?;
                if let Ok(s) = val.parse::<u64>() {
                    opts.retry_max_time_secs = s;
                } else {
                    eprintln!("curl: invalid retry-max-time value: {val}");
                    return Err(1);
                }
            }
            "--retry-all-errors" => {
                opts.retry_all_errors = true;
            }
            "-Z" | "--parallel" => {
                opts.parallel = true;
            }
            "--parallel-max" => {
                i += 1;
                let val = require_arg(args, i, "--parallel-max")?;
                if let Ok(n) = val.parse::<usize>() {
                    opts.parallel_max = n;
                } else {
                    eprintln!("curl: invalid parallel-max value: {val}");
                    return Err(1);
                }
            }
            "--socks5-hostname" => {
                i += 1;
                let val = require_arg(args, i, "--socks5-hostname")?;
                let proxy_url = format!("socks5h://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("curl: invalid SOCKS5 proxy: {e}");
                    return Err(1);
                }
            }
            "--tcp-nodelay" => {
                opts.easy.tcp_nodelay(true);
            }
            "--tcp-keepalive" => {
                i += 1;
                let val = require_arg(args, i, "--tcp-keepalive")?;
                if let Ok(secs) = val.parse::<u64>() {
                    opts.easy.tcp_keepalive(std::time::Duration::from_secs(secs));
                } else {
                    eprintln!("curl: invalid tcp-keepalive value: {val}");
                    return Err(1);
                }
            }
            "--keepalive-time" => {
                i += 1;
                let val = require_arg(args, i, "--keepalive-time")?;
                if let Ok(secs) = val.parse::<u64>() {
                    opts.easy.tcp_keepalive(std::time::Duration::from_secs(secs));
                } else {
                    eprintln!("curl: invalid keepalive-time value: {val}");
                    return Err(1);
                }
            }
            "--hsts" => {
                i += 1;
                let val = require_arg(args, i, "--hsts")?;
                if let Err(e) = opts.easy.hsts_file(val) {
                    eprintln!("curl: error reading HSTS file '{val}': {e}");
                    return Err(1);
                }
            }
            "--bearer" => {
                i += 1;
                let val = require_arg(args, i, "--bearer")?;
                opts.easy.bearer_token(val);
                opts.use_bearer = true;
            }
            "-c" | "--cookie-jar" => {
                i += 1;
                let val = require_arg(args, i, "-c")?;
                opts.cookie_jar_file = Some(val.to_string());
                opts.easy.cookie_jar_file(val);
            }
            "--limit-rate" => {
                i += 1;
                let val = require_arg(args, i, "--limit-rate")?;
                opts.limit_rate = Some(val.to_string());
                if let Some(bps) = parse_rate_limit(val) {
                    opts.easy.max_recv_speed(bps);
                    opts.easy.max_send_speed(bps);
                } else {
                    eprintln!("curl: invalid rate limit: {val}");
                    return Err(1);
                }
            }
            "-Y" | "--speed-limit" => {
                i += 1;
                let val = require_arg(args, i, "--speed-limit")?;
                if let Ok(limit) = val.parse::<u32>() {
                    opts.speed_limit = Some(limit);
                    opts.easy.low_speed_limit(limit);
                } else {
                    eprintln!("curl: invalid speed limit: {val}");
                    return Err(1);
                }
            }
            "-y" | "--speed-time" => {
                i += 1;
                let val = require_arg(args, i, "--speed-time")?;
                if let Ok(secs) = val.parse::<u64>() {
                    opts.speed_time = Some(secs);
                    opts.easy.low_speed_time(std::time::Duration::from_secs(secs));
                } else {
                    eprintln!("curl: invalid speed time: {val}");
                    return Err(1);
                }
            }
            "--trace" => {
                i += 1;
                let val = require_arg(args, i, "--trace")?;
                opts.trace_file = Some(val.to_string());
                // Don't set verbose — trace output goes to file, not stderr
            }
            "--trace-ascii" => {
                i += 1;
                let val = require_arg(args, i, "--trace-ascii")?;
                opts.trace_ascii_file = Some(val.to_string());
                // Don't set verbose — trace output goes to file, not stderr
            }
            "--trace-time" => {
                opts.trace_time = true;
            }
            "--stderr" => {
                i += 1;
                let val = require_arg(args, i, "--stderr")?;
                opts.stderr_file = Some(val.to_string());
            }
            "-K" | "--config" => {
                i += 1;
                let val = require_arg(args, i, "-K")?;
                if config_depth >= MAX_CONFIG_DEPTH {
                    eprintln!("curl: error: config file nesting too deep");
                    return Err(2);
                }
                let contents_result = if val == "-" {
                    // Read config from stdin as raw bytes, then convert to
                    // String using lossy UTF-8 so that invalid byte sequences
                    // (e.g., truncated multi-byte chars) reach URL parsing where
                    // they are rejected as malformed URLs rather than causing an
                    // IO read error (curl compat: test 1034).
                    use std::io::Read as _;
                    let mut bytes = Vec::new();
                    std::io::stdin()
                        .read_to_end(&mut bytes)
                        .map(|_| String::from_utf8_lossy(&bytes).into_owned())
                } else {
                    std::fs::read_to_string(val)
                };
                match contents_result {
                    Ok(contents) => {
                        let config_args = parse_config_file_with_path(
                            &contents,
                            if val == "-" { None } else { Some(val) },
                        );
                        // Re-parse with: args before -K, config args, args after -K
                        let mut full_args = vec!["urlx".to_string()];
                        // Include CLI args that came before -K (skip program name at [0])
                        for arg in args.iter().take(i - 1).skip(1) {
                            full_args.push(arg.clone());
                        }
                        full_args.extend(config_args);
                        // Include CLI args that came after -K <value>
                        for arg in args.iter().skip(i + 1) {
                            full_args.push(arg.clone());
                        }
                        let expanded = expand_combined_flags(&full_args);
                        return parse_args_options_with_depth(&expanded, config_depth + 1);
                    }
                    Err(_e) => {
                        eprintln!("curl: cannot read config from '{val}'");
                        eprintln!("curl: option -K: error encountered when reading a file");
                        eprintln!(
                            "curl: try 'curl --help' or 'curl --manual' for more information"
                        );
                        return Err(26);
                    }
                }
            }
            "--libcurl" => {
                i += 1;
                let val = require_arg(args, i, "--libcurl")?;
                opts.libcurl = Some(val.to_string());
            }
            "--proto" => {
                i += 1;
                let val = require_arg(args, i, "--proto")?;
                opts.proto = Some(val.to_string());
            }
            "--proto-redir" => {
                i += 1;
                let val = require_arg(args, i, "--proto-redir")?;
                opts.proto_redir = Some(val.to_string());
            }
            "--max-filesize" => {
                i += 1;
                let val = require_arg(args, i, "--max-filesize")?;
                if let Ok(size) = val.parse::<u64>() {
                    opts.max_filesize = Some(size);
                    opts.easy.max_filesize(size);
                } else {
                    eprintln!("curl: invalid max-filesize: {val}");
                    return Err(1);
                }
            }
            "--no-keepalive" => {
                opts.no_keepalive = true;
            }
            "-n" | "--netrc" => {
                // Check $NETRC env var first (curl compat: test 755)
                if let Ok(netrc_path) = std::env::var("NETRC") {
                    opts.netrc_file = Some(netrc_path);
                } else {
                    let home = std::env::var("HOME").unwrap_or_default();
                    opts.netrc_file = Some(format!("{home}/.netrc"));
                }
            }
            "--netrc-file" => {
                i += 1;
                let val = require_arg(args, i, "--netrc-file")?;
                opts.netrc_file = Some(val.to_string());
            }
            "--netrc-optional" => {
                let home = std::env::var("HOME").unwrap_or_default();
                opts.netrc_file = Some(format!("{home}/.netrc"));
                opts.netrc_optional = true;
            }
            "--proxy-header" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-header")?;
                if let Some((name, value)) = val.split_once(':') {
                    opts.easy.proxy_header(name.trim(), value.trim());
                } else {
                    eprintln!("curl: invalid proxy-header format: {val}");
                    return Err(1);
                }
            }
            "--post301" => {
                opts.post301 = true;
                opts.easy.post301(true);
            }
            "--post302" => {
                opts.post302 = true;
                opts.easy.post302(true);
            }
            "--post303" => {
                opts.post303 = true;
                opts.easy.post303(true);
            }
            "--remote-time" | "-R" => {
                opts.remote_time = true;
            }
            "-g" | "--globoff" => {
                opts.globoff = true;
            }
            // FTPS: explicit mode (AUTH TLS) + STARTTLS for other protocols
            "--ftp-ssl" | "--ssl" => {
                opts.easy.ftp_ssl_mode(liburlx::protocol::ftp::FtpSslMode::Explicit);
                opts.easy.use_ssl(liburlx::protocol::ftp::UseSsl::Try);
            }
            "--ftp-ssl-reqd" | "--ssl-reqd" => {
                opts.easy.ftp_ssl_mode(liburlx::protocol::ftp::FtpSslMode::Explicit);
                opts.easy.use_ssl(liburlx::protocol::ftp::UseSsl::All);
            }
            "--ftp-ssl-control" => {
                opts.easy.ftp_ssl_control(true);
            }
            "--ftp-ssl-ccc" => {
                opts.easy.ftp_ssl_ccc(true);
            }
            "--ftp-port" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("curl: --ftp-port requires an argument");
                    return Err(1);
                }
                opts.easy.ftp_active_port(&args[i]);
            }
            "--path-as-is" => {
                opts.easy.path_as_is(true);
            }
            "--raw" => {
                opts.easy.raw(true);
            }
            "-J" | "--remote-header-name" => {
                opts.remote_header_name = true;
                opts.remote_name = true;
            }
            "--url-query" => {
                i += 1;
                let val = require_arg(args, i, "--url-query")?;
                opts.url_queries.push(val.to_string());
            }
            "--json" => {
                i += 1;
                let val = require_arg(args, i, "--json")?;
                // Read data from file/stdin if @-prefixed (like -d)
                #[allow(clippy::items_after_statements)]
                let json_data = if let Some(path) = val.strip_prefix('@') {
                    if path == "-" {
                        let mut buf = Vec::new();
                        use std::io::Read;
                        let _ = std::io::stdin().read_to_end(&mut buf);
                        buf
                    } else {
                        match std::fs::read(path) {
                            Ok(data) => data,
                            Err(e) => {
                                eprintln!("curl: can't read file '{path}': {e}");
                                return Err(1);
                            }
                        }
                    }
                } else {
                    val.as_bytes().to_vec()
                };
                // Multiple --json flags: append data (curl compat: test 385)
                opts.easy.append_body(&json_data);
                // Mark as JSON mode — headers will be added after all args are parsed
                // (curl compat: tests 383, 384 — Content-Type/Accept order depends on -H)
                opts.json_mode = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
            }
            "--rate" => {
                i += 1;
                let val = require_arg(args, i, "--rate")?;
                opts.rate = Some(val.to_string());
            }
            "--ciphers" => {
                i += 1;
                let val = require_arg(args, i, "--ciphers")?;
                opts.easy.ssl_cipher_list(val);
            }
            "--ntlm" => {
                opts.use_ntlm = true;
            }
            "--negotiate" => {
                opts.use_negotiate = true;
            }
            "--proxy-negotiate" => {
                opts.proxy_negotiate = true;
            }
            "--anyauth" => {
                opts.use_anyauth = true;
            }
            "--delegation" => {
                i += 1;
                let val = require_arg(args, i, "--delegation")?;
                match val.to_lowercase().as_str() {
                    "none" => {
                        opts.easy.gss_api_delegation(liburlx::auth::GssApiDelegation::None);
                    }
                    "policy" => {
                        opts.easy.gss_api_delegation(liburlx::auth::GssApiDelegation::Policy);
                    }
                    "always" => {
                        opts.easy.gss_api_delegation(liburlx::auth::GssApiDelegation::Always);
                    }
                    _ => {
                        eprintln!("curl: option --delegation: expected a proper string");
                        eprintln!(
                            "curl: try 'curl --help' or 'curl --manual' for more information"
                        );
                        return Err(2);
                    }
                }
            }
            "--sasl-authzid" => {
                i += 1;
                let val = require_arg(args, i, "--sasl-authzid")?;
                opts.easy.sasl_authzid(val);
            }
            "--login-options" => {
                i += 1;
                let val = require_arg(args, i, "--login-options")?;
                opts.easy.login_options(val);
            }
            "--sasl-ir" => {
                opts.easy.sasl_ir(true);
            }
            "--mail-from" => {
                i += 1;
                let val = require_arg(args, i, "--mail-from")?;
                opts.easy.mail_from(val);
            }
            "--mail-rcpt" => {
                i += 1;
                let val = require_arg(args, i, "--mail-rcpt")?;
                opts.easy.mail_rcpt(val);
            }
            "--mail-auth" => {
                i += 1;
                let val = require_arg(args, i, "--mail-auth")?;
                opts.easy.mail_auth(val);
            }
            "--ftp-create-dirs" => {
                opts.easy.ftp_create_dirs(true);
            }
            "--ftp-pret" => {
                opts.easy.ftp_use_pret(true);
            }
            "--ftp-skip-pasv-ip" => {
                opts.easy.ftp_skip_pasv_ip(true);
            }
            "--ftp-account" => {
                i += 1;
                let val = require_arg(args, i, "--ftp-account")?;
                opts.easy.ftp_account(val);
            }
            "--ftp-alternative-to-user" => {
                i += 1;
                let val = require_arg(args, i, "--ftp-alternative-to-user")?;
                opts.easy.ftp_alternative_to_user(val);
            }
            "--ftp-method" => {
                i += 1;
                let val = require_arg(args, i, "--ftp-method")?;
                let method = match val.to_lowercase().as_str() {
                    "multicwd" => liburlx::protocol::ftp::FtpMethod::MultiCwd,
                    "singlecwd" => liburlx::protocol::ftp::FtpMethod::SingleCwd,
                    "nocwd" => liburlx::protocol::ftp::FtpMethod::NoCwd,
                    _ => {
                        eprintln!("curl: invalid FTP method: {val}");
                        eprintln!("  Valid values: multicwd, singlecwd, nocwd");
                        return Err(1);
                    }
                };
                opts.easy.ftp_method(method);
                current_ftp_method = method;
            }
            "--connect-to" => {
                i += 1;
                let val = require_arg(args, i, "--connect-to")?;
                opts.easy.connect_to(val);
            }
            "--alt-svc" => {
                i += 1;
                let val = require_arg(args, i, "--alt-svc")?;
                opts.alt_svc_file = Some(val.to_string());
            }
            "--ssl-sessions" => {
                i += 1;
                let val = require_arg(args, i, "--ssl-sessions")?;
                opts.ssl_session_file = Some(val.to_string());
            }
            "--etag-save" => {
                i += 1;
                let val = require_arg(args, i, "--etag-save")?;
                opts.etag_save_file = Some(val.to_string());
                // If multiple URLs already exist, this etag option is the culprit
                if opts.urls.len() > 1 {
                    opts.etag_conflict_blame = Some("--etag-save".to_string());
                }
            }
            "--etag-compare" => {
                i += 1;
                let val = require_arg(args, i, "--etag-compare")?;
                opts.etag_compare_file = Some(val.to_string());
                if opts.urls.len() > 1 {
                    opts.etag_conflict_blame = Some("--etag-compare".to_string());
                }
            }
            "--ipfs-gateway" => {
                i += 1;
                let val = require_arg(args, i, "--ipfs-gateway")?;
                opts.ipfs_gateway = Some(val.to_string());
            }
            "--haproxy-protocol" => {
                opts.easy.haproxy_protocol(true);
            }
            "--abstract-unix-socket" => {
                i += 1;
                let val = require_arg(args, i, "--abstract-unix-socket")?;
                opts.easy.abstract_unix_socket(val);
            }
            "--proxy-cacert" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-cacert")?;
                opts.easy.proxy_tls_config(liburlx::TlsConfig {
                    ca_cert: Some(val.into()),
                    ..Default::default()
                });
            }
            "--proxy-cert" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-cert")?;
                opts.easy.proxy_tls_config(liburlx::TlsConfig {
                    client_cert: Some(val.into()),
                    ..Default::default()
                });
            }
            "--proxy-key" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-key")?;
                opts.easy.proxy_tls_config(liburlx::TlsConfig {
                    client_key: Some(val.into()),
                    ..Default::default()
                });
            }
            "--doh-insecure" => {
                opts.easy.doh_insecure(true);
            }
            "--proto-default" => {
                i += 1;
                let val = require_arg(args, i, "--proto-default")?;
                opts.proto_default = Some(val.to_string());
            }
            "--form-string" => {
                i += 1;
                let val = require_arg(args, i, "--form-string")?;
                if let Some((name, value)) = val.split_once('=') {
                    // Unlike --form, @ is not interpreted as a file path
                    opts.easy.form_field(name, value);
                } else {
                    eprintln!("curl: invalid form-string format: {val}");
                    eprintln!("  Use: --form-string name=value");
                    return Err(1);
                }
            }
            "--form-escape" => {
                opts.easy.set_form_escape_mode(liburlx::FilenameEscapeMode::BackslashEscape);
            }
            "--request-target" => {
                i += 1;
                let val = require_arg(args, i, "--request-target")?;
                opts.easy.custom_request_target(val);
            }
            "--socks4" => {
                i += 1;
                let val = require_arg(args, i, "--socks4")?;
                let proxy_url = format!("socks4://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("curl: invalid SOCKS4 proxy: {e}");
                    return Err(1);
                }
            }
            "--socks4a" => {
                i += 1;
                let val = require_arg(args, i, "--socks4a")?;
                let proxy_url = format!("socks4a://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("curl: invalid SOCKS4a proxy: {e}");
                    return Err(1);
                }
            }
            "--socks5" => {
                i += 1;
                let val = require_arg(args, i, "--socks5")?;
                let proxy_url = format!("socks5://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("curl: invalid SOCKS5 proxy: {e}");
                    return Err(1);
                }
            }
            arg @ ("--proxy-1.0" | "--proxy1.0") => {
                i += 1;
                let val = require_arg(args, i, arg)?;
                if let Err(e) = opts.easy.proxy(val) {
                    eprintln!("curl: invalid proxy URL: {e}");
                    return Err(1);
                }
                // Use HTTP/1.0 for the CONNECT proxy request, not for the inner request
                opts.easy.proxy_http_10(true);
            }
            "--preproxy" => {
                i += 1;
                let val = require_arg(args, i, "--preproxy")?;
                opts.easy.pre_proxy(val);
            }
            "--tftp-blksize" => {
                i += 1;
                let val = require_arg(args, i, "--tftp-blksize")?;
                if let Ok(bs) = val.parse::<u16>() {
                    opts.easy.tftp_blksize(bs);
                } else {
                    eprintln!("curl: invalid tftp-blksize: {val}");
                    return Err(1);
                }
            }
            "--tftp-no-options" => {
                opts.easy.tftp_no_options(true);
            }
            "--url" => {
                i += 1;
                let val = require_arg(args, i, "--url")?;
                // --url @- reads URLs from stdin, --url @file reads from file
                // (curl compat: tests 488, 489)
                if let Some(source) = val.strip_prefix('@') {
                    let content = if source == "-" {
                        use std::io::Read as _;
                        let mut buf = String::new();
                        if std::io::stdin().read_to_string(&mut buf).is_ok() {
                            buf
                        } else {
                            String::new()
                        }
                    } else {
                        std::fs::read_to_string(source).unwrap_or_default()
                    };
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() {
                            opts.urls.push(line.to_string());
                            opts.per_url_credentials.push(opts.user_credentials.clone());
                            opts.per_url_ftp_methods.push(current_ftp_method);
                            opts.per_url_easy.push(None);
                            opts.per_url_upload_files.push(pending_upload_file.take());
                            opts.per_url_custom_request.push(opts.custom_request_original.clone());
                            opts.per_url_group.push(opts.group_id);
                        }
                    }
                } else {
                    opts.urls.push(val.to_string());
                    opts.per_url_credentials.push(opts.user_credentials.clone());
                    opts.per_url_ftp_methods.push(current_ftp_method);
                    opts.per_url_easy.push(None);
                    opts.per_url_upload_files.push(pending_upload_file.take());
                    opts.per_url_custom_request.push(opts.custom_request_original.clone());
                    opts.per_url_group.push(opts.group_id);
                    // If etag options are set and this adds a second URL, blame --url
                    if opts.urls.len() > 1
                        && (opts.etag_save_file.is_some() || opts.etag_compare_file.is_some())
                    {
                        opts.etag_conflict_blame = Some("--url".to_string());
                    }
                }
                opts.next_needs_url = false;
            }
            "--output-dir" => {
                i += 1;
                let val = require_arg(args, i, "--output-dir")?;
                opts.output_dir = Some(val.to_string());
            }
            "--remove-on-error" => {
                opts.remove_on_error = true;
            }
            "--no-clobber" => {
                opts.no_clobber = true;
            }
            "--skip-existing" => {
                opts.skip_existing = true;
            }
            "--proxy-insecure" => {
                opts.easy.proxy_ssl_verify_peer(false);
            }
            // TLS version flags
            "--tlsv1" | "--tlsv1.0" | "--tlsv1.1" => {
                // TLS 1.0/1.1 are deprecated; treat as minimum TLS 1.2
                opts.easy.ssl_min_version(liburlx::TlsVersion::Tls12);
            }
            "--sslv3" => {
                // SSLv3 is insecure; accepted for compat but treated as TLS 1.2
                opts.easy.ssl_min_version(liburlx::TlsVersion::Tls12);
            }
            "-z" | "--time-cond" => {
                i += 1;
                let val = require_arg(args, i, "-z")?;
                opts.time_cond = Some(val.to_string());
            }
            "--capath" => {
                i += 1;
                let val = require_arg(args, i, "--capath")?;
                // rustls doesn't support CA directories — load all certs from directory
                opts.easy.ssl_ca_cert(std::path::Path::new(val));
            }
            "--variable" => {
                i += 1;
                let val = require_arg(args, i, "--variable")?;
                let (name, value) = parse_variable(val)?;
                // Duplicate variable names override (curl compat: test 451)
                if let Some(existing) = opts.variables.iter_mut().find(|(n, _)| *n == name) {
                    existing.1 = value;
                } else {
                    opts.variables.push((name, value));
                }
            }
            "--expand-data" => {
                i += 1;
                let val = require_arg(args, i, "--expand-data")?;
                let expanded = expand_variables(val, &opts.variables)?;
                opts.easy.body(expanded.as_bytes());
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
            }
            "--expand-url" => {
                i += 1;
                let val = require_arg(args, i, "--expand-url")?;
                let expanded = expand_variables(val, &opts.variables)?;
                opts.urls.push(expanded);
                opts.per_url_credentials.push(opts.user_credentials.clone());
                opts.per_url_easy.push(None);
                opts.per_url_upload_files.push(pending_upload_file.take());
                opts.per_url_custom_request.push(opts.custom_request_original.clone());
                opts.per_url_group.push(opts.group_id);
                opts.next_needs_url = false;
            }
            "--expand-output" => {
                i += 1;
                let val = require_arg(args, i, "--expand-output")?;
                let expanded = expand_variables(val, &opts.variables)?;
                opts.output_file = Some(expanded.clone());
                opts.output_files.push(expanded);
            }
            // No-op flags for compatibility (accepted but not implemented)
            "-N"
            | "--no-buffer"
            | "--no-sessionid"
            | "--no-alpn"
            | "--no-npn"
            | "--cert-status"
            | "--false-start"
            | "--compressed-ssh"
            | "--doh-cert-status"
            | "--ftp-pasv"
            | "--styled-output"
            | "--no-styled-output"
            | "--xattr"
            | "-q"
            | "--disable"
            | "--metalink"
            | "--basic"
            | "--proxy-basic"
            | "--tcp-fastopen"
            | "--ca-native"
            | "--no-ca-native"
            | "--disallow-username-in-url"
            | "--ssl-allow-beast"
            | "--ssl-auto-client-cert"
            | "--ssl-no-revoke"
            | "--ssl-revoke-best-effort"
            | "--proxy-ssl-allow-beast"
            | "--proxy-ssl-auto-client-cert"
            | "--socks5-basic"
            | "--socks5-gssapi"
            | "--ntlm-wb"
            | "--trace-ids"
            | "--socks5-gssapi-nec"
            | "-4"
            | "--ipv4"
            | "-6"
            | "--ipv6"
            | "-j"
            | "--junk-session-cookies" => {}
            // FTP: disable EPRT (use PORT for active mode)
            "--disable-eprt" => {
                opts.easy.ftp_use_eprt(false);
            }
            // FTP: disable EPSV (use PASV for passive mode)
            "--disable-epsv" => {
                opts.easy.ftp_use_epsv(false);
            }
            // FTP: list only (NLST instead of LIST)
            "-l" | "--list-only" => {
                opts.easy.ftp_list_only(true);
            }
            // FTP: ASCII transfer mode
            "-B" | "--use-ascii" => {
                opts.easy.ftp_use_ascii(true);
            }
            // FTP: append to remote file
            "-a" | "--append" => {
                opts.easy.ftp_append(true);
            }
            // FTP: convert LF to CRLF on upload
            "--crlf" => {
                opts.easy.ftp_crlf(true);
            }
            // FTP: active mode with specified address
            "-P" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("curl: -P requires an argument");
                    return Err(1);
                }
                opts.easy.ftp_active_port(&args[i]);
            }
            // FTP quote commands
            "-Q" | "--quote" => {
                i += 1;
                let val = require_arg(args, i, &args[i - 1].clone())?;
                opts.easy.ftp_quote(val);
            }
            // OAuth2 bearer token (alias for --bearer)
            "--oauth2-bearer" => {
                i += 1;
                let val = require_arg(args, i, "--oauth2-bearer")?;
                opts.easy.bearer_token(val);
                opts.use_bearer = true;
            }
            // SSH public key file
            "--pubkey" => {
                i += 1;
                let _val = require_arg(args, i, &args[i - 1].clone())?;
                // Accepted for compat; ssh key auth handled by ssh module
            }
            // SSL crypto engine selection (curl compat: tests 307, 308)
            "--engine" => {
                i += 1;
                let val = require_arg(args, i, &args[i - 1].clone())?;
                match val {
                    // "openssl" and "default" are accepted as no-ops (built-in engine)
                    "list" | "openssl" | "default" => {}
                    _ => {
                        eprintln!("curl: (53) SSL crypto engine '{val}' not found");
                        return Err(53);
                    }
                }
            }
            // No-op flags that take an argument
            "--create-file-mode"
            | "--service-name"
            | "--proxy-service-name"
            | "--proxy-tlsv1"
            | "--proxy-tls13-ciphers"
            | "--proxy-ciphers"
            | "--tls13-ciphers"
            | "--cert-type"
            | "--key-type"
            | "--pass"
            | "--proxy-cert-type"
            | "--proxy-key-type"
            | "--proxy-crlfile"
            | "--proxy-pinnedpubkey"
            | "--proxy-pass"
            | "--curves"
            | "--krb"
            | "--random-file"
            | "--egd-file"
            | "--dns-interface"
            | "--telnet-option"
            | "--proxy-tlsauthtype"
            | "--proxy-tlsuser"
            | "--proxy-tlspassword"
            | "--socks5-gssapi-service"
            | "--ftp-ssl-ccc-mode"
            | "--mail-rcpt-allowfails"
            | "--trace-config" => {
                i += 1;
                let _val = require_arg(args, i, &args[i - 1].clone())?;
                // Accepted for compatibility; not implemented
            }
            "-:" | "--next" => {
                // --next without a preceding URL is an error (curl compat: test 422).
                // But --next at the start of a config file is fine (curl compat: tests 430-432).
                // In config files (config_depth > 0), --next without a URL is silently ignored.
                let has_urls_in_group = opts.urls.len() > opts.group_easy_start;
                if !has_urls_in_group && config_depth == 0 && group_has_options {
                    eprintln!("curl: missing URL before --next");
                    eprintln!("curl: option --next: is badly used here");
                    eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                    return Err(2);
                }
                // If no URLs in current group (e.g., --next at start of config file),
                // skip the group separator logic (curl compat: tests 430-432)
                if !has_urls_in_group {
                    i += 1;
                    continue;
                }

                // --next separates URL groups; assign current group's -u credentials
                // to URLs in the current group (from group_start_idx onwards), then reset.
                let group_creds = opts.user_credentials.clone();
                for cred_slot in opts.per_url_credentials[group_start_idx..].iter_mut() {
                    if cred_slot.is_none() {
                        *cred_slot = group_creds.clone();
                    }
                }
                // Assign current ftp_method to all URLs in the current group
                for slot in opts.per_url_ftp_methods[group_start_idx..].iter_mut() {
                    *slot = current_ftp_method;
                }
                // Apply deferred --json headers to the current group before saving
                // (curl compat: test 386 — json headers must not leak to next group)
                if opts.json_mode {
                    let has_ct = opts.easy.has_header("content-type");
                    let has_accept = opts.easy.has_header("accept");
                    if !has_ct {
                        opts.easy.header("Content-Type", "application/json");
                    }
                    if !has_accept {
                        opts.easy.header("Accept", "application/json");
                    }
                }
                // Save per-URL Easy handles and custom requests for the current group
                let current_easy = opts.easy.clone();
                for slot in opts.per_url_easy[opts.group_easy_start..].iter_mut() {
                    if slot.is_none() {
                        *slot = Some(current_easy.clone());
                    }
                }
                // Update per-URL custom request for URLs in this group that
                // were added before -X was processed (curl compat: tests 815, 816)
                for slot in opts.per_url_custom_request[opts.group_easy_start..].iter_mut() {
                    if slot.is_none() && opts.custom_request_original.is_some() {
                        *slot = opts.custom_request_original.clone();
                    }
                }
                opts.group_easy_start = opts.per_url_easy.len();
                group_start_idx = opts.per_url_credentials.len();
                opts.user_credentials = None;
                current_ftp_method = liburlx::protocol::ftp::FtpMethod::default();
                // Reset per-request state (curl compat: tests 430-432)
                opts.easy.clear_headers();
                opts.easy.clear_body();
                opts.has_post_data = false;
                opts.easy.reset_method();
                opts.easy.clear_custom_request_target();
                opts.easy.set_form_data(false);
                opts.json_mode = false;
                opts.custom_request_original = None;
                opts.next_needs_url = true;
                opts.had_next = true;
                opts.group_id += 1;
                group_has_options = false;
            }
            arg if arg.starts_with("--no-") => {
                // --no- prefix used on a non-boolean option (curl returns exit code 2)
                eprintln!("curl: option {arg}: is unknown");
                eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                return Err(2);
            }
            arg if arg.starts_with("--") => {
                eprintln!("curl: option {arg}: is unknown");
                eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                return Err(2);
            }
            arg if arg.starts_with('-') => {
                eprintln!("curl: option {arg}: is unknown");
                eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
                return Err(2);
            }
            url => {
                opts.urls.push(url.to_string());
                opts.per_url_credentials.push(opts.user_credentials.clone());
                opts.per_url_ftp_methods.push(current_ftp_method);
                opts.per_url_easy.push(None); // Will be filled on --next or at end
                                              // Associate pending -T upload file with this URL (if any)
                opts.per_url_upload_files.push(pending_upload_file.take());
                opts.per_url_custom_request.push(opts.custom_request_original.clone());
                opts.per_url_group.push(opts.group_id);
                opts.next_needs_url = false;
            }
        }
        i += 1;
    }

    // Assign last group's -u credentials to URLs in the last group that weren't assigned yet
    {
        let group_creds = opts.user_credentials.clone();
        for cred_slot in opts.per_url_credentials[group_start_idx..].iter_mut() {
            if cred_slot.is_none() {
                *cred_slot = group_creds.clone();
            }
        }
    }

    // Assign last group's ftp_method to all URLs in the last group
    for slot in opts.per_url_ftp_methods[group_start_idx..].iter_mut() {
        *slot = current_ftp_method;
    }

    // --next at the end with no URL is a parse error (curl returns exit code 2)
    if opts.next_needs_url {
        eprintln!("curl: (2) no URL specified after --next");
        return Err(2);
    }

    // Detect mutually exclusive option combinations (curl compat: tests 481, 482)
    if opts.resume_check && opts.no_clobber {
        eprintln!("curl: --continue-at is mutually exclusive with --no-clobber");
        eprintln!("curl: option -C: is badly used here");
        eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
        return Err(2);
    }
    if opts.resume_check && opts.remove_on_error {
        eprintln!("curl: --continue-at is mutually exclusive with --remove-on-error");
        eprintln!("curl: option -C: is badly used here");
        eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
        return Err(2);
    }

    // Etag options only work with a single URL (curl compat: tests 484, 485).
    // With --next, URLs in different groups don't conflict (test 369).
    if (opts.etag_save_file.is_some() || opts.etag_compare_file.is_some())
        && !opts.had_next
        && opts.urls.len() > 1
    {
        eprintln!("curl: The etag options only work on a single URL");
        eprintln!(
            "curl: option {}: is badly used here",
            opts.etag_conflict_blame.as_deref().unwrap_or("--etag-save")
        );
        eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
        return Err(2);
    }

    // Apply proxy auth credentials before site auth so Proxy-Authorization
    // appears before Authorization in the header order (curl compat).
    if let Some((ref user, ref pass)) = opts.proxy_user {
        if opts.proxy_negotiate {
            opts.easy.proxy_negotiate_auth(user, pass);
        } else if opts.proxy_ntlm {
            opts.easy.proxy_ntlm_auth(user, pass);
        } else if opts.proxy_digest {
            opts.easy.proxy_digest_auth(user, pass);
        } else if opts.proxy_anyauth {
            opts.easy.proxy_anyauth(user, pass);
        } else {
            opts.easy.proxy_auth(user, pass);
        }
    } else if opts.proxy_digest || opts.proxy_ntlm || opts.proxy_anyauth || opts.proxy_negotiate {
        // Proxy credentials were extracted from the URL (in proxy()). Override the auth
        // method if --proxy-digest/--proxy-ntlm/--proxy-anyauth/--proxy-negotiate was specified.
        if let Some(creds) = opts.easy.proxy_credentials_ref() {
            let user = creds.username.clone();
            let pass = creds.password.clone();
            if opts.proxy_negotiate {
                opts.easy.proxy_negotiate_auth(&user, &pass);
            } else if opts.proxy_ntlm {
                opts.easy.proxy_ntlm_auth(&user, &pass);
            } else if opts.proxy_digest {
                opts.easy.proxy_digest_auth(&user, &pass);
            } else if opts.proxy_anyauth {
                opts.easy.proxy_anyauth(&user, &pass);
            }
        }
    }

    // Apply auth credentials after proxy auth (for correct header ordering).
    // Skip when --oauth2-bearer is set — the Bearer token is already in the headers
    // and basic_auth would overwrite it.
    if let Some((ref user, ref pass)) = opts.user_credentials {
        if opts.use_aws_sigv4 {
            opts.easy.aws_credentials(user, pass);
        } else if opts.use_negotiate {
            opts.easy.negotiate_auth(user, pass);
        } else if opts.use_ntlm {
            opts.easy.ntlm_auth(user, pass);
        } else if opts.use_anyauth {
            opts.easy.anyauth(user, pass);
        } else if opts.use_digest {
            opts.easy.digest_auth(user, pass);
        } else if !opts.use_bearer {
            opts.easy.basic_auth(user, pass);
        }
    } else if opts.use_negotiate {
        // --negotiate without -u: use empty credentials (system Kerberos ccache)
        opts.easy.negotiate_auth("", "");
    }
    // Note: netrc credential loading is deferred to run() where the URL is known

    // Assign last group's Easy handle to URLs that weren't assigned yet.
    // This must happen AFTER auth credentials are applied so per-URL Easy
    // handles have correct auth state (curl compat: test 338 — ANYAUTH).
    {
        let current_easy = opts.easy.clone();
        for slot in opts.per_url_easy[opts.group_easy_start..].iter_mut() {
            if slot.is_none() {
                *slot = Some(current_easy.clone());
            }
        }
        // Update per-URL custom request for the last group
        for slot in opts.per_url_custom_request[opts.group_easy_start..].iter_mut() {
            if slot.is_none() && opts.custom_request_original.is_some() {
                *slot = opts.custom_request_original.clone();
            }
        }
    }

    // Apply accumulated inline cookies as a single Cookie header
    if !opts.inline_cookies.is_empty() {
        let cookie_header = opts.inline_cookies.join("; ");
        opts.easy.header("Cookie", &cookie_header);
    }

    // Set output_file from the first collected output file (each -o pairs with a URL by position)
    if !opts.output_files.is_empty() {
        opts.output_file = Some(opts.output_files[0].clone());
        // Warn if more -o options than URLs (curl compat: test 371)
        if opts.output_files.len() > opts.urls.len().max(1) {
            eprintln!("Warning: Got more output options than URLs");
        }
    }

    // Post-processing: add --json Content-Type and Accept headers AFTER all args
    // are parsed, only if they're not already set by -H (curl compat: tests 383, 384).
    // This matches curl's get_args() behavior: --json headers are deferred.
    if opts.json_mode {
        let has_ct = opts.easy.has_header("content-type");
        let has_accept = opts.easy.has_header("accept");
        if !has_ct {
            opts.easy.header("Content-Type", "application/json");
        }
        if !has_accept {
            opts.easy.header("Accept", "application/json");
        }
    }

    Ok(opts)
}

/// Used by `-d @filename` and `--data-binary @filename`.
/// The path `-` reads from stdin.
pub fn read_data_source(path: &str) -> Result<Vec<u8>, std::io::Error> {
    if path == "-" {
        use std::io::Read as _;
        let mut buf = Vec::new();
        let _bytes = std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

/// Encode a string for form-URL-encoding (application/x-www-form-urlencoded).
///
/// Supports the following formats (matching curl):
/// - `content` — encode entire string
/// - `=content` — use content as-is (no encoding)
/// - `name=content` — encode only the content, prepend `name=`
/// - `@filename` — read file, encode contents
/// - `name@filename` — read file, encode contents, prepend `name=`
#[cfg(test)]
pub fn urlencoded(input: &str) -> String {
    // Check for @filename (starts with @)
    if let Some(filename) = input.strip_prefix('@') {
        let data = std::fs::read_to_string(filename).unwrap_or_default();
        return form_urlencode(&data);
    }
    // Check for =content (starts with =) — use as-is
    if let Some(content) = input.strip_prefix('=') {
        return content.to_string();
    }
    // Check for name@filename (has @ before any =)
    if let Some(at_pos) = input.find('@') {
        let eq_pos = input.find('=');
        if eq_pos.is_none() || at_pos < eq_pos.unwrap_or(usize::MAX) {
            let name = &input[..at_pos];
            let filename = &input[at_pos + 1..];
            let data = std::fs::read_to_string(filename).unwrap_or_default();
            return format!("{}={}", name, form_urlencode(&data));
        }
    }
    // name=content or plain content
    if let Some((name, value)) = input.split_once('=') {
        let encoded = form_urlencode(value);
        format!("{name}={encoded}")
    } else {
        form_urlencode(input)
    }
}

/// Handle `--data-urlencode` with full curl syntax (curl compat: test 1015).
///
/// Supported forms:
/// - `content` — URL-encode the entire string
/// - `=content` — URL-encode content (no name prefix)
/// - `name=content` — name is literal, content is URL-encoded
/// - `@filename` — read file, URL-encode entire contents
/// - `name@filename` — name is literal, file contents are URL-encoded as value
fn data_urlencode(input: &str) -> Result<String, u8> {
    // Check for @filename form first (no name prefix)
    if let Some(path) = input.strip_prefix('@') {
        let data = std::fs::read(path).map_err(|e| {
            eprintln!("curl: error reading data file '{path}': {e}");
            1_u8
        })?;
        let s = String::from_utf8_lossy(&data);
        return Ok(curl_urlencode(&s));
    }

    // Check for name@filename form: find @ before any =
    if let Some(at_pos) = input.find('@') {
        let eq_pos = input.find('=');
        if eq_pos.is_none() || at_pos < eq_pos.unwrap_or(usize::MAX) {
            let name = &input[..at_pos];
            let path = &input[at_pos + 1..];
            let data = std::fs::read(path).map_err(|e| {
                eprintln!("curl: error reading data file '{path}': {e}");
                1_u8
            })?;
            let s = String::from_utf8_lossy(&data);
            return Ok(format!("{name}={}", curl_urlencode(&s)));
        }
    }

    // =content form: encode entire content without name
    if let Some(content) = input.strip_prefix('=') {
        return Ok(curl_urlencode(content));
    }

    // name=content form: name is literal, content is URL-encoded
    if let Some((name, content)) = input.split_once('=') {
        return Ok(format!("{name}={}", curl_urlencode(content)));
    }

    // Plain content: URL-encode the entire string
    Ok(curl_urlencode(input))
}

/// URL-encode using curl's convention: spaces become `+`, other special chars
/// become `%XX`. This matches `application/x-www-form-urlencoded` encoding.
pub fn curl_urlencode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => {
                result.push('+');
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX_CHARS[(byte >> 4) as usize]));
                result.push(char::from(HEX_CHARS[(byte & 0x0F) as usize]));
            }
        }
    }
    result
}

/// Percent-encode a string per RFC 3986 (unreserved characters are not encoded).
#[cfg(test)]
pub fn percent_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX_CHARS[(byte >> 4) as usize]));
                result.push(char::from(HEX_CHARS[(byte & 0x0F) as usize]));
            }
        }
    }
    result
}

/// Form-URL-encode a string (application/x-www-form-urlencoded).
///
/// Like `percent_encode` but encodes spaces as `+` instead of `%20`,
/// matching curl's `--data-urlencode` and `--url-query` behavior.
/// Uses lowercase hex digits to match curl's output.
pub fn form_urlencode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => {
                result.push('+');
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX_CHARS_LOWER[(byte >> 4) as usize]));
                result.push(char::from(HEX_CHARS_LOWER[(byte & 0x0F) as usize]));
            }
        }
    }
    result
}

/// Hex lookup table for percent encoding (uppercase, used by `percent_encode`).
const HEX_CHARS: [u8; 16] = *b"0123456789ABCDEF";

/// Hex lookup table for percent encoding (lowercase, used by `form_urlencode`).
const HEX_CHARS_LOWER: [u8; 16] = *b"0123456789abcdef";

/// Extract filename from URL for `-O/--remote-name`.
///
/// Supports suffixes: K/k (1024), M/m (1024*1024), G/g (1024^3).
/// Returns `None` if the value cannot be parsed.
pub fn parse_rate_limit(input: &str) -> Option<u64> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let (num_str, multiplier) = match input.as_bytes().last()? {
        b'k' | b'K' => (&input[..input.len() - 1], 1024_u64),
        b'm' | b'M' => (&input[..input.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&input[..input.len() - 1], 1024 * 1024 * 1024),
        _ => (input, 1_u64),
    };

    num_str.parse::<u64>().ok().map(|n| n * multiplier)
}

/// Parse a .curlrc-style config file into argument strings.
///
/// Config file format:
/// - Lines starting with `#` are comments
/// - Empty lines are ignored
/// - Lines may contain `--flag value`, `--flag=value`, or `-f value`
/// - Values may be quoted with `"` or `'`
/// - Backslash escaping is supported within double quotes
///
/// If `file_path` is provided, emits warnings about unquoted whitespace.
pub fn parse_config_file(contents: &str) -> Vec<String> {
    parse_config_file_with_path(contents, None)
}

/// Parse config file, optionally with a file path for warning messages.
pub fn parse_config_file_with_path(contents: &str, file_path: Option<&str>) -> Vec<String> {
    let mut args = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Helper to check for unquoted whitespace in values and warn
        let warn_unquoted_whitespace = |flag: &str, value: &str| {
            // Only warn if value is unquoted and contains whitespace
            if !value.starts_with('"') && !value.starts_with('\'') && value.contains(' ') {
                if let Some(path) = file_path {
                    eprintln!(
                        "Warning: {path}:{} Option '{}' uses argument with unquoted whitespace. ",
                        line_num + 1,
                        flag
                    );
                    eprintln!("Warning: This may cause side-effects. Consider double quotes.");
                }
            }
        };

        // Handle --flag syntax
        if let Some(rest) = trimmed.strip_prefix("--") {
            // Check for = in the flag name only (before any whitespace)
            // This distinguishes `--flag=value` from `--flag value_with_=`
            let first_ws = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let eq_in_flag = rest[..first_ws].find('=');
            if let Some(eq_pos) = eq_in_flag {
                let flag = &rest[..eq_pos];
                let value = rest[eq_pos + 1..].trim();
                args.push(format!("--{flag}"));
                warn_unquoted_whitespace(flag, value);
                // For unquoted values with whitespace, only take the first word (curl compat: test 459)
                let effective_value = if !value.starts_with('"') && !value.starts_with('\'') {
                    value.split_whitespace().next().unwrap_or(value)
                } else {
                    value
                };
                args.push(unquote(effective_value));
            } else {
                // --flag or --flag value
                let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();
                args.push(format!("--{}", parts[0]));
                if parts.len() > 1 {
                    let value = parts[1].trim();
                    if !value.is_empty() {
                        args.push(unquote(value));
                    }
                }
            }
            continue;
        }

        // Handle -f syntax (short flags)
        if trimmed.starts_with('-') {
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            args.push(parts[0].to_string());
            if parts.len() > 1 {
                let value = parts[1].trim();
                if !value.is_empty() {
                    args.push(unquote(value));
                }
            }
            continue;
        }

        // Bare word (no leading dash) → treat as --longflag (curl config convention)
        // Handle both `flag value` and `flag = value` syntax (with optional = separator)
        if let Some(eq_pos) = trimmed.find('=') {
            let flag = trimmed[..eq_pos].trim();
            let value = trimmed[eq_pos + 1..].trim();
            args.push(format!("--{flag}"));
            if !value.is_empty() {
                warn_unquoted_whitespace(flag, value);
                // For unquoted values with whitespace, only take the first word
                let effective_value = if !value.starts_with('"') && !value.starts_with('\'') {
                    value.split_whitespace().next().unwrap_or(value)
                } else {
                    value
                };
                args.push(unquote(effective_value));
            }
        } else {
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            args.push(format!("--{}", parts[0]));
            if parts.len() > 1 {
                let value = parts[1].trim();
                if !value.is_empty() {
                    args.push(unquote(value));
                }
            }
        }
    }
    args
}

/// Remove surrounding quotes from a config file value and process escape sequences.
///
/// Double-quoted strings process `\t`, `\n`, `\r`, `\\`, `\"`.
/// Single-quoted strings are returned as-is (no escape processing).
pub fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        if bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
            // Double-quoted: process escape sequences
            let inner = &s[1..s.len() - 1];
            return unescape(inner);
        }
        if bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
            // Single-quoted: no escape processing
            return s[1..s.len() - 1].to_string();
        }
    }
    // Unquoted: also process escape sequences (curl config behavior)
    unescape(s)
}

/// Process backslash escape sequences in a string (curl config file convention).
fn unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => result.push('\t'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('\\') | None => result.push('\\'),
                Some('"') => result.push('"'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse a `-F name=value` form field (simple wrapper for backward compatibility).
#[allow(dead_code)]
fn parse_form_field(easy: &mut liburlx::Easy, val: &str) -> Result<(), String> {
    let mut stack = Vec::new();
    parse_form_field_ext(easy, val, &mut stack, false)
}

/// Parse a `-F name=value` form field with full curl MIME API syntax.
///
/// Supports:
/// - `name=value` — text field
/// - `name=@filepath` — file upload
/// - `name=@filepath;type=mime` — file with custom Content-Type
/// - `name=@filepath;filename=custom` — file with custom filename
/// - `name=@"filepath"` — quoted file path
/// - `=(;type=multipart/alternative` — open nested multipart container
/// - `=)` — close nested multipart container
/// - `;encoder=base64` — Content-Transfer-Encoding
/// - `;headers=Header: value` — custom part header
/// - `;headers=@file` or `;headers=<file` — headers from file
#[allow(clippy::too_many_lines)]
fn parse_form_field_ext(
    easy: &mut liburlx::Easy,
    val: &str,
    container_stack: &mut Vec<usize>,
    _form_string: bool,
) -> Result<(), String> {
    let (name, value) =
        val.split_once('=').ok_or_else(|| format!("invalid form field format: {val}"))?;

    // Handle multipart container open: "=(;type=multipart/alternative"
    if let Some(rest) = value.strip_prefix('(') {
        let mut content_type = "multipart/mixed".to_string();
        // Parse modifiers after '('
        if let Some(mods) = rest.strip_prefix(';') {
            let parts: Vec<&str> = mods.split(';').collect();
            for part in parts {
                let trimmed = part.trim();
                if let Some(t) = trimmed.strip_prefix("type=") {
                    content_type = t.to_string();
                }
            }
        }
        let idx = easy.form_open_container(&content_type);
        container_stack.push(idx);
        return Ok(());
    }

    // Handle multipart container close: "=)"
    if value == ")" {
        if container_stack.is_empty() {
            return Err("unmatched =) — no open multipart container".to_string());
        }
        let _ = container_stack.pop();
        return Ok(());
    }

    if let Some(rest) = value.strip_prefix('@') {
        // File upload — parse filepath and optional modifiers
        let file_specs = split_comma_file_specs(rest);

        if file_specs.len() > 1 {
            // Multi-file: create a multipart/mixed sub-part
            let mut files: Vec<(String, String, Vec<u8>)> = Vec::new();
            for spec in file_specs {
                let (filepath, modifiers) = parse_form_file_spec(spec);
                let mut custom_type: Option<String> = None;
                for modifier in modifiers {
                    if let Some(t) = modifier.strip_prefix("type=") {
                        custom_type = Some(t.to_string());
                    }
                }
                let data = std::fs::read(&filepath)
                    .map_err(|e| format!("error reading form file: {e}"))?;
                let original_filename = std::path::Path::new(&filepath)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let ct = custom_type
                    .unwrap_or_else(|| liburlx::guess_form_content_type(&original_filename));
                files.push((original_filename, ct, data));
            }
            easy.form_multi_file(name, files);
        } else {
            // Single file
            let (filepath, modifiers) = parse_form_file_spec(rest);

            let mut custom_type: Option<String> = None;
            let mut custom_filename: Option<String> = None;
            let mut custom_headers: Vec<String> = Vec::new();
            let mut encoder: Option<String> = None;

            for modifier in modifiers {
                if let Some(t) = modifier.strip_prefix("type=") {
                    custom_type = Some(t.to_string());
                } else if let Some(f) = modifier.strip_prefix("filename=") {
                    custom_filename = Some(unescape_form_filename(f));
                } else if let Some(f) = modifier.strip_prefix("format=") {
                    if let Some(ref mut ct) = custom_type {
                        ct.push_str(";format=");
                        ct.push_str(f);
                    }
                } else if let Some(h) = modifier.strip_prefix("headers=") {
                    parse_headers_modifier(h, &mut custom_headers)?;
                } else if let Some(e) = modifier.strip_prefix("encoder=") {
                    encoder = Some(e.to_string());
                }
            }

            // Read the file (or stdin for @-)
            let data = if filepath == "-" {
                use std::io::Read as _;
                let mut buf = Vec::new();
                let _bytes = std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("error reading stdin: {e}"))?;
                buf
            } else {
                std::fs::read(&filepath).map_err(|e| format!("error reading form file: {e}"))?
            };

            let original_filename = std::path::Path::new(&filepath)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let has_custom_filename = custom_filename.is_some();
            let display_filename = custom_filename.unwrap_or_else(|| original_filename.clone());

            if custom_headers.is_empty() && encoder.is_none() && container_stack.is_empty() {
                // Simple path — use existing API
                if let Some(ref ct) = custom_type {
                    easy.form_file_with_type(name, &display_filename, ct, &data);
                } else if has_custom_filename {
                    // Custom filename but no explicit type — guess content type from
                    // original filename, not the display filename (curl compat: test 39).
                    let guessed = liburlx::guess_form_content_type(&original_filename);
                    easy.form_file_with_type(name, &display_filename, &guessed, &data);
                } else {
                    // No explicit type — use form_file_data which sets explicit_type=false.
                    // In SMTP/IMAP mode, Content-Type is only output for explicit types.
                    // For HTTP, Content-Type is always output (explicit_type=false still
                    // outputs a guessed type in the non-SMTP encode path).
                    easy.form_file_data(name, &display_filename, &data);
                }
            } else if let Some(&container_idx) = container_stack.last() {
                // Inside a nested container
                easy.form_add_to_container(
                    container_idx,
                    &data,
                    custom_type.as_deref(),
                    Some(&display_filename),
                    custom_headers,
                    encoder.as_deref(),
                );
            } else {
                // Top-level part with custom headers/encoder
                easy.form_add_with_options(
                    name,
                    &data,
                    custom_type.as_deref(),
                    Some(&display_filename),
                    custom_headers,
                    encoder.as_deref(),
                );
            }
        }
    } else if let Some(rest) = value.strip_prefix('<') {
        // Read field value from file: name=<filepath or name=<filepath;type=mime
        let (filepath, modifiers) = parse_form_file_spec(rest);

        let mut custom_type: Option<&str> = None;
        for modifier in &modifiers {
            if let Some(t) = modifier.strip_prefix("type=") {
                custom_type = Some(t);
            }
        }

        let data = std::fs::read_to_string(&filepath)
            .map_err(|e| format!("error reading form file: {e}"))?;

        if let Some(ct) = custom_type {
            easy.form_field_with_type(name, &data, ct);
        } else {
            easy.form_field(name, &data);
        }
    } else {
        // Text field — parse value and optional modifiers (;type=, ;filename=)
        // The value can be quoted: "..." — in which case the closing quote ends the value
        // and modifiers follow after a `;`.
        let (raw_value, modifiers) = parse_text_value_and_modifiers(value);
        // curl strips leading whitespace from unquoted text field values (curl compat: tests 186, 646)
        let field_value =
            if value.starts_with('"') { raw_value } else { raw_value.trim_start().to_string() };

        let mut custom_type: Option<String> = None;
        let mut custom_filename: Option<String> = None;
        let mut custom_headers: Vec<String> = Vec::new();
        let mut encoder: Option<String> = None;

        for modifier in &modifiers {
            let trimmed = modifier.trim();
            if let Some(t) = trimmed.strip_prefix("type=") {
                custom_type = Some(t.to_string());
            } else if let Some(f) = trimmed.strip_prefix("filename=") {
                custom_filename = Some(unescape_form_filename(f));
            } else if let Some(h) = trimmed.strip_prefix("headers=") {
                parse_headers_modifier(h, &mut custom_headers)?;
            } else if let Some(e) = trimmed.strip_prefix("encoder=") {
                encoder = Some(e.to_string());
            }
        }

        // Merge type sub-parameters: e.g., "type=text/html;charset=utf-8" where
        // charset= is a Content-Type parameter, not a form modifier.
        // curl treats unknown modifiers after type= as Content-Type sub-params
        // and joins them with `;` (no space) matching the original input (curl compat: test 186).
        if let Some(ref mut ct) = custom_type {
            for modifier in &modifiers {
                let trimmed = modifier.trim();
                if !trimmed.starts_with("type=")
                    && !trimmed.starts_with("filename=")
                    && !trimmed.starts_with("format=")
                    && !trimmed.starts_with("headers=")
                    && !trimmed.starts_with("encoder=")
                    && !trimmed.is_empty()
                {
                    // Unknown modifier after type — append as Content-Type sub-param.
                    // Preserve original spacing (curl compat: test 186 has no space,
                    // test 1133 has space after semicolon).
                    ct.push(';');
                    ct.push_str(modifier);
                }
            }
        }

        if !container_stack.is_empty() {
            // Inside a nested container — add as subpart
            let container_idx = *container_stack.last().unwrap_or(&0);
            easy.form_add_to_container(
                container_idx,
                field_value.as_bytes(),
                custom_type.as_deref(),
                custom_filename.as_deref(),
                custom_headers,
                encoder.as_deref(),
            );
        } else if !custom_headers.is_empty() || encoder.is_some() {
            // Top-level with custom headers/encoder
            easy.form_add_with_options(
                name,
                field_value.as_bytes(),
                custom_type.as_deref(),
                custom_filename.as_deref(),
                custom_headers,
                encoder.as_deref(),
            );
        } else if let Some(ref filename) = custom_filename {
            if let Some(ref ct) = custom_type {
                easy.form_file_with_type(name, filename, ct, field_value.as_bytes());
            } else {
                easy.form_file_no_type(name, filename, field_value.as_bytes());
            }
        } else if let Some(ref ct) = custom_type {
            easy.form_field_with_type(name, &field_value, ct);
        } else {
            easy.form_field(name, &field_value);
        }
    }

    Ok(())
}

/// Parse a `headers=` modifier value.
///
/// Supports:
/// - `headers=Header-Name: value` — inline header
/// - `headers=@filename` or `headers=<filename` — headers from file
fn parse_headers_modifier(value: &str, headers: &mut Vec<String>) -> Result<(), String> {
    if let Some(path) = value.strip_prefix('@').or_else(|| value.strip_prefix('<')) {
        // Headers from file
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("error reading headers file: {e}"))?;
        read_header_file_contents(&contents, headers);
    } else {
        // Inline header
        headers.push(value.to_string());
    }
    Ok(())
}

/// Read headers from file contents (curl format).
///
/// Lines starting with `#` are comments. Header folding (continuation with space/tab)
/// is supported. Blank lines are ignored.
fn read_header_file_contents(contents: &str, headers: &mut Vec<String>) {
    let mut current_header: Option<String> = None;

    for line in contents.lines() {
        // Skip comment lines (starting with #)
        if line.starts_with('#') {
            continue;
        }
        // Skip empty lines
        if line.trim().is_empty() {
            // Flush current header
            if let Some(h) = current_header.take() {
                headers.push(h);
            }
            continue;
        }
        // Folded header (continuation line starts with space or tab)
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref mut h) = current_header {
                // Fold: join with single space, trim the leading whitespace from continuation
                h.push(' ');
                h.push_str(line.trim());
                continue;
            }
        }
        // New header — flush previous
        if let Some(h) = current_header.take() {
            headers.push(h);
        }
        // Strip trailing whitespace and \r
        let trimmed = line.trim_end().trim_end_matches('\r');
        current_header = Some(trimmed.to_string());
    }
    // Flush last header
    if let Some(h) = current_header {
        headers.push(h);
    }
}

/// Split comma-separated file specs, respecting quoted paths.
///
/// E.g., `"file1.txt",file2.txt;type=foo,"file3.txt"` →
/// `["\"file1.txt\"", "file2.txt;type=foo", "\"file3.txt\""]`
fn split_comma_file_specs(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && in_quote && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == b'"' {
            in_quote = !in_quote;
            i += 1;
        } else if bytes[i] == b',' && !in_quote {
            parts.push(&s[start..i]);
            start = i + 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Parse a text value and its modifiers from a form field value string.
///
/// The value can be:
/// - A quoted string: `"value with ;special chars"` followed by `;type=...`
/// - An unquoted string: `value;type=...`
///
/// Returns `(value, modifiers)` where modifiers are the `;`-separated parts.
fn parse_text_value_and_modifiers(s: &str) -> (String, Vec<String>) {
    if let Some(inner) = s.strip_prefix('"') {
        // Quoted value — find closing quote (respecting backslash escapes)
        let mut end = 0;
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                end += c.len_utf8();
                if let Some(next) = chars.next() {
                    end += next.len_utf8();
                }
            } else if c == '"' {
                break;
            } else {
                end += c.len_utf8();
            }
        }
        let raw_value = &inner[..end];
        // Unescape the value
        let value = unescape_form_value(raw_value);
        let rest = &inner[end..];
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        // Parse modifiers from the rest (;-separated)
        let modifiers = if rest.is_empty() { vec![] } else { split_modifiers_owned(rest) };
        (value, modifiers)
    } else {
        // Unquoted value — find first unquoted `;` followed by a known modifier
        // (type=, filename=, format=)
        if let Some(pos) = find_first_modifier_semicolon(s) {
            let value = s[..pos].to_string();
            let rest = &s[pos..]; // includes the leading `;`
            let modifiers = split_modifiers_owned(rest);
            (value, modifiers)
        } else {
            (s.to_string(), vec![])
        }
    }
}

/// Find the position of the first `;` that starts a known modifier.
fn find_first_modifier_semicolon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b';' {
            let rest = s[i + 1..].trim_start();
            if rest.starts_with("type=")
                || rest.starts_with("filename=")
                || rest.starts_with("format=")
                || rest.starts_with("headers=")
                || rest.starts_with("encoder=")
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Split modifiers on `;`, returning owned strings. Handles quoted values.
fn split_modifiers_owned(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && in_quote && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == b'"' {
            in_quote = !in_quote;
            i += 1;
        } else if bytes[i] == b';' && !in_quote {
            // Preserve leading whitespace (needed for Content-Type sub-params
            // like "; charset=utf-8"), only trim trailing whitespace.
            let part = s[start..i].trim_end().to_string();
            if !part.trim().is_empty() {
                parts.push(part);
            }
            start = i + 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    let part = s[start..].trim_end().to_string();
    if !part.trim().is_empty() {
        parts.push(part);
    }
    parts
}

/// Unescape a form value string (from inside quotes).
fn unescape_form_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    '\\' | '"' => {
                        result.push(next);
                        let _ = chars.next();
                    }
                    _ => {
                        result.push('\\');
                    }
                }
            } else {
                result.push('\\');
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Split a modifier string on `;` while respecting quoted values.
///
/// For example: `type=foo;filename="a;b"` → `["type=foo", "filename=\"a;b\""]`
fn split_modifiers(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' && in_quote && i + 1 < bytes.len() {
            i += 2; // skip escaped char
        } else if bytes[i] == b'"' {
            in_quote = !in_quote;
            i += 1;
        } else if bytes[i] == b';' && !in_quote {
            let part = s[start..i].trim();
            if !part.is_empty() {
                parts.push(part);
            }
            start = i + 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    let part = s[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

/// Parse a form file spec, extracting filepath and modifiers.
///
/// Handles quoted paths: `"path";type=foo` and unquoted: `path;type=foo`.
#[allow(clippy::option_if_let_else)] // if-let is clearer here
fn parse_form_file_spec(spec: &str) -> (String, Vec<&str>) {
    if let Some(inner) = spec.strip_prefix('"') {
        // Quoted path — find the closing quote (handling escaped quotes)
        let mut end = 0;
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                end += c.len_utf8();
                if let Some(next) = chars.next() {
                    end += next.len_utf8();
                }
            } else if c == '"' {
                break;
            } else {
                end += c.len_utf8();
            }
        }
        let path = &inner[..end];
        // Unescape backslashes in the path
        let unescaped_path = path.replace("\\\"", "\"").replace("\\\\", "\\");
        let rest = &inner[end..];
        // Skip closing quote
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        let modifiers = split_modifiers(rest);
        (unescaped_path, modifiers)
    } else {
        // Unquoted — split on first ; to get filepath
        let parts: Vec<&str> = spec.splitn(2, ';').collect();
        let filepath = parts[0].to_string();
        let modifiers = if parts.len() > 1 { split_modifiers(parts[1]) } else { vec![] };
        (filepath, modifiers)
    }
}

/// Unescape backslash sequences in form filenames per curl's rules.
fn unescape_form_filename(s: &str) -> String {
    // Handle quoted filenames
    let s =
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 { &s[1..s.len() - 1] } else { s };

    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    '\\' | '"' => {
                        result.push(next);
                        let _ = chars.next();
                    }
                    _ => {
                        // Keep the backslash — curl keeps literal backslash for unknown escapes
                        result.push('\\');
                    }
                }
            } else {
                result.push('\\');
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub fn require_arg<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, u8> {
    if i >= args.len() {
        eprintln!("curl: option {flag}: requires parameter");
        eprintln!("curl: try 'curl --help' or 'curl --manual' for more information");
        Err(2)
    } else {
        Ok(&args[i])
    }
}

/// Check if a string starts with a leading Unicode character (UTF-8 E2 80 xx).
///
/// curl warns about these to help users who accidentally paste text with
/// "smart quotes" (curly quotes) or other Unicode punctuation from word processors.
/// Matches curl's `has_leading_unicode()`: checks for E2 80 + high-bit byte.
/// (curl compat: tests 469, 470)
fn has_leading_unicode(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 3 && bytes[0] == 0xE2 && bytes[1] == 0x80 && (bytes[2] & 0x80) != 0
}

/// Emit a warning about a leading Unicode character in an argument value.
///
/// Uses curl's `voutf` wrapping logic: `"Warning: "` prefix on each line,
/// line break at terminal width (79 in tests). The format string is:
/// `"The argument '%s' starts with a Unicode character. Maybe ASCII was intended?"`
fn warn_unicode_quote(s: &str) {
    if has_leading_unicode(s) {
        let msg = format!(
            "The argument '{}' starts with a Unicode character. Maybe ASCII was intended?",
            s
        );
        warnf_wrapped(&msg);
    }
}

/// Emit a warning message with curl-compatible line wrapping.
///
/// Matches curl's `voutf()` behavior: wraps at terminal width (79) minus
/// prefix length (9 for "Warning: "), breaking at the last blank character
/// before the wrap point. Each continuation line gets the same prefix.
fn warnf_wrapped(msg: &str) {
    let prefix = "Warning: ";
    let term_width: usize = 79;
    let prefw = prefix.len();
    let width = if term_width > prefw { term_width - prefw } else { usize::MAX };

    let bytes = msg.as_bytes();
    let mut pos: usize = 0;
    let len = bytes.len();

    while pos < len {
        let remaining = len - pos;
        if remaining > width {
            // Find last blank before width-1
            let mut cut = width - 1;
            while cut > 0 && bytes[pos + cut] != b' ' && bytes[pos + cut] != b'\t' {
                cut -= 1;
            }
            if cut == 0 {
                // No blank found, hard break at width-1
                cut = width - 1;
            }
            // Write prefix + content up to and including the blank
            eprint!("{prefix}");
            let slice = &msg[pos..=pos + cut];
            eprintln!("{slice}");
            pos += cut + 1;
        } else {
            // Last segment: write prefix + remaining
            eprint!("{prefix}");
            eprintln!("{}", &msg[pos..]);
            pos = len;
        }
    }
}

/// Warn if a filename argument looks like a flag (starts with `-`).
///
/// curl emits this warning when a file-type option receives a value
/// that looks like a command-line flag.
/// (curl compat: test 1268)
fn warn_filename_like_flag(val: &str) {
    if val.starts_with('-') && val.len() > 1 {
        warnf_wrapped(&format!("The filename argument '{}' looks like a flag.", val));
    }
}

/// Check if a URL's protocol is in the allowed protocol list.
///
/// Protocol list format matches curl: comma-separated protocol names,
/// optionally prefixed with `=` for exact set (e.g., `=http,https`).
#[allow(dead_code)]
pub fn is_protocol_allowed(url: &str, proto_list: &str) -> bool {
    let scheme = url.split("://").next().unwrap_or("").to_lowercase();
    if scheme.is_empty() {
        return false;
    }

    let list = proto_list.strip_prefix('=').unwrap_or(proto_list);
    list.split(',').any(|p| p.trim().eq_ignore_ascii_case(&scheme))
}

/// Parse a `--proto` / `--proto-redir` protocol specification.
///
/// Supports the curl protocol specification syntax:
///   - `=proto1,proto2` — only these protocols
///   - `+proto` — add to default set
///   - `-proto` — remove from default set
///   - `all,-proto` — all minus specific protocols
///
/// Returns the list of allowed protocol names (lowercase).
pub fn parse_proto_spec(spec: &str) -> Vec<String> {
    let all_protocols: &[&str] = &[
        "http", "https", "ftp", "ftps", "scp", "sftp", "imap", "imaps", "ipfs", "ipns", "ldap",
        "ldaps", "pop3", "pop3s", "smtp", "smtps", "dict", "file", "tftp", "mqtt", "rtsp", "ws",
        "wss", "gopher", "gophers",
    ];

    // "=proto1,proto2" means exactly these protocols
    if let Some(rest) = spec.strip_prefix('=') {
        return rest
            .split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect();
    }

    // Start with all protocols, then apply +/- modifiers
    let mut allowed: Vec<String> = all_protocols.iter().map(|s| s.to_string()).collect();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(proto) = part.strip_prefix('+') {
            if proto.eq_ignore_ascii_case("all") {
                // +all means add all protocols
                allowed = all_protocols.iter().map(|s| s.to_string()).collect();
            } else {
                let proto = proto.to_lowercase();
                if !allowed.contains(&proto) {
                    allowed.push(proto);
                }
            }
        } else if let Some(proto) = part.strip_prefix('-') {
            if proto.eq_ignore_ascii_case("all") {
                // -all means remove all protocols
                allowed.clear();
            } else {
                let proto = proto.to_lowercase();
                allowed.retain(|p| p != &proto);
            }
        } else if part.eq_ignore_ascii_case("all") {
            allowed = all_protocols.iter().map(|s| s.to_string()).collect();
        } else {
            // Bare protocol name: treat as "add"
            let proto = part.to_lowercase();
            if !allowed.contains(&proto) {
                allowed.push(proto);
            }
        }
    }

    allowed
}

/// Parse a `--variable` argument.
///
/// Formats:
///   - `name=value` — direct assignment
///   - `name@file` — load from file (binary)
///   - `name@-` — load from stdin
///   - `name[start-end]=value` — byte range from direct value
///   - `name[start-end]@file` — byte range from file
///   - `name[start-]@file` — byte range from start to end of data
///   - `%ENV` — load from environment variable ENV
///   - `%ENV=default` — load from env var, fallback to default if unset
///
/// Returns `(name, value_bytes)` after applying byte range if specified.
fn parse_variable(spec: &str) -> Result<(String, Vec<u8>), u8> {
    // Check for %ENV syntax (environment variable)
    if let Some(env_spec) = spec.strip_prefix('%') {
        // Split on '=' for default value
        let (env_name, default_value) = env_spec
            .split_once('=')
            .map_or((env_spec, None), |(name, default)| (name, Some(default)));
        // Look up the environment variable
        if let Ok(val) = std::env::var(env_name) {
            return Ok((env_name.to_string(), val.into_bytes()));
        }
        if let Some(default) = default_value {
            return Ok((env_name.to_string(), default.as_bytes().to_vec()));
        }
        // Missing env var without default is an error (curl compat: test 462)
        eprintln!("curl: variable: importing \"{env_name}\" failed, and no default was given");
        return Err(2);
    }

    // Parse optional byte range: name[start-end]
    let (name, byte_range, rest) = if let Some(bracket_start) = spec.find('[') {
        let bracket_end = spec[bracket_start..].find(']').map(|p| bracket_start + p);
        if let Some(bracket_end) = bracket_end {
            let name = &spec[..bracket_start];
            let range_str = &spec[bracket_start + 1..bracket_end];
            let rest = &spec[bracket_end + 1..];
            // Parse range: "start-end" or "start-"
            let range = if let Some((s, e)) = range_str.split_once('-') {
                let start: usize = s.parse().map_err(|_| {
                    eprintln!("curl: invalid byte range start: {s}");
                    2
                })?;
                let end: Option<usize> = if e.is_empty() {
                    None
                } else {
                    Some(e.parse().map_err(|_| {
                        eprintln!("curl: invalid byte range end: {e}");
                        2
                    })?)
                };
                Some((start, end))
            } else {
                eprintln!("curl: invalid byte range: {range_str}");
                return Err(2);
            };
            (name.to_string(), range, rest)
        } else {
            (spec.to_string(), None, "")
        }
    } else {
        (spec.to_string(), None, "")
    };

    // Parse value source: =value or @file
    let raw_value: Vec<u8> = if let Some(rest) = rest.strip_prefix('=') {
        rest.as_bytes().to_vec()
    } else if let Some(rest) = rest.strip_prefix('@') {
        if rest == "-" {
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut buf);
            buf
        } else {
            std::fs::read(rest).map_err(|e| {
                eprintln!("curl: can't read variable file '{rest}': {e}");
                2
            })?
        }
    } else if byte_range.is_none() {
        // No range and no = or @ — check the original spec for = or @
        if let Some(eq_pos) = name.find('=') {
            let (n, v) = name.split_at(eq_pos);
            return Ok((n.to_string(), v.as_bytes()[1..].to_vec()));
        }
        if let Some(at_pos) = name.find('@') {
            let (n, f) = name.split_at(at_pos);
            let file = &f[1..];
            let content: Vec<u8> = if file == "-" {
                use std::io::Read as _;
                let mut buf = Vec::new();
                let _ = std::io::stdin().read_to_end(&mut buf);
                buf
            } else {
                std::fs::read(file).map_err(|e| {
                    eprintln!("curl: can't read variable file '{file}': {e}");
                    2
                })?
            };
            return Ok((n.to_string(), content));
        }
        // No value source specified — empty value
        Vec::new()
    } else {
        Vec::new()
    };

    // Apply byte range
    let value = if let Some((start, end)) = byte_range {
        if start >= raw_value.len() {
            Vec::new()
        } else {
            let end = end.map_or(raw_value.len() - 1, |e| e.min(raw_value.len() - 1));
            raw_value[start..=end].to_vec()
        }
    } else {
        raw_value
    };

    Ok((name, value))
}

/// Expand `{{variable}}` placeholders in a string using the provided variables.
/// Simple base64 encoder (no external dependency needed).
fn simple_base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Apply a single transform function to a value (as bytes).
///
/// Returns `Ok(transformed)` or `Err(2)` for unknown functions.
fn apply_variable_function(value: &[u8], func: &str) -> Result<Vec<u8>, u8> {
    match func {
        "trim" => {
            // Trim ASCII whitespace from both ends
            let start = value.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(value.len());
            let end = value.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
            Ok(value[start..end].to_vec())
        }
        "url" | "urlencode" => {
            let mut s = String::with_capacity(value.len());
            for &byte in value {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        s.push(byte as char);
                    }
                    _ => {
                        s.push('%');
                        s.push(char::from(HEX_CHARS[(byte >> 4) as usize]));
                        s.push(char::from(HEX_CHARS[(byte & 0x0F) as usize]));
                    }
                }
            }
            Ok(s.into_bytes())
        }
        "b64" | "base64" => Ok(simple_base64_encode(value).into_bytes()),
        "64dec" | "b64dec" | "base64dec" => {
            // Base64 decode — if input is invalid base64, return "[64dec-fail]"
            // (curl compat: test 487)
            match strict_base64_decode(value) {
                Some(decoded) => Ok(decoded),
                None => Ok(b"[64dec-fail]".to_vec()),
            }
        }
        "json" => {
            // JSON string escaping (no wrapping quotes — curl compat).
            // Operates on raw bytes: non-ASCII bytes are passed through as-is
            // to preserve UTF-8 multibyte sequences (curl compat: test 268).
            let mut out = Vec::with_capacity(value.len());
            for &byte in value {
                match byte {
                    b'"' => out.extend_from_slice(b"\\\""),
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'\t' => out.extend_from_slice(b"\\t"),
                    b if b < 0x20 => {
                        let hex = format!("\\u{b:04x}");
                        out.extend_from_slice(hex.as_bytes());
                    }
                    b => out.push(b),
                }
            }
            Ok(out)
        }
        _ => {
            eprintln!("curl: unknown variable function: {func}");
            Err(2)
        }
    }
}

/// Strict base64 decoder that returns `None` if input contains invalid characters.
/// Used by `{{var:64dec}}` to detect bad input (curl compat: test 487).
fn strict_base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    // Check that all non-whitespace, non-padding characters are valid base64
    for &b in data {
        if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
            continue;
        }
        if !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/') {
            return None;
        }
    }
    Some(simple_base64_decode(data))
}

/// Simple base64 decoder.
fn simple_base64_decode(data: &[u8]) -> Vec<u8> {
    const fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut result = Vec::with_capacity(data.len() * 3 / 4);
    let filtered: Vec<u8> = data
        .iter()
        .copied()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    for chunk in filtered.chunks(4) {
        let mut buf = [0u8; 4];
        let mut count = 0;
        for &b in chunk {
            if let Some(v) = decode_char(b) {
                buf[count] = v;
                count += 1;
            }
        }
        if count >= 2 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if count >= 3 {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if count >= 4 {
            result.push((buf[2] << 6) | buf[3]);
        }
    }
    result
}

/// Maximum variable name length (curl uses 128).
const MAX_VARIABLE_NAME_LEN: usize = 128;

fn expand_variables(template: &str, variables: &[(String, Vec<u8>)]) -> Result<String, u8> {
    let mut result = String::with_capacity(template.len());
    let mut i = 0;
    let bytes = template.as_bytes();
    while i < bytes.len() {
        // Check for backslash-escaped {{ → literal {{
        if i + 2 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'{' && bytes[i + 2] == b'{'
        {
            result.push_str("{{");
            i += 3;
            // Find the closing }} and output it literally too
            if let Some(end) = template[i..].find("}}") {
                result.push_str(&template[i..i + end + 2]);
                i += end + 2;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find closing }}
            if let Some(end) = template[i + 2..].find("}}") {
                let inner = &template[i + 2..i + 2 + end];

                // Empty inner → leave as literal {{}} (curl compat: test 428)
                if inner.is_empty() {
                    result.push_str("{{}}");
                    i += 2 + end + 2;
                    continue;
                }

                // Variable name length check (>=128 chars → leave unexpanded, curl compat: test 429/448)
                let var_name = inner.split(':').next().unwrap_or(inner);
                if var_name.len() >= MAX_VARIABLE_NAME_LEN {
                    result.push_str(&template[i..i + 2 + end + 2]);
                    i += 2 + end + 2;
                    continue;
                }

                // Parse function chain: name:func1:func2:...
                let parts: Vec<&str> = inner.splitn(2, ':').collect();
                let var_name = parts[0];
                let func_chain_str = if parts.len() > 1 { parts[1] } else { "" };

                // Validate function chain: split by ':' and validate each
                let functions: Vec<&str> = if func_chain_str.is_empty() {
                    Vec::new()
                } else {
                    func_chain_str.split(':').collect()
                };

                // Check for invalid function separators (commas etc.)
                for func in &functions {
                    if func.contains(',') || func.contains(';') || func.contains(' ') {
                        eprintln!("curl: bad function in variable expansion");
                        return Err(2);
                    }
                }

                if let Some((_, value)) = variables.iter().find(|(n, _)| n == var_name) {
                    let mut current_value: Vec<u8> = value.clone();

                    // Apply function chain
                    for func in &functions {
                        current_value = apply_variable_function(&current_value, func)?;
                    }

                    // If no functions applied (raw expansion), check for null bytes
                    if functions.is_empty() && current_value.contains(&0) {
                        eprintln!("curl: (2) expanded variable contains null bytes");
                        return Err(2);
                    }

                    result.push_str(&String::from_utf8_lossy(&current_value));
                } else if inner.contains('.') {
                    // Variables with dots (like {{not.good}}) are left as-is (curl compat: test 428)
                    result.push_str(&template[i..i + 2 + end + 2]);
                }
                // Else: undefined variable — expand to empty string
                i += 2 + end + 2;
                continue;
            }
            // No closing }} found → leave the {{ and rest as literal (unbalanced braces)
            result.push_str(&template[i..]);
            break;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::process::ExitCode;

    use super::*;
    use crate::output::*;
    use crate::transfer::*;

    /// Helper to extract `CliOptions` from `ParseResult`, panicking if not Options.
    fn unwrap_opts(result: ParseResult) -> CliOptions {
        match result {
            ParseResult::Options(opts) => *opts,
            ParseResult::Help => panic!("expected Options, got Help"),
            ParseResult::Version => panic!("expected Options, got Version"),
            ParseResult::EngineList => panic!("expected Options, got EngineList"),
            ParseResult::Error(_) => panic!("expected Options, got Error"),
        }
    }

    /// Helper to check if `ParseResult` is an error.
    fn is_error(result: &ParseResult) -> bool {
        matches!(result, ParseResult::Error(_))
    }

    /// Helper to construct arg list from string slices.
    fn make_args(args: &[&str]) -> Vec<String> {
        let mut result = vec!["urlx".to_string()];
        result.extend(args.iter().map(|s| (*s).to_string()));
        result
    }

    #[test]
    fn format_write_out_http_code() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        );
        let result = format_write_out("%{http_code}", &response, false);
        assert_eq!(result, "200");
    }

    #[test]
    fn format_write_out_http_version() {
        let mut response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        );
        response.set_http_version(liburlx::ResponseHttpVersion::Http2);
        let result = format_write_out("%{http_version}", &response, false);
        assert_eq!(result, "2");
    }

    #[test]
    fn format_write_out_http_version_11() {
        let mut response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".to_string(),
        );
        response.set_http_version(liburlx::ResponseHttpVersion::Http11);
        let result = format_write_out("%{http_version}", &response, false);
        assert_eq!(result, "1.1");
    }

    #[test]
    fn format_write_out_escape_sequences() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            String::new(),
        );
        let result = format_write_out("a\\nb\\tc", &response, false);
        assert_eq!(result, "a\nb\tc");
    }

    #[test]
    fn format_write_out_multiple_vars() {
        let response = liburlx::Response::new(
            404,
            std::collections::HashMap::new(),
            b"body".to_vec(),
            "http://test.com/path".to_string(),
        );
        let result =
            format_write_out("%{http_code} %{size_download} %{url_effective}", &response, false);
        assert_eq!(result, "404 4 http://test.com/path");
    }

    #[test]
    fn http_status_text_known() {
        assert_eq!(http_status_text(200), "OK");
        assert_eq!(http_status_text(404), "Not Found");
        assert_eq!(http_status_text(500), "Internal Server Error");
    }

    #[test]
    fn http_status_text_unknown() {
        assert_eq!(http_status_text(999), "");
    }

    #[test]
    fn format_headers_basic() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-type".to_string(), "text/plain".to_string());
        let mut response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        response.set_http_version(liburlx::ResponseHttpVersion::Http11);
        let result = format_headers(&response);
        assert!(result.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(result.contains("content-type: text/plain\r\n"));
        assert!(result.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parse_args_basic_url() {
        let args = vec!["urlx".to_string(), "http://example.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
        assert!(!opts.silent);
        assert!(!opts.fail_on_error);
    }

    #[test]
    fn parse_args_silent_and_fail() {
        let args = vec![
            "urlx".to_string(),
            "-s".to_string(),
            "-f".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.silent);
        assert!(opts.fail_on_error);
    }

    #[test]
    fn parse_args_include_headers() {
        let args = vec!["urlx".to_string(), "-i".to_string(), "http://x.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.include_headers);
    }

    #[test]
    fn parse_args_user_agent() {
        let args = vec![
            "urlx".to_string(),
            "-A".to_string(),
            "TestAgent/1.0".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_max_redirs() {
        let args = vec![
            "urlx".to_string(),
            "--max-redirs".to_string(),
            "5".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_dump_header() {
        let args = vec![
            "urlx".to_string(),
            "-D".to_string(),
            "headers.txt".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.dump_header.as_deref(), Some("headers.txt"));
    }

    #[test]
    fn parse_args_data_raw() {
        let args = vec![
            "urlx".to_string(),
            "--data-raw".to_string(),
            "@notafile".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_unknown_option() {
        let args = vec!["urlx".to_string(), "--bogus".to_string()];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_missing_arg() {
        let args = vec!["urlx".to_string(), "-X".to_string()];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_multiple_urls() {
        let args = vec!["urlx".to_string(), "http://a.com".to_string(), "http://b.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls.len(), 2);
        assert_eq!(opts.urls[0], "http://a.com");
        assert_eq!(opts.urls[1], "http://b.com");
    }

    #[test]
    fn parse_args_all_http_methods() {
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"] {
            let args = vec![
                "urlx".to_string(),
                "-X".to_string(),
                method.to_string(),
                "http://x.com".to_string(),
            ];
            assert!(
                matches!(parse_args(&args), ParseResult::Options(_)),
                "method {method} should parse"
            );
        }
    }

    #[test]
    fn parse_args_header_invalid_format() {
        // curl silently ignores headers without colon or semicolon
        let args = vec![
            "urlx".to_string(),
            "-H".to_string(),
            "NoColonHere".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_compressed() {
        let args = vec!["urlx".to_string(), "--compressed".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_connect_timeout() {
        let args = vec![
            "urlx".to_string(),
            "--connect-timeout".to_string(),
            "5.5".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_connect_timeout_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--connect-timeout".to_string(),
            "not-a-number".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_max_time() {
        let args = vec![
            "urlx".to_string(),
            "-m".to_string(),
            "10".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_max_redirs_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--max-redirs".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_proxy() {
        let args = vec![
            "urlx".to_string(),
            "-x".to_string(),
            "http://proxy:8080".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_form_field() {
        let args = vec![
            "urlx".to_string(),
            "-F".to_string(),
            "name=value".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_form_invalid() {
        let args = vec![
            "urlx".to_string(),
            "-F".to_string(),
            "noequalssign".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_range() {
        let args = vec![
            "urlx".to_string(),
            "-r".to_string(),
            "0-499".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_continue_at() {
        let args = vec![
            "urlx".to_string(),
            "-C".to_string(),
            "1024".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_continue_at_invalid() {
        let args = vec![
            "urlx".to_string(),
            "-C".to_string(),
            "not-a-number".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_progress_bar() {
        let args = vec!["urlx".to_string(), "-#".to_string(), "http://x.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.show_progress);
    }

    #[test]
    fn parse_args_verbose() {
        let args = vec!["urlx".to_string(), "-v".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_combined_flags() {
        let args = vec![
            "urlx".to_string(),
            "-s".to_string(),
            "-S".to_string(),
            "-f".to_string(),
            "-L".to_string(),
            "-i".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.silent);
        assert!(opts.show_error);
        assert!(opts.fail_on_error);
        assert!(opts.include_headers);
    }

    #[test]
    fn parse_args_write_out() {
        let args = vec![
            "urlx".to_string(),
            "-w".to_string(),
            "%{http_code}\\n".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.write_out.as_deref(), Some("%{http_code}\\n"));
    }

    #[test]
    fn parse_args_output_file() {
        let args = vec![
            "urlx".to_string(),
            "-o".to_string(),
            "output.txt".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.output_file.as_deref(), Some("output.txt"));
    }

    #[test]
    fn parse_args_noproxy() {
        let args = vec![
            "urlx".to_string(),
            "--noproxy".to_string(),
            "localhost,127.0.0.1".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_user_without_colon() {
        let args = vec![
            "urlx".to_string(),
            "-u".to_string(),
            "admin".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn format_write_out_all_variables() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-type".to_string(), "text/html".to_string());
        let response = liburlx::Response::new(
            201,
            headers,
            b"body".to_vec(),
            "http://example.com/page".to_string(),
        );
        let result = format_write_out(
            "%{http_code} %{response_code} %{url_effective} %{content_type} %{size_download}",
            &response,
            false,
        );
        assert!(result.contains("201"));
        assert!(result.contains("http://example.com/page"));
        assert!(result.contains("text/html"));
        assert!(result.contains('4')); // body length
    }

    #[test]
    fn format_write_out_escape_r() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            String::new(),
        );
        let result = format_write_out("a\\rb", &response, false);
        assert_eq!(result, "a\rb");
    }

    #[test]
    fn format_write_out_no_content_type() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            String::new(),
        );
        let result = format_write_out("%{content_type}", &response, false);
        assert_eq!(result, "");
    }

    #[test]
    fn format_write_out_timing_variables() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            String::new(),
        );
        let result = format_write_out(
            "%{time_namelookup} %{time_appconnect} %{time_pretransfer} %{time_starttransfer} %{speed_download} %{speed_upload} %{size_upload}",
            &response,
            false,
        );
        // All default to zero
        assert!(result.contains("0.000000"));
        assert!(result.contains("0.000"));
        assert!(result.contains('0'));
    }

    #[test]
    fn run_no_args_returns_failure() {
        let args = vec!["urlx".to_string()];
        let code = run(&args);
        assert_ne!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn parse_args_insecure() {
        let args = vec!["urlx".to_string(), "-k".to_string(), "https://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_insecure_long() {
        let args = vec!["urlx".to_string(), "--insecure".to_string(), "https://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_cacert() {
        let args = vec![
            "urlx".to_string(),
            "--cacert".to_string(),
            "/tmp/ca.pem".to_string(),
            "https://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_cert_and_key() {
        let args = vec![
            "urlx".to_string(),
            "--cert".to_string(),
            "/tmp/cert.pem".to_string(),
            "--key".to_string(),
            "/tmp/key.pem".to_string(),
            "https://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_cacert_missing_arg() {
        let args = vec!["urlx".to_string(), "--cacert".to_string()];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_tlsv12() {
        let args = vec!["urlx".to_string(), "--tlsv1.2".to_string(), "https://x.com".to_string()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tlsv13() {
        let args = vec!["urlx".to_string(), "--tlsv1.3".to_string(), "https://x.com".to_string()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tls_max() {
        let args = vec![
            "urlx".to_string(),
            "--tls-max".to_string(),
            "1.2".to_string(),
            "https://x.com".to_string(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tls_max_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--tls-max".to_string(),
            "1.1".to_string(),
            "https://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_cookie() {
        let args = vec![
            "urlx".to_string(),
            "-b".to_string(),
            "name=value".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_cookie_long() {
        let args = vec![
            "urlx".to_string(),
            "--cookie".to_string(),
            "a=1; b=2".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_data_binary() {
        let args = vec![
            "urlx".to_string(),
            "--data-binary".to_string(),
            "raw bytes here".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_data_urlencode() {
        let args = vec![
            "urlx".to_string(),
            "--data-urlencode".to_string(),
            "key=hello world".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_resolve() {
        let args = vec![
            "urlx".to_string(),
            "--resolve".to_string(),
            "example.com:443:127.0.0.1".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_resolve_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--resolve".to_string(),
            "bad-format".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_http10() {
        let args = vec!["urlx".to_string(), "--http1.0".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_http11() {
        let args = vec!["urlx".to_string(), "--http1.1".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_http2() {
        let args = vec!["urlx".to_string(), "--http2".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_http3() {
        let args = vec!["urlx".to_string(), "--http3".to_string(), "https://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_expect100_timeout() {
        let args = vec![
            "urlx".to_string(),
            "--expect100-timeout".to_string(),
            "1000".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_expect100_timeout_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--expect100-timeout".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_retry() {
        let args = vec![
            "urlx".to_string(),
            "--retry".to_string(),
            "3".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.retry_count, 3);
    }

    #[test]
    fn parse_args_retry_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--retry".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_retry_delay() {
        let args = vec![
            "urlx".to_string(),
            "--retry-delay".to_string(),
            "5".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.retry_delay_secs, 5);
    }

    #[test]
    fn parse_args_retry_max_time() {
        let args = vec![
            "urlx".to_string(),
            "--retry-max-time".to_string(),
            "60".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.retry_max_time_secs, 60);
    }

    #[test]
    fn parse_args_parallel() {
        let args = vec!["urlx".to_string(), "-Z".to_string(), "http://x.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.parallel);
        assert_eq!(opts.parallel_max, 50); // default
    }

    #[test]
    fn parse_args_parallel_long() {
        let args = vec!["urlx".to_string(), "--parallel".to_string(), "http://x.com".to_string()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.parallel);
    }

    #[test]
    fn parse_args_parallel_max() {
        let args = vec![
            "urlx".to_string(),
            "--parallel-max".to_string(),
            "10".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.parallel_max, 10);
    }

    #[test]
    fn parse_args_parallel_max_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--parallel-max".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_socks5_hostname() {
        let args = vec![
            "urlx".to_string(),
            "--socks5-hostname".to_string(),
            "127.0.0.1:1080".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tcp_nodelay() {
        let args =
            vec!["urlx".to_string(), "--tcp-nodelay".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tcp_keepalive() {
        let args = vec![
            "urlx".to_string(),
            "--tcp-keepalive".to_string(),
            "60".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_tcp_keepalive_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--tcp-keepalive".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_hsts() {
        let args = vec!["urlx".to_string(), "--hsts".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_bearer() {
        let args = vec![
            "urlx".to_string(),
            "--bearer".to_string(),
            "mytoken123".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.use_bearer);
    }

    #[test]
    fn parse_args_bearer_missing_arg() {
        let args = vec!["urlx".to_string(), "--bearer".to_string()];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn urlencoded_basic() {
        // form_urlencode uses + for spaces (matching curl's --data-urlencode)
        assert_eq!(urlencoded("hello world"), "hello+world");
    }

    #[test]
    fn urlencoded_with_name() {
        assert_eq!(urlencoded("key=hello world"), "key=hello+world");
    }

    #[test]
    fn urlencoded_special_chars() {
        // Input has '=' so it splits: name="a&b", value="c" → "a&b=c"
        assert_eq!(urlencoded("a&b=c"), "a&b=c");
        // Without '=', the whole string is encoded (lowercase hex)
        assert_eq!(urlencoded("a&b"), "a%26b");
    }

    #[test]
    fn urlencoded_unreserved_chars() {
        assert_eq!(urlencoded("abc-_.~123"), "abc-_.~123");
    }

    #[test]
    fn percent_encode_empty() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn percent_encode_space() {
        assert_eq!(percent_encode(" "), "%20");
    }

    #[test]
    fn is_retryable_status_true() {
        for code in [408, 429, 500, 502, 503, 504] {
            assert!(is_retryable_status(code), "status {code} should be retryable");
        }
    }

    #[test]
    fn is_retryable_status_false() {
        for code in [200, 301, 400, 401, 403, 404] {
            assert!(!is_retryable_status(code), "status {code} should not be retryable");
        }
    }

    #[test]
    fn parse_rate_limit_plain() {
        assert_eq!(parse_rate_limit("1000"), Some(1000));
    }

    #[test]
    fn parse_rate_limit_kilobytes() {
        assert_eq!(parse_rate_limit("100K"), Some(100 * 1024));
        assert_eq!(parse_rate_limit("100k"), Some(100 * 1024));
    }

    #[test]
    fn parse_rate_limit_megabytes() {
        assert_eq!(parse_rate_limit("1M"), Some(1024 * 1024));
        assert_eq!(parse_rate_limit("1m"), Some(1024 * 1024));
    }

    #[test]
    fn parse_rate_limit_gigabytes() {
        assert_eq!(parse_rate_limit("1G"), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn parse_rate_limit_invalid() {
        assert_eq!(parse_rate_limit(""), None);
        assert_eq!(parse_rate_limit("abc"), None);
        assert_eq!(parse_rate_limit("K"), None);
    }

    #[test]
    fn parse_args_cookie_jar() {
        let args = vec![
            "urlx".to_string(),
            "-c".to_string(),
            "/tmp/cookies.txt".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.cookie_jar_file, Some("/tmp/cookies.txt".to_string()));
    }

    #[test]
    fn parse_args_cookie_jar_long() {
        let args = vec![
            "urlx".to_string(),
            "--cookie-jar".to_string(),
            "/tmp/cookies.txt".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.cookie_jar_file, Some("/tmp/cookies.txt".to_string()));
    }

    #[test]
    fn parse_args_limit_rate() {
        let args = vec![
            "urlx".to_string(),
            "--limit-rate".to_string(),
            "100K".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.limit_rate, Some("100K".to_string()));
    }

    #[test]
    fn parse_args_limit_rate_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--limit-rate".to_string(),
            "notanumber".to_string(),
            "http://example.com".to_string(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_speed_limit() {
        let args = vec![
            "urlx".to_string(),
            "--speed-limit".to_string(),
            "1000".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.speed_limit, Some(1000));
    }

    #[test]
    fn parse_args_speed_time() {
        let args = vec![
            "urlx".to_string(),
            "--speed-time".to_string(),
            "60".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.speed_time, Some(60));
    }

    #[test]
    fn parse_args_referer() {
        let args = vec![
            "urlx".to_string(),
            "-e".to_string(),
            "http://prev.com".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.urls.contains(&"http://example.com".to_string()));
    }

    #[test]
    fn parse_args_referer_long() {
        let args = vec![
            "urlx".to_string(),
            "--referer".to_string(),
            "http://prev.com".to_string(),
            "http://example.com".to_string(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_remote_name() {
        let args = vec![
            "urlx".to_string(),
            "-O".to_string(),
            "http://example.com/file.tar.gz".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remote_name);
    }

    #[test]
    fn parse_args_get_flag() {
        let args = vec!["urlx".to_string(), "-G".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_create_dirs() {
        let args = vec![
            "urlx".to_string(),
            "--create-dirs".to_string(),
            "-o".to_string(),
            "a/b/c/file.txt".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.create_dirs);
    }

    #[test]
    fn remote_name_from_url_basic() {
        assert_eq!(remote_name_from_url("http://example.com/file.tar.gz"), "file.tar.gz");
    }

    #[test]
    fn remote_name_from_url_with_query() {
        assert_eq!(remote_name_from_url("http://example.com/download.zip?v=1"), "download.zip");
    }

    #[test]
    fn remote_name_from_url_no_filename() {
        assert_eq!(remote_name_from_url("http://example.com/"), "curl_response");
    }

    #[test]
    fn remote_name_from_url_root() {
        assert_eq!(remote_name_from_url("http://example.com"), "curl_response");
    }

    #[test]
    fn remote_name_from_url_path_segments() {
        assert_eq!(remote_name_from_url("http://example.com/path/to/file.txt"), "file.txt");
    }

    #[test]
    fn parse_args_dns_servers() {
        let args = vec![
            "urlx".into(),
            "--dns-servers".into(),
            "8.8.8.8,8.8.4.4".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_doh_url() {
        let args = vec![
            "urlx".into(),
            "--doh-url".into(),
            "https://dns.google/dns-query".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_happy_eyeballs_timeout() {
        let args = vec![
            "urlx".into(),
            "--happy-eyeballs-timeout-ms".into(),
            "100".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_happy_eyeballs_timeout_invalid() {
        let args = vec![
            "urlx".into(),
            "--happy-eyeballs-timeout-ms".into(),
            "abc".into(),
            "http://example.com".into(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_unrestricted_auth() {
        let args = vec!["urlx".into(), "--unrestricted-auth".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_ignore_content_length() {
        let args =
            vec!["urlx".into(), "--ignore-content-length".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_trace() {
        let args = vec![
            "urlx".into(),
            "--trace".into(),
            "/tmp/trace.log".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.trace_file, Some("/tmp/trace.log".to_string()));
    }

    #[test]
    fn parse_args_trace_ascii() {
        let args = vec![
            "urlx".into(),
            "--trace-ascii".into(),
            "/tmp/trace.log".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.trace_ascii_file, Some("/tmp/trace.log".to_string()));
    }

    #[test]
    fn parse_args_trace_time() {
        let args = vec!["urlx".into(), "--trace-time".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.trace_time);
    }

    #[test]
    fn parse_args_libcurl() {
        let args =
            vec!["urlx".into(), "--libcurl".into(), "out.c".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.libcurl, Some("out.c".to_string()));
    }

    #[test]
    fn parse_args_proto() {
        let args = vec![
            "urlx".into(),
            "--proto".into(),
            "=http,https".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.proto, Some("=http,https".to_string()));
    }

    #[test]
    fn parse_args_proto_redir() {
        let args = vec![
            "urlx".into(),
            "--proto-redir".into(),
            "=https".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.proto_redir, Some("=https".to_string()));
    }

    #[test]
    fn parse_args_max_filesize() {
        let args = vec![
            "urlx".into(),
            "--max-filesize".into(),
            "1048576".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.max_filesize, Some(1_048_576));
    }

    #[test]
    fn parse_args_max_filesize_invalid() {
        let args =
            vec!["urlx".into(), "--max-filesize".into(), "abc".into(), "http://example.com".into()];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_no_keepalive() {
        let args = vec!["urlx".into(), "--no-keepalive".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.no_keepalive);
    }

    #[test]
    fn parse_config_file_basic() {
        let config = "--silent\n--location\n-o output.txt\n";
        let args = parse_config_file(config);
        assert_eq!(args, vec!["--silent", "--location", "-o", "output.txt"]);
    }

    #[test]
    fn parse_config_file_comments_and_empty() {
        let config = "# comment\n\n--verbose\n# another comment\n";
        let args = parse_config_file(config);
        assert_eq!(args, vec!["--verbose"]);
    }

    #[test]
    fn parse_config_file_equals_syntax() {
        let config = "--max-redirs=10\n--user-agent=\"Test Agent\"\n";
        let args = parse_config_file(config);
        assert_eq!(args, vec!["--max-redirs", "10", "--user-agent", "Test Agent"]);
    }

    #[test]
    fn parse_config_file_quoted_values() {
        let config = "-H \"Content-Type: application/json\"\n-d 'hello world'\n";
        let args = parse_config_file(config);
        assert_eq!(args, vec!["-H", "Content-Type: application/json", "-d", "hello world"]);
    }

    #[test]
    fn parse_config_file_empty() {
        let config = "";
        let args = parse_config_file(config);
        assert!(args.is_empty());
    }

    #[test]
    fn unquote_double_quotes() {
        assert_eq!(unquote("\"hello\""), "hello");
    }

    #[test]
    fn unquote_single_quotes() {
        assert_eq!(unquote("'hello'"), "hello");
    }

    #[test]
    fn unquote_no_quotes() {
        assert_eq!(unquote("hello"), "hello");
    }

    #[test]
    fn is_protocol_allowed_basic() {
        assert!(is_protocol_allowed("http://example.com", "http,https"));
        assert!(is_protocol_allowed("https://example.com", "http,https"));
        assert!(!is_protocol_allowed("ftp://example.com", "http,https"));
    }

    #[test]
    fn is_protocol_allowed_equals_prefix() {
        assert!(is_protocol_allowed("http://example.com", "=http,https"));
        assert!(!is_protocol_allowed("ftp://example.com", "=http,https"));
    }

    #[test]
    fn is_protocol_allowed_case_insensitive() {
        assert!(is_protocol_allowed("HTTP://example.com", "http,https"));
        assert!(is_protocol_allowed("http://example.com", "HTTP,HTTPS"));
    }

    #[test]
    fn is_protocol_allowed_empty_scheme() {
        assert!(!is_protocol_allowed("example.com", "http"));
    }

    #[test]
    fn generate_libcurl_code_basic() {
        let args = vec!["urlx".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        let code = generate_libcurl_code(&opts);
        assert!(code.contains("#include <curl/curl.h>"));
        assert!(code.contains("CURLOPT_URL"));
        assert!(code.contains("http://example.com"));
        assert!(code.contains("curl_easy_perform"));
        assert!(code.contains("curl_easy_cleanup"));
    }

    #[test]
    fn generate_libcurl_code_with_options() {
        let args =
            vec!["urlx".into(), "-s".into(), "-f".into(), "-i".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        let code = generate_libcurl_code(&opts);
        assert!(code.contains("CURLOPT_NOPROGRESS"));
        assert!(code.contains("CURLOPT_FAILONERROR"));
        assert!(code.contains("CURLOPT_HEADER"));
    }

    #[test]
    fn parse_args_post301() {
        let args = vec!["urlx".into(), "--post301".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.post301);
    }

    #[test]
    fn parse_args_post302() {
        let args = vec!["urlx".into(), "--post302".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.post302);
    }

    #[test]
    fn parse_args_post303() {
        let args = vec!["urlx".into(), "--post303".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.post303);
    }

    #[test]
    fn parse_args_proxy_header() {
        let args = vec![
            "urlx".into(),
            "--proxy-header".into(),
            "X-Proxy: value".into(),
            "http://example.com".into(),
        ];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_proxy_header_invalid() {
        let args = vec![
            "urlx".into(),
            "--proxy-header".into(),
            "NoColonHere".into(),
            "http://example.com".into(),
        ];
        assert!(is_error(&parse_args(&args)));
    }

    #[test]
    fn parse_args_netrc() {
        let args = vec!["urlx".into(), "--netrc".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.netrc_file.is_some());
        assert!(!opts.netrc_optional);
    }

    #[test]
    fn parse_args_netrc_optional() {
        let args = vec!["urlx".into(), "--netrc-optional".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.netrc_file.is_some());
        assert!(opts.netrc_optional);
    }

    #[test]
    fn parse_args_netrc_file() {
        let args = vec![
            "urlx".into(),
            "--netrc-file".into(),
            "/tmp/my.netrc".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.netrc_file.as_deref(), Some("/tmp/my.netrc"));
    }

    #[test]
    fn parse_args_remote_time() {
        let args = vec!["urlx".into(), "-R".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remote_time);
    }

    #[test]
    fn parse_args_remote_time_long() {
        let args = vec!["urlx".into(), "--remote-time".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remote_time);
    }

    #[test]
    fn parse_args_next() {
        let args =
            vec!["urlx".into(), "http://a.com".into(), "--next".into(), "http://b.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls.len(), 2);
    }

    #[test]
    fn parse_args_ftp_pasv() {
        let args = vec!["urlx".into(), "--ftp-pasv".into(), "ftp://example.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_ftp_ssl() {
        let args = vec!["urlx".into(), "--ftp-ssl".into(), "ftp://example.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_ssl() {
        let args = vec!["urlx".into(), "--ssl".into(), "ftp://example.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_ftp_ssl_reqd() {
        let args = vec!["urlx".into(), "--ftp-ssl-reqd".into(), "ftp://example.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_ssl_reqd() {
        let args = vec!["urlx".into(), "--ssl-reqd".into(), "ftp://example.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_key_sets_ssh_key_path() {
        let args = vec![
            "urlx".into(),
            "--key".into(),
            "/home/user/.ssh/id_ed25519".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_hostpubsha256() {
        let args = vec![
            "urlx".into(),
            "--hostpubsha256".into(),
            "abcdef1234567890".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_known_hosts() {
        let args = vec![
            "urlx".into(),
            "--known-hosts".into(),
            "/home/user/.ssh/known_hosts".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_hostpubmd5_valid() {
        let args = vec![
            "urlx".into(),
            "--hostpubmd5".into(),
            "00112233445566778899aabbccddeeff".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_hostpubmd5_invalid() {
        // Too short: 2 hex chars instead of 32
        let args = vec![
            "urlx".into(),
            "--hostpubmd5".into(),
            "00".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Error(2)));
    }

    #[test]
    fn extract_hostname_basic() {
        assert_eq!(extract_hostname("http://example.com/path"), "example.com");
    }

    #[test]
    fn extract_hostname_with_port() {
        assert_eq!(extract_hostname("http://example.com:8080/path"), "example.com");
    }

    #[test]
    fn extract_hostname_with_userinfo() {
        assert_eq!(extract_hostname("http://user:pass@example.com/path"), "example.com");
    }

    #[test]
    fn extract_hostname_no_scheme() {
        assert_eq!(extract_hostname("example.com/path"), "example.com");
    }

    #[test]
    fn parse_http_date_rfc7231() {
        // "Sun, 06 Nov 1994 08:49:37 GMT" → 784111777
        let ts = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784_111_777);
    }

    #[test]
    fn parse_http_date_invalid() {
        assert!(parse_http_date("not a date").is_none());
    }

    #[test]
    fn parse_http_date_recent() {
        // "Mon, 09 Mar 2026 00:00:00 GMT"
        let ts = parse_http_date("Mon, 09 Mar 2026 00:00:00 GMT");
        assert!(ts.is_some());
        let ts = ts.unwrap();
        // Should be after 2025-01-01 (1735689600)
        assert!(ts > 1_735_689_600);
    }

    #[test]
    fn is_leap_year_basic() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn parse_args_stderr() {
        let args = vec![
            "urlx".into(),
            "--stderr".into(),
            "/tmp/err.log".into(),
            "http://example.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.stderr_file, Some("/tmp/err.log".to_string()));
    }

    #[test]
    fn hex_dump_basic() {
        let mut out = String::new();
        let data = b"Hello, World!";
        hex_dump(&mut out, data, &|| String::new());
        assert!(out.contains("0000:"));
        assert!(out.contains("48 65 6c 6c 6f"));
        assert!(out.contains("Hello, World!"));
    }

    #[test]
    fn hex_dump_multiline() {
        let mut out = String::new();
        let data: Vec<u8> = (0..32).collect();
        hex_dump(&mut out, &data, &|| String::new());
        assert!(out.contains("0000:"));
        assert!(out.contains("0010:"));
    }

    #[test]
    fn hex_dump_with_timestamp() {
        let mut out = String::new();
        let data = b"test";
        hex_dump(&mut out, data, &|| "12345.000000 ".to_string());
        assert!(out.starts_with("12345.000000 0000:"));
    }

    #[test]
    #[allow(unused_results)]
    fn write_trace_file_ascii() {
        let tmp = std::env::temp_dir().join("urlx_trace_test_ascii.txt");
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());
        let response =
            liburlx::Response::new(200, headers, b"Hello".to_vec(), "http://example.com".into());
        let req_headers = vec![("Host".to_string(), "example.com".to_string())];
        write_trace_file(
            tmp.to_str().unwrap(),
            &response,
            "http://example.com",
            "GET",
            &req_headers,
            false,
            false,
        );
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("=> Send header"));
        assert!(content.contains("<= Recv header"));
        assert!(content.contains("Hello"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn write_trace_file_hex() {
        let tmp = std::env::temp_dir().join("urlx_trace_test_hex.txt");
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            b"data".to_vec(),
            "http://example.com".into(),
        );
        write_trace_file(
            tmp.to_str().unwrap(),
            &response,
            "http://example.com",
            "GET",
            &[],
            true,
            false,
        );
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("0000:"));
        assert!(content.contains("64 61 74 61")); // "data" in hex
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn write_trace_file_with_time() {
        let tmp = std::env::temp_dir().join("urlx_trace_test_time.txt");
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            "http://example.com".into(),
        );
        write_trace_file(
            tmp.to_str().unwrap(),
            &response,
            "http://example.com",
            "GET",
            &[],
            false,
            true,
        );
        let content = std::fs::read_to_string(&tmp).unwrap();
        // Should contain timestamp digits
        assert!(content.contains('.'));
        let _ = std::fs::remove_file(&tmp);
    }

    // --- Phase 33 tests ---

    #[test]
    fn parse_args_globoff() {
        let args = vec!["urlx".into(), "--globoff".into(), "http://x.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.globoff);
    }

    #[test]
    fn parse_args_path_as_is() {
        let args = vec!["urlx".into(), "--path-as-is".into(), "http://x.com/a/../b".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_raw() {
        let args = vec!["urlx".into(), "--raw".into(), "http://x.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_remote_header_name_short() {
        let args = vec!["urlx".into(), "-J".into(), "http://x.com/file".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remote_header_name);
        assert!(opts.remote_name);
    }

    #[test]
    fn parse_args_remote_header_name_long() {
        let args = vec!["urlx".into(), "--remote-header-name".into(), "http://x.com/file".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remote_header_name);
    }

    #[test]
    fn parse_args_styled_output() {
        let args = vec!["urlx".into(), "--styled-output".into(), "http://x.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_no_styled_output() {
        let args = vec!["urlx".into(), "--no-styled-output".into(), "http://x.com".into()];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_url_query() {
        let args =
            vec!["urlx".into(), "--url-query".into(), "key=value".into(), "http://x.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.url_queries, vec!["key=value"]);
    }

    #[test]
    fn parse_args_url_query_multiple() {
        let args = vec![
            "urlx".into(),
            "--url-query".into(),
            "a=1".into(),
            "--url-query".into(),
            "b=2".into(),
            "http://x.com".into(),
        ];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.url_queries, vec!["a=1", "b=2"]);
    }

    #[test]
    fn parse_args_json() {
        let args =
            vec!["urlx".into(), "--json".into(), r#"{"key":"val"}"#.into(), "http://x.com".into()];
        let opts = parse_args(&args);
        assert!(matches!(opts, ParseResult::Options(_)));
    }

    #[test]
    fn parse_args_rate() {
        let args = vec!["urlx".into(), "--rate".into(), "10/s".into(), "http://x.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.rate, Some("10/s".to_string()));
    }

    #[test]
    fn append_url_queries_basic() {
        let result = append_url_queries("http://example.com", &["key=value".to_string()]).unwrap();
        assert_eq!(result, "http://example.com?key=value");
    }

    #[test]
    fn append_url_queries_existing_query() {
        let result = append_url_queries("http://example.com?a=1", &["b=2".to_string()]).unwrap();
        assert_eq!(result, "http://example.com?a=1&b=2");
    }

    #[test]
    fn append_url_queries_multiple() {
        let result = append_url_queries(
            "http://example.com",
            &["a=1".to_string(), "b=hello world".to_string()],
        )
        .unwrap();
        assert!(result.starts_with("http://example.com?a=1&b=hello+world"));
    }

    #[test]
    fn append_url_queries_no_equals() {
        let result = append_url_queries("http://example.com", &["raw_string".to_string()]).unwrap();
        assert_eq!(result, "http://example.com?raw_string");
    }

    #[test]
    fn content_disposition_filename_quoted() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert(
            "content-disposition".to_string(),
            "attachment; filename=\"report.pdf\"".to_string(),
        );
        let response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        assert_eq!(content_disposition_filename(&response), Some("report.pdf".to_string()));
    }

    #[test]
    fn content_disposition_filename_unquoted() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert(
            "content-disposition".to_string(),
            "attachment; filename=report.pdf".to_string(),
        );
        let response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        assert_eq!(content_disposition_filename(&response), Some("report.pdf".to_string()));
    }

    #[test]
    fn content_disposition_filename_missing() {
        let response = liburlx::Response::new(
            200,
            std::collections::HashMap::new(),
            Vec::new(),
            String::new(),
        );
        assert_eq!(content_disposition_filename(&response), None);
    }

    #[test]
    fn content_disposition_filename_no_filename() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert("content-disposition".to_string(), "inline".to_string());
        let response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        assert_eq!(content_disposition_filename(&response), None);
    }

    #[test]
    fn content_disposition_filename_with_semicolon() {
        let mut headers = std::collections::HashMap::new();
        let _old = headers.insert(
            "content-disposition".to_string(),
            "attachment; filename=data.csv; size=1234".to_string(),
        );
        let response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        assert_eq!(content_disposition_filename(&response), Some("data.csv".to_string()));
    }

    #[test]
    fn parse_ciphers_flag() {
        let args = make_args(&["--ciphers", "ECDHE-RSA-AES256-GCM-SHA384", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_ntlm_flag() {
        let args = make_args(&["--ntlm", "-u", "user:pass", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.use_ntlm);
    }

    #[test]
    fn parse_negotiate_flag() {
        let args = make_args(&["--negotiate", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.use_negotiate);
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_negotiate_flag() {
        let args =
            make_args(&["--proxy-negotiate", "-x", "http://proxy:8080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.proxy_negotiate);
    }

    #[test]
    fn parse_delegation_flag() {
        let args = make_args(&["--delegation", "always", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_delegation_none() {
        let args = make_args(&["--delegation", "none", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_delegation_policy() {
        let args = make_args(&["--delegation", "policy", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_delegation_invalid() {
        let args = make_args(&["--delegation", "invalid", "http://example.com"]);
        assert!(matches!(parse_args(&args), ParseResult::Error(2)));
    }

    #[test]
    fn negotiate_sets_auth_credentials() {
        let args = make_args(&["--negotiate", "-u", "user:pass", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.use_negotiate);
        assert!(opts.easy.uses_challenge_auth());
    }

    #[test]
    fn parse_sasl_flags() {
        let args = make_args(&["--sasl-authzid", "myid", "--sasl-ir", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_mail_from_flag() {
        let args = make_args(&["--mail-from", "sender@example.com", "smtp://mail.example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["smtp://mail.example.com"]);
    }

    #[test]
    fn parse_mail_rcpt_flag() {
        let args = make_args(&[
            "--mail-rcpt",
            "alice@example.com",
            "--mail-rcpt",
            "bob@example.com",
            "smtp://mail.example.com",
        ]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["smtp://mail.example.com"]);
    }

    #[test]
    fn parse_mail_auth_flag() {
        let args = make_args(&["--mail-auth", "sender@example.com", "smtp://mail.example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["smtp://mail.example.com"]);
    }

    #[test]
    fn parse_ftp_create_dirs_flag() {
        let args = make_args(&["--ftp-create-dirs", "ftp://example.com/dir/file.txt"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["ftp://example.com/dir/file.txt"]);
    }

    #[test]
    fn parse_ftp_method_flag() {
        let args = make_args(&["--ftp-method", "singlecwd", "ftp://example.com/dir/file.txt"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["ftp://example.com/dir/file.txt"]);
    }

    #[test]
    fn parse_ftp_method_invalid() {
        let args = make_args(&["--ftp-method", "invalid", "ftp://example.com/"]);
        assert!(is_error(&parse_args(&args)));
    }

    // --- Phase 41 tests: URL globbing ---

    #[test]
    fn parse_args_globoff_sets_flag() {
        let args = make_args(&["--globoff", "http://example.com/{a,b}"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.globoff);
        // With globoff, URL is stored literally (not expanded)
        assert_eq!(opts.urls, vec!["http://example.com/{a,b}"]);
    }

    #[test]
    fn glob_expansion_in_run() {
        // Verify that glob expansion works at the parse level
        let args = make_args(&["http://example.com/{a,b}"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.globoff);
        // URLs collected as-is at parse time
        assert_eq!(opts.urls, vec!["http://example.com/{a,b}"]);
        // Expansion happens in run(), not parse_args()
    }

    #[test]
    fn glob_numeric_range_collected() {
        let args = make_args(&["http://example.com/[1-3]"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com/[1-3]"]);
    }

    // --- Phase 42 tests: CLI Expansion V ---

    #[test]
    fn parse_connect_to() {
        let args = make_args(&["--connect-to", "a.com:80:b.com:8080", "http://a.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://a.com"]);
    }

    #[test]
    fn parse_alt_svc() {
        let args = make_args(&["--alt-svc", "/tmp/altsvc.txt", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.alt_svc_file.as_deref(), Some("/tmp/altsvc.txt"));
    }

    #[test]
    fn parse_ssl_sessions() {
        let args = make_args(&["--ssl-sessions", "/tmp/sessions.txt", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.ssl_session_file.as_deref(), Some("/tmp/sessions.txt"));
    }

    #[test]
    fn parse_etag_save() {
        let args = make_args(&["--etag-save", "/tmp/etag.txt", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.etag_save_file.as_deref(), Some("/tmp/etag.txt"));
    }

    #[test]
    fn parse_etag_compare() {
        let args = make_args(&["--etag-compare", "/tmp/etag.txt", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.etag_compare_file.as_deref(), Some("/tmp/etag.txt"));
    }

    #[test]
    fn parse_ipfs_gateway() {
        let args = make_args(&["--ipfs-gateway", "http://127.0.0.1:8080", "ipfs://bafyhash"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.ipfs_gateway.as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn parse_haproxy_protocol() {
        let args = make_args(&["--haproxy-protocol", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_abstract_unix_socket() {
        let args = make_args(&["--abstract-unix-socket", "/my/sock", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_tls_flags() {
        let args = make_args(&[
            "--proxy-cacert",
            "/path/ca.pem",
            "--proxy-cert",
            "/path/cert.pem",
            "--proxy-key",
            "/path/key.pem",
            "http://example.com",
        ]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_doh_insecure() {
        let args = make_args(&["--doh-insecure", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proto_default() {
        let args = make_args(&["--proto-default", "https", "example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.proto_default.as_deref(), Some("https"));
    }

    #[test]
    fn parse_compressed_ssh_noop() {
        let args = make_args(&["--compressed-ssh", "sftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["sftp://example.com"]);
    }

    // --- Phase 47 tests: CLI Expansion VI ---

    #[test]
    fn parse_form_string() {
        let args = make_args(&["--form-string", "name=@notafile", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_request_target() {
        let args = make_args(&["--request-target", "/custom/path", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks4() {
        let args = make_args(&["--socks4", "127.0.0.1:1080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks4a() {
        let args = make_args(&["--socks4a", "127.0.0.1:1080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks5() {
        let args = make_args(&["--socks5", "127.0.0.1:1080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_1_0() {
        let args = make_args(&["--proxy-1.0", "http://proxy:8080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_tftp_blksize() {
        let args = make_args(&["--tftp-blksize", "1024", "tftp://example.com/file"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["tftp://example.com/file"]);
    }

    #[test]
    fn parse_tftp_no_options() {
        let args = make_args(&["--tftp-no-options", "tftp://example.com/file"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["tftp://example.com/file"]);
    }

    #[test]
    fn parse_no_buffer() {
        let args = make_args(&["-N", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_sessionid() {
        let args = make_args(&["--no-sessionid", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_alpn() {
        let args = make_args(&["--no-alpn", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_npn() {
        let args = make_args(&["--no-npn", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_tlsv1() {
        let args = make_args(&["--tlsv1", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_sslv3() {
        let args = make_args(&["--sslv3", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_insecure() {
        let args = make_args(&["--proxy-insecure", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_disable_eprt() {
        let args = make_args(&["--disable-eprt", "ftp://example.com/file"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["ftp://example.com/file"]);
    }

    #[test]
    fn parse_disable_epsv() {
        let args = make_args(&["--disable-epsv", "ftp://example.com/file"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["ftp://example.com/file"]);
    }

    #[test]
    fn parse_tlsv1_0() {
        let args = make_args(&["--tlsv1.0", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_pinnedpubkey_sha256() {
        let args = make_args(&["--pinnedpubkey", "sha256//abc123", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_cert_status() {
        let args = make_args(&["--cert-status", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_false_start() {
        let args = make_args(&["--false-start", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_create_file_mode() {
        let args = make_args(&["--create-file-mode", "0644", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_output_dir() {
        let args = make_args(&["--output-dir", "/tmp", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.output_dir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn parse_remove_on_error() {
        let args = make_args(&["--remove-on-error", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.remove_on_error);
    }

    #[test]
    fn parse_url_flag() {
        let args = make_args(&["--url", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    // --- Phase 52: --help, --version, combined short flags ---

    #[test]
    fn parse_args_help_short() {
        let args = make_args(&["-h"]);
        assert!(matches!(parse_args(&args), ParseResult::Help));
    }

    #[test]
    fn parse_args_help_long() {
        let args = make_args(&["--help"]);
        assert!(matches!(parse_args(&args), ParseResult::Help));
    }

    #[test]
    fn parse_args_help_with_url() {
        // --help takes priority even with a URL
        let args = make_args(&["http://example.com", "--help"]);
        assert!(matches!(parse_args(&args), ParseResult::Help));
    }

    #[test]
    fn parse_args_version_short() {
        let args = make_args(&["-V"]);
        assert!(matches!(parse_args(&args), ParseResult::Version));
    }

    #[test]
    fn parse_args_version_long() {
        let args = make_args(&["--version"]);
        assert!(matches!(parse_args(&args), ParseResult::Version));
    }

    #[test]
    fn parse_args_combined_short_flags_basic() {
        // -sSf should be expanded to -s -S -f
        let args = make_args(&["-sSf", "http://x.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.silent);
        assert!(opts.show_error);
        assert!(opts.fail_on_error);
    }

    #[test]
    fn parse_args_combined_short_flags_sslfi() {
        // -sSfLi should work
        let args = make_args(&["-sSfLi", "http://x.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.silent);
        assert!(opts.show_error);
        assert!(opts.fail_on_error);
        assert!(opts.include_headers);
    }

    #[test]
    fn parse_args_combined_with_arg_flag_last() {
        // -Lo output.txt — -L is a boolean flag, -o takes an argument
        let args = make_args(&["-Lo", "output.txt", "http://x.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.output_file.as_deref(), Some("output.txt"));
    }

    #[test]
    fn parse_args_combined_with_arg_inline() {
        // -ofile.txt — -o takes an argument, rest of the flag is the value
        let args = make_args(&["-ofile.txt", "http://x.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.output_file.as_deref(), Some("file.txt"));
    }

    #[test]
    fn parse_args_combined_help_in_group() {
        // -sh should trigger help since -h is in the group
        let args = make_args(&["-sh"]);
        assert!(matches!(parse_args(&args), ParseResult::Help));
    }

    #[test]
    fn parse_args_combined_version_in_group() {
        // -sV should trigger version since -V is in the group
        let args = make_args(&["-sV"]);
        assert!(matches!(parse_args(&args), ParseResult::Version));
    }

    #[test]
    fn expand_combined_flags_passthrough_long() {
        // Long flags should pass through unchanged
        let args = vec!["urlx".into(), "--silent".into(), "http://x.com".into()];
        let expanded = expand_combined_flags(&args);
        assert_eq!(expanded, args);
    }

    #[test]
    fn expand_combined_flags_single_short() {
        // Single short flags should pass through unchanged
        let args = vec!["urlx".into(), "-s".into(), "http://x.com".into()];
        let expanded = expand_combined_flags(&args);
        assert_eq!(expanded, args);
    }

    #[test]
    fn expand_combined_flags_hash() {
        // -# should not be expanded (it's a valid single flag)
        let args = vec!["urlx".into(), "-#".into(), "http://x.com".into()];
        let expanded = expand_combined_flags(&args);
        assert_eq!(expanded, args);
    }

    #[test]
    fn parse_args_fail_with_body() {
        let args = make_args(&["--fail-with-body", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.fail_on_error);
        assert!(opts.fail_with_body);
    }

    #[test]
    fn parse_args_retry_all_errors() {
        let args = make_args(&["--retry", "3", "--retry-all-errors", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.retry_count, 3);
        assert!(opts.retry_all_errors);
    }

    #[test]
    fn parse_args_no_progress_meter() {
        let args = make_args(&["--no-progress-meter", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.no_progress_meter);
    }

    #[test]
    fn parse_args_location_trusted() {
        let args = make_args(&["--location-trusted", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.location_trusted);
    }

    #[test]
    fn parse_args_time_cond() {
        let args = make_args(&["-z", "Wed, 01 Jan 2025 00:00:00 GMT", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.time_cond.as_deref(), Some("Wed, 01 Jan 2025 00:00:00 GMT"));
    }

    #[test]
    fn parse_args_time_cond_negate() {
        let args =
            make_args(&["--time-cond", "-Wed, 01 Jan 2025 00:00:00 GMT", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.time_cond.as_deref().unwrap().starts_with('-'));
    }

    #[test]
    fn parse_args_capath() {
        let args = make_args(&["--capath", "/etc/ssl/certs", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        // --capath is wired to ssl_ca_cert for compat; just verify it parses
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_cert_type_noop() {
        let args = make_args(&["--cert-type", "PEM", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_key_type_noop() {
        let args = make_args(&["--key-type", "PEM", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_engine_list() {
        let args = make_args(&["--engine", "list"]);
        let result = parse_args(&args);
        assert!(matches!(result, ParseResult::EngineList));
    }

    #[test]
    fn parse_args_engine_openssl() {
        let args = make_args(&["--engine", "openssl", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_engine_default() {
        let args = make_args(&["--engine", "default", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_engine_invalid() {
        let args = make_args(&["--engine", "invalid-crypto-engine-xyzzy", "https://example.com"]);
        let result = parse_args(&args);
        assert!(matches!(result, ParseResult::Error(53)));
    }

    #[test]
    fn parse_args_pass_noop() {
        let args = make_args(&["--pass", "mypassword", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_basic_auth() {
        let args = make_args(&["--basic", "-u", "user:pass", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_anyauth() {
        let args = make_args(&["--anyauth", "-u", "user:pass", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_proxy_basic() {
        let args = make_args(&["--proxy-basic", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_proxy_anyauth() {
        let args = make_args(&["--proxy-anyauth", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_http2_prior_knowledge() {
        let args = make_args(&["--http2-prior-knowledge", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        // Verifies flag parses without error
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_ftp_skip_pasv_ip() {
        let args = make_args(&["--ftp-skip-pasv-ip", "ftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_ftp_account() {
        let args = make_args(&["--ftp-account", "myaccount", "ftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_preproxy() {
        let args = make_args(&["--preproxy", "socks5://proxy:1080", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_data_ascii() {
        let args = make_args(&["--data-ascii", "hello", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_keepalive_time() {
        let args = make_args(&["--keepalive-time", "30", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_crlfile_noop() {
        let args = make_args(&["--crlfile", "/path/to/crl.pem", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_proxy_pinnedpubkey_noop() {
        let args = make_args(&["--proxy-pinnedpubkey", "sha256//abc123", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_xattr_noop() {
        let args = make_args(&["--xattr", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_ipv4() {
        let args = make_args(&["-4", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_ipv6() {
        let args = make_args(&["--ipv6", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_junk_session_cookies() {
        let args = make_args(&["-j", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_list_only() {
        let args = make_args(&["-l", "ftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_http3_only() {
        let args = make_args(&["--http3-only", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_oauth2_bearer() {
        let args = make_args(&["--oauth2-bearer", "token123", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.use_bearer);
    }

    #[test]
    fn parse_args_quote() {
        let args = make_args(&["-Q", "DELE file.txt", "ftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_tcp_fastopen() {
        let args = make_args(&["--tcp-fastopen", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_no_clobber() {
        let args = make_args(&["--no-clobber", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_curves_noop() {
        let args = make_args(&["--curves", "X25519", "https://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    #[test]
    fn parse_args_pubkey_noop() {
        let args = make_args(&["--pubkey", "/path/to/key.pub", "sftp://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert!(!opts.urls.is_empty());
    }

    // --next + --config + --json tests (curl compat: tests 386, 430, 431, 432)

    /// Test 386: --json sets Content-Type and Accept for the first group,
    /// but --next resets them so the second group gets default Accept: */*.
    #[test]
    fn parse_args_json_next_headers_reset() {
        let args = make_args(&[
            "--json",
            r#"{ "drink": "coffee" }"#,
            "http://example.com/386",
            "--next",
            "http://example.com/3860002",
        ]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls.len(), 2);
        assert!(opts.had_next);
        assert_eq!(opts.per_url_group.len(), 2);
        assert_eq!(opts.per_url_group[0], 0);
        assert_eq!(opts.per_url_group[1], 1);

        // First group: should have JSON headers
        let first_easy = opts.per_url_easy[0].as_ref().unwrap();
        assert!(first_easy.has_header("content-type"), "first group should have Content-Type");
        assert!(first_easy.has_header("accept"), "first group should have Accept");
        let ct = first_easy
            .header_list()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("application/json"));
        let accept = first_easy
            .header_list()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
            .map(|(_, v)| v.as_str());
        assert_eq!(accept, Some("application/json"));

        // First group should be POST with body
        assert_eq!(first_easy.method_str(), Some("POST"));
        assert!(first_easy.has_body());

        // Second group: should NOT have JSON headers (reset by --next)
        let second_easy = opts.per_url_easy[1].as_ref().unwrap();
        assert!(
            !second_easy.header_list().iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
            "second group should not have Content-Type"
        );
        // Second group should not have body or POST method
        assert!(!second_easy.has_body());
    }

    /// Test 430: Three -K config files, each starting with --next.
    /// Each group should have its own header, data, and URL.
    #[test]
    fn parse_args_three_config_files_with_next() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("urlx_test_430");
        let _ = std::fs::create_dir_all(&dir);

        let write_config = |name: &str, content: &str| {
            let path = dir.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            path.to_str().unwrap().to_string()
        };

        let config_a = write_config(
            "config-a",
            "--next\nurl = http://example.com/4300001\nheader = \"a: a\"\ndata = \"a\"\n",
        );
        let config_b = write_config(
            "config-b",
            "--next\nurl = http://example.com/4300002\nheader = \"b: b\"\ndata = \"b\"\n",
        );
        let config_c = write_config(
            "config-c",
            "--next\nurl = http://example.com/4300003\nheader = \"c: c\"\ndata = \"c\"\n",
        );

        let args = make_args(&["-K", &config_a, "-K", &config_b, "-K", &config_c]);
        let opts = unwrap_opts(parse_args(&args));

        assert_eq!(opts.urls.len(), 3, "should have 3 URLs");
        assert!(opts.had_next, "should have had --next");
        assert_eq!(opts.per_url_group, vec![0, 1, 2], "each URL in its own group");

        // Verify each group has correct headers and body
        for (i, (expected_header, expected_body, expected_url_suffix)) in
            [("a", "a", "4300001"), ("b", "b", "4300002"), ("c", "c", "4300003")].iter().enumerate()
        {
            let easy =
                opts.per_url_easy[i].as_ref().unwrap_or_else(|| panic!("URL {i} should have Easy"));
            assert!(
                opts.urls[i].contains(expected_url_suffix),
                "URL {i} should contain {expected_url_suffix}, got {}",
                opts.urls[i]
            );
            let header_val = easy
                .header_list()
                .iter()
                .find(|(k, _)| k == expected_header)
                .map(|(_, v)| v.as_str());
            assert_eq!(
                header_val,
                Some(*expected_header),
                "group {i} should have header {expected_header}: {expected_header}"
            );
            assert_eq!(
                easy.peek_body().map(|b| std::str::from_utf8(b).unwrap()),
                Some(*expected_body),
                "group {i} should have body {expected_body}"
            );
            assert_eq!(easy.method_str(), Some("POST"), "group {i} should be POST");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test 431: Two -K config files with --next, then --next on cmdline.
    #[test]
    fn parse_args_two_configs_then_cmdline_next() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("urlx_test_431");
        let _ = std::fs::create_dir_all(&dir);

        let write_config = |name: &str, content: &str| {
            let path = dir.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            path.to_str().unwrap().to_string()
        };

        let config_a = write_config(
            "config-a",
            "--next\nurl = http://example.com/4310001\nheader = \"a: a\"\ndata = \"a\"\n",
        );
        let config_b = write_config(
            "config-b",
            "--next\nurl = http://example.com/4310002\nheader = \"b: b\"\ndata = \"b\"\n",
        );

        let args = make_args(&[
            "-K",
            &config_a,
            "-K",
            &config_b,
            "--next",
            "-d",
            "c",
            "http://example.com/4310003",
            "-H",
            "c: c",
        ]);
        let opts = unwrap_opts(parse_args(&args));

        assert_eq!(opts.urls.len(), 3, "should have 3 URLs");
        assert!(opts.had_next);
        assert_eq!(opts.per_url_group, vec![0, 1, 2]);

        // Verify all 3 groups have correct state
        for (i, (expected_header, expected_body)) in
            [("a", "a"), ("b", "b"), ("c", "c")].iter().enumerate()
        {
            let easy =
                opts.per_url_easy[i].as_ref().unwrap_or_else(|| panic!("URL {i} should have Easy"));
            let header_val = easy
                .header_list()
                .iter()
                .find(|(k, _)| k == expected_header)
                .map(|(_, v)| v.as_str());
            assert_eq!(header_val, Some(*expected_header), "group {i} header mismatch");
            assert_eq!(
                easy.peek_body().map(|b| std::str::from_utf8(b).unwrap()),
                Some(*expected_body),
                "group {i} body mismatch"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test 432: Single -K with multiple --next inside, plus nested config directive.
    #[test]
    fn parse_args_config_with_nested_config_and_next() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("urlx_test_432");
        let _ = std::fs::create_dir_all(&dir);

        let write_config = |name: &str, content: &str| {
            let path = dir.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            path.to_str().unwrap().to_string()
        };

        let config_c_path = write_config(
            "config-c",
            "--next\nurl = http://example.com/4320003\nheader = \"c: c\"\ndata = \"c\"\n",
        );

        let main_config = write_config(
            "config",
            &format!(
                "--next\nurl = http://example.com/4320001\nheader = \"a: a\"\ndata = \"a\"\n\
                 --next\nurl = http://example.com/4320002\nheader = \"b: b\"\ndata = \"b\"\n\
                 config = \"{config_c_path}\"\n"
            ),
        );

        let args = make_args(&["-K", &main_config]);
        let opts = unwrap_opts(parse_args(&args));

        assert_eq!(opts.urls.len(), 3, "should have 3 URLs");
        assert!(opts.had_next);
        assert_eq!(opts.per_url_group, vec![0, 1, 2]);

        // Verify all 3 groups
        for (i, (expected_header, expected_body, expected_url_suffix)) in
            [("a", "a", "4320001"), ("b", "b", "4320002"), ("c", "c", "4320003")].iter().enumerate()
        {
            let easy =
                opts.per_url_easy[i].as_ref().unwrap_or_else(|| panic!("URL {i} should have Easy"));
            assert!(
                opts.urls[i].contains(expected_url_suffix),
                "URL {i} should contain {expected_url_suffix}"
            );
            let header_val = easy
                .header_list()
                .iter()
                .find(|(k, _)| k == expected_header)
                .map(|(_, v)| v.as_str());
            assert_eq!(header_val, Some(*expected_header), "group {i} header mismatch");
            assert_eq!(
                easy.peek_body().map(|b| std::str::from_utf8(b).unwrap()),
                Some(*expected_body),
                "group {i} body mismatch"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
