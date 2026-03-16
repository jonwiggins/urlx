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
    pub(crate) proxy_user: Option<(String, String)>,
    pub(crate) trace_file: Option<String>,
    pub(crate) trace_ascii_file: Option<String>,
    pub(crate) trace_time: bool,
    pub(crate) max_filesize: Option<u64>,
    pub(crate) no_keepalive: bool,
    pub(crate) proto: Option<String>,
    pub(crate) proto_redir: Option<String>,
    pub(crate) libcurl: bool,
    pub(crate) netrc_file: Option<String>,
    pub(crate) netrc_optional: bool,
    pub(crate) post301: bool,
    pub(crate) post302: bool,
    pub(crate) post303: bool,
    pub(crate) remote_time: bool,
    pub(crate) stderr_file: Option<String>,
    pub(crate) remote_header_name: bool,
    pub(crate) url_queries: Vec<String>,
    pub(crate) rate: Option<String>,
    pub(crate) use_ntlm: bool,
    pub(crate) use_anyauth: bool,
    pub(crate) globoff: bool,
    pub(crate) alt_svc_file: Option<String>,
    pub(crate) etag_save_file: Option<String>,
    pub(crate) etag_compare_file: Option<String>,
    pub(crate) proto_default: Option<String>,
    pub(crate) output_dir: Option<String>,
    pub(crate) remove_on_error: bool,
    pub(crate) fail_with_body: bool,
    pub(crate) retry_all_errors: bool,
    pub(crate) no_progress_meter: bool,
    pub(crate) location_trusted: bool,
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
    /// Accumulated inline cookie values from `-b` (joined with "; " before sending).
    pub(crate) inline_cookies: Vec<String>,
    /// Whether `--next` was seen without a following URL (parse error if true at end).
    pub(crate) next_needs_url: bool,
    /// Original -X value preserving case (for non-HTTP protocol commands).
    pub(crate) custom_request_original: Option<String>,
    /// Variables set via `--variable` for `--expand-*` expansion.
    pub(crate) variables: Vec<(String, String)>,
}

/// Print version information to stdout.
///
/// Matches curl's `--version` output format: name, version, and feature list.
pub fn print_version() {
    println!("urlx {}", env!("CARGO_PKG_VERSION"));
    println!("Features: alt-svc AsynchDNS cookies crypto Digest HSTS HTTP2 HTTP3 HTTPS-proxy IPv6 Largefile libz Mime NTLM proxy SSL UnixSockets");
    println!("Protocols: dict file ftp ftps http https imap imaps mqtt pop3 pop3s scp sftp smtp smtps ws wss");
}

/// Print usage information to stderr.
#[allow(clippy::too_many_lines)]
pub fn print_usage() {
    eprintln!("urlx 0.1.0 — a memory-safe curl replacement");
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
    eprintln!("      --hostpubmd5 <hash>   SSH host key MD5 fingerprint (ignored, deprecated)");
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
    eprintln!("      --libcurl             Output equivalent C code using libcurl");
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

    // Step 2: Check for --help/-h and --version/-V (early exit, like curl)
    for arg in expanded.iter().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => return ParseResult::Help,
            "-V" | "--version" => return ParseResult::Version,
            _ => {}
        }
    }

    // Step 3: Parse options
    match parse_args_options(&expanded) {
        Ok(opts) => ParseResult::Options(Box::new(opts)),
        Err(code) => ParseResult::Error(code),
    }
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
        } else {
            result.push(arg.clone());
            // For single-char short flags or long flags that take args,
            // mark the next arg to skip expansion.
            if arg.len() == 2 && arg.starts_with('-') && !arg.starts_with("--") {
                let ch = arg.as_bytes()[1] as char;
                if ARG_FLAGS.contains(&ch) {
                    skip_next = true;
                }
            }
        }
    }
    result
}

/// Internal option parser. Returns `Err(exit_code)` if parsing fails (error already printed).
#[allow(clippy::too_many_lines)]
fn parse_args_options(args: &[String]) -> Result<CliOptions, u8> {
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
        proxy_user: None,
        trace_file: None,
        trace_ascii_file: None,
        trace_time: false,
        max_filesize: None,
        no_keepalive: false,
        proto: None,
        proto_redir: None,
        libcurl: false,
        netrc_file: None,
        netrc_optional: false,
        post301: false,
        post302: false,
        post303: false,
        remote_time: false,
        stderr_file: None,
        remote_header_name: false,
        url_queries: Vec::new(),
        rate: None,
        use_ntlm: false,
        use_anyauth: false,
        globoff: false,
        alt_svc_file: None,
        etag_save_file: None,
        etag_compare_file: None,
        proto_default: None,
        output_dir: None,
        remove_on_error: false,
        fail_with_body: false,
        retry_all_errors: false,
        no_progress_meter: false,
        location_trusted: false,
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
        inline_cookies: Vec::new(),
        next_needs_url: false,
        custom_request_original: None,
        variables: Vec::new(),
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-X" | "--request" => {
                i += 1;
                let val = require_arg(args, i, "-X")?;
                opts.easy.method(val);
                // Store original case value for non-HTTP protocols
                // (IMAP/POP3/SMTP use -X as custom protocol command)
                opts.custom_request_original = Some(val.to_string());
            }
            "-H" | "--header" => {
                i += 1;
                let val = require_arg(args, i, "-H")?;
                if let Some((name, value)) = val.split_once(':') {
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
                        Ok(mut data) => {
                            // curl's -d @file strips trailing \r\n (unlike --data-binary)
                            while data.last() == Some(&b'\n') || data.last() == Some(&b'\r') {
                                let _ = data.pop();
                            }
                            opts.easy.body(&data);
                        }
                        Err(e) => {
                            eprintln!("urlx: error reading data: {e}");
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
            "-L" | "--location" | "--follow" => {
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
                    eprintln!("urlx: invalid max-redirs value: {val}");
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
            }
            "-O" | "--remote-name" | "--remote-name-all" => {
                opts.remote_name = true;
            }
            "--no-remote-name" => {
                opts.remote_name = false;
            }
            "-e" | "--referer" => {
                i += 1;
                let val = require_arg(args, i, "-e")?;
                opts.easy.header("Referer", val);
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
            "-i" | "--include" => {
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
            "--compressed" => {
                opts.easy.accept_encoding(true);
            }
            "--tr-encoding" => {
                // Add TE: gzip and Connection: TE headers for transfer-encoding request
                opts.easy.header("TE", "gzip");
                opts.easy.header("Connection", "TE");
            }
            "--connect-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--connect-timeout")?;
                if let Ok(secs) = val.parse::<f64>() {
                    opts.easy.connect_timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {val}");
                    return Err(1);
                }
            }
            "-m" | "--max-time" => {
                i += 1;
                let val = require_arg(args, i, "-m")?;
                if let Ok(secs) = val.parse::<f64>() {
                    opts.easy.timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {val}");
                    return Err(1);
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
                if let Err(e) = opts.easy.proxy(val) {
                    eprintln!("urlx: invalid proxy URL: {e}");
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
                if let Err(msg) = parse_form_field(&mut opts.easy, val) {
                    eprintln!("urlx: {msg}");
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
                    eprintln!("urlx: invalid offset value: {val}");
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
                // Recognized but not implemented — MD5 fingerprints are deprecated
                i += 1;
                let _val = require_arg(args, i, "--hostpubmd5")?;
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
                        eprintln!("urlx: unsupported TLS version: {val}");
                        return Err(1);
                    }
                }
            }
            "--pinnedpubkey" => {
                i += 1;
                let val = require_arg(args, i, "--pinnedpubkey")?;
                opts.easy.ssl_pinned_public_key(val);
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
                let port: u16 = val.parse().ok().unwrap_or_else(|| {
                    eprintln!("urlx: invalid port: {val}");
                    0
                });
                if port == 0 {
                    return Err(1);
                }
                opts.easy.local_port(port);
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
                    eprintln!("urlx: invalid DNS servers: {e}");
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
                    eprintln!("urlx: invalid happy-eyeballs-timeout-ms: {val}");
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
                        eprintln!("urlx: can't read from stdin: {e}");
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
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                let val = require_arg(args, i, "-b")?;
                // "-b none" or "-b ''" enables the cookie engine without sending cookies
                if val == "none" || val.is_empty() {
                    opts.easy.cookie_jar(true);
                } else if !val.contains('=') && std::path::Path::new(val).exists() {
                    // File path: load cookies from cookie file
                    if let Err(e) = opts.easy.cookie_file(val) {
                        eprintln!("urlx: error reading cookie file '{val}': {e}");
                        return Err(1);
                    }
                } else {
                    // Inline cookie string: accumulate verbatim for later joining
                    opts.easy.cookie_jar(true);
                    opts.inline_cookies.push(val.to_string());
                }
            }
            "--data-binary" => {
                i += 1;
                let val = require_arg(args, i, "--data-binary")?;
                if let Some(path) = val.strip_prefix('@') {
                    match read_data_source(path) {
                        Ok(data) => opts.easy.body(&data),
                        Err(e) => {
                            eprintln!("urlx: error reading data: {e}");
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
                let encoded = urlencoded(val);
                opts.easy.body(encoded.as_bytes());
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
                    eprintln!("urlx: invalid --resolve format: {val}");
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
            "--expect100-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--expect100-timeout")?;
                if let Ok(ms) = val.parse::<u64>() {
                    opts.easy.expect_100_timeout(std::time::Duration::from_millis(ms));
                } else {
                    eprintln!("urlx: invalid expect100-timeout value: {val}");
                    return Err(1);
                }
            }
            "--retry" => {
                i += 1;
                let val = require_arg(args, i, "--retry")?;
                if let Ok(n) = val.parse::<u32>() {
                    opts.retry_count = n;
                } else {
                    eprintln!("urlx: invalid retry count: {val}");
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
                        eprintln!("urlx: too large --retry-delay value");
                        return Err(2);
                    }
                    opts.retry_delay_secs = s;
                } else {
                    eprintln!("urlx: invalid retry-delay value: {val}");
                    return Err(2);
                }
            }
            "--retry-max-time" => {
                i += 1;
                let val = require_arg(args, i, "--retry-max-time")?;
                if let Ok(s) = val.parse::<u64>() {
                    opts.retry_max_time_secs = s;
                } else {
                    eprintln!("urlx: invalid retry-max-time value: {val}");
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
                    eprintln!("urlx: invalid parallel-max value: {val}");
                    return Err(1);
                }
            }
            "--socks5-hostname" => {
                i += 1;
                let val = require_arg(args, i, "--socks5-hostname")?;
                let proxy_url = format!("socks5h://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS5 proxy: {e}");
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
                    eprintln!("urlx: invalid tcp-keepalive value: {val}");
                    return Err(1);
                }
            }
            "--keepalive-time" => {
                i += 1;
                let val = require_arg(args, i, "--keepalive-time")?;
                if let Ok(secs) = val.parse::<u64>() {
                    opts.easy.tcp_keepalive(std::time::Duration::from_secs(secs));
                } else {
                    eprintln!("urlx: invalid keepalive-time value: {val}");
                    return Err(1);
                }
            }
            "--hsts" => {
                opts.easy.hsts(true);
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
                    eprintln!("urlx: invalid rate limit: {val}");
                    return Err(1);
                }
            }
            "--speed-limit" => {
                i += 1;
                let val = require_arg(args, i, "--speed-limit")?;
                if let Ok(limit) = val.parse::<u32>() {
                    opts.speed_limit = Some(limit);
                    opts.easy.low_speed_limit(limit);
                } else {
                    eprintln!("urlx: invalid speed limit: {val}");
                    return Err(1);
                }
            }
            "--speed-time" => {
                i += 1;
                let val = require_arg(args, i, "--speed-time")?;
                if let Ok(secs) = val.parse::<u64>() {
                    opts.speed_time = Some(secs);
                    opts.easy.low_speed_time(std::time::Duration::from_secs(secs));
                } else {
                    eprintln!("urlx: invalid speed time: {val}");
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
                let contents_result = if val == "-" {
                    // Read config from stdin
                    use std::io::Read as _;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf).map(|_| buf)
                } else {
                    std::fs::read_to_string(val)
                };
                match contents_result {
                    Ok(contents) => {
                        let config_args = parse_config_file(&contents);
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
                        return parse_args_options(&expanded);
                    }
                    Err(e) => {
                        eprintln!("urlx: can't read config file '{val}': {e}");
                        return Err(1);
                    }
                }
            }
            "--libcurl" => {
                opts.libcurl = true;
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
                } else {
                    eprintln!("urlx: invalid max-filesize: {val}");
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
                    eprintln!("urlx: invalid proxy-header format: {val}");
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
            // FTPS: explicit mode (AUTH TLS)
            "--ftp-ssl" | "--ssl" | "--ftp-ssl-reqd" | "--ssl-reqd" => {
                opts.easy.ftp_ssl_mode(liburlx::protocol::ftp::FtpSslMode::Explicit);
            }
            "--ftp-port" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: --ftp-port requires an argument");
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
                                eprintln!("urlx: can't read file '{path}': {e}");
                                return Err(1);
                            }
                        }
                    }
                } else {
                    val.as_bytes().to_vec()
                };
                // Multiple --json flags: append data (curl compat: test 385)
                opts.easy.append_body(&json_data);
                opts.easy.header("Content-Type", "application/json");
                opts.easy.header("Accept", "application/json");
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
            "--anyauth" => {
                opts.use_anyauth = true;
            }
            "--delegation" => {
                i += 1;
                let _val = require_arg(args, i, "--delegation")?;
                // GSS-API delegation not implemented; accepted for compatibility
            }
            "--sasl-authzid" => {
                i += 1;
                let val = require_arg(args, i, "--sasl-authzid")?;
                opts.easy.sasl_authzid(val);
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
            "--ftp-skip-pasv-ip" => {
                opts.easy.ftp_skip_pasv_ip(true);
            }
            "--ftp-account" => {
                i += 1;
                let val = require_arg(args, i, "--ftp-account")?;
                opts.easy.ftp_account(val);
            }
            "--ftp-method" => {
                i += 1;
                let val = require_arg(args, i, "--ftp-method")?;
                match val.to_lowercase().as_str() {
                    "multicwd" => {
                        opts.easy.ftp_method(liburlx::protocol::ftp::FtpMethod::MultiCwd);
                    }
                    "singlecwd" => {
                        opts.easy.ftp_method(liburlx::protocol::ftp::FtpMethod::SingleCwd);
                    }
                    "nocwd" => {
                        opts.easy.ftp_method(liburlx::protocol::ftp::FtpMethod::NoCwd);
                    }
                    _ => {
                        eprintln!("urlx: invalid FTP method: {val}");
                        eprintln!("  Valid values: multicwd, singlecwd, nocwd");
                        return Err(1);
                    }
                }
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
            "--etag-save" => {
                i += 1;
                let val = require_arg(args, i, "--etag-save")?;
                opts.etag_save_file = Some(val.to_string());
            }
            "--etag-compare" => {
                i += 1;
                let val = require_arg(args, i, "--etag-compare")?;
                opts.etag_compare_file = Some(val.to_string());
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
                    eprintln!("urlx: invalid form-string format: {val}");
                    eprintln!("  Use: --form-string name=value");
                    return Err(1);
                }
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
                    eprintln!("urlx: invalid SOCKS4 proxy: {e}");
                    return Err(1);
                }
            }
            "--socks4a" => {
                i += 1;
                let val = require_arg(args, i, "--socks4a")?;
                let proxy_url = format!("socks4a://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS4a proxy: {e}");
                    return Err(1);
                }
            }
            "--socks5" => {
                i += 1;
                let val = require_arg(args, i, "--socks5")?;
                let proxy_url = format!("socks5://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS5 proxy: {e}");
                    return Err(1);
                }
            }
            arg @ ("--proxy-1.0" | "--proxy1.0") => {
                i += 1;
                let val = require_arg(args, i, arg)?;
                if let Err(e) = opts.easy.proxy(val) {
                    eprintln!("urlx: invalid proxy URL: {e}");
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
                    eprintln!("urlx: invalid tftp-blksize: {val}");
                    return Err(1);
                }
            }
            "--tftp-no-options" => {
                opts.easy.tftp_no_options(true);
            }
            "--url" => {
                i += 1;
                let val = require_arg(args, i, "--url")?;
                opts.urls.push(val.to_string());
            }
            "--output-dir" => {
                i += 1;
                let val = require_arg(args, i, "--output-dir")?;
                opts.output_dir = Some(val.to_string());
            }
            "--remove-on-error" => {
                opts.remove_on_error = true;
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
                opts.variables.push((name, value));
            }
            "--expand-data" => {
                i += 1;
                let val = require_arg(args, i, "--expand-data")?;
                let expanded = expand_variables(val, &opts.variables);
                opts.easy.body(expanded.as_bytes());
                opts.has_post_data = true;
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.set_form_data(true);
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
            | "--negotiate"
            | "--xattr"
            | "--disable"
            | "--metalink"
            | "--basic"
            | "--proxy-basic"
            | "--proxy-anyauth"
            | "--tcp-fastopen"
            | "--suppress-connect-headers"
            | "--no-clobber"
            | "--http0.9"
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
            | "--proxy-negotiate"
            | "--trace-ids"
            | "--ftp-ssl-control"
            | "--ftp-ssl-ccc"
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
                    eprintln!("urlx: -P requires an argument");
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
            // No-op flags that take an argument
            "--create-file-mode"
            | "--service-name"
            | "--proxy-service-name"
            | "--proxy-tlsv1"
            | "--proxy-tls13-ciphers"
            | "--proxy-ciphers"
            | "--tls13-ciphers"
            | "--login-options"
            | "--cert-type"
            | "--key-type"
            | "--pass"
            | "--proxy-cert-type"
            | "--proxy-key-type"
            | "--crlfile"
            | "--proxy-crlfile"
            | "--proxy-pinnedpubkey"
            | "--proxy-pass"
            | "--curves"
            | "--engine"
            | "--ftp-alternative-to-user"
            | "--krb"
            | "--random-file"
            | "--egd-file"
            | "--dns-interface"
            | "--telnet-option"
            | "--proxy-tlsauthtype"
            | "--proxy-tlsuser"
            | "--proxy-tlspassword"
            | "--tlsauthtype"
            | "--tlsuser"
            | "--tlspassword"
            | "--socks5-gssapi-service"
            | "--ftp-pret"
            | "--ftp-ssl-ccc-mode"
            | "--mail-rcpt-allowfails"
            | "--trace-config" => {
                i += 1;
                let _val = require_arg(args, i, &args[i - 1].clone())?;
                // Accepted for compatibility; not implemented
            }
            "--next" => {
                // --next separates URL groups; mark that we need a URL for the next group
                opts.next_needs_url = true;
            }
            arg if arg.starts_with("--no-") => {
                // --no- prefix used on a non-boolean option (curl returns exit code 2)
                eprintln!("urlx: option {arg}: is unknown");
                return Err(2);
            }
            arg if arg.starts_with('-') => {
                eprintln!("urlx: unknown option: {arg}");
                return Err(2);
            }
            url => {
                opts.urls.push(url.to_string());
                opts.next_needs_url = false;
            }
        }
        i += 1;
    }

    // --next at the end with no URL is a parse error (curl returns exit code 2)
    if opts.next_needs_url {
        eprintln!("urlx: (2) no URL specified after --next");
        return Err(2);
    }

    // Apply proxy auth credentials before site auth so Proxy-Authorization
    // appears before Authorization in the header order (curl compat).
    if let Some((ref user, ref pass)) = opts.proxy_user {
        if opts.proxy_ntlm {
            opts.easy.proxy_ntlm_auth(user, pass);
        } else if opts.proxy_digest {
            opts.easy.proxy_digest_auth(user, pass);
        } else {
            opts.easy.proxy_auth(user, pass);
        }
    }

    // Apply auth credentials after proxy auth (for correct header ordering).
    // Skip when --oauth2-bearer is set — the Bearer token is already in the headers
    // and basic_auth would overwrite it.
    if let Some((ref user, ref pass)) = opts.user_credentials {
        if opts.use_aws_sigv4 {
            opts.easy.aws_credentials(user, pass);
        } else if opts.use_ntlm {
            opts.easy.ntlm_auth(user, pass);
        } else if opts.use_anyauth {
            opts.easy.anyauth(user, pass);
        } else if opts.use_digest {
            opts.easy.digest_auth(user, pass);
        } else if !opts.use_bearer {
            opts.easy.basic_auth(user, pass);
        }
    }
    // Note: netrc credential loading is deferred to run() where the URL is known

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

/// If the value contains `=`, only the part after the first `=` is encoded
/// (the name is passed through as-is). Otherwise the entire value is encoded.
pub fn urlencoded(input: &str) -> String {
    if let Some((name, value)) = input.split_once('=') {
        let encoded = percent_encode(value);
        format!("{name}={encoded}")
    } else {
        percent_encode(input)
    }
}

/// Percent-encode a string per RFC 3986 (unreserved characters are not encoded).
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

/// Hex lookup table for percent encoding.
const HEX_CHARS: [u8; 16] = *b"0123456789ABCDEF";

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
pub fn parse_config_file(contents: &str) -> Vec<String> {
    let mut args = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handle --flag=value syntax
        if let Some(rest) = trimmed.strip_prefix("--") {
            if let Some(eq_pos) = rest.find('=') {
                let flag = &rest[..eq_pos];
                let value = rest[eq_pos + 1..].trim();
                args.push(format!("--{flag}"));
                args.push(unquote(value));
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
                args.push(unquote(value));
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

/// Helper to require an argument value for an option flag.
/// Parse a `-F name=value` form field with full curl syntax.
///
/// Supports:
/// - `name=value` — text field
/// - `name=@filepath` — file upload
/// - `name=@filepath;type=mime` — file with custom Content-Type
/// - `name=@filepath;filename=custom` — file with custom filename
/// - `name=@"filepath"` — quoted file path
/// - Complex backslash escaping in filenames
fn parse_form_field(easy: &mut liburlx::Easy, val: &str) -> Result<(), String> {
    let (name, value) =
        val.split_once('=').ok_or_else(|| format!("invalid form field format: {val}"))?;

    if let Some(rest) = value.strip_prefix('@') {
        // File upload — parse filepath and optional ;type= ;filename= modifiers
        let (filepath, modifiers) = parse_form_file_spec(rest);

        let mut custom_type: Option<String> = None;
        let mut custom_filename: Option<String> = None;

        // Parse semicolon-separated modifiers
        for modifier in modifiers {
            if let Some(t) = modifier.strip_prefix("type=") {
                custom_type = Some(t.to_string());
            } else if let Some(f) = modifier.strip_prefix("filename=") {
                custom_filename = Some(unescape_form_filename(f));
            } else if let Some(f) = modifier.strip_prefix("format=") {
                // format= appends to type: e.g., type=text/x-null;format=x-curl
                if let Some(ref mut ct) = custom_type {
                    ct.push_str(";format=");
                    ct.push_str(f);
                }
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
        let display_filename = custom_filename.unwrap_or_else(|| original_filename.clone());

        if let Some(ref ct) = custom_type {
            easy.form_file_with_type(name, &display_filename, ct, &data);
        } else {
            // Guess content type from the original filepath, not the custom filename
            easy.form_file_with_type(
                name,
                &display_filename,
                &liburlx::guess_form_content_type(&original_filename),
                &data,
            );
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
        // Text field — may have ;type= modifier (curl compat: -F "name=val;type=mime")
        // Split on ;type= to extract the Content-Type. Everything after ;type= is the type
        // (including sub-parameters like ;charset=X).
        if let Some(type_pos) = find_type_modifier(value) {
            let field_value = value[..type_pos].trim_start();
            let content_type = &value[type_pos + 6..]; // skip ";type="
            easy.form_field_with_type(name, field_value, content_type);
        } else {
            easy.form_field(name, value);
        }
    }

    Ok(())
}

/// Find the position of `;type=` in a form field value, respecting quotes.
///
/// Returns the byte offset of the `;` before `type=`, or `None` if not found.
fn find_type_modifier(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b';' && value[i + 1..].starts_with("type=") {
            return Some(i);
        }
        i += 1;
    }
    None
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
        eprintln!("urlx: option {flag} requires an argument");
        Err(1)
    } else {
        Ok(&args[i])
    }
}

/// Check if a URL's protocol is in the allowed protocol list.
///
/// Protocol list format matches curl: comma-separated protocol names,
/// optionally prefixed with `=` for exact set (e.g., `=http,https`).
pub fn is_protocol_allowed(url: &str, proto_list: &str) -> bool {
    let scheme = url.split("://").next().unwrap_or("").to_lowercase();
    if scheme.is_empty() {
        return false;
    }

    let list = proto_list.strip_prefix('=').unwrap_or(proto_list);
    list.split(',').any(|p| p.trim().eq_ignore_ascii_case(&scheme))
}

/// Parse a `--variable` argument.
///
/// Formats:
///   - `name=value` — direct assignment
///   - `name@file` — load from file
///   - `name@-` — load from stdin
///   - `name[start-end]=value` — byte range from direct value
///   - `name[start-end]@file` — byte range from file
///   - `name[start-]@file` — byte range from start to end of data
///
/// Returns `(name, value)` after applying byte range if specified.
fn parse_variable(spec: &str) -> Result<(String, String), u8> {
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
                    eprintln!("urlx: invalid byte range start: {s}");
                    2
                })?;
                let end: Option<usize> = if e.is_empty() {
                    None
                } else {
                    Some(e.parse().map_err(|_| {
                        eprintln!("urlx: invalid byte range end: {e}");
                        2
                    })?)
                };
                Some((start, end))
            } else {
                eprintln!("urlx: invalid byte range: {range_str}");
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
    let raw_value = if let Some(rest) = rest.strip_prefix('=') {
        rest.to_string()
    } else if let Some(rest) = rest.strip_prefix('@') {
        if rest == "-" {
            use std::io::Read as _;
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            buf
        } else {
            std::fs::read_to_string(rest).map_err(|e| {
                eprintln!("urlx: can't read variable file '{rest}': {e}");
                2
            })?
        }
    } else if byte_range.is_none() {
        // No range and no = or @ — check the original spec for = or @
        if let Some(eq_pos) = name.find('=') {
            let (n, v) = name.split_at(eq_pos);
            return Ok((n.to_string(), v[1..].to_string()));
        }
        if let Some(at_pos) = name.find('@') {
            let (n, f) = name.split_at(at_pos);
            let file = &f[1..];
            let content = if file == "-" {
                use std::io::Read as _;
                let mut buf = String::new();
                let _ = std::io::stdin().read_to_string(&mut buf);
                buf
            } else {
                std::fs::read_to_string(file).map_err(|e| {
                    eprintln!("urlx: can't read variable file '{file}': {e}");
                    2
                })?
            };
            return Ok((n.to_string(), content));
        }
        // No value source specified — empty value
        String::new()
    } else {
        String::new()
    };

    // Apply byte range
    let value = if let Some((start, end)) = byte_range {
        let bytes = raw_value.as_bytes();
        if start >= bytes.len() {
            String::new()
        } else {
            let end = end.map_or(bytes.len() - 1, |e| e.min(bytes.len() - 1));
            String::from_utf8_lossy(&bytes[start..=end]).to_string()
        }
    } else {
        raw_value
    };

    Ok((name, value))
}

/// Expand `{{variable}}` placeholders in a string using the provided variables.
fn expand_variables(template: &str, variables: &[(String, String)]) -> String {
    let mut result = template.to_string();
    for (name, value) in variables {
        let placeholder = format!("{{{{{name}}}}}");
        result = result.replace(&placeholder, value);
    }
    result
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
        let result = format_write_out("%{http_code}", &response);
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
        let result = format_write_out("%{http_version}", &response);
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
        let result = format_write_out("%{http_version}", &response);
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
        let result = format_write_out("a\\nb\\tc", &response);
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
        let result = format_write_out("%{http_code} %{size_download} %{url_effective}", &response);
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
        let result = format_write_out("a\\rb", &response);
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
        let result = format_write_out("%{content_type}", &response);
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
        assert_eq!(urlencoded("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoded_with_name() {
        assert_eq!(urlencoded("key=hello world"), "key=hello%20world");
    }

    #[test]
    fn urlencoded_special_chars() {
        // Input has '=' so it splits: name="a&b", value="c" → "a&b=c"
        assert_eq!(urlencoded("a&b=c"), "a&b=c");
        // Without '=', the whole string is encoded
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
        let args = vec!["urlx".into(), "--libcurl".into(), "http://example.com".into()];
        let opts = unwrap_opts(parse_args(&args));
        assert!(opts.libcurl);
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
    fn parse_hostpubmd5_noop() {
        let args = vec![
            "urlx".into(),
            "--hostpubmd5".into(),
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(matches!(parse_args(&args), ParseResult::Options(_)));
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
        let result = append_url_queries("http://example.com", &["key=value".to_string()]);
        assert_eq!(result, "http://example.com?key=value");
    }

    #[test]
    fn append_url_queries_existing_query() {
        let result = append_url_queries("http://example.com?a=1", &["b=2".to_string()]);
        assert_eq!(result, "http://example.com?a=1&b=2");
    }

    #[test]
    fn append_url_queries_multiple() {
        let result = append_url_queries(
            "http://example.com",
            &["a=1".to_string(), "b=hello world".to_string()],
        );
        assert!(result.starts_with("http://example.com?a=1&b=hello%20world"));
    }

    #[test]
    fn append_url_queries_no_equals() {
        let result = append_url_queries("http://example.com", &["raw_string".to_string()]);
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
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_delegation_flag() {
        let args = make_args(&["--delegation", "always", "http://example.com"]);
        let opts = unwrap_opts(parse_args(&args));
        assert_eq!(opts.urls, vec!["http://example.com"]);
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
}
