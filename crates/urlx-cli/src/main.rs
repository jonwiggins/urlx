//! `urlx` — A memory-safe command-line URL transfer tool.
//!
//! Drop-in replacement for the `curl` command.

#![deny(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    run(&args)
}

/// Parsed CLI options.
#[allow(clippy::struct_excessive_bools)]
struct CliOptions {
    easy: liburlx::Easy,
    urls: Vec<String>,
    output_file: Option<String>,
    write_out: Option<String>,
    show_progress: bool,
    silent: bool,
    show_error: bool,
    fail_on_error: bool,
    include_headers: bool,
    dump_header: Option<String>,
    use_digest: bool,
    use_aws_sigv4: bool,
    use_bearer: bool,
    user_credentials: Option<(String, String)>,
    retry_count: u32,
    retry_delay_secs: u64,
    retry_max_time_secs: u64,
    parallel: bool,
    parallel_max: usize,
    cookie_jar_file: Option<String>,
    limit_rate: Option<String>,
    speed_limit: Option<u32>,
    speed_time: Option<u64>,
    remote_name: bool,
    create_dirs: bool,
    proxy_digest: bool,
    proxy_ntlm: bool,
    proxy_user: Option<(String, String)>,
    trace_file: Option<String>,
    trace_ascii_file: Option<String>,
    trace_time: bool,
    max_filesize: Option<u64>,
    no_keepalive: bool,
    proto: Option<String>,
    proto_redir: Option<String>,
    libcurl: bool,
    netrc_file: Option<String>,
    netrc_optional: bool,
    post301: bool,
    post302: bool,
    post303: bool,
    remote_time: bool,
    stderr_file: Option<String>,
    remote_header_name: bool,
    url_queries: Vec<String>,
    rate: Option<String>,
    use_ntlm: bool,
    globoff: bool,
    alt_svc_file: Option<String>,
    etag_save_file: Option<String>,
    etag_compare_file: Option<String>,
    proto_default: Option<String>,
    output_dir: Option<String>,
    remove_on_error: bool,
}

/// Print usage information to stderr.
#[allow(clippy::too_many_lines)]
fn print_usage() {
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

/// Parse CLI arguments into options.
///
/// Returns `None` if parsing fails (error already printed).
#[allow(clippy::too_many_lines)]
fn parse_args(args: &[String]) -> Option<CliOptions> {
    let mut opts = CliOptions {
        easy: liburlx::Easy::new(),
        urls: Vec::new(),
        output_file: None,
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
        globoff: false,
        alt_svc_file: None,
        etag_save_file: None,
        etag_compare_file: None,
        proto_default: None,
        output_dir: None,
        remove_on_error: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-X" | "--request" => {
                i += 1;
                let val = require_arg(args, i, "-X")?;
                opts.easy.method(val);
            }
            "-H" | "--header" => {
                i += 1;
                let val = require_arg(args, i, "-H")?;
                if let Some((name, value)) = val.split_once(':') {
                    opts.easy.header(name.trim(), value.trim());
                } else {
                    eprintln!("urlx: invalid header format: {val}");
                    return None;
                }
            }
            "-d" | "--data" => {
                i += 1;
                let val = require_arg(args, i, "-d")?;
                // Support @filename to read from file, @- for stdin
                if let Some(path) = val.strip_prefix('@') {
                    match read_data_source(path) {
                        Ok(data) => opts.easy.body(&data),
                        Err(e) => {
                            eprintln!("urlx: error reading data: {e}");
                            return None;
                        }
                    }
                } else {
                    opts.easy.body(val.as_bytes());
                }
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
            }
            "--data-raw" => {
                i += 1;
                let val = require_arg(args, i, "--data-raw")?;
                opts.easy.body(val.as_bytes());
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
            }
            "-L" | "--location" => {
                opts.easy.follow_redirects(true);
            }
            "--max-redirs" => {
                i += 1;
                let val = require_arg(args, i, "--max-redirs")?;
                if let Ok(max) = val.parse::<u32>() {
                    opts.easy.max_redirects(max);
                } else {
                    eprintln!("urlx: invalid max-redirs value: {val}");
                    return None;
                }
            }
            "-I" | "--head" => {
                opts.easy.method("HEAD");
            }
            "-o" | "--output" => {
                i += 1;
                let val = require_arg(args, i, "-o")?;
                opts.output_file = Some(val.to_string());
            }
            "-O" | "--remote-name" => {
                opts.remote_name = true;
            }
            "-e" | "--referer" => {
                i += 1;
                let val = require_arg(args, i, "-e")?;
                opts.easy.header("Referer", val);
            }
            "-G" | "--get" => {
                opts.easy.method("GET");
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
            "-v" | "--verbose" => {
                opts.easy.verbose(true);
            }
            "-s" | "--silent" => {
                opts.silent = true;
            }
            "-S" | "--show-error" => {
                opts.show_error = true;
            }
            "-f" | "--fail" => {
                opts.fail_on_error = true;
            }
            "--compressed" => {
                opts.easy.accept_encoding(true);
            }
            "--connect-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--connect-timeout")?;
                if let Ok(secs) = val.parse::<f64>() {
                    opts.easy.connect_timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {val}");
                    return None;
                }
            }
            "-m" | "--max-time" => {
                i += 1;
                let val = require_arg(args, i, "-m")?;
                if let Ok(secs) = val.parse::<f64>() {
                    opts.easy.timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {val}");
                    return None;
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
                    return None;
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
                opts.easy.header("User-Agent", val);
            }
            "-F" | "--form" => {
                i += 1;
                let val = require_arg(args, i, "-F")?;
                if let Some((name, value)) = val.split_once('=') {
                    if let Some(path) = value.strip_prefix('@') {
                        if let Err(e) = opts.easy.form_file(name, std::path::Path::new(path)) {
                            eprintln!("urlx: error reading form file: {e}");
                            return None;
                        }
                    } else {
                        opts.easy.form_field(name, value);
                    }
                } else {
                    eprintln!("urlx: invalid form field format: {val}");
                    eprintln!("  Use: -F name=value or -F name=@filename");
                    return None;
                }
            }
            "-r" | "--range" => {
                i += 1;
                let val = require_arg(args, i, "-r")?;
                opts.easy.range(val);
            }
            "-C" | "--continue-at" => {
                i += 1;
                let val = require_arg(args, i, "-C")?;
                if let Ok(offset) = val.parse::<u64>() {
                    opts.easy.resume_from(offset);
                } else {
                    eprintln!("urlx: invalid offset value: {val}");
                    return None;
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
            "--proxy-user" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-user")?;
                let (user, pass) =
                    if let Some((u, p)) = val.split_once(':') { (u, p) } else { (val, "") };
                opts.proxy_user = Some((user.to_string(), pass.to_string()));
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
                        return None;
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
                    return None;
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
                    return None;
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
                    return None;
                }
            }
            "-T" | "--upload-file" => {
                i += 1;
                let val = require_arg(args, i, "-T")?;
                match std::fs::read(val) {
                    Ok(data) => {
                        opts.easy.body(&data);
                        if opts.easy.method_is_default() {
                            opts.easy.method("PUT");
                        }
                    }
                    Err(e) => {
                        eprintln!("urlx: can't read file '{val}': {e}");
                        return None;
                    }
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                let val = require_arg(args, i, "-b")?;
                // If the value looks like a file path (contains no = and exists on disk), load from file
                if !val.contains('=') && std::path::Path::new(val).exists() {
                    if let Err(e) = opts.easy.cookie_file(val) {
                        eprintln!("urlx: error reading cookie file '{val}': {e}");
                        return None;
                    }
                } else {
                    // Treat as inline cookie string
                    opts.easy.cookie_jar(true);
                    opts.easy.header("Cookie", val);
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
                            return None;
                        }
                    }
                } else {
                    opts.easy.body(val.as_bytes());
                }
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
            }
            "--data-urlencode" => {
                i += 1;
                let val = require_arg(args, i, "--data-urlencode")?;
                let encoded = urlencoded(val);
                opts.easy.body(encoded.as_bytes());
                if opts.easy.method_is_default() {
                    opts.easy.method("POST");
                }
                opts.easy.header("Content-Type", "application/x-www-form-urlencoded");
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
                    return None;
                }
            }
            "--http1.0" => {
                opts.easy.http_version(liburlx::HttpVersion::Http10);
            }
            "--http1.1" => {
                opts.easy.http_version(liburlx::HttpVersion::Http11);
            }
            "--http2" => {
                opts.easy.http_version(liburlx::HttpVersion::Http2);
            }
            "--http3" => {
                opts.easy.http_version(liburlx::HttpVersion::Http3);
            }
            "--expect100-timeout" => {
                i += 1;
                let val = require_arg(args, i, "--expect100-timeout")?;
                if let Ok(ms) = val.parse::<u64>() {
                    opts.easy.expect_100_timeout(std::time::Duration::from_millis(ms));
                } else {
                    eprintln!("urlx: invalid expect100-timeout value: {val}");
                    return None;
                }
            }
            "--retry" => {
                i += 1;
                let val = require_arg(args, i, "--retry")?;
                if let Ok(n) = val.parse::<u32>() {
                    opts.retry_count = n;
                } else {
                    eprintln!("urlx: invalid retry count: {val}");
                    return None;
                }
            }
            "--retry-delay" => {
                i += 1;
                let val = require_arg(args, i, "--retry-delay")?;
                if let Ok(s) = val.parse::<u64>() {
                    opts.retry_delay_secs = s;
                } else {
                    eprintln!("urlx: invalid retry-delay value: {val}");
                    return None;
                }
            }
            "--retry-max-time" => {
                i += 1;
                let val = require_arg(args, i, "--retry-max-time")?;
                if let Ok(s) = val.parse::<u64>() {
                    opts.retry_max_time_secs = s;
                } else {
                    eprintln!("urlx: invalid retry-max-time value: {val}");
                    return None;
                }
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
                    return None;
                }
            }
            "--socks5-hostname" => {
                i += 1;
                let val = require_arg(args, i, "--socks5-hostname")?;
                let proxy_url = format!("socks5h://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS5 proxy: {e}");
                    return None;
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
                    return None;
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
                    return None;
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
                    return None;
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
                    return None;
                }
            }
            "--trace" => {
                i += 1;
                let val = require_arg(args, i, "--trace")?;
                opts.trace_file = Some(val.to_string());
                opts.easy.verbose(true);
            }
            "--trace-ascii" => {
                i += 1;
                let val = require_arg(args, i, "--trace-ascii")?;
                opts.trace_ascii_file = Some(val.to_string());
                opts.easy.verbose(true);
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
                match std::fs::read_to_string(val) {
                    Ok(contents) => {
                        let config_args = parse_config_file(&contents);
                        let mut full_args = vec!["urlx".to_string()];
                        full_args.extend(config_args);
                        // Re-parse with the remaining CLI args
                        for arg in args.iter().skip(i + 1) {
                            full_args.push(arg.clone());
                        }
                        return parse_args(&full_args);
                    }
                    Err(e) => {
                        eprintln!("urlx: can't read config file '{val}': {e}");
                        return None;
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
                    return None;
                }
            }
            "--no-keepalive" => {
                opts.no_keepalive = true;
            }
            "--netrc" => {
                let home = std::env::var("HOME").unwrap_or_default();
                opts.netrc_file = Some(format!("{home}/.netrc"));
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
                    return None;
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
            "--globoff" => {
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
                    return None;
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
                opts.easy.body(val.as_bytes());
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
                        return None;
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
                    return None;
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
                    return None;
                }
            }
            "--socks4a" => {
                i += 1;
                let val = require_arg(args, i, "--socks4a")?;
                let proxy_url = format!("socks4a://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS4a proxy: {e}");
                    return None;
                }
            }
            "--socks5" => {
                i += 1;
                let val = require_arg(args, i, "--socks5")?;
                let proxy_url = format!("socks5://{val}");
                if let Err(e) = opts.easy.proxy(&proxy_url) {
                    eprintln!("urlx: invalid SOCKS5 proxy: {e}");
                    return None;
                }
            }
            "--proxy-1.0" => {
                i += 1;
                let val = require_arg(args, i, "--proxy-1.0")?;
                if let Err(e) = opts.easy.proxy(val) {
                    eprintln!("urlx: invalid proxy URL: {e}");
                    return None;
                }
                opts.easy.http_version(liburlx::HttpVersion::Http10);
            }
            "--tftp-blksize" => {
                i += 1;
                let val = require_arg(args, i, "--tftp-blksize")?;
                if let Ok(bs) = val.parse::<u16>() {
                    opts.easy.tftp_blksize(bs);
                } else {
                    eprintln!("urlx: invalid tftp-blksize: {val}");
                    return None;
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
            // No-op flags for compatibility (accepted but not implemented)
            "-N" | "--no-buffer" | "--no-sessionid" | "--no-alpn" | "--no-npn"
            | "--cert-status" | "--false-start" | "--disable-eprt" | "--disable-epsv"
            | "--compressed-ssh" | "--doh-cert-status" | "--next" | "--ftp-pasv"
            | "--styled-output" | "--no-styled-output" | "--negotiate" => {}
            // No-op flags that take an argument
            "--create-file-mode"
            | "--service-name"
            | "--proxy-service-name"
            | "--proxy-tlsv1"
            | "--proxy-tls13-ciphers"
            | "--proxy-ciphers"
            | "--tls13-ciphers"
            | "--login-options" => {
                i += 1;
                let _val = require_arg(args, i, &args[i - 1].clone())?;
                // Accepted for compatibility; not implemented
            }
            arg if arg.starts_with('-') => {
                eprintln!("urlx: unknown option: {arg}");
                return None;
            }
            url => {
                opts.urls.push(url.to_string());
            }
        }
        i += 1;
    }

    // Apply auth credentials after all flags are parsed
    if let Some((ref user, ref pass)) = opts.user_credentials {
        if opts.use_aws_sigv4 {
            opts.easy.aws_credentials(user, pass);
        } else if opts.use_ntlm {
            opts.easy.ntlm_auth(user, pass);
        } else if opts.use_digest {
            opts.easy.digest_auth(user, pass);
        } else {
            opts.easy.basic_auth(user, pass);
        }
    }
    // Note: netrc credential loading is deferred to run() where the URL is known

    // Apply proxy auth credentials
    if let Some((ref user, ref pass)) = opts.proxy_user {
        if opts.proxy_ntlm {
            opts.easy.proxy_ntlm_auth(user, pass);
        } else if opts.proxy_digest {
            opts.easy.proxy_digest_auth(user, pass);
        } else {
            opts.easy.proxy_auth(user, pass);
        }
    }

    Some(opts)
}

/// Read data from a file path or stdin (`-`).
///
/// Used by `-d @filename` and `--data-binary @filename`.
/// The path `-` reads from stdin.
fn read_data_source(path: &str) -> Result<Vec<u8>, std::io::Error> {
    if path == "-" {
        use std::io::Read as _;
        let mut buf = Vec::new();
        let _bytes = std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

/// URL-encode a string value for `--data-urlencode`.
///
/// If the value contains `=`, only the part after the first `=` is encoded
/// (the name is passed through as-is). Otherwise the entire value is encoded.
fn urlencoded(input: &str) -> String {
    if let Some((name, value)) = input.split_once('=') {
        let encoded = percent_encode(value);
        format!("{name}={encoded}")
    } else {
        percent_encode(input)
    }
}

/// Percent-encode a string per RFC 3986 (unreserved characters are not encoded).
fn percent_encode(input: &str) -> String {
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
/// Takes the last path segment. Falls back to `"index.html"` if no filename.
fn remote_name_from_url(url: &str) -> String {
    // Strip scheme (e.g., "http://")
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);

    // Strip query string and fragment
    let without_query = without_scheme
        .split('?')
        .next()
        .unwrap_or(without_scheme)
        .split('#')
        .next()
        .unwrap_or(without_scheme);

    // Find the path part (after the first '/')
    if let Some(slash_pos) = without_query.find('/') {
        let path = &without_query[slash_pos..];
        if let Some(name) = path.rsplit('/').next() {
            if name.is_empty() {
                return "index.html".to_string();
            }
            return name.to_string();
        }
    }

    "index.html".to_string()
}

/// Set a file's modification time from an HTTP `Last-Modified` header value.
///
/// Parses the RFC 7231 date format (e.g., "Tue, 15 Nov 1994 08:12:31 GMT")
/// and sets the file's modification time accordingly. Best-effort: errors
/// are silently ignored unless not in silent mode.
fn set_file_mtime(path: &str, last_modified: &str, silent: bool) {
    if let Some(timestamp) = parse_http_date(last_modified) {
        let mtime = filetime::FileTime::from_unix_time(timestamp, 0);
        if let Err(e) = filetime::set_file_mtime(path, mtime) {
            if !silent {
                eprintln!("urlx: warning: could not set file time: {e}");
            }
        }
    }
}

/// Parse an HTTP date string into a Unix timestamp (seconds since epoch).
///
/// Supports RFC 7231 preferred format: `"Sun, 06 Nov 1994 08:49:37 GMT"`.
/// Returns `None` if parsing fails.
fn parse_http_date(s: &str) -> Option<i64> {
    // RFC 7231: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }

    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1_u32,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: i64 = time_parts[0].parse().ok()?;
    let minute: i64 = time_parts[1].parse().ok()?;
    let second: i64 = time_parts[2].parse().ok()?;

    // Convert to Unix timestamp using a simplified calculation
    // Days from epoch (1970-01-01) to the given date
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += i64::from(month_days[m as usize]);
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += i64::from(day) - 1;

    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Check if a year is a leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Extract hostname from a URL string.
///
/// Handles `scheme://host:port/path` format. Returns the host part only.
fn extract_hostname(url: &str) -> String {
    let without_scheme = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    let without_userinfo =
        without_path.rfind('@').map_or(without_path, |pos| &without_path[pos + 1..]);
    // Strip port
    without_userinfo.rsplit_once(':').map_or(without_userinfo, |(host, _)| host).to_string()
}

/// Append query parameters to a URL string.
///
/// Each query string is appended with `&` if the URL already has a `?`,
/// or with `?` if it doesn't. Values containing `=` are used as-is;
/// plain values are URL-encoded.
fn append_url_queries(url: &str, queries: &[String]) -> String {
    let mut result = url.to_string();
    for query in queries {
        let separator = if result.contains('?') { '&' } else { '?' };
        result.push(separator);
        if query.contains('=') {
            // name=value format: encode only the value
            if let Some((name, value)) = query.split_once('=') {
                result.push_str(name);
                result.push('=');
                result.push_str(&percent_encode(value));
            }
        } else {
            // Plain string: use as-is (already encoded or literal)
            result.push_str(query);
        }
    }
    result
}

/// Extract filename from a `Content-Disposition` response header.
///
/// Supports both `filename="quoted"` and `filename=unquoted` forms.
/// Returns `None` if the header is absent or doesn't contain a filename.
fn content_disposition_filename(response: &liburlx::Response) -> Option<String> {
    let header = response.header("content-disposition")?;
    // Look for filename= parameter
    let filename_start = header.find("filename=")?;
    let after = &header[filename_start + 9..];
    if let Some(quoted) = after.strip_prefix('"') {
        // Quoted filename: extract until closing quote
        let end = quoted.find('"')?;
        Some(quoted[..end].to_string())
    } else {
        // Unquoted: take until semicolon or end
        let end = after.find(';').unwrap_or(after.len());
        let name = after[..end].trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }
}

/// Parse a rate limit string like "100K", "1M", "500" into bytes per second.
///
/// Supports suffixes: K/k (1024), M/m (1024*1024), G/g (1024^3).
/// Returns `None` if the value cannot be parsed.
fn parse_rate_limit(input: &str) -> Option<u64> {
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
fn parse_config_file(contents: &str) -> Vec<String> {
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
                continue;
            }
        }

        // Split on first whitespace: flag + optional value
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        args.push(parts[0].to_string());
        if parts.len() > 1 {
            let value = parts[1].trim();
            if !value.is_empty() {
                args.push(unquote(value));
            }
        }
    }
    args
}

/// Remove surrounding quotes from a config file value.
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Helper to require an argument value for an option flag.
fn require_arg<'a>(args: &'a [String], i: usize, flag: &str) -> Option<&'a str> {
    if i >= args.len() {
        eprintln!("urlx: option {flag} requires an argument");
        None
    } else {
        Some(&args[i])
    }
}

/// Check if a URL's protocol is in the allowed protocol list.
///
/// Protocol list format matches curl: comma-separated protocol names,
/// optionally prefixed with `=` for exact set (e.g., `=http,https`).
fn is_protocol_allowed(url: &str, proto_list: &str) -> bool {
    let scheme = url.split("://").next().unwrap_or("").to_lowercase();
    if scheme.is_empty() {
        return false;
    }

    let list = proto_list.strip_prefix('=').unwrap_or(proto_list);
    list.split(',').any(|p| p.trim().eq_ignore_ascii_case(&scheme))
}

/// Generate equivalent C code using libcurl for `--libcurl` output.
fn generate_libcurl_code(opts: &CliOptions) -> String {
    let url = opts.urls.first().map_or("", String::as_str);
    let mut code = String::new();
    code.push_str("/*** Code generated by urlx --libcurl ***/\n");
    code.push_str("#include <curl/curl.h>\n\n");
    code.push_str("int main(void) {\n");
    code.push_str("    CURL *curl;\n");
    code.push_str("    CURLcode res;\n\n");
    code.push_str("    curl = curl_easy_init();\n");
    code.push_str("    if (curl) {\n");
    code.push_str("        curl_easy_setopt(curl, CURLOPT_URL, \"");
    code.push_str(url);
    code.push_str("\");\n");
    if opts.include_headers {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);\n");
    }
    if opts.silent {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);\n");
    }
    if opts.fail_on_error {
        code.push_str("        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);\n");
    }
    code.push_str("        res = curl_easy_perform(curl);\n");
    code.push_str("        curl_easy_cleanup(curl);\n");
    code.push_str("    }\n");
    code.push_str("    return (int)res;\n");
    code.push_str("}\n");
    code
}

#[allow(clippy::too_many_lines)]
fn run(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        print_usage();
        return ExitCode::FAILURE;
    }

    let Some(mut opts) = parse_args(args) else {
        return ExitCode::FAILURE;
    };

    // Expand URL globs unless --globoff is set
    if !opts.globoff {
        let mut expanded = Vec::new();
        for url in &opts.urls {
            match liburlx::glob::expand_glob(url) {
                Ok(urls) => expanded.extend(urls),
                Err(e) => {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: glob error: {e}");
                    }
                    return ExitCode::FAILURE;
                }
            }
        }
        opts.urls = expanded;
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if opts.urls.len() > 1 {
        return run_multi(
            &opts.easy,
            &opts.urls,
            opts.output_file.as_deref(),
            opts.write_out.as_deref(),
            opts.silent,
            opts.show_error,
            opts.fail_on_error,
            opts.parallel,
            opts.parallel_max,
        );
    }

    // Single URL: use Easy API
    if let Some(url) = opts.urls.first() {
        // --url-query: append query parameters to URL
        let url = if opts.url_queries.is_empty() {
            url.clone()
        } else {
            append_url_queries(url, &opts.url_queries)
        };

        // --proto-default: add default scheme if URL has none
        let url = if let Some(ref default_proto) = opts.proto_default {
            if url.contains("://") {
                url
            } else {
                format!("{default_proto}://{url}")
            }
        } else {
            url
        };

        // --proto: validate URL scheme against allowed protocols
        if let Some(ref proto_list) = opts.proto {
            if !is_protocol_allowed(&url, proto_list) {
                if !opts.silent || opts.show_error {
                    eprintln!("urlx: protocol not allowed by --proto");
                }
                return ExitCode::FAILURE;
            }
        }

        if let Err(e) = opts.easy.url(&url) {
            if !opts.silent || opts.show_error {
                eprintln!("urlx: error parsing URL: {e}");
            }
            return ExitCode::FAILURE;
        }

        // --netrc: load credentials from .netrc file for this URL
        if opts.user_credentials.is_none() {
            if let Some(ref netrc_path) = opts.netrc_file {
                match std::fs::read_to_string(netrc_path) {
                    Ok(contents) => {
                        let host = extract_hostname(&url);
                        if let Some(entry) = liburlx::netrc::lookup(&contents, &host) {
                            let user = entry.login.unwrap_or_default();
                            let pass = entry.password.unwrap_or_default();
                            if opts.use_digest {
                                opts.easy.digest_auth(&user, &pass);
                            } else {
                                opts.easy.basic_auth(&user, &pass);
                            }
                        }
                    }
                    Err(e) => {
                        if !opts.netrc_optional {
                            if !opts.silent || opts.show_error {
                                eprintln!("urlx: can't read netrc file '{netrc_path}': {e}");
                            }
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
        }

        // -O/--remote-name: derive output filename from URL
        if opts.remote_name && opts.output_file.is_none() {
            opts.output_file = Some(remote_name_from_url(&url));
        }
    }

    // --create-dirs: create parent directories for output file
    if opts.create_dirs {
        if let Some(ref path) = opts.output_file {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        if !opts.silent || opts.show_error {
                            eprintln!("urlx: error creating directories: {e}");
                        }
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }

    if opts.show_progress && !opts.silent {
        opts.easy.progress_callback(liburlx::make_progress_callback(|info| {
            let pct = if info.dl_total > 0 { (info.dl_now * 100) / info.dl_total } else { 0 };
            let bar_width: usize = 40;
            #[allow(clippy::cast_possible_truncation)]
            let filled = ((pct as usize) * bar_width) / 100;
            let empty = bar_width.saturating_sub(filled);
            eprint!(
                "\r[{}{}] {}% ({} bytes)",
                "#".repeat(filled),
                " ".repeat(empty),
                pct,
                info.dl_now,
            );
            true
        }));
    }

    let result = perform_with_retry(&mut opts);

    // Save cookie jar after transfer (even on error)
    if opts.cookie_jar_file.is_some() {
        if let Err(e) = opts.easy.save_cookie_jar() {
            if !opts.silent || opts.show_error {
                eprintln!("urlx: error saving cookies: {e}");
            }
        }
    }

    match result {
        Ok(response) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }

            // --etag-save: save ETag from response header
            if let Some(ref path) = opts.etag_save_file {
                if let Some(etag) = response.header("etag") {
                    if let Err(e) = std::fs::write(path, etag) {
                        if !opts.silent || opts.show_error {
                            eprintln!("urlx: error saving ETag to '{path}': {e}");
                        }
                    }
                }
            }

            // --fail: exit 22 on HTTP error status codes
            if opts.fail_on_error && response.status() >= 400 {
                if !opts.silent || opts.show_error {
                    eprintln!(
                        "urlx: The requested URL returned error: {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    );
                }
                return ExitCode::from(22);
            }

            // --max-filesize: check response body size
            if let Some(max_size) = opts.max_filesize {
                if response.body().len() as u64 > max_size {
                    if !opts.silent || opts.show_error {
                        eprintln!(
                            "urlx: maximum file size exceeded ({} > {max_size} bytes)",
                            response.body().len(),
                        );
                    }
                    return ExitCode::from(63);
                }
            }

            // -J/--remote-header-name: override output filename from Content-Disposition
            if opts.remote_header_name {
                if let Some(name) = content_disposition_filename(&response) {
                    opts.output_file = Some(name);
                }
            }

            // --dump-header: write headers to file
            if let Some(ref path) = opts.dump_header {
                let header_text = format_headers(&response);
                if let Err(e) = std::fs::write(path, header_text) {
                    if !opts.silent || opts.show_error {
                        eprintln!("urlx: error writing headers to {path}: {e}");
                    }
                    return ExitCode::FAILURE;
                }
            }

            // --trace / --trace-ascii: write trace to file
            if opts.trace_file.is_some() || opts.trace_ascii_file.is_some() {
                let url_str = opts.urls.first().map_or("", String::as_str);
                let method = opts.easy.method_str().unwrap_or("GET");
                let request_headers = opts.easy.header_list();

                if let Some(ref path) = opts.trace_file {
                    write_trace_file(
                        path,
                        &response,
                        url_str,
                        method,
                        request_headers,
                        true,
                        opts.trace_time,
                    );
                }
                if let Some(ref path) = opts.trace_ascii_file {
                    write_trace_file(
                        path,
                        &response,
                        url_str,
                        method,
                        request_headers,
                        false,
                        opts.trace_time,
                    );
                }
            }

            // --libcurl: output equivalent C code
            if opts.libcurl {
                let c_code = generate_libcurl_code(&opts);
                eprintln!("{c_code}");
            }

            let exit = output_response(
                &response,
                opts.output_file.as_deref(),
                opts.write_out.as_deref(),
                opts.include_headers,
                opts.silent,
            );

            // --remote-time: set output file's modification time from Last-Modified
            if opts.remote_time {
                if let Some(ref path) = opts.output_file {
                    if let Some(last_modified) = response.header("last-modified") {
                        set_file_mtime(path, last_modified, opts.silent);
                    }
                }
            }

            exit
        }
        Err(e) => {
            if opts.show_progress && !opts.silent {
                eprintln!();
            }
            if !opts.silent || opts.show_error {
                eprintln!("urlx: {e}");
            }
            error_to_exit_code(&e)
        }
    }
}

/// Map a liburlx error to a curl-compatible exit code.
///
/// Matches curl's exit code conventions for the most common errors.
fn error_to_exit_code(err: &liburlx::Error) -> ExitCode {
    match err {
        liburlx::Error::UrlParse(_) => ExitCode::from(3),
        liburlx::Error::Connect(io_err) => {
            match io_err.kind() {
                // DNS resolution failure
                std::io::ErrorKind::Other => {
                    let msg = io_err.to_string();
                    if msg.contains("dns") || msg.contains("DNS") || msg.contains("resolve") {
                        ExitCode::from(6) // CURLE_COULDNT_RESOLVE_HOST
                    } else {
                        ExitCode::from(7) // CURLE_COULDNT_CONNECT
                    }
                }
                _ => ExitCode::from(7), // CURLE_COULDNT_CONNECT
            }
        }
        liburlx::Error::Tls(e) => {
            let msg = e.to_string();
            if msg.contains("certificate") || msg.contains("verify") {
                ExitCode::from(60) // CURLE_PEER_FAILED_VERIFICATION
            } else {
                ExitCode::from(35) // CURLE_SSL_CONNECT_ERROR
            }
        }
        liburlx::Error::Http(msg) => {
            if msg.contains("too many redirects") || msg.contains("Too many redirects") {
                ExitCode::from(47) // CURLE_TOO_MANY_REDIRECTS
            } else if msg.contains("fail_on_error") {
                ExitCode::from(22) // CURLE_HTTP_RETURNED_ERROR
            } else {
                ExitCode::from(56) // CURLE_RECV_ERROR
            }
        }
        liburlx::Error::Timeout(_) | liburlx::Error::SpeedLimit { .. } => {
            ExitCode::from(28) // CURLE_OPERATION_TIMEDOUT
        }
        liburlx::Error::Io(_) => ExitCode::from(23), // CURLE_WRITE_ERROR
        liburlx::Error::Ssh(_) => ExitCode::from(67), // CURLE_LOGIN_DENIED
        liburlx::Error::Transfer { code, .. } => {
            ExitCode::from(u8::try_from(*code).map_or(1, |c| c))
        }
        _ => ExitCode::FAILURE,
    }
}

/// Perform a transfer with optional retry logic.
fn perform_with_retry(opts: &mut CliOptions) -> Result<liburlx::Response, liburlx::Error> {
    // --etag-compare: send If-None-Match header from saved ETag
    if let Some(ref path) = opts.etag_compare_file {
        if let Ok(etag) = std::fs::read_to_string(path) {
            let etag = etag.trim().to_string();
            if !etag.is_empty() {
                opts.easy.header("If-None-Match", &etag);
            }
        }
    }

    let max_retries = opts.retry_count;
    let delay = std::time::Duration::from_secs(opts.retry_delay_secs);
    let max_time = if opts.retry_max_time_secs > 0 {
        Some(std::time::Duration::from_secs(opts.retry_max_time_secs))
    } else {
        None
    };
    let start = std::time::Instant::now();

    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            // Check max time budget
            if let Some(max) = max_time {
                if start.elapsed() >= max {
                    break;
                }
            }
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            if !opts.silent {
                eprintln!(
                    "Warning: Transient problem: {} — retrying after {} seconds. Retry {} of {}.",
                    last_err.as_ref().map_or("unknown error", |_| "transfer error"),
                    delay.as_secs(),
                    attempt,
                    max_retries,
                );
            }
        }

        match opts.easy.perform() {
            Ok(response) => {
                // Retry on 408, 429, 500, 502, 503, 504 if retries remain
                if is_retryable_status(response.status()) && attempt < max_retries {
                    last_err = Some(liburlx::Error::Http(format!(
                        "HTTP {} {}",
                        response.status(),
                        http_status_text(response.status()),
                    )));
                    continue;
                }
                return Ok(response);
            }
            Err(e) => {
                last_err = Some(e);
                if attempt == max_retries {
                    break;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| liburlx::Error::Http("retry exhausted".to_string())))
}

/// Check if an HTTP status code is retryable (transient error).
const fn is_retryable_status(code: u16) -> bool {
    matches!(code, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Format response headers as HTTP status line + headers.
fn format_headers(response: &liburlx::Response) -> String {
    let mut result =
        format!("HTTP/1.1 {} {}\r\n", response.status(), http_status_text(response.status()),);
    for (name, value) in response.headers() {
        result.push_str(name);
        result.push_str(": ");
        result.push_str(value);
        result.push_str("\r\n");
    }
    result.push_str("\r\n");
    result
}

/// Write trace output to a file.
///
/// `--trace` writes hex + ASCII dump; `--trace-ascii` writes plain text.
/// If `trace_time` is true, each section is prefixed with a timestamp.
fn write_trace_file(
    path: &str,
    response: &liburlx::Response,
    url: &str,
    method: &str,
    request_headers: &[(String, String)],
    is_hex: bool,
    trace_time: bool,
) {
    use std::fmt::Write as _;

    let mut out = String::new();

    // Timestamp prefix helper
    let time_prefix = || -> String {
        if trace_time {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}.{:06} ", now.as_secs(), now.subsec_micros())
        } else {
            String::new()
        }
    };

    // Reconstruct approximate request headers
    let request_line = format!("{method} {url} HTTP/1.1\r\n");
    let mut req_text = request_line;
    for (name, value) in request_headers {
        req_text.push_str(name);
        req_text.push_str(": ");
        req_text.push_str(value);
        req_text.push_str("\r\n");
    }
    req_text.push_str("\r\n");

    // Write request headers section
    let _ = writeln!(out, "{}== Info: Request to {url}", time_prefix());
    let _ = writeln!(out, "{}=> Send header, {} bytes", time_prefix(), req_text.len());
    if is_hex {
        hex_dump(&mut out, req_text.as_bytes(), &time_prefix);
    } else {
        for line in req_text.lines() {
            let _ = writeln!(out, "{}=> {line}", time_prefix());
        }
    }

    // Write response headers section
    let resp_headers = format_headers(response);
    let _ = writeln!(out, "{}<= Recv header, {} bytes", time_prefix(), resp_headers.len());
    if is_hex {
        hex_dump(&mut out, resp_headers.as_bytes(), &time_prefix);
    } else {
        for line in resp_headers.lines() {
            let _ = writeln!(out, "{}<= {line}", time_prefix());
        }
    }

    // Write response body section
    let body = response.body();
    if !body.is_empty() {
        let _ = writeln!(out, "{}<= Recv data, {} bytes", time_prefix(), body.len());
        if is_hex {
            hex_dump(&mut out, body, &time_prefix);
        } else {
            let text = String::from_utf8_lossy(body);
            for line in text.lines() {
                let _ = writeln!(out, "{}{line}", time_prefix());
            }
        }
    }

    if let Err(e) = std::fs::write(path, out) {
        eprintln!("urlx: error writing trace file '{path}': {e}");
    }
}

/// Write a hex dump of data, 16 bytes per line.
fn hex_dump(out: &mut String, data: &[u8], time_prefix: &dyn Fn() -> String) {
    use std::fmt::Write;

    for (offset, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{}{:04x}: ", time_prefix(), offset * 16);

        // Hex bytes
        for (i, &byte) in chunk.iter().enumerate() {
            let _ = write!(out, "{byte:02x} ");
            if i == 7 {
                out.push(' ');
            }
        }

        // Padding for incomplete lines
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }

        // ASCII representation
        out.push(' ');
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                out.push(byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
}

/// Get a human-readable HTTP status text.
const fn http_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Output a single response to stdout or file.
fn output_response(
    response: &liburlx::Response,
    output_file: Option<&str>,
    write_out: Option<&str>,
    include_headers: bool,
    silent: bool,
) -> ExitCode {
    // --include: prepend headers to output
    if include_headers {
        let header_text = format_headers(response);
        if let Err(e) = std::io::stdout().write_all(header_text.as_bytes()) {
            if !silent {
                eprintln!("urlx: write error: {e}");
            }
            return ExitCode::FAILURE;
        }
    }

    if let Some(path) = output_file {
        if let Err(e) = std::fs::write(path, response.body()) {
            if !silent {
                eprintln!("urlx: error writing to {path}: {e}");
            }
            return ExitCode::FAILURE;
        }
    } else if let Err(e) = std::io::stdout().write_all(response.body()) {
        if !silent {
            eprintln!("urlx: write error: {e}");
        }
        return ExitCode::FAILURE;
    }

    if let Some(fmt) = write_out {
        let output = format_write_out(fmt, response);
        print!("{output}");
    }

    ExitCode::SUCCESS
}

/// Run multiple URLs concurrently using the Multi API.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn run_multi(
    template: &liburlx::Easy,
    urls: &[String],
    _output_file: Option<&str>,
    write_out: Option<&str>,
    silent: bool,
    show_error: bool,
    fail_on_error: bool,
    parallel: bool,
    parallel_max: usize,
) -> ExitCode {
    let mut multi = liburlx::Multi::new();
    if parallel {
        multi.max_total_connections(parallel_max);
    }

    for url in urls {
        let mut easy = template.clone();
        if let Err(e) = easy.url(url) {
            if !silent || show_error {
                eprintln!("urlx: error parsing URL '{url}': {e}");
            }
            return ExitCode::FAILURE;
        }
        multi.add(easy);
    }

    let results = match multi.perform_blocking() {
        Ok(results) => results,
        Err(e) => {
            if !silent || show_error {
                eprintln!("urlx: {e}");
            }
            return ExitCode::FAILURE;
        }
    };
    let mut any_failed = false;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(response) => {
                if fail_on_error && response.status() >= 400 {
                    any_failed = true;
                    continue;
                }
                if let Err(e) = std::io::stdout().write_all(response.body()) {
                    if !silent || show_error {
                        eprintln!("urlx: write error: {e}");
                    }
                    any_failed = true;
                }
                if let Some(fmt) = write_out {
                    let output = format_write_out(fmt, &response);
                    print!("{output}");
                }
            }
            Err(e) => {
                if !silent || show_error {
                    eprintln!("urlx: transfer {} ({}): {e}", i + 1, urls[i]);
                }
                any_failed = true;
            }
        }
    }

    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Return the HTTP version string for a response (e.g., "1.1", "2", "3").
const fn http_version_string(_response: &liburlx::Response) -> &'static str {
    // Default to "1.1" since we don't currently store HTTP version in Response
    "1.1"
}

/// Format a `--write-out` string by replacing `%{variable}` placeholders.
fn format_write_out(fmt: &str, response: &liburlx::Response) -> String {
    let info = response.transfer_info();
    let mut result = fmt.to_string();

    // Replace known variables
    result = result.replace("%{http_code}", &response.status().to_string());
    result = result.replace("%{response_code}", &response.status().to_string());
    result = result.replace("%{url_effective}", response.effective_url());
    result = result.replace("%{content_type}", response.content_type().unwrap_or(""));
    result = result.replace("%{size_download}", &response.size_download().to_string());
    result =
        result.replace("%{time_namelookup}", &format!("{:.6}", info.time_namelookup.as_secs_f64()));
    result = result.replace("%{time_connect}", &format!("{:.6}", info.time_connect.as_secs_f64()));
    result =
        result.replace("%{time_appconnect}", &format!("{:.6}", info.time_appconnect.as_secs_f64()));
    result = result
        .replace("%{time_pretransfer}", &format!("{:.6}", info.time_pretransfer.as_secs_f64()));
    result = result
        .replace("%{time_starttransfer}", &format!("{:.6}", info.time_starttransfer.as_secs_f64()));
    result = result.replace("%{time_total}", &format!("{:.6}", info.time_total.as_secs_f64()));
    result = result.replace("%{num_redirects}", &info.num_redirects.to_string());
    result = result.replace("%{speed_download}", &format!("{:.3}", info.speed_download));
    result = result.replace("%{speed_upload}", &format!("{:.3}", info.speed_upload));
    result = result.replace("%{size_upload}", &info.size_upload.to_string());
    // Additional curl-compatible variables
    result = result.replace("%{http_version}", http_version_string(response));
    result =
        result.replace("%{scheme}", response.effective_url().split("://").next().unwrap_or(""));
    // Header sizes: approximate from response headers
    let header_size: usize = response.headers().iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    result = result.replace("%{size_header}", &header_size.to_string());
    result = result.replace("%{num_connects}", "1");
    result = result
        .replace("%{time_redirect}", &format!("{:.6}", info.time_namelookup.as_secs_f64() * 0.0));
    result = result.replace("%{redirect_url}", response.header("location").unwrap_or(""));
    result = result.replace("%{method}", "GET");
    result = result.replace("%{errormsg}", "");
    result = result.replace("%{exitcode}", "0");

    // Handle escape sequences
    result = result.replace("\\n", "\n");
    result = result.replace("\\t", "\t");
    result = result.replace("\\r", "\r");

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        let response = liburlx::Response::new(200, headers, Vec::new(), String::new());
        let result = format_headers(&response);
        assert!(result.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(result.contains("content-type: text/plain\r\n"));
        assert!(result.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parse_args_basic_url() {
        let args = vec!["urlx".to_string(), "http://example.com".to_string()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert!(opts.silent);
        assert!(opts.fail_on_error);
    }

    #[test]
    fn parse_args_include_headers() {
        let args = vec!["urlx".to_string(), "-i".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args).unwrap();
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_dump_header() {
        let args = vec![
            "urlx".to_string(),
            "-D".to_string(),
            "headers.txt".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_unknown_option() {
        let args = vec!["urlx".to_string(), "--bogus".to_string()];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_missing_arg() {
        let args = vec!["urlx".to_string(), "-X".to_string()];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_multiple_urls() {
        let args = vec!["urlx".to_string(), "http://a.com".to_string(), "http://b.com".to_string()];
        let opts = parse_args(&args).unwrap();
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
            assert!(parse_args(&args).is_some(), "method {method} should parse");
        }
    }

    #[test]
    fn parse_args_header_invalid_format() {
        let args = vec![
            "urlx".to_string(),
            "-H".to_string(),
            "NoColonHere".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_compressed() {
        let args = vec!["urlx".to_string(), "--compressed".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_connect_timeout_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--connect-timeout".to_string(),
            "not-a-number".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_max_redirs_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--max-redirs".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_form_invalid() {
        let args = vec![
            "urlx".to_string(),
            "-F".to_string(),
            "noequalssign".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_continue_at_invalid() {
        let args = vec![
            "urlx".to_string(),
            "-C".to_string(),
            "not-a-number".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_progress_bar() {
        let args = vec!["urlx".to_string(), "-#".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.show_progress);
    }

    #[test]
    fn parse_args_verbose() {
        let args = vec!["urlx".to_string(), "-v".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_insecure_long() {
        let args = vec!["urlx".to_string(), "--insecure".to_string(), "https://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_cacert_missing_arg() {
        let args = vec!["urlx".to_string(), "--cacert".to_string()];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_tlsv12() {
        let args = vec!["urlx".to_string(), "--tlsv1.2".to_string(), "https://x.com".to_string()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_tlsv13() {
        let args = vec!["urlx".to_string(), "--tlsv1.3".to_string(), "https://x.com".to_string()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_tls_max() {
        let args = vec![
            "urlx".to_string(),
            "--tls-max".to_string(),
            "1.2".to_string(),
            "https://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_tls_max_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--tls-max".to_string(),
            "1.1".to_string(),
            "https://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_resolve_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--resolve".to_string(),
            "bad-format".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_http10() {
        let args = vec!["urlx".to_string(), "--http1.0".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_http11() {
        let args = vec!["urlx".to_string(), "--http1.1".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_http2() {
        let args = vec!["urlx".to_string(), "--http2".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_http3() {
        let args = vec!["urlx".to_string(), "--http3".to_string(), "https://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_expect100_timeout_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--expect100-timeout".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_retry() {
        let args = vec![
            "urlx".to_string(),
            "--retry".to_string(),
            "3".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
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
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_retry_delay() {
        let args = vec![
            "urlx".to_string(),
            "--retry-delay".to_string(),
            "5".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.retry_max_time_secs, 60);
    }

    #[test]
    fn parse_args_parallel() {
        let args = vec!["urlx".to_string(), "-Z".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.parallel);
        assert_eq!(opts.parallel_max, 50); // default
    }

    #[test]
    fn parse_args_parallel_long() {
        let args = vec!["urlx".to_string(), "--parallel".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        assert!(parse_args(&args).is_none());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_tcp_nodelay() {
        let args =
            vec!["urlx".to_string(), "--tcp-nodelay".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_tcp_keepalive_invalid() {
        let args = vec![
            "urlx".to_string(),
            "--tcp-keepalive".to_string(),
            "abc".to_string(),
            "http://x.com".to_string(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_hsts() {
        let args = vec!["urlx".to_string(), "--hsts".to_string(), "http://x.com".to_string()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_bearer() {
        let args = vec![
            "urlx".to_string(),
            "--bearer".to_string(),
            "mytoken123".to_string(),
            "http://x.com".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(opts.use_bearer);
    }

    #[test]
    fn parse_args_bearer_missing_arg() {
        let args = vec!["urlx".to_string(), "--bearer".to_string()];
        assert!(parse_args(&args).is_none());
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_speed_limit() {
        let args = vec![
            "urlx".to_string(),
            "--speed-limit".to_string(),
            "1000".to_string(),
            "http://example.com".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_remote_name() {
        let args = vec![
            "urlx".to_string(),
            "-O".to_string(),
            "http://example.com/file.tar.gz".to_string(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(opts.remote_name);
    }

    #[test]
    fn parse_args_get_flag() {
        let args = vec!["urlx".to_string(), "-G".to_string(), "http://example.com".to_string()];
        assert!(parse_args(&args).is_some());
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
        let opts = parse_args(&args).unwrap();
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
        assert_eq!(remote_name_from_url("http://example.com/"), "index.html");
    }

    #[test]
    fn remote_name_from_url_root() {
        assert_eq!(remote_name_from_url("http://example.com"), "index.html");
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_unrestricted_auth() {
        let args = vec!["urlx".into(), "--unrestricted-auth".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_args_ignore_content_length() {
        let args =
            vec!["urlx".into(), "--ignore-content-length".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.trace_ascii_file, Some("/tmp/trace.log".to_string()));
    }

    #[test]
    fn parse_args_trace_time() {
        let args = vec!["urlx".into(), "--trace-time".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.trace_time);
    }

    #[test]
    fn parse_args_libcurl() {
        let args = vec!["urlx".into(), "--libcurl".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.max_filesize, Some(1_048_576));
    }

    #[test]
    fn parse_args_max_filesize_invalid() {
        let args =
            vec!["urlx".into(), "--max-filesize".into(), "abc".into(), "http://example.com".into()];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_no_keepalive() {
        let args = vec!["urlx".into(), "--no-keepalive".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        let code = generate_libcurl_code(&opts);
        assert!(code.contains("CURLOPT_NOPROGRESS"));
        assert!(code.contains("CURLOPT_FAILONERROR"));
        assert!(code.contains("CURLOPT_HEADER"));
    }

    #[test]
    fn parse_args_post301() {
        let args = vec!["urlx".into(), "--post301".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.post301);
    }

    #[test]
    fn parse_args_post302() {
        let args = vec!["urlx".into(), "--post302".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.post302);
    }

    #[test]
    fn parse_args_post303() {
        let args = vec!["urlx".into(), "--post303".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
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
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_proxy_header_invalid() {
        let args = vec![
            "urlx".into(),
            "--proxy-header".into(),
            "NoColonHere".into(),
            "http://example.com".into(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_netrc() {
        let args = vec!["urlx".into(), "--netrc".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.netrc_file.is_some());
        assert!(!opts.netrc_optional);
    }

    #[test]
    fn parse_args_netrc_optional() {
        let args = vec!["urlx".into(), "--netrc-optional".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.netrc_file.as_deref(), Some("/tmp/my.netrc"));
    }

    #[test]
    fn parse_args_remote_time() {
        let args = vec!["urlx".into(), "-R".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.remote_time);
    }

    #[test]
    fn parse_args_remote_time_long() {
        let args = vec!["urlx".into(), "--remote-time".into(), "http://example.com".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.remote_time);
    }

    #[test]
    fn parse_args_next() {
        let args =
            vec!["urlx".into(), "http://a.com".into(), "--next".into(), "http://b.com".into()];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls.len(), 2);
    }

    #[test]
    fn parse_args_ftp_pasv() {
        let args = vec!["urlx".into(), "--ftp-pasv".into(), "ftp://example.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_ftp_ssl() {
        let args = vec!["urlx".into(), "--ftp-ssl".into(), "ftp://example.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_ssl() {
        let args = vec!["urlx".into(), "--ssl".into(), "ftp://example.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_ftp_ssl_reqd() {
        let args = vec!["urlx".into(), "--ftp-ssl-reqd".into(), "ftp://example.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_ssl_reqd() {
        let args = vec!["urlx".into(), "--ssl-reqd".into(), "ftp://example.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_key_sets_ssh_key_path() {
        let args = vec![
            "urlx".into(),
            "--key".into(),
            "/home/user/.ssh/id_ed25519".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_hostpubsha256() {
        let args = vec![
            "urlx".into(),
            "--hostpubsha256".into(),
            "abcdef1234567890".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_known_hosts() {
        let args = vec![
            "urlx".into(),
            "--known-hosts".into(),
            "/home/user/.ssh/known_hosts".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_hostpubmd5_noop() {
        let args = vec![
            "urlx".into(),
            "--hostpubmd5".into(),
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".into(),
            "sftp://example.com/file".into(),
        ];
        assert!(parse_args(&args).is_some());
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
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert!(opts.globoff);
    }

    #[test]
    fn parse_args_path_as_is() {
        let args = vec!["urlx".into(), "--path-as-is".into(), "http://x.com/a/../b".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_raw() {
        let args = vec!["urlx".into(), "--raw".into(), "http://x.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_remote_header_name_short() {
        let args = vec!["urlx".into(), "-J".into(), "http://x.com/file".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.remote_header_name);
        assert!(opts.remote_name);
    }

    #[test]
    fn parse_args_remote_header_name_long() {
        let args = vec!["urlx".into(), "--remote-header-name".into(), "http://x.com/file".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.remote_header_name);
    }

    #[test]
    fn parse_args_styled_output() {
        let args = vec!["urlx".into(), "--styled-output".into(), "http://x.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_no_styled_output() {
        let args = vec!["urlx".into(), "--no-styled-output".into(), "http://x.com".into()];
        assert!(parse_args(&args).is_some());
    }

    #[test]
    fn parse_args_url_query() {
        let args =
            vec!["urlx".into(), "--url-query".into(), "key=value".into(), "http://x.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.url_queries, vec!["a=1", "b=2"]);
    }

    #[test]
    fn parse_args_json() {
        let args =
            vec!["urlx".into(), "--json".into(), r#"{"key":"val"}"#.into(), "http://x.com".into()];
        let opts = parse_args(&args);
        assert!(opts.is_some());
    }

    #[test]
    fn parse_args_rate() {
        let args = vec!["urlx".into(), "--rate".into(), "10/s".into(), "http://x.com".into()];
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_ntlm_flag() {
        let args = make_args(&["--ntlm", "-u", "user:pass", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert!(opts.use_ntlm);
    }

    #[test]
    fn parse_negotiate_flag() {
        let args = make_args(&["--negotiate", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_delegation_flag() {
        let args = make_args(&["--delegation", "always", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_sasl_flags() {
        let args = make_args(&["--sasl-authzid", "myid", "--sasl-ir", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_mail_from_flag() {
        let args = make_args(&["--mail-from", "sender@example.com", "smtp://mail.example.com"]);
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["smtp://mail.example.com"]);
    }

    #[test]
    fn parse_mail_auth_flag() {
        let args = make_args(&["--mail-auth", "sender@example.com", "smtp://mail.example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["smtp://mail.example.com"]);
    }

    #[test]
    fn parse_ftp_create_dirs_flag() {
        let args = make_args(&["--ftp-create-dirs", "ftp://example.com/dir/file.txt"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["ftp://example.com/dir/file.txt"]);
    }

    #[test]
    fn parse_ftp_method_flag() {
        let args = make_args(&["--ftp-method", "singlecwd", "ftp://example.com/dir/file.txt"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["ftp://example.com/dir/file.txt"]);
    }

    #[test]
    fn parse_ftp_method_invalid() {
        let args = make_args(&["--ftp-method", "invalid", "ftp://example.com/"]);
        assert!(parse_args(&args).is_none());
    }

    // --- Phase 41 tests: URL globbing ---

    #[test]
    fn parse_args_globoff_sets_flag() {
        let args = make_args(&["--globoff", "http://example.com/{a,b}"]);
        let opts = parse_args(&args).unwrap();
        assert!(opts.globoff);
        // With globoff, URL is stored literally (not expanded)
        assert_eq!(opts.urls, vec!["http://example.com/{a,b}"]);
    }

    #[test]
    fn glob_expansion_in_run() {
        // Verify that glob expansion works at the parse level
        let args = make_args(&["http://example.com/{a,b}"]);
        let opts = parse_args(&args).unwrap();
        assert!(!opts.globoff);
        // URLs collected as-is at parse time
        assert_eq!(opts.urls, vec!["http://example.com/{a,b}"]);
        // Expansion happens in run(), not parse_args()
    }

    #[test]
    fn glob_numeric_range_collected() {
        let args = make_args(&["http://example.com/[1-3]"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com/[1-3]"]);
    }

    // --- Phase 42 tests: CLI Expansion V ---

    #[test]
    fn parse_connect_to() {
        let args = make_args(&["--connect-to", "a.com:80:b.com:8080", "http://a.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://a.com"]);
    }

    #[test]
    fn parse_alt_svc() {
        let args = make_args(&["--alt-svc", "/tmp/altsvc.txt", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.alt_svc_file.as_deref(), Some("/tmp/altsvc.txt"));
    }

    #[test]
    fn parse_etag_save() {
        let args = make_args(&["--etag-save", "/tmp/etag.txt", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.etag_save_file.as_deref(), Some("/tmp/etag.txt"));
    }

    #[test]
    fn parse_etag_compare() {
        let args = make_args(&["--etag-compare", "/tmp/etag.txt", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.etag_compare_file.as_deref(), Some("/tmp/etag.txt"));
    }

    #[test]
    fn parse_haproxy_protocol() {
        let args = make_args(&["--haproxy-protocol", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_abstract_unix_socket() {
        let args = make_args(&["--abstract-unix-socket", "/my/sock", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
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
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_doh_insecure() {
        let args = make_args(&["--doh-insecure", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proto_default() {
        let args = make_args(&["--proto-default", "https", "example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.proto_default.as_deref(), Some("https"));
    }

    #[test]
    fn parse_compressed_ssh_noop() {
        let args = make_args(&["--compressed-ssh", "sftp://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["sftp://example.com"]);
    }

    // --- Phase 47 tests: CLI Expansion VI ---

    #[test]
    fn parse_form_string() {
        let args = make_args(&["--form-string", "name=@notafile", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_request_target() {
        let args = make_args(&["--request-target", "/custom/path", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks4() {
        let args = make_args(&["--socks4", "127.0.0.1:1080", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks4a() {
        let args = make_args(&["--socks4a", "127.0.0.1:1080", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_socks5() {
        let args = make_args(&["--socks5", "127.0.0.1:1080", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_1_0() {
        let args = make_args(&["--proxy-1.0", "http://proxy:8080", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_tftp_blksize() {
        let args = make_args(&["--tftp-blksize", "1024", "tftp://example.com/file"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["tftp://example.com/file"]);
    }

    #[test]
    fn parse_tftp_no_options() {
        let args = make_args(&["--tftp-no-options", "tftp://example.com/file"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["tftp://example.com/file"]);
    }

    #[test]
    fn parse_no_buffer() {
        let args = make_args(&["-N", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_sessionid() {
        let args = make_args(&["--no-sessionid", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_alpn() {
        let args = make_args(&["--no-alpn", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_no_npn() {
        let args = make_args(&["--no-npn", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_tlsv1() {
        let args = make_args(&["--tlsv1", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_sslv3() {
        let args = make_args(&["--sslv3", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_proxy_insecure() {
        let args = make_args(&["--proxy-insecure", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_disable_eprt() {
        let args = make_args(&["--disable-eprt", "ftp://example.com/file"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["ftp://example.com/file"]);
    }

    #[test]
    fn parse_disable_epsv() {
        let args = make_args(&["--disable-epsv", "ftp://example.com/file"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["ftp://example.com/file"]);
    }

    #[test]
    fn parse_tlsv1_0() {
        let args = make_args(&["--tlsv1.0", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_pinnedpubkey_sha256() {
        let args = make_args(&["--pinnedpubkey", "sha256//abc123", "https://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_cert_status() {
        let args = make_args(&["--cert-status", "https://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_false_start() {
        let args = make_args(&["--false-start", "https://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["https://example.com"]);
    }

    #[test]
    fn parse_create_file_mode() {
        let args = make_args(&["--create-file-mode", "0644", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }

    #[test]
    fn parse_output_dir() {
        let args = make_args(&["--output-dir", "/tmp", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.output_dir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn parse_remove_on_error() {
        let args = make_args(&["--remove-on-error", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert!(opts.remove_on_error);
    }

    #[test]
    fn parse_url_flag() {
        let args = make_args(&["--url", "http://example.com"]);
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.urls, vec!["http://example.com"]);
    }
}
