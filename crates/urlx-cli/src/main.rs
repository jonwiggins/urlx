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

#[allow(clippy::too_many_lines)]
fn run(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("urlx 0.1.0 — a memory-safe curl replacement");
        eprintln!("Usage: urlx [options] <url>");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -X, --request <method>   HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH)");
        eprintln!(
            "  -H, --header <header>    Custom header (e.g., 'Content-Type: application/json')"
        );
        eprintln!("  -d, --data <data>        Request body data");
        eprintln!("  -L, --location           Follow redirects");
        eprintln!("  -I, --head               Send HEAD request");
        eprintln!("  -o, --output <file>      Write output to file");
        eprintln!("  -v, --verbose            Verbose output");
        eprintln!("      --compressed         Request compressed response and decompress");
        eprintln!("      --connect-timeout <s> Maximum time for connection in seconds");
        eprintln!("  -m, --max-time <s>       Maximum time for transfer in seconds");
        eprintln!("  -u, --user <user:pass>   HTTP Basic authentication");
        eprintln!("  -w, --write-out <fmt>    Output format after transfer");
        eprintln!("  -x, --proxy <url>        Use proxy (e.g., http://proxy:8080)");
        eprintln!("      --noproxy <list>     Comma-separated list of hosts to bypass proxy");
        eprintln!("  -F, --form <name=value>  Multipart form field (use @file for file upload)");
        eprintln!("  -r, --range <range>      Byte range (e.g., 0-499, 500-, -500)");
        eprintln!("  -C, --continue-at <off>  Resume download from byte offset");
        return ExitCode::FAILURE;
    }

    let mut easy = liburlx::Easy::new();
    let mut urls: Vec<String> = Vec::new();
    let mut output_file: Option<String> = None;
    let mut write_out: Option<String> = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-X" | "--request" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -X requires an argument");
                    return ExitCode::FAILURE;
                }
                easy.method(&args[i]);
            }
            "-H" | "--header" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -H requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Some((name, value)) = args[i].split_once(':') {
                    easy.header(name.trim(), value.trim());
                } else {
                    eprintln!("urlx: invalid header format: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }
            "-d" | "--data" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -d requires an argument");
                    return ExitCode::FAILURE;
                }
                easy.body(args[i].as_bytes());
                // curl auto-sets POST when -d is used
                if easy.method_is_default() {
                    easy.method("POST");
                }
            }
            "-L" | "--location" => {
                easy.follow_redirects(true);
            }
            "-I" | "--head" => {
                easy.method("HEAD");
            }
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -o requires an argument");
                    return ExitCode::FAILURE;
                }
                output_file = Some(args[i].clone());
            }
            "-v" | "--verbose" => {
                easy.verbose(true);
            }
            "--compressed" => {
                easy.accept_encoding(true);
            }
            "--connect-timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option --connect-timeout requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Ok(secs) = args[i].parse::<f64>() {
                    easy.connect_timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }
            "-m" | "--max-time" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -m requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Ok(secs) = args[i].parse::<f64>() {
                    easy.timeout(std::time::Duration::from_secs_f64(secs));
                } else {
                    eprintln!("urlx: invalid timeout value: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }
            "-w" | "--write-out" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -w requires an argument");
                    return ExitCode::FAILURE;
                }
                write_out = Some(args[i].clone());
            }
            "-x" | "--proxy" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -x requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Err(e) = easy.proxy(&args[i]) {
                    eprintln!("urlx: invalid proxy URL: {e}");
                    return ExitCode::FAILURE;
                }
            }
            "--noproxy" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option --noproxy requires an argument");
                    return ExitCode::FAILURE;
                }
                easy.noproxy(&args[i]);
            }
            "-u" | "--user" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -u requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Some((user, pass)) = args[i].split_once(':') {
                    easy.basic_auth(user, pass);
                } else {
                    // No password — use empty password (curl compat)
                    easy.basic_auth(&args[i], "");
                }
            }
            "-F" | "--form" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -F requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Some((name, value)) = args[i].split_once('=') {
                    if let Some(path) = value.strip_prefix('@') {
                        if let Err(e) = easy.form_file(name, std::path::Path::new(path)) {
                            eprintln!("urlx: error reading form file: {e}");
                            return ExitCode::FAILURE;
                        }
                    } else {
                        easy.form_field(name, value);
                    }
                } else {
                    eprintln!("urlx: invalid form field format: {}", args[i]);
                    eprintln!("  Use: -F name=value or -F name=@filename");
                    return ExitCode::FAILURE;
                }
            }
            "-r" | "--range" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -r requires an argument");
                    return ExitCode::FAILURE;
                }
                easy.range(&args[i]);
            }
            "-C" | "--continue-at" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("urlx: option -C requires an argument");
                    return ExitCode::FAILURE;
                }
                if let Ok(offset) = args[i].parse::<u64>() {
                    easy.resume_from(offset);
                } else {
                    eprintln!("urlx: invalid offset value: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }
            arg if arg.starts_with('-') => {
                eprintln!("urlx: unknown option: {arg}");
                return ExitCode::FAILURE;
            }
            url => {
                urls.push(url.to_string());
            }
        }
        i += 1;
    }

    // Multiple URLs: use Multi API for concurrent transfers
    if urls.len() > 1 {
        return run_multi(&easy, &urls, output_file.as_deref(), write_out.as_deref());
    }

    // Single URL: use Easy API
    if let Some(url) = urls.first() {
        if let Err(e) = easy.url(url) {
            eprintln!("urlx: error parsing URL: {e}");
            return ExitCode::FAILURE;
        }
    }

    match easy.perform() {
        Ok(response) => output_response(&response, output_file.as_deref(), write_out.as_deref()),
        Err(e) => {
            eprintln!("urlx: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Output a single response to stdout or file.
fn output_response(
    response: &liburlx::Response,
    output_file: Option<&str>,
    write_out: Option<&str>,
) -> ExitCode {
    if let Some(path) = output_file {
        if let Err(e) = std::fs::write(path, response.body()) {
            eprintln!("urlx: error writing to {path}: {e}");
            return ExitCode::FAILURE;
        }
    } else if let Err(e) = std::io::stdout().write_all(response.body()) {
        eprintln!("urlx: write error: {e}");
        return ExitCode::FAILURE;
    }

    if let Some(fmt) = write_out {
        let output = format_write_out(fmt, response);
        print!("{output}");
    }

    ExitCode::SUCCESS
}

/// Run multiple URLs concurrently using the Multi API.
fn run_multi(
    template: &liburlx::Easy,
    urls: &[String],
    _output_file: Option<&str>,
    write_out: Option<&str>,
) -> ExitCode {
    let mut multi = liburlx::Multi::new();

    for url in urls {
        let mut easy = template.clone();
        if let Err(e) = easy.url(url) {
            eprintln!("urlx: error parsing URL '{url}': {e}");
            return ExitCode::FAILURE;
        }
        multi.add(easy);
    }

    let results = match multi.perform_blocking() {
        Ok(results) => results,
        Err(e) => {
            eprintln!("urlx: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut any_failed = false;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(response) => {
                if let Err(e) = std::io::stdout().write_all(response.body()) {
                    eprintln!("urlx: write error: {e}");
                    any_failed = true;
                }
                if let Some(fmt) = write_out {
                    let output = format_write_out(fmt, &response);
                    print!("{output}");
                }
            }
            Err(e) => {
                eprintln!("urlx: transfer {} ({}): {e}", i + 1, urls[i]);
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

/// Format a --write-out string by replacing %{variable} placeholders.
fn format_write_out(fmt: &str, response: &liburlx::Response) -> String {
    let info = response.transfer_info();
    let mut result = fmt.to_string();

    // Replace known variables
    result = result.replace("%{http_code}", &response.status().to_string());
    result = result.replace("%{response_code}", &response.status().to_string());
    result = result.replace("%{url_effective}", response.effective_url());
    result = result.replace("%{content_type}", response.content_type().unwrap_or(""));
    result = result.replace("%{size_download}", &response.size_download().to_string());
    result = result.replace("%{time_total}", &format!("{:.6}", info.time_total.as_secs_f64()));
    result = result.replace("%{time_connect}", &format!("{:.6}", info.time_connect.as_secs_f64()));
    result = result.replace("%{num_redirects}", &info.num_redirects.to_string());

    // Handle escape sequences
    result = result.replace("\\n", "\n");
    result = result.replace("\\t", "\t");
    result = result.replace("\\r", "\r");

    result
}
