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
        return ExitCode::FAILURE;
    }

    let mut easy = liburlx::Easy::new();
    let mut output_file: Option<String> = None;
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
            arg if arg.starts_with('-') => {
                eprintln!("urlx: unknown option: {arg}");
                return ExitCode::FAILURE;
            }
            url => {
                if let Err(e) = easy.url(url) {
                    eprintln!("urlx: error parsing URL: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        i += 1;
    }

    match easy.perform() {
        Ok(response) => {
            if let Some(ref path) = output_file {
                match std::fs::write(path, response.body()) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("urlx: error writing to {path}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else if let Err(e) = std::io::stdout().write_all(response.body()) {
                eprintln!("urlx: write error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("urlx: {e}");
            ExitCode::FAILURE
        }
    }
}
