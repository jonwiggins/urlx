//! `urlx` — A memory-safe command-line URL transfer tool.
//!
//! Drop-in replacement for the `curl` command.

#![deny(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("urlx 0.1.0 — a memory-safe curl replacement");
        eprintln!("Usage: urlx <url>");
        return ExitCode::FAILURE;
    }

    let url = &args[1];
    let mut easy = liburlx::Easy::new();

    if let Err(e) = easy.url(url) {
        eprintln!("urlx: error parsing URL: {e}");
        return ExitCode::FAILURE;
    }

    match easy.perform() {
        Ok(response) => {
            if let Ok(body) = response.body_str() {
                print!("{body}");
            } else {
                // Binary body: write raw bytes to stdout
                use std::io::Write;
                if let Err(e) = std::io::stdout().write_all(response.body()) {
                    eprintln!("urlx: write error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("urlx: {e}");
            ExitCode::FAILURE
        }
    }
}
