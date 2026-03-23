//! # urlx
//!
//! A memory-safe command-line URL transfer tool — drop-in replacement for `curl`.
//!
//! `urlx` accepts the same flags and produces the same output as `curl`, backed
//! by the pure-Rust [`liburlx`](https://docs.rs/liburlx) engine. 261 long flags
//! and 46 short flags are supported.
//!
//! ## Install
//!
//! ```sh
//! cargo install urlx-cli
//! # or
//! brew install jonwiggins/tap/urlx
//! ```
//!
//! ## Examples
//!
//! ```sh
//! urlx https://example.com                                     # GET
//! urlx -d '{"key":"val"}' -H 'Content-Type: application/json'  # POST JSON
//! urlx -Lo file.tar.gz https://example.com/file.tar.gz         # Download
//! urlx -u user:pass --digest https://api.example.com           # Digest auth
//! urlx -Z https://a.com https://b.com https://c.com            # Parallel
//! ```

#![deny(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::explicit_iter_loop,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::cast_lossless,
    clippy::option_if_let_else,
    clippy::redundant_clone,
    clippy::uninlined_format_args,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::items_after_statements,
    clippy::assigning_clones,
    clippy::too_many_lines
)]

mod args;
mod ipfs;
mod output;
mod transfer;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    transfer::run(&args)
}
