//! `urlx` — A memory-safe command-line URL transfer tool.
//!
//! Drop-in replacement for the `curl` command.

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
mod output;
mod transfer;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    transfer::run(&args)
}
