//! `urlx` — A memory-safe command-line URL transfer tool.
//!
//! Drop-in replacement for the `curl` command.

#![deny(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

fn main() {
    println!("urlx 0.1.0 — a memory-safe curl replacement");
    println!("Usage: urlx <url>");
    println!();
    println!("No protocols implemented yet. Coming soon!");
}
