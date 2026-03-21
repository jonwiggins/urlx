# Contributing to urlx

Thanks for your interest in contributing to urlx, a memory-safe Rust reimplementation of curl.

## Prerequisites

- **Rust 1.85+** (install via [rustup](https://rustup.rs/))
- **Perl** (for running the curl test suite)
- **Git** (with submodule support -- the curl test suite lives in `vendor/curl/`)

## Getting Started

```bash
git clone --recurse-submodules https://github.com/jonwiggins/urlx.git
cd urlx
cargo build --workspace --release
```

## Running Tests

**Rust tests:**

```bash
cargo test --workspace
```

**curl compatibility tests** (runs curl's own test suite against urlx):

```bash
./scripts/run-curl-tests.sh
```

## Code Style

- Format with `cargo fmt` before committing.
- Lint with `cargo clippy --all-targets` and fix all warnings.
- No `unsafe` code outside of `crates/liburlx-ffi/`. The core library and CLI must be 100% safe Rust.
- No `unwrap()` in library code. Use proper error handling with `Result`.
- Every public item needs a doc comment.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
fix(http): handle chunked encoding edge case (test 123)
feat(ftp): add MLSD command support
chore: update dependencies
docs: clarify TLS backend configuration
```

Scope names match crate or module names: `http`, `ftp`, `tls`, `url`, `cookie`, `dns`, `proxy`, `auth`, `ffi`, `cli`, `pool`, `ws`, `mqtt`, `smtp`, `imap`.

## Development Methodology

**curl's test suite is the specification.** We import curl's own test suite, run it against our binaries, and use failing tests as the work queue. The measure of success is curl's tests passing against urlx.

When working on a failing test:

1. Read the test file at `vendor/curl/tests/data/testNNN` to understand what it expects.
2. Make the minimum change to pass the test.
3. Verify no regressions by running all previously-passing tests.

## Pull Requests

- Keep PRs focused on one logical change.
- Reference curl test numbers when applicable.
- Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
- Run the curl test suite to check for regressions.

## More Information

See [CLAUDE.md](CLAUDE.md) for detailed project documentation, architecture, and current status.
