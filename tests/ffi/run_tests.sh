#!/bin/bash
# Build and run FFI C test harness against liburlx-ffi.
#
# Usage: ./tests/ffi/run_tests.sh
#
# Prerequisites: cargo build --release -p liburlx-ffi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$ROOT_DIR/target/release"

echo "Building liburlx-ffi (release)..."
cargo build --release -p liburlx-ffi --manifest-path "$ROOT_DIR/Cargo.toml"

echo "Compiling C test..."
cc -o "$SCRIPT_DIR/test_basic" \
    "$SCRIPT_DIR/test_basic.c" \
    -L"$TARGET_DIR" \
    -lliburlx_ffi \
    -lpthread -ldl -lm \
    -Wl,-rpath,"$TARGET_DIR"

echo "Running C test..."
echo ""
DYLD_LIBRARY_PATH="$TARGET_DIR" LD_LIBRARY_PATH="$TARGET_DIR" "$SCRIPT_DIR/test_basic"

echo ""
echo "C test harness passed."
