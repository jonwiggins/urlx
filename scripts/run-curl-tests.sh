#!/bin/bash
# Run curl's test suite against the urlx binary.
#
# Usage:
#   ./scripts/run-curl-tests.sh [test-numbers...]
#   ./scripts/run-curl-tests.sh 1 2 3        # run specific tests
#   ./scripts/run-curl-tests.sh 1 to 20      # run a range
#   ./scripts/run-curl-tests.sh              # run ALL tests (slow!)
#
# Prerequisites:
#   - curl built at vendor/curl-build/ (cmake --build vendor/curl-build --target curl curlinfo servers)
#   - urlx built in release mode (cargo build --release -p urlx-cli)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CURL_BUILD="$PROJECT_ROOT/vendor/curl-build"
CURL_SRC="$PROJECT_ROOT/vendor/curl"
TESTS_DIR="$CURL_BUILD/tests"
WRAPPER="$SCRIPT_DIR/urlx-as-curl"
URLX="$PROJECT_ROOT/target/release/urlx"

# Verify prerequisites
if [ ! -x "$URLX" ]; then
    echo "ERROR: urlx binary not found at $URLX"
    echo "Run: cargo build --release -p urlx-cli"
    exit 1
fi

if [ ! -x "$CURL_BUILD/tests/server/servers" ]; then
    echo "ERROR: curl test servers not built"
    echo "Run: cmake --build vendor/curl-build --target servers curl curlinfo"
    exit 1
fi

if [ ! -x "$WRAPPER" ]; then
    echo "ERROR: urlx-as-curl wrapper not found at $WRAPPER"
    exit 1
fi

# Ensure symlinks are in place
cd "$TESTS_DIR"
[ ! -e data ] && ln -sf "$CURL_SRC/tests/data" data
[ ! -e certs ] && ln -sf "$CURL_SRC/tests/certs" certs
for f in "$CURL_SRC/tests/"*.pm "$CURL_SRC/tests/"*.pl; do
    base=$(basename "$f")
    [ ! -e "$base" ] && ln -sf "$f" "$base"
done

# Run the tests
# -a = continue after failures
# -c = custom curl binary
# -vc = curl binary for server verification (use system curl)
echo "=== Running curl test suite against urlx ==="
echo "urlx binary: $URLX"
echo "Tests: ${*:-ALL}"
echo ""

perl runtests.pl \
    -a \
    -c "$WRAPPER" \
    -vc /usr/bin/curl \
    "$@" 2>&1

exit_code=$?
echo ""
echo "=== Done (exit code: $exit_code) ==="
exit $exit_code
