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
EXCLUDE_FILE="$PROJECT_ROOT/tests/excluded-tests.txt"
export URLX_BIN="$URLX"

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

# Set up libtests for libcurl C API tests (e.g., test 678).
#
# Strategy:
#   1. If curl's libtests binary exists AND our FFI .so exists, use LD_PRELOAD
#      to substitute our liburlx-ffi so that curl API calls go through urlx.
#   2. Otherwise, install our libtests-shim script as a fallback. The shim
#      translates supported lib tests (e.g., lib678) into urlx CLI invocations.
FFI_LIB="$PROJECT_ROOT/target/release/libliburlx_ffi.so"
LIBTESTS="$CURL_BUILD/tests/libtest/libtests"
LIBTESTS_REAL="$CURL_BUILD/tests/libtest/libtests.real"
LIBTESTS_SHIM="$SCRIPT_DIR/libtests-shim"

if [ -f "$FFI_LIB" ] && [ -x "$LIBTESTS" ] && [ ! -f "$LIBTESTS_REAL" ]; then
    # LD_PRELOAD approach: override curl_easy_* symbols with our FFI
    mv "$LIBTESTS" "$LIBTESTS_REAL"
    cat > "$LIBTESTS" <<WRAPPER
#!/bin/bash
LD_PRELOAD="$FFI_LIB" LD_LIBRARY_PATH="$CURL_BUILD/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}" exec "$LIBTESTS_REAL" "\$@"
WRAPPER
    chmod +x "$LIBTESTS"
elif [ ! -x "$LIBTESTS" ] && [ ! -f "$LIBTESTS_REAL" ]; then
    # Fallback: use the libtests-shim script for supported C API tests.
    # This handles tests like 678 (CAINFO_BLOB) via equivalent CLI invocations.
    mkdir -p "$CURL_BUILD/tests/libtest"
    cp "$LIBTESTS_SHIM" "$LIBTESTS"
    chmod +x "$LIBTESTS"
    echo "Installed libtests-shim for C API tests (e.g., test 678)"
fi

# Override curlinfo to report urlx's actual capabilities.
#
# curl's curlinfo binary reflects curl's build configuration, not urlx's.
# For example, curl may be built without ssl-sessions support, causing the
# test harness to skip test 777 even though urlx supports ssl-sessions.
# We replace curlinfo with a wrapper that patches the output.
CURLINFO_BIN="$CURL_BUILD/src/curlinfo"
CURLINFO_REAL="$CURL_BUILD/src/curlinfo.real"
CURLINFO_WRAPPER="$SCRIPT_DIR/curlinfo-urlx"

if [ -x "$CURLINFO_BIN" ] && [ ! -f "$CURLINFO_REAL" ]; then
    # Move the real binary aside and install our wrapper
    mv "$CURLINFO_BIN" "$CURLINFO_REAL"
    cat > "$CURLINFO_BIN" <<CURLINFO_SHIM
#!/bin/bash
export CURLINFO_REAL="$CURLINFO_REAL"
exec "$CURLINFO_WRAPPER" "\$@"
CURLINFO_SHIM
    chmod +x "$CURLINFO_BIN"
elif [ ! -x "$CURLINFO_BIN" ] && [ ! -f "$CURLINFO_REAL" ]; then
    # No curlinfo binary at all — install our wrapper directly
    mkdir -p "$CURL_BUILD/src"
    cat > "$CURLINFO_BIN" <<CURLINFO_SHIM
#!/bin/bash
exec "$CURLINFO_WRAPPER" "\$@"
CURLINFO_SHIM
    chmod +x "$CURLINFO_BIN"
fi

# Ensure symlinks are in place
cd "$TESTS_DIR"
[ ! -e data ] && ln -sf "$CURL_SRC/tests/data" data
[ ! -e certs ] && ln -sf "$CURL_SRC/tests/certs" certs
for f in "$CURL_SRC/tests/"*.pm "$CURL_SRC/tests/"*.pl; do
    base=$(basename "$f")
    [ ! -e "$base" ] && ln -sf "$f" "$base"
done
# Symlink libtest .pl scripts for SSH postcheck tests
if [ -d libtest ] && [ -d "$CURL_SRC/tests/libtest" ]; then
    for f in "$CURL_SRC/tests/libtest/"*.pl; do
        base=$(basename "$f")
        [ ! -e "libtest/$base" ] && ln -sf "$f" "libtest/$base"
    done
fi

# Patch sshserver.pl to also generate ed25519 host keys.
# russh 0.57.x has issues verifying RSA server signatures with some
# OpenSSH versions. Adding an ed25519 host key lets russh negotiate
# ed25519 instead, which works reliably.
if [ -L sshserver.pl ]; then
    cp --remove-destination "$CURL_SRC/tests/sshserver.pl" sshserver.pl
    python3 "$SCRIPT_DIR/patch-sshserver.py" sshserver.pl
fi

# Run the tests
# -a = continue after failures
# -c = custom curl binary
# -vc = curl binary for server verification (use system curl)
echo "=== Running curl test suite against urlx ==="
echo "urlx binary: $URLX"
echo "Tests: ${*:-ALL}"
echo ""

# Build exclusion args from exclude file (skip test numbers listed there)
EXCLUDE_ARGS=()
if [ -f "$EXCLUDE_FILE" ]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        # Parse "test:NNN:reason" format
        if [[ "$line" =~ ^test:([0-9]+): ]]; then
            EXCLUDE_ARGS+=("!${BASH_REMATCH[1]}")
        fi
    done < "$EXCLUDE_FILE"
    if [ ${#EXCLUDE_ARGS[@]} -gt 0 ]; then
        echo "Excluding ${#EXCLUDE_ARGS[@]} tests from: $EXCLUDE_FILE"
        echo ""
    fi
fi

perl runtests.pl \
    -a \
    -c "$WRAPPER" \
    -vc /usr/bin/curl \
    "${EXCLUDE_ARGS[@]}" \
    "$@" 2>&1

exit_code=$?
echo ""
echo "=== Done (exit code: $exit_code) ==="
exit $exit_code
