#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_examples_optional_deps.sh
#
# `make examples` with one optional demo dependency missing skips the
# examples that need it and still builds the rest. A pkg-config shim
# hides one package at a time.
#
# Requires:
#   - bash, make, a C compiler, pkg-config
#
# Runs unprivileged; rebuilds the examples in the build tree and leaves
# them built.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
REAL_PKG_CONFIG=$(command -v pkg-config || true)
BUILD_DIR=${BUILD_DIR:-build}
if [[ "$BUILD_DIR" == /* ]]; then
    EXAMPLES_OUT="$BUILD_DIR/examples"
else
    EXAMPLES_OUT="$REPO_DIR/$BUILD_DIR/examples"
fi
MAKE_EXAMPLES=(make -C "$REPO_DIR" BUILD_DIR="$BUILD_DIR")

if [[ -z "$REAL_PKG_CONFIG" ]]; then
    echo "[examples-deps] pkg-config not installed" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

SHIM_BIN="$WORK_DIR/bin"
mkdir -p "$SHIM_BIN"

# pkg-config reporting one package absent, passing the rest through
cat >"$SHIM_BIN/pkg-config" <<SHIM
#!/bin/bash
for arg in "\$@"; do
	if [[ "\$arg" == "\$LOTA_TEST_HIDDEN_PKG" ]]; then
		echo "Package \$LOTA_TEST_HIDDEN_PKG was not found" >&2
		exit 1
	fi
done
exec "$REAL_PKG_CONFIG" "\$@"
SHIM
chmod +x "$SHIM_BIN/pkg-config"

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
        echo "PASS: $msg"
    else
        echo "FAIL: $msg"
        failures=$((failures + 1))
    fi
}

says() { printf '%s' "$1" | grep -qF -- "$2"; }
lacks() { ! printf '%s' "$1" | grep -qF -- "$2"; }
has() { "$REAL_PKG_CONFIG" --exists "$1"; }

# One run of `make examples` with $1 hidden; prints the combined output
run_examples_without() {
    local pkg="$1"
    "${MAKE_EXAMPLES[@]}" examples-clean >/dev/null 2>&1 || true
    LOTA_TEST_HIDDEN_PKG="$pkg" PATH="$SHIM_BIN:$PATH" \
                        "${MAKE_EXAMPLES[@]}" examples 2>&1 || echo "MAKE-FAILED"
}

echo "=== make examples without libcurl ==="
out=$(run_examples_without libcurl)
check "the target completes" lacks "$out" "MAKE-FAILED"
check "the CI attestation step says it is skipped" \
      says "$out" "SKIP: lota-ci-attest"
check "the heartbeat producer says it is skipped" \
      says "$out" "SKIP: demo_anticheat"
check "trust_pong says it is skipped" says "$out" "SKIP: trust_pong"
check "the example that needs no libcurl is built" \
      test -x "$EXAMPLES_OUT/runtime_remeasure"
check "the block demo is built" test -x "$EXAMPLES_OUT/block_victim"
check "the release gate is built" \
      test -x "$EXAMPLES_OUT/lota-release-gate"
check "no example that needs libcurl is left behind" \
      test ! -e "$EXAMPLES_OUT/demo_anticheat"

echo ""
echo "=== make examples without sdl2 ==="
out=$(run_examples_without sdl2)
check "the target completes" lacks "$out" "MAKE-FAILED"
check "trust_pong says it is skipped" says "$out" "SKIP: trust_pong"
if has libcurl; then
    check "the CI attestation step is built" \
          test -x "$EXAMPLES_OUT/lota-ci-attest"
    check "the heartbeat producer is built" \
          test -x "$EXAMPLES_OUT/demo_anticheat"
fi
check "trust_pong is not left behind" \
      test ! -e "$EXAMPLES_OUT/trust_pong"

echo ""
echo "=== make examples with every dependency present ==="
"${MAKE_EXAMPLES[@]}" examples-clean >/dev/null 2>&1 || true
full=$("${MAKE_EXAMPLES[@]}" examples 2>&1 || echo "MAKE-FAILED")

# $1 is skipped exactly when the host lacks one of the packages after it
skipped_iff_missing() {
    local example="$1" pkg
    shift
    for pkg in "$@"; do
        if ! has "$pkg"; then
            says "$full" "SKIP: $example"
            return
        fi
    done
    lacks "$full" "SKIP: $example"
}

check "the target completes" lacks "$full" "MAKE-FAILED"
check "the CI attestation step is skipped only for a missing package" \
      skipped_iff_missing lota-ci-attest libcurl
check "the heartbeat producer is skipped only for a missing package" \
      skipped_iff_missing demo_anticheat libcurl
check "trust_pong is skipped only for a missing package" \
      skipped_iff_missing trust_pong sdl2 libcurl

echo ""
if [[ $failures -gt 0 ]]; then
    echo "[examples-deps] $failures check(s) failed"
    exit 1
fi
echo "[examples-deps] all checks passed"
