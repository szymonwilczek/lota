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

. "$(dirname "$0")/../lib/test.sh"
test_begin "examples optional deps"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
EXAMPLES_DIR="$BUILD_DIR/examples"
REAL_PKG_CONFIG=$(command -v pkg-config || true)

if [[ -z "$REAL_PKG_CONFIG" ]]; then
    FAIL "pkg-config not installed"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

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

says() { printf '%s' "$1" | grep -qF -- "$2"; }
lacks() { ! printf '%s' "$1" | grep -qF -- "$2"; }
has() { "$REAL_PKG_CONFIG" --exists "$1"; }

# One run of `make examples` with $1 hidden; prints the combined output
run_examples_without() {
    local pkg="$1"
    make -C "$REPO_DIR" BUILD_DIR="$BUILD_DIR" examples-clean \
         >/dev/null 2>&1 || true
    LOTA_TEST_HIDDEN_PKG="$pkg" PATH="$SHIM_BIN:$PATH" \
                        make -C "$REPO_DIR" BUILD_DIR="$BUILD_DIR" examples 2>&1 ||
        echo "MAKE-FAILED"
}

out=$(run_examples_without libcurl)
TEST "the target completes"
lacks "$out" "MAKE-FAILED" || FAIL
TEST "the CI attestation step says it is skipped"
says "$out" "SKIP: lota-ci-attest" || FAIL "%s" "$out"
TEST "the heartbeat producer says it is skipped"
says "$out" "SKIP: demo_anticheat" || FAIL "%s" "$out"
TEST "trust_pong says it is skipped"
says "$out" "SKIP: trust_pong" || FAIL "%s" "$out"
TEST "the example that needs no libcurl is built"
test -x "$EXAMPLES_DIR/runtime_remeasure" || FAIL
TEST "the block demo is built"
test -x "$EXAMPLES_DIR/block_victim" || FAIL
TEST "the release gate is built"
test -x "$EXAMPLES_DIR/lota-release-gate" || FAIL
TEST "no example that needs libcurl is left behind"
test ! -e "$EXAMPLES_DIR/demo_anticheat" || FAIL

echo ""
out=$(run_examples_without sdl2)
TEST "the target completes"
lacks "$out" "MAKE-FAILED" || FAIL
TEST "trust_pong says it is skipped"
says "$out" "SKIP: trust_pong" || FAIL "%s" "$out"
if has libcurl; then
    TEST "the CI attestation step is built"
    test -x "$EXAMPLES_DIR/lota-ci-attest" || FAIL
    TEST "the heartbeat producer is built"
    test -x "$EXAMPLES_DIR/demo_anticheat" || FAIL
fi
TEST "trust_pong is not left behind"
test ! -e "$EXAMPLES_DIR/trust_pong" || FAIL

echo ""
make -C "$REPO_DIR" BUILD_DIR="$BUILD_DIR" examples-clean >/dev/null 2>&1 || true
full=$(make -C "$REPO_DIR" BUILD_DIR="$BUILD_DIR" examples 2>&1 ||
           echo "MAKE-FAILED")

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

TEST "the target completes"
lacks "$full" "MAKE-FAILED" || FAIL
TEST "the CI attestation step is skipped only for a missing package"
skipped_iff_missing lota-ci-attest libcurl || FAIL
TEST "the heartbeat producer is skipped only for a missing package"
skipped_iff_missing demo_anticheat libcurl || FAIL
TEST "trust_pong is skipped only for a missing package"
skipped_iff_missing trust_pong sdl2 libcurl || FAIL

test_end
