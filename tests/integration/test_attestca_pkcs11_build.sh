#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_attestca_pkcs11_build.sh
#
# The lota-attest-ca that `make attest-ca` builds, and so the one in the
# release manifest, carries the PKCS#11 signer; checked in the binary.
#
# Requires:
#   - go, a C toolchain (the CA is cgo), make
#
# Runs unprivileged in a scratch BUILD_DIR.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "[attestca-pkcs11-build] missing toolchain: go" >&2
    exit 2
fi
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "[attestca-pkcs11-build] missing toolchain: a C compiler" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

BIN="$WORK_DIR/build/lota-attest-ca"

# Strings only a CA without the signer, or only one with it, carries
STUB_MARKER='built without PKCS#11 support'
SIGNER_MARKER='token PIN is required in LOTA_CA_PKCS11_PIN'

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

carries() { grep -qaF -- "$1" "$BIN"; }
lacks() { ! grep -qaF -- "$1" "$BIN"; }

if ! make -C "$REPO_DIR" BUILD_DIR="$WORK_DIR/build" attest-ca \
     >"$WORK_DIR/build.log" 2>&1; then
    echo "[attestca-pkcs11-build] the build failed" >&2
    cat "$WORK_DIR/build.log" >&2
    exit 2
fi
check "the CA carries the PKCS#11 signer" carries "$SIGNER_MARKER"
check "the CA has no build without PKCS#11" lacks "$STUB_MARKER"

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
