#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_attestca_build_tags.sh
#
# Adding or dropping GO_TAGS=pkcs11 on an already built tree must rebuild
# lota-attest-ca; checked in the binary, not in make's output.
#
# Requires:
#   - go, a C toolchain (the pkcs11 build is cgo), make
#
# Runs unprivileged in a scratch BUILD_DIR.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "[attestca-build-tags] missing toolchain: go" >&2
    exit 2
fi
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "[attestca-build-tags] missing toolchain: a C compiler (the pkcs11 build is cgo)" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

BIN="$WORK_DIR/build/lota-attest-ca"

# Strings only the pure-Go stub, or only the pkcs11 build, carries
STUB_MARKER='built without PKCS#11 support'
TAGGED_MARKER='token PIN is required in LOTA_CA_PKCS11_PIN'

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

build() {
    make -C "$REPO_DIR" BUILD_DIR="$WORK_DIR/build" attest-ca "$@" >>"$WORK_DIR/build.log" 2>&1
}

carries() { grep -qaF -- "$1" "$BIN"; }
lacks() { ! grep -qaF -- "$1" "$BIN"; }

if ! build; then
    echo "[attestca-build-tags] the default build failed; see $WORK_DIR/build.log" >&2
    cat "$WORK_DIR/build.log" >&2
    exit 2
fi
check "the default build has no PKCS#11 support" carries "$STUB_MARKER"

if ! build GO_TAGS=pkcs11; then
    echo "[attestca-build-tags] the pkcs11 build failed; see $WORK_DIR/build.log" >&2
    cat "$WORK_DIR/build.log" >&2
    exit 2
fi
check "asking for the tag on a built tree rebuilds with it" lacks "$STUB_MARKER"
check "the rebuilt binary carries the PKCS#11 signer" carries "$TAGGED_MARKER"

if ! build; then
    echo "[attestca-build-tags] the rebuild without tags failed; see $WORK_DIR/build.log" >&2
    cat "$WORK_DIR/build.log" >&2
    exit 2
fi
check "dropping the tag rebuilds back to the pure-Go binary" carries "$STUB_MARKER"

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
