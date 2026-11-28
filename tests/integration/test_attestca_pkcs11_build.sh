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

. "$(dirname "$0")/../lib/test.sh"
test_begin "attestca pkcs11 build"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    FAIL "missing toolchain: go"
    test_end
fi
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    FAIL "missing toolchain: a C compiler"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

BIN="$WORK_DIR/build/lota-attest-ca"

# Strings only a CA without the signer, or only one with it, carries
STUB_MARKER='built without PKCS#11 support'
SIGNER_MARKER='token PIN is required in LOTA_CA_PKCS11_PIN'

carries() { grep -qaF -- "$1" "$BIN"; }
lacks() { ! grep -qaF -- "$1" "$BIN"; }

TEST "make attest-ca builds the CA"
if ! make -C "$REPO_DIR" BUILD_DIR="$WORK_DIR/build" attest-ca \
     >"$WORK_DIR/build.log" 2>&1; then
    FAIL "%s" "$(tail -n 20 "$WORK_DIR/build.log")"
    test_end
fi
TEST "the CA carries the PKCS#11 signer"
carries "$SIGNER_MARKER" || FAIL
TEST "the CA has no build without PKCS#11"
lacks "$STUB_MARKER" || FAIL

test_end
