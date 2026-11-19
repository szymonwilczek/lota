#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Check that the published images are built as documented: the verifier
# static without cgo, the CA with cgo on distroless cc-debian13, whose glibc
# loader can dlopen a PKCS#11 module, and make container-images building the
# CA image.
# Reads the build configuration, not a built image.

set -euo pipefail

cd "$(dirname "$0")/.."

CA_CONFIG=src/attestca/.ko.yaml
VERIFIER_CONFIG=src/verifier/.ko.yaml

fail=0

check() {
    local msg="$1"
    shift
    if "$@"; then
        echo "PASS: $msg"
    else
        echo "FAIL: $msg"
        fail=1
    fi
}

has() { [[ -f $1 ]] && grep -qF -- "$2" "$1"; }
lacks() { [[ -f $1 ]] && ! grep -qF -- "$2" "$1"; }

# Verifier: static, no cgo, no tags, on distroless static
check "$VERIFIER_CONFIG builds without cgo" \
    has "$VERIFIER_CONFIG" "CGO_ENABLED=0"
check "$VERIFIER_CONFIG sits on the static base" \
    has "$VERIFIER_CONFIG" "distroless/static"
check "$VERIFIER_CONFIG selects no build tags" \
    lacks "$VERIFIER_CONFIG" "-tags"

# CA dlopens a PKCS#11 module: needs cgo and the glibc of cc-debian13
check "$CA_CONFIG is built with cgo" has "$CA_CONFIG" "CGO_ENABLED=1"
check "$CA_CONFIG sits on the cc base" \
    grep -qE '^defaultBaseImage: gcr\.io/distroless/cc-debian13:' "$CA_CONFIG"
check "$CA_CONFIG overrides no base" lacks "$CA_CONFIG" "baseImageOverrides"
check "$CA_CONFIG selects no build tags" lacks "$CA_CONFIG" "-tags"

check "make container-images builds the CA image" \
    grep -qE '^container-images:.*container-image-attest-ca( |$)' Makefile

if ((fail != 0)); then
    echo "container-images: an image is not built as documented" >&2
    exit 1
fi
echo "container-images: OK"
