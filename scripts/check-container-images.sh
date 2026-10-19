#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Check that the published images offer the CA key roads they document: a PEM
# key on the static images, a PKCS#11 token on the HSM image.
# Reads the build configuration, not a built image.

set -euo pipefail

cd "$(dirname "$0")/.."

CA_CONFIG=src/attestca/.ko.yaml
VERIFIER_CONFIG=src/verifier/.ko.yaml
HSM_CONFIG=packaging/ko/attestca-hsm/.ko.yaml
RELEASE_WORKFLOW=.github/workflows/release.yml

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

# Pure-Go images: static, no cgo, no tags, on distroless static
for config in "$VERIFIER_CONFIG" "$CA_CONFIG"; do
    check "$config builds without cgo" has "$config" "CGO_ENABLED=0"
    check "$config sits on the static base" has "$config" "distroless/static"
    check "$config selects no build tags" lacks "$config" "-tags"
done

# HSM image dlopens a PKCS#11 module: needs tag, cgo and a base with a loader
check "an HSM-capable CA image is configured" test -f "$HSM_CONFIG"
check "the HSM image selects the pkcs11 tag" has "$HSM_CONFIG" "-tags=pkcs11"
check "the HSM image is built with cgo" has "$HSM_CONFIG" "CGO_ENABLED=1"
check "the HSM image does not sit on the static base" lacks "$HSM_CONFIG" "distroless/static"

# make container-images must publish it
check "make container-images builds the HSM image" \
    grep -qE '^container-images:.*container-image-attest-ca-hsm' Makefile
check "the HSM image has a target of its own" \
    grep -qE '^container-image-attest-ca-hsm:' Makefile

# The release must sign the HSM tag the Makefile names
suffix=$(sed -n 's/^KO_HSM_TAG_SUFFIX *?*= *//p' Makefile | head -1)
if [[ -z $suffix ]]; then
    echo "FAIL: the Makefile names no tag suffix for the HSM image"
    fail=1
else
    echo "PASS: the HSM image tag suffix is ${suffix}"
    check "the release signs the ${suffix} image" \
        grep -qF -- "$suffix" "$RELEASE_WORKFLOW"
fi

if ((fail != 0)); then
    echo "container-images: the image set does not offer the key roads it documents" >&2
    exit 1
fi
echo "container-images: OK"
