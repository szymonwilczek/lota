#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Resolving an EK root on a TPM whose leaf carries no AIA.
#
# The documented procedure -- follow "CA Issuers" up until issuer == subject
# -- has no first step on Intel PTT, the default TPM of the consumer target
# hardware: its EK certificate carries a CRL distribution point and nothing
# else. The intermediates are on the chip, at NV index 0x01c00100,
# as concatenated DER certificates in one blob, and AIA only appears from
# the certificates above them.
#
# So the tool has to take that blob as path material. This test builds
# a three-level chain locally, hands the tool the leaf and a blob shaped
# like the NV one, and expects the root's pin -- with no network involved.
#
# Requires: openssl, and scripts/lota-ek-root-pin.sh.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
PIN_TOOL="$REPO_DIR/scripts/lota-ek-root-pin.sh"

if [[ ! -x "$PIN_TOOL" ]]; then
    echo "[ek-root-pin] missing artifact: $PIN_TOOL" >&2
    exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "[ek-root-pin] openssl not found" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

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

cd "$WORK_DIR"

# A manufacturer PKI in miniature: self-signed root, one intermediate under it,
# and an EK leaf under the intermediate that carries no AIA at all -- which is
# the whole point.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -days 2 -out root.pem \
	-subj "/CN=Example TPM Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign" 2>/dev/null

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out int.key 2>/dev/null
openssl req -new -key int.key -out int.csr -subj "/CN=Example TPM Issuing CA" 2>/dev/null
openssl x509 -req -in int.csr -days 2 -CA root.pem -CAkey root.key -CAcreateserial \
	-out int.pem -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n') 2>/dev/null

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ek.key 2>/dev/null
openssl req -new -key ek.key -out ek.csr -subj "/CN=Example EK" 2>/dev/null
openssl x509 -req -in ek.csr -days 2 -CA int.pem -CAkey int.key -CAcreateserial \
	-out ek.pem -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\n') 2>/dev/null
openssl x509 -in ek.pem -outform DER -out ek.der 2>/dev/null

# The blob a TPM hands over: concatenated DER, no separators, in no promised
# order. Intel PTT stores three certificates this way.
openssl x509 -in int.pem -outform DER -out int.der 2>/dev/null
openssl x509 -in root.pem -outform DER -out root.der 2>/dev/null
cat int.der root.der >nvchain.bin

expected_pin=$(openssl x509 -in root.pem -outform DER | sha256sum | cut -d' ' -f1)

check "the EK leaf really carries no AIA" \
      bash -c "! openssl x509 -in ek.pem -noout -ext authorityInfoAccess 2>/dev/null | grep -q 'CA Issuers'"

# The tool must climb through the on-chip certificates without a network hop.
rc=0
out=$("$PIN_TOOL" --nv-chain nvchain.bin ek.der 2>"$WORK_DIR/err.txt") || rc=$?

check "the tool resolves a root from the on-chip chain" test "$rc" -eq 0
check "it prints the root's pin" bash -c "grep -q '$expected_pin' <<<'$out'"

# The pin is over the root, not over an intermediate that happens to be in
# the blob: pinning an intermediate is a different, narrower decision.
int_pin=$(openssl x509 -in int.pem -outform DER | sha256sum | cut -d' ' -f1)
check "it does not stop at the intermediate" \
      bash -c "! grep -q '$int_pin' <<<'$out'"

# A blob that carries no path to a root leaves the operator where they were,
# and has to say so.
cat int.der >partial.bin
rc=0
"$PIN_TOOL" --nv-chain partial.bin ek.der >/dev/null 2>&1 || rc=$?
check "a chain that reaches no root is refused" test "$rc" -ne 0

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    sed -n '1,10p' "$WORK_DIR/err.txt" 2>/dev/null
    exit 1
fi
echo "All tests passed"
