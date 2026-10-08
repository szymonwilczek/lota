#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_ek_root_pin_bundle_lines.sh
#
# What an operator has to put in a bundle so a platform can enrol.
#
# The CA holds the pinned anchors; the device supplies whatever its TPM keeps
# on the chip. Everything in between -- the certificates published only over
# the vendor's HTTPS endpoint -- is the operator's half of the path,
# and a bundle missing any of it refuses a genuine TPM with an error that blames
# the endorsement key. So the tool that drafts the bundle has to draft a line
# for every certificate it had to fetch, not only for the root it ended at,
# and each line has to say whether the certificate is a trust anchor or path
# material.
#
# A certificate the device carries itself needs no line: the enrollment
# request brings it along.
#
# Requires: openssl, curl, python3 (a local stand-in for the vendor's
# distribution point), and scripts/lota-ek-root-pin.sh. No network.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
PIN_TOOL="$REPO_DIR/scripts/lota-ek-root-pin.sh"

if [[ ! -x "$PIN_TOOL" ]]; then
    echo "[ek-root-pin-lines] missing artifact: $PIN_TOOL" >&2
    exit 2
fi
for tool in openssl curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
	echo "[ek-root-pin-lines] $tool not found" >&2
	exit 2
    fi
done

WORK_DIR=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

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
mkdir -p www

# A free port the vendor stand-in can bind. Picked and released, which is a race
# only another test binding the same port at the same instant could lose.
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
BASE="http://127.0.0.1:$PORT"

# Vendor PKI: a self-signed root, an issuing CA under it that is published only
# at the distribution point, and an EK leaf that points at the issuing CA through
# AIA the way a discrete TPM's does.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -days 2 -out root.pem \
	-subj "/CN=Example TPM Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign" 2>/dev/null

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out int.key 2>/dev/null
openssl req -new -key int.key -out int.csr -subj "/CN=Example TPM Issuing CA" 2>/dev/null
openssl x509 -req -in int.csr -days 2 -CA root.pem -CAkey root.key -CAcreateserial \
	-out int.pem -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nauthorityInfoAccess=caIssuers;URI:%s/root.der\n' "$BASE") 2>/dev/null

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ek.key 2>/dev/null
openssl req -new -key ek.key -out ek.csr -subj "/CN=Example EK" 2>/dev/null
openssl x509 -req -in ek.csr -days 2 -CA int.pem -CAkey int.key -CAcreateserial \
	-out ek.pem -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nauthorityInfoAccess=caIssuers;URI:%s/int.der\n' "$BASE") 2>/dev/null
openssl x509 -in ek.pem -outform DER -out ek.der 2>/dev/null

openssl x509 -in int.pem -outform DER -out www/int.der 2>/dev/null
openssl x509 -in root.pem -outform DER -out www/root.der 2>/dev/null

root_pin=$(openssl x509 -in root.pem -outform DER | sha256sum | cut -d' ' -f1)
int_pin=$(openssl x509 -in int.pem -outform DER | sha256sum | cut -d' ' -f1)

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK_DIR/www" \
	>/dev/null 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "$BASE/root.der" 2>/dev/null && break
    sleep 0.1
done

# class_of prints the class column of the sources line pinning $1
class_of() {
    awk -v pin="$1" '$1 == pin { print $3 }' <<<"$2"
}

rc=0
out=$("$PIN_TOOL" ek.der 2>"$WORK_DIR/err.txt") || rc=$?

check "the tool resolves the root over the distribution point" test "$rc" -eq 0

# One line, for the root, and the operator is never told that the issuing CA
# has to be pinned too. The chain then breaks at the leaf's issuer.
check "it drafts a line for the root" \
      bash -c "grep -q '$root_pin' <<<'$out'"
check "it drafts a line for the intermediate it had to fetch" \
      bash -c "grep -q '$int_pin' <<<'$out'"
check "the root line is classed as a trust anchor" \
      test "$(class_of "$root_pin" "$out")" = "root"
check "the fetched intermediate is classed as path material" \
      test "$(class_of "$int_pin" "$out")" = "intermediate"
check "every drafted line names where it was fetched from" \
      bash -c "! grep -q 'REPLACE_WITH_VENDOR_PUBLISHED_URL' <<<'$out'"

# A certificate the chip carries is supplied with the enrollment request,
# so pinning it is redundant: the tool must climb through it without drafting
# a line for it.
rc=0
out=$("$PIN_TOOL" --nv-chain www/int.der ek.der 2>"$WORK_DIR/err2.txt") || rc=$?
check "the tool climbs a chain the device carries" test "$rc" -eq 0
check "it drafts no line for a certificate the device supplies" \
      bash -c "! grep -q '$int_pin' <<<'$out'"
check "it still drafts the root the device does not carry" \
      bash -c "grep -q '$root_pin' <<<'$out'"

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    echo "--- stdout ---"
    printf '%s\n' "$out"
    echo "--- stderr ---"
    sed -n '1,10p' "$WORK_DIR/err.txt" 2>/dev/null
    exit 1
fi
echo "All tests passed"
