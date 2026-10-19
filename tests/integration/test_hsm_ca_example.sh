#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_hsm_ca_example.sh
#
# examples/hsm-ca/setup-token.sh must produce all a CA needs to start:
# CA certificate over the token key, listener keypair chained to it,
# pseudonym secret. Runs with stdin closed, so a PIN prompt fails.
#
# Requires:
#   - softhsm2-util, pkcs11-tool (opensc), openssl with the pkcs11 provider
#
# Runs unprivileged on a token store under the output directory.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/examples/hsm-ca/setup-token.sh"

if [[ ! -x $SETUP ]]; then
    echo "[hsm-ca-example] missing artifact: $SETUP" >&2
    exit 2
fi
for tool in softhsm2-util pkcs11-tool openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[hsm-ca-example] missing tool: $tool" >&2
        exit 2
    fi
done

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

OUT_DIR="$WORK_DIR/ca"

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

if ! "$SETUP" "$OUT_DIR" >"$WORK_DIR/setup.log" 2>&1 </dev/null; then
    echo "FAIL: setup-token.sh runs with no terminal to prompt at"
    sed 's/^/  /' "$WORK_DIR/setup.log" >&2
    echo "1 check(s) failed"
    exit 1
fi
echo "PASS: setup-token.sh runs with no terminal to prompt at"

check "it writes the CA certificate the CA is started with" \
    test -s "$OUT_DIR/ca.crt"
check "it writes the listener keypair the agent verifies" \
    test -s "$OUT_DIR/tls.crt" -a -s "$OUT_DIR/tls.key"
check "it writes the pseudonym secret" test -s "$OUT_DIR/pseudonym.key"

if [[ -s $OUT_DIR/ca.crt ]]; then
    ca_text=$(openssl x509 -in "$OUT_DIR/ca.crt" -noout -text)
    check "the certificate it issues is a CA certificate" \
        grep -q "CA:TRUE" <<<"$ca_text"

    # The CA refuses to start unless ca.crt carries the token key
    conf="$OUT_DIR/softhsm2.conf"
    if [[ -s $conf ]]; then
        SOFTHSM2_CONF="$conf" openssl pkey -provider pkcs11 -provider default \
            -in "pkcs11:token=lota-ca;object=lota-ca-key;type=public" \
            -pubin -pubout -out "$WORK_DIR/token.pub" >/dev/null 2>&1 || true
        openssl x509 -in "$OUT_DIR/ca.crt" -noout -pubkey >"$WORK_DIR/cert.pub" 2>/dev/null
        check "the CA certificate carries the token key" \
            cmp -s "$WORK_DIR/token.pub" "$WORK_DIR/cert.pub"
    else
        echo "FAIL: the example leaves no token configuration to read the key back with"
        failures=$((failures + 1))
    fi
fi

if [[ -s $OUT_DIR/tls.crt && -s $OUT_DIR/ca.crt ]]; then
    check "the listener certificate chains to the CA certificate" \
        openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/tls.crt"
    check "the listener certificate names the host the reader connects to" \
        grep -q "DNS:localhost" <<<"$(openssl x509 -in "$OUT_DIR/tls.crt" -noout -text)"
fi

check "it prints the token configuration the CA needs in its environment" \
    grep -q "SOFTHSM2_CONF" "$WORK_DIR/setup.log"

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
