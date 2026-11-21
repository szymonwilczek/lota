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

. "$(dirname "$0")/../lib/test.sh"
test_begin "hsm ca example"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/examples/hsm-ca/setup-token.sh"

if [[ ! -x $SETUP ]]; then
    FAIL "missing artifact: %s" "$SETUP"
    test_end
fi
for tool in softhsm2-util pkcs11-tool openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        FAIL "missing tool: %s" "$tool"
        test_end
    fi
done

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

OUT_DIR="$WORK_DIR/ca"

TEST "setup-token.sh runs with no terminal to prompt at"
if ! "$SETUP" "$OUT_DIR" >"$WORK_DIR/setup.log" 2>&1 </dev/null; then
    FAIL "%s" "$(cat "$WORK_DIR/setup.log")"
    test_end
fi

TEST "it writes the CA certificate the CA is started with"
test -s "$OUT_DIR/ca.crt" || FAIL
TEST "it writes the listener keypair the agent verifies"
test -s "$OUT_DIR/tls.crt" -a -s "$OUT_DIR/tls.key" || FAIL
TEST "it writes the pseudonym secret"
test -s "$OUT_DIR/pseudonym.key" || FAIL

if [[ -s $OUT_DIR/ca.crt ]]; then
    ca_text=$(openssl x509 -in "$OUT_DIR/ca.crt" -noout -text)
    TEST "the certificate it issues is a CA certificate"
    grep -q "CA:TRUE" <<<"$ca_text" || FAIL
    # The verifier refuses a CRL from an issuer without cRLSign
    TEST "the certificate it issues may sign CRLs"
    grep -q "CRL Sign" <<<"$ca_text" || FAIL

    # The CA refuses to start unless ca.crt carries the token key
    conf="$OUT_DIR/softhsm2.conf"
    if [[ -s $conf ]]; then
        SOFTHSM2_CONF="$conf" openssl pkey -provider pkcs11 -provider default \
            -in "pkcs11:token=lota-ca;object=lota-ca-key;type=public" \
            -pubin -pubout -out "$WORK_DIR/token.pub" >/dev/null 2>&1 || true
        openssl x509 -in "$OUT_DIR/ca.crt" -noout -pubkey >"$WORK_DIR/cert.pub" 2>/dev/null
        TEST "the CA certificate carries the token key"
        cmp -s "$WORK_DIR/token.pub" "$WORK_DIR/cert.pub" || FAIL
    else
        TEST "the example leaves a token configuration to read the key back"
        FAIL "no %s" "$conf"
    fi
fi

if [[ -s $OUT_DIR/tls.crt && -s $OUT_DIR/ca.crt ]]; then
    TEST "the listener certificate chains to the CA certificate"
    openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/tls.crt" >/dev/null ||
        FAIL
    TEST "the listener certificate names the host the reader connects to"
    grep -q "DNS:localhost" <<<"$(openssl x509 -in "$OUT_DIR/tls.crt" -noout -text)" || FAIL
fi

TEST "it prints the token configuration the CA needs in its environment"
grep -q "SOFTHSM2_CONF" "$WORK_DIR/setup.log" || FAIL

# a second token under the label would leave the CA to pick one by label
before=$(sha256sum "$OUT_DIR/ca.crt")
rc=0
"$SETUP" "$OUT_DIR" >"$WORK_DIR/again.log" 2>&1 </dev/null || rc=$?
TEST "a second run on the same directory is refused"
test "$rc" -eq 1 ||
    FAIL "exit %d: %s" "$rc" "$(cat "$WORK_DIR/again.log")"
TEST "the refusal names the token already there"
grep -q "already holds a token" "$WORK_DIR/again.log" || FAIL
TEST "a refused run leaves ca.crt alone"
test "$(sha256sum "$OUT_DIR/ca.crt")" = "$before" || FAIL

test_end
