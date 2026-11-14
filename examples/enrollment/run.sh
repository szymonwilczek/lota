#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Starts the attestation CA, enrolls this host's AIK with it through
# credential activation, then attests once to a verifier that trusts only
# the CA certificate. Needs a TPM with a readable EK certificate, and sudo.
#
#   BIN=/usr/bin EK_ROOT=/var/lib/swtpm-localca/issuercert.pem ./run.sh
#
# EK_ROOT, required, is a PEM file of roots for -ek-root, or a pinned bundle
# directory for -ek-root-bundle. CA_ADDR defaults to 127.0.0.1:8444 and
# VERIFIER_ADDR to 127.0.0.1:9443; a taken address is refused.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${LOTA_BUILD_DIR:-$HERE/../../build}"
BIN="${BIN:-$BUILD_DIR}"
CA_DIR="${CA_DIR:-$HERE/ca}"
EK_ROOT="${EK_ROOT:?set it to a manufacturer root, or a pinned bundle dir}"
RUN_DIR="${RUN_DIR:-}"
POLICY="${POLICY:-$HERE/../../policies/testing.yaml}"

CA_ADDR="${CA_ADDR:-127.0.0.1:8444}"
VERIFIER_ADDR="${VERIFIER_ADDR:-127.0.0.1:9443}"

# a listener on the host itself or on a wildcard address holds host:port;
# any listener on the port holds a wildcard or empty host
addr_in_use() {
    local host=${1%:*} port=${1##*:}

    if command -v ss >/dev/null 2>&1; then
        ss -ltnH "sport = :$port" 2>/dev/null | awk -v h="$host" '
            function bare(a) {
                sub(/%[^\]]*/, "", a)
                gsub(/^\[|\]$/, "", a)
                return a
            }
            {
                a = $4
                sub(/:[^:]*$/, "", a)
                a = bare(a)
                w = bare(h)
                if (w == "localhost" && (a == "127.0.0.1" || a == "::1"))
                    f = 1
                if (a == w || a == "0.0.0.0" || a == "::" || a == "*" ||
                    w == "" || w == "0.0.0.0" || w == "::")
                    f = 1
            }
            END { exit !f }'
        return
    fi
    (exec 3<>"/dev/tcp/${host:-127.0.0.1}/$port") 2>/dev/null
}

# the hint is the first free port of the next 100 on the same host,
# other than the port the demo's other address takes
refuse_if_taken() {
    local var=$1 addr=$2 other=${3##*:}
    local host=${addr%:*} port=${addr##*:} try free=""

    addr_in_use "$addr" || return 0
    echo "$addr is already in use, and the demo will not take it from" \
         "whatever holds it." >&2
    if [[ "$port" =~ ^[0-9]+$ ]]; then
        for ((try = port + 1; try <= 65535 && try <= port + 100; try++)); do
            [ "$try" = "$other" ] && continue
            if ! addr_in_use "$host:$try"; then
                free=$try
                break
            fi
        done
    fi
    if [ -z "$free" ]; then
        echo "Set $var to a free host:port." >&2
        exit 1
    fi
    echo "Give the demo an address of its own:" >&2
    echo "  $var=$host:$free ./$(basename "$0")" >&2
    exit 1
}

refuse_if_taken CA_ADDR "$CA_ADDR" "$VERIFIER_ADDR"
refuse_if_taken VERIFIER_ADDR "$VERIFIER_ADDR" "$CA_ADDR"

agent="$BIN/lota-agent"
ca="$BIN/lota-attest-ca"
verifier="$BIN/lota-verifier"
for b in "$agent" "$ca" "$verifier"; do
    [ -x "$b" ] || {
        echo "missing binary: $b (run 'make all')" >&2
        exit 1
    }
done

[ -f "$CA_DIR/ca.crt" ] || {
    echo "no CA material; run ./gen-ca.sh $CA_DIR first" >&2
    exit 1
}
[ -f "$POLICY" ] || {
    echo "missing verifier policy: $POLICY" >&2
    exit 1
}
# made after the refusals, so a refused start leaves no directory
if [ -n "$RUN_DIR" ]; then
    mkdir -p "$RUN_DIR"
else
    RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lota-enrollment.XXXXXX")
fi
STATE_DB="${STATE_DB:-$RUN_DIR/verifier-state.sqlite}"

# the publisher id: SHA-256 of ca.crt's SPKI
publisher_id() {
    command -v openssl >/dev/null 2>&1 || return 1
    openssl x509 -in "$CA_DIR/ca.crt" -noout -pubkey |
        openssl pkey -pubin -outform DER |
        openssl dgst -sha256 -r | cut -d' ' -f1
}

CONSENT_ATTEMPTED=0

# --enroll records consent before it enrolls, so a failed run keeps the slot
say_what_was_left() {
    local id

    [ "$CONSENT_ATTEMPTED" = 1 ] || return 0

    echo
    if id=$(publisher_id); then
        echo "This run answered to publisher $id."
        echo "That is one of this machine's publisher slots, and a failed" \
            "run holds it exactly as a successful one does. Give it" \
            "back with:"
        echo "  sudo lota-agent --forget-publisher $id"
    else
        echo "This run claimed one of this machine's publisher slots," \
            "which a failed run holds exactly as a successful one" \
            "does. Find it and give it back with:"
        echo "  sudo lota-agent --list-publishers"
        echo "  sudo lota-agent --forget-publisher <id>"
    fi
    echo "Keeping $CA_DIR costs that one slot however often this runs;" \
        "CA material generated elsewhere is another publisher and" \
        "another slot."
}

cleanup() {
    kill "${CA_PID:-}" "${VERIFIER_PID:-}" 2>/dev/null || true
    say_what_was_left
}
trap cleanup EXIT

if [ -d "$EK_ROOT" ]; then
    ek_material=(-ek-root-bundle "$EK_ROOT")
else
    ek_material=(-ek-root "$EK_ROOT")
fi

echo "== 1/4 start the attestation CA =="
"$ca" -listen "$CA_ADDR" \
      -ca-cert "$CA_DIR/ca.crt" -ca-key "$CA_DIR/ca.key" \
      -tls-cert "$CA_DIR/tls.crt" -tls-key "$CA_DIR/tls.key" \
      -pseudonym-key "$CA_DIR/pseudonym.key" \
      "${ek_material[@]}" &
CA_PID=$!
sleep 1

echo "== 2/4 enroll the AIK (credential activation) =="
CONSENT_ATTEMPTED=1
sudo "$agent" --enroll \
     --ca-server "${CA_ADDR%%:*}" --ca-port "${CA_ADDR##*:}" \
     --ca-cert "$CA_DIR/ca.crt"
echo "AIK certificate stored in the publisher profile the CA anchor names," \
     "under /var/lib/lota/profiles/"

# tls.crt chains to ca.crt and names only 127.0.0.1 and localhost, so at
# the default VERIFIER_ADDR the agent's --ca-cert also verifies this verifier.
echo "== 3/4 start the verifier (trusts only the CA root) =="
(
    cd "$RUN_DIR"
    "$verifier" -addr "$VERIFIER_ADDR" \
                -aik-ca-cert "$CA_DIR/ca.crt" \
                -cert "$CA_DIR/tls.crt" -key "$CA_DIR/tls.key" \
                -state-db "$STATE_DB" \
                -policy "$POLICY" \
                -allow-permissive-policy \
                -allow-tofu-boot-baseline
) &
VERIFIER_PID=$!
sleep 1

# --attest refuses --server when the config has profiles, so this config
# has none; it is written as root because the agent refuses one it does not
# own.
DEMO_CONF="$RUN_DIR/demo.conf"
printf '%s\n' \
       "# Enrollment demo: no profiles; attests once to the named verifier." |
    sudo tee "$DEMO_CONF" >/dev/null

echo "== 4/4 attest =="
sudo "$agent" --attest --config "$DEMO_CONF" \
     --server "${VERIFIER_ADDR%%:*}" --port "${VERIFIER_ADDR##*:}" \
     --ca-cert "$CA_DIR/ca.crt"

echo
echo "Done. A VERIFY_OK above means the AIK was activation-bound to the EK"
echo "by the CA and the verifier trusted it through the certificate chain"
echo "alone -- the EK never reached the verifier."
