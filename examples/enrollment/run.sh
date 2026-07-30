#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# End-to-end Privacy CA enrollment demo on one host with a TPM (real or
# swTPM). It stands up the attestation CA, enrolls the agent's AIK
# through credential activation, then attests to a verifier that trusts
# only the CA. A software-only client cannot complete this: the CA issues
# the AIK certificate only after the TPM proves, via TPM2_ActivateCredential,
# that the AIK and the certified EK share one chip.
#
# Requires a provisioned TPM with a readable EK certificate. Override the
# binary directory and the EK manufacturer roots via the environment:
#
#   BIN=/usr/bin EK_ROOT=/var/lib/swtpm-localca/issuercert.pem ./run.sh
#
# For swTPM the EK certificate chains to the local swtpm CA; point EK_ROOT
# at its issuer certificate. For real hardware, use your vendor's roots.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$HERE/../../build}"
CA_DIR="${CA_DIR:-$HERE/ca}"
EK_ROOT="${EK_ROOT:?set EK_ROOT to the TPM manufacturer / swtpm root certificate}"
RUN_DIR="${RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/lota-enrollment.XXXXXX")}"
AIK_STORE="${AIK_STORE:-$RUN_DIR/aiks}"
NONCE_DB="${NONCE_DB:-$AIK_STORE/nonces.sqlite}"
POLICY="${POLICY:-$HERE/../../policies/testing.yaml}"

CA_ADDR="127.0.0.1:8444"
VERIFIER_ADDR="127.0.0.1:9443"

agent="$BIN/lota-agent"
ca="$BIN/lota-attest-ca"
verifier="$BIN/lota-verifier"
for b in "$agent" "$ca" "$verifier"; do
	[ -x "$b" ] || { echo "missing binary: $b (run 'make all')" >&2; exit 1; }
done

[ -f "$CA_DIR/ca.crt" ] || { echo "no CA material; run ./gen-ca.sh $CA_DIR first" >&2; exit 1; }
[ -f "$POLICY" ] || { echo "missing verifier policy: $POLICY" >&2; exit 1; }
mkdir -p "$RUN_DIR" "$AIK_STORE"

cleanup() { kill "${CA_PID:-}" "${VERIFIER_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

echo "== 1/4 start the attestation CA =="
"$ca" -listen "$CA_ADDR" \
	-ca-cert "$CA_DIR/ca.crt" -ca-key "$CA_DIR/ca.key" \
	-tls-cert "$CA_DIR/tls.crt" -tls-key "$CA_DIR/tls.key" \
	-pseudonym-key "$CA_DIR/pseudonym.key" \
	-ek-root "$EK_ROOT" &
CA_PID=$!
sleep 1

echo "== 2/4 enroll the AIK (credential activation) =="
sudo "$agent" --enroll \
	--ca-server "${CA_ADDR%%:*}" --ca-port "${CA_ADDR##*:}" \
	--ca-cert "$CA_DIR/tls.crt"
echo "AIK certificate stored in the publisher profile the CA anchor names," \
	"under /var/lib/lota/profiles/"

echo "== 3/4 start the verifier (trusts only the CA root) =="
(
	cd "$RUN_DIR"
	"$verifier" -addr "$VERIFIER_ADDR" \
		-aik-ca-cert "$CA_DIR/ca.crt" \
		-aik-store "$AIK_STORE" \
		-nonce-db "$NONCE_DB" \
		-policy "$POLICY" \
		-generate-cert -allow-permissive-policy \
		-allow-tofu-boot-baseline
) &
VERIFIER_PID=$!
sleep 1

echo "== 4/4 attest =="
sudo "$agent" --attest \
	--server "${VERIFIER_ADDR%%:*}" --port "${VERIFIER_ADDR##*:}" \
	--ca-cert "$RUN_DIR/lota-verifier.crt"

echo
echo "Done. A VERIFY_OK above means the AIK was activation-bound to the EK"
echo "by the CA and the verifier trusted it through the certificate chain"
echo "alone -- the EK never reached the verifier."
