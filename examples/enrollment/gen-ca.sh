#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Generate the trust material an operator hosts for the LOTA attestation
# CA: the CA signing key and certificate (it signs AIK certificates), a
# device-pseudonym secret, and a server TLS keypair. Each adopter runs
# this once on their own infrastructure; the keys never leave it.
#
# It does NOT generate the TPM manufacturer EK roots -- those come from
# your hardware vendor (Infineon/Intel/STM/...) or, for swTPM, from the
# local swtpm CA. Point lota-attest-ca --ek-root at that file (see
# run.sh / README.rst).

set -euo pipefail

OUT_DIR="${1:-./ca}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"
umask 077

# CA signing key + self-signed CA certificate (ECDSA P-256). The CA
# certificate is the trust root operators load into every verifier via
# --aik-ca-cert.
if [ ! -f ca.key ]; then
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
	openssl req -x509 -new -key ca.key -days 1825 -out ca.crt \
		-subj "/CN=lota-attest-ca" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign"
	echo "generated CA key + cert"
fi

# Device-pseudonym secret. Keyed hash of the EK modulus uses this so the
# same TPM maps to a stable device id that a verifier cannot reverse to
# the EK. Keep it secret; rotating it re-pseudonymises the whole fleet.
if [ ! -f pseudonym.key ]; then
	openssl rand -out pseudonym.key 32
	echo "generated pseudonym key"
fi

# Server TLS keypair for the enrollment endpoint. The agent verifies the
# CA server against this certificate (--ca-cert on the agent side).
if [ ! -f tls.key ]; then
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out tls.key
	openssl req -x509 -new -key tls.key -days 825 -out tls.crt \
		-subj "/CN=lota-attest-ca" \
		-addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
	echo "generated server TLS key + cert"
fi

echo
echo "CA material in $(pwd):"
echo "  ca.crt          -> load into every verifier:  --aik-ca-cert ca.crt"
echo "  ca.key          -> lota-attest-ca --ca-key"
echo "  pseudonym.key   -> lota-attest-ca --pseudonym-key"
echo "  tls.crt/tls.key -> lota-attest-ca --tls-cert/--tls-key"
echo "                     and the agent: --ca-cert tls.crt"
