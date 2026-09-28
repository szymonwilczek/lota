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

# Server TLS keypair for the enrollment endpoint, ISSUED BY the CA above.
#
# The agent passes one file as --ca-cert and it serves two roles:
# the trust anchor the CA server's TLS chain is verified against,
# and the identity of the publisher this host answers to
# (the SHA-256 of its SubjectPublicKeyInfo).
# Issuing the listener from the CA is what lets an operator name the anchor
# for both. A self-signed listener would force the identity onto the one
# certificate in the deployment that is rotated on a schedule, and a rotation
# with a new key would make every host of this publisher a new device:
# a new profile, a new AIK in a new TPM persistent handle, and consent asked again.
if [ ! -f tls.key ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out tls.key
    openssl req -new -key tls.key -out tls.csr -subj "/CN=lota-attest-ca"
    openssl x509 -req -in tls.csr -days 825 -sha256 \
	    -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt \
	    -extfile <(printf '%s\n%s\n%s\n' \
			      "subjectAltName=IP:127.0.0.1,DNS:localhost" \
			      "keyUsage=critical,digitalSignature,keyEncipherment" \
			      "extendedKeyUsage=serverAuth")
    rm -f tls.csr
    echo "generated server TLS key + cert, issued by ca.crt"
fi

echo
echo "CA material in $(pwd):"
echo "  ca.crt          -> load into every verifier:  --aik-ca-cert ca.crt"
echo "                     and the agent:             --ca-cert ca.crt"
echo "                     This is the publisher's identity on every host that"
echo "                     enrolls with it. Keep it and its key for the life of"
echo "                     the publisher; replacing it makes every enrolled"
echo "                     host a new device."
echo "  ca.key          -> lota-attest-ca --ca-key"
echo "  pseudonym.key   -> lota-attest-ca --pseudonym-key"
echo "  tls.crt/tls.key -> lota-attest-ca --tls-cert/--tls-key"
echo "                     Rotate these as often as you like: they chain to"
echo "                     ca.crt, so no host's identity moves with them."
