#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Writes into $1 (default ./ca) the attestation CA's key and certificate,
# its device-pseudonym secret and its TLS listener key and certificate.
# A pair whose key exists is skipped with its certificate, present or not,
# and an existing pseudonym.key is kept. The EK manufacturer roots are not
# made here.

set -euo pipefail

OUT_DIR="${1:-./ca}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"
umask 077

if [ ! -f ca.key ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
    openssl req -x509 -new -key ca.key -days 1825 -out ca.crt \
	    -subj "/CN=lota-attest-ca" \
	    -addext "basicConstraints=critical,CA:TRUE" \
	    -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "generated CA key + cert"
fi

# The HMAC key of the device id over the EK modulus, with a named tenant
# prefixed; a new key gives every TPM a new device id.
if [ ! -f pseudonym.key ]; then
    openssl rand -out pseudonym.key 32
    echo "generated pseudonym key"
fi

# Issued by ca.crt, not self-signed: the agent's --ca-cert both anchors this
# chain and names the publisher by the SHA-256 of its SPKI, so the listener
# can be replaced without moving any host to a new profile.
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
echo "  tls.crt/tls.key -> lota-attest-ca --tls-cert/--tls-key, and any"
echo "                     verifier that should present a listener the agent"
echo "                     verifies against ca.crt (--cert/--key)"
echo "                     Rotate these as often as you like: they chain to"
echo "                     ca.crt, so no host's identity moves with them."
